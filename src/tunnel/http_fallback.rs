use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::config;
use crate::crypto;
use crate::tun::TunDevice;
use crate::tunnel;

#[derive(Clone)]
pub struct HttpFallbackClient {
    host: String,
    port: u16,
    session_id: String,
}

async fn http_post(
    host: &str,
    port: u16,
    path: &str,
    body: &[u8],
    session_id: Option<&str>,
) -> Result<(u16, Bytes)> {
    log::debug!("http_post: resolving {}:{}", host, port);
    let addr = tokio::net::lookup_host(format!("{}:{}", host, port))
        .await?
        .next()
        .context("dns resolution failed")?;
    log::debug!("http_post: connecting to {}", addr);
    let mut stream = TcpStream::connect(addr).await?;
    log::debug!("http_post: connected");

    let content_length = body.len();
    let mut request = format!(
        "POST {} HTTP/1.1\r\nHost: {}:{}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n",
        path, host, port, content_length
    );
    if let Some(sid) = session_id {
        request.push_str(&format!("X-Session-Id: {}\r\n", sid));
    }
    request.push_str("Connection: close\r\n\r\n");

    log::debug!("http_post: writing request ({} bytes)", request.len() + content_length);
    stream.write_all(request.as_bytes()).await?;
    if !body.is_empty() {
        stream.write_all(body).await?;
    }
    stream.flush().await?;
    log::debug!("http_post: request written, reading response");

    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader.read_line(&mut status_line).await?;
    log::debug!("http_post: status line: {}", status_line.trim());

    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .context("invalid status line")?;

    let mut content_length: Option<usize> = None;
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).await?;
        if header == "\r\n" || header == "\n" {
            break;
        }
        if header.to_lowercase().starts_with("content-length:") {
            if let Some(len) = header.split(':').nth(1).and_then(|v| v.trim().parse::<usize>().ok()) {
                content_length = Some(len);
            }
        }
    }

    let body_buf = match content_length {
        Some(len) => {
            let mut buf = vec![0u8; len];
            reader.read_exact(&mut buf).await?;
            buf
        }
        None => {
            let mut buf = Vec::new();
            reader.read_to_end(&mut buf).await?;
            buf
        }
    };
    log::debug!("http_post: read {} bytes response body", body_buf.len());

    Ok((status_code, Bytes::from(body_buf)))
}

impl HttpFallbackClient {
    pub async fn connect(
        server_hostname: &str,
        port: u16,
        psk_hash: &[u8; 32],
        _insecure: bool,
    ) -> Result<(Self, [u8; 32])> {
        let mut handshake = crypto::Handshake::new();
        let auth_payload = crypto::build_auth_payload(&handshake, psk_hash);
        let auth_frame = tunnel::encode(tunnel::FRAME_AUTH, &auth_payload)?;

        let (status, resp_bytes) = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            http_post(server_hostname, port, "/http/init", &auth_frame, None),
        )
        .await
        .context("http init request timed out")?
        .context("http init request failed")?;

        anyhow::ensure!(status == 200, "http init rejected: {}", status);

        let session_id = std::str::from_utf8(&resp_bytes[..36])
            .context("invalid session id")?
            .to_string();
        let key_frame_data = &resp_bytes[36..];

        let mut cursor = BytesMut::from(key_frame_data);
        let (frame_type, key_payload) =
            tunnel::decode(&mut cursor)?.context("expected key exchange frame")?;
        anyhow::ensure!(
            frame_type == tunnel::FRAME_KEY_EXCHANGE,
            "expected key exchange, got {}",
            frame_type
        );

        let peer_pub_bytes: [u8; crypto::PUBKEY_SIZE] =
            key_payload[..crypto::PUBKEY_SIZE].try_into()?;
        let peer_pub = x25519_dalek::PublicKey::from(peer_pub_bytes);
        let shared_key = handshake.derive_key(&peer_pub)?;

        log::info!("http fallback handshake complete");
        Ok((Self { host: server_hostname.to_string(), port, session_id }, shared_key))
    }

    pub async fn send_frame(&self, frame: &[u8]) -> Result<()> {
        let (status, _) = http_post(
            &self.host,
            self.port,
            "/http/send",
            frame,
            Some(&self.session_id),
        )
        .await?;
        anyhow::ensure!(status == 200, "http send rejected: {}", status);
        Ok(())
    }

    pub async fn open_stream(
        &self,
        frame_tx: mpsc::UnboundedSender<(u8, Bytes)>,
    ) -> Result<()> {
        let addr = tokio::net::lookup_host(format!("{}:{}", self.host, self.port))
            .await?
            .next()
            .context("dns resolution failed")?;
        let stream = TcpStream::connect(addr).await?;

        let request = format!(
            "GET /http/stream HTTP/1.1\r\nHost: {}:{}\r\nX-Session-Id: {}\r\n\r\n",
            self.host, self.port, self.session_id
        );
        let (reader_half, mut writer_half) = stream.into_split();
        writer_half.write_all(request.as_bytes()).await?;
        writer_half.flush().await?;

        let mut reader = BufReader::new(reader_half);
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        if !line.starts_with("HTTP/1.1 200") {
            anyhow::bail!("stream rejected: {}", line.trim());
        }
        loop {
            line.clear();
            reader.read_line(&mut line).await?;
            if line == "\r\n" || line == "\n" {
                break;
            }
        }

        // Read raw length-prefixed frames from response body
        // Frame format: 2 bytes length (big-endian) + 1 byte type + payload
        let mut buf = BytesMut::new();
        loop {
            // Read frame length (2 bytes, big-endian)
            while buf.len() < 2 {
                let n = reader.read_buf(&mut buf).await?;
                if n == 0 {
                    return Ok(()); // EOF
                }
            }
            let frame_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
            
            // Read frame type (1 byte) + payload
            let total_needed = 2 + 1 + frame_len;
            while buf.len() < total_needed {
                let n = reader.read_buf(&mut buf).await?;
                if n == 0 {
                    return Ok(()); // EOF
                }
            }
            
            let frame_type = buf[2];
            let payload = buf[3..total_needed].to_vec().into();
            let _ = buf.split_off(total_needed);

            if frame_tx.send((frame_type, payload)).is_err() {
                return Ok(());
            }
        }
    }
}

pub async fn run_tunnel(
    tun: &TunDevice,
    client: HttpFallbackClient,
    shared_key: [u8; 32],
) -> Result<()> {
    let (frame_tx, mut frame_rx) = mpsc::unbounded_channel::<(u8, Bytes)>();
    let (send_tx, mut send_rx) = mpsc::unbounded_channel::<Bytes>();

    let stream_client = client.clone();
    let stream_task = tokio::spawn(async move {
        while let Err(e) = stream_client.clone().open_stream(frame_tx.clone()).await {
            log::warn!("http stream error: {}, reconnecting in 1s", e);
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    });

    let keepalive_tx = send_tx.clone();
    let keepalive_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(config::KEEPALIVE_INTERVAL);
        interval.tick().await;
        loop {
            interval.tick().await;
            match tunnel::encode(tunnel::FRAME_KEEPALIVE, &[]) {
                Ok(frame) => {
                    if keepalive_tx.send(frame).is_err() {
                        break;
                    }
                }
                Err(e) => log::warn!("keepalive encode error: {}", e),
            }
        }
    });

    let send_client = client.clone();
    let send_task = tokio::spawn(async move {
        while let Some(frame) = send_rx.recv().await {
            if send_client.send_frame(&frame).await.is_err() {
                log::warn!("http send failed");
                break;
            }
        }
    });

    let tun_reader_tun = tun.clone();
    let tun_reader = tokio::spawn(async move {
        let mut write_counter: u64 = 0;
        let mut buf = vec![0u8; config::MAX_FRAME_SIZE];
        loop {
            match tun_reader_tun.recv_packet(&mut buf).await {
                Ok(len) if len > 0 => {
                    let packet = Bytes::copy_from_slice(&buf[..len]);
                    let encrypted = match crypto::encrypt(&shared_key, write_counter, &packet) {
                        Ok(v) => v,
                        Err(e) => {
                            log::warn!("encrypt error: {}", e);
                            break;
                        }
                    };
                    write_counter += 1;
                    match tunnel::encode(tunnel::FRAME_DATA, &encrypted) {
                        Ok(frame) => {
                            if send_tx.send(frame).is_err() {
                                break;
                            }
                        }
                        Err(e) => log::warn!("encode error: {}", e),
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    log::error!("tun read error: {}", e);
                    break;
                }
            }
        }
    });

    let mut read_counter: u64 = 0;

    while let Some((frame_type, payload)) = frame_rx.recv().await {
        match frame_type {
            tunnel::FRAME_DATA => {
                match crypto::decrypt(&shared_key, read_counter, &payload) {
                    Ok(plaintext) => {
                        if let Err(e) = tun.send_packet(&plaintext).await {
                            log::warn!("tun send error ({} bytes): {}", plaintext.len(), e);
                        }
                        read_counter += 1;
                    }
                    Err(e) => log::warn!("decrypt error: {}", e),
                }
            }
            tunnel::FRAME_KEEPALIVE => {}
            t => log::warn!("unknown frame type: {}", t),
        }
    }

    keepalive_task.abort();
    stream_task.abort();
    send_task.abort();
    tun_reader.abort();

    Ok(())
}
