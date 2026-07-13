use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;
use tokio::sync::mpsc;

use crate::config;
use crate::crypto;
use crate::tun::TunDevice;
use crate::tunnel;

#[derive(Clone)]
pub struct HttpFallbackClient {
    http_client: reqwest::Client,
    base_url: String,
    session_id: String,
}

impl HttpFallbackClient {
    pub async fn connect(
        server_hostname: &str,
        port: u16,
        psk_hash: &[u8; 32],
        insecure: bool,
    ) -> Result<(Self, [u8; 32])> {
        let scheme = if insecure { "http" } else { "https" };
        let base_url = format!("{}://{}:{}", scheme, server_hostname, port);

        let http_client = reqwest::Client::builder()
            .danger_accept_invalid_certs(insecure)
            .build()?;

        let mut handshake = crypto::Handshake::new();
        let auth_payload = crypto::build_auth_payload(&handshake, psk_hash);
        let auth_frame = tunnel::encode(tunnel::FRAME_AUTH, &auth_payload)?;

        let resp = http_client
            .post(format!("{}/http/init", base_url))
            .body(auth_frame.to_vec())
            .send()
            .await
            .context("http init request failed")?;

        let status = resp.status();
        let resp_bytes = resp.bytes().await?;
        anyhow::ensure!(status.is_success(), "http init rejected: {}", status);

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
        Ok((Self { http_client, base_url, session_id }, shared_key))
    }

    pub async fn send_frame(&self, frame: &[u8]) -> Result<()> {
        let resp = self
            .http_client
            .post(format!("{}/http/send", self.base_url))
            .header("X-Session-Id", &self.session_id)
            .body(frame.to_vec())
            .send()
            .await?;
        let status = resp.status();
        anyhow::ensure!(status.is_success(), "http send rejected: {}", status);
        Ok(())
    }

    pub async fn open_stream(
        &self,
        frame_tx: mpsc::UnboundedSender<(u8, Bytes)>,
    ) -> Result<()> {
        let resp = self
            .http_client
            .get(format!("{}/http/stream", self.base_url))
            .header("X-Session-Id", &self.session_id)
            .send()
            .await?;

        anyhow::ensure!(
            resp.status().is_success(),
            "http stream rejected: {}",
            resp.status()
        );

        let mut stream = resp.bytes_stream();
        let mut buf = BytesMut::new();

        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            buf.extend_from_slice(&chunk);
            while let Some((frame_type, payload)) = tunnel::decode(&mut buf)? {
                if frame_tx.send((frame_type, payload)).is_err() {
                    return Ok(());
                }
            }
        }

        Ok(())
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
