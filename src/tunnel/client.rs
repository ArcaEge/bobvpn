use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

use crate::config;
use crate::crypto;
use crate::tun::TunDevice;
use crate::tunnel;
use crate::tunnel::http_fallback;

pub async fn run(tun: TunDevice, server_hostname: &str) -> Result<()> {
    let psk_hash = crypto::load_preshared_secret()?;
    reconnect_loop(tun, server_hostname, psk_hash, false).await
}

pub async fn run_insecure(tun: TunDevice, server_hostname: &str) -> Result<()> {
    let psk_hash = crypto::load_preshared_secret()?;
    reconnect_loop(tun, server_hostname, psk_hash, true).await
}

pub async fn run_http(tun: TunDevice, server_hostname: &str, insecure: bool) -> Result<()> {
    let psk_hash = crypto::load_preshared_secret()?;
    let mut attempt = 0u32;
    loop {
        match try_http_connect(&tun, server_hostname, &psk_hash, insecure).await {
            Ok(()) => log::info!("http tunnel closed, reconnecting"),
            Err(e) => log::error!("http tunnel error: {}", e),
        }
        attempt += 1;
        let delay = std::cmp::min(
            config::RECONNECT_BASE_DELAY * 2u32.pow(attempt.saturating_sub(1)),
            config::RECONNECT_MAX_DELAY,
        );
        log::info!("reconnecting in {:?}", delay);
        tokio::time::sleep(delay).await;
    }
}

async fn reconnect_loop(
    tun: TunDevice,
    server_hostname: &str,
    psk_hash: [u8; 32],
    insecure: bool,
) -> Result<()> {
    let mut attempt = 0u32;
    loop {
        match try_connect(&tun, server_hostname, &psk_hash, insecure).await {
            Ok(()) => log::info!("connection closed, reconnecting"),
            Err(e) => log::error!("tunnel error: {}", e),
        }
        attempt += 1;
        let delay = std::cmp::min(
            config::RECONNECT_BASE_DELAY * 2u32.pow(attempt.saturating_sub(1)),
            config::RECONNECT_MAX_DELAY,
        );
        log::info!("reconnecting in {:?}", delay);
        tokio::time::sleep(delay).await;
    }
}

async fn try_connect(
    tun: &TunDevice,
    server_hostname: &str,
    psk_hash: &[u8; 32],
    insecure: bool,
) -> Result<()> {
    match try_ws_connect(tun, server_hostname, psk_hash, insecure).await {
        Ok(()) => return Ok(()),
        Err(e) => log::warn!("ws connect failed, trying http: {}", e),
    }
    try_http_connect(tun, server_hostname, psk_hash, insecure).await
}

async fn try_ws_connect(
    tun: &TunDevice,
    server_hostname: &str,
    psk_hash: &[u8; 32],
    insecure: bool,
) -> Result<()> {
    let port = if insecure {
        config::DEV_PORT
    } else {
        config::SERVER_PORT
    };
    let url = format!("wss://{}:{}/ws", server_hostname, port);
    log::info!("connecting to {}", url);

    let (ws_stream, _) = if insecure {
        connect_insecure(&url).await?
    } else {
        tokio_tungstenite::connect_async(&url)
            .await
            .context("websocket connection failed")?
    };

    log::info!("websocket connected, performing handshake");

    let (mut ws_write, mut ws_read) = ws_stream.split();

    let mut handshake = crypto::Handshake::new();
    let auth_payload = crypto::build_auth_payload(&handshake, psk_hash);
    let auth_frame = tunnel::encode(tunnel::FRAME_AUTH, &auth_payload)?;
    ws_write.send(Message::Binary(auth_frame.to_vec())).await?;

    let key_resp = wait_for_frame(&mut ws_read)
        .await?
        .context("expected key exchange")?;
    anyhow::ensure!(
        key_resp.0 == tunnel::FRAME_KEY_EXCHANGE,
        "unexpected frame type: {}",
        key_resp.0
    );
    anyhow::ensure!(
        key_resp.1.len() >= crypto::PUBKEY_SIZE,
        "key exchange too short"
    );

    let peer_pub_bytes: [u8; crypto::PUBKEY_SIZE] = key_resp.1[..crypto::PUBKEY_SIZE].try_into()?;
    let peer_pub = x25519_dalek::PublicKey::from(peer_pub_bytes);

    let shared_key = handshake.derive_key(&peer_pub)?;
    log::info!("handshake complete, tunnel established");

    run_ws_tunnel(tun, ws_write, ws_read, shared_key).await
}

async fn try_http_connect(
    tun: &TunDevice,
    server_hostname: &str,
    psk_hash: &[u8; 32],
    insecure: bool,
) -> Result<()> {
    let port = if insecure {
        config::DEV_PORT
    } else {
        config::SERVER_PORT
    };
    log::info!("connecting via http fallback to {}:{}", server_hostname, port);

    let (client, shared_key) =
        http_fallback::HttpFallbackClient::connect(server_hostname, port, psk_hash, insecure)
            .await?;

    log::info!("http fallback handshake complete, tunnel established");
    http_fallback::run_tunnel(tun, client, shared_key).await
}

async fn run_ws_tunnel(
    tun: &TunDevice,
    mut ws_write: futures_util::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        Message,
    >,
    mut ws_read: futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
    shared_key: [u8; 32],
) -> Result<()> {
    let (tun_tx, mut tun_rx) = mpsc::unbounded_channel::<Bytes>();

    let keepalive_tx = tun_tx.clone();
    let tun_reader_tun = tun.clone();
    let tun_reader = tokio::spawn(async move {
        let mut write_counter: u64 = 0;
        let mut buf = vec![0u8; config::MAX_FRAME_SIZE];
        loop {
            match tun_reader_tun.recv_packet(&mut buf).await {
                Ok(len) if len > 0 => {
                    log::debug!("TUN read {} bytes, first 20: {:02x?}", len, &buf[..len.min(20)]);
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
                            if tun_tx.send(frame).is_err() {
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

    let tun_writer = tokio::spawn(async move {
        while let Some(frame) = tun_rx.recv().await {
            if ws_write
                .send(Message::Binary(frame.to_vec()))
                .await
                .is_err()
            {
                break;
            }
        }
    });

    let mut read_counter: u64 = 0;

    while let Some(msg_result) = ws_read.next().await {
        let msg = match msg_result {
            Ok(m) => m,
            Err(e) => {
                log::warn!("ws error: {}", e);
                break;
            }
        };

        match msg {
            Message::Binary(data) => {
                let mut cursor = BytesMut::from(&data[..]);
                match tunnel::decode(&mut cursor) {
                    Ok(Some((frame_type, payload))) => match frame_type {
                        tunnel::FRAME_DATA => {
                            match crypto::decrypt(&shared_key, read_counter, &payload) {
                                Ok(plaintext) => {
                                    log::debug!("WS recv DATA frame, writing {} bytes to TUN", plaintext.len());
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
                    },
                    Ok(None) => {}
                    Err(e) => log::warn!("frame decode error: {}", e),
                }
            }
            Message::Ping(_) => {}
            Message::Close(_) | Message::Frame(_) => break,
            _ => {}
        }
    }

    keepalive_task.abort();
    tun_reader.abort();
    tun_writer.abort();

    Ok(())
}

async fn connect_insecure(
    url: &str,
) -> Result<
    (
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        tokio_tungstenite::tungstenite::handshake::client::Response,
    ),
> {
    // Replace wss:// with ws:// to skip TLS entirely
    let ws_url = url.replacen("wss://", "ws://", 1);
    tokio_tungstenite::connect_async(&ws_url)
        .await
        .context("insecure websocket connection failed")
}

async fn wait_for_frame(
    reader: &mut futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
) -> Result<Option<(u8, Bytes)>> {
    while let Some(msg) = reader.next().await {
        match msg? {
            Message::Binary(data) => {
                let mut cursor = BytesMut::from(&data[..]);
                return tunnel::decode(&mut cursor);
            }
            Message::Close(_) => return Ok(None),
            _ => {}
        }
    }
    Ok(None)
}
