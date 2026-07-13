use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    response::IntoResponse,
    routing::get,
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use bytes::{Bytes, BytesMut};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;

use crate::config::{self, CertMode};
use crate::crypto;
use crate::tun::TunDevice;
use crate::tunnel;
use crate::tunnel::http_server;
use crate::web;

pub async fn run(tun: TunDevice, cert_mode: CertMode) -> Result<()> {
    let psk_hash = crypto::load_preshared_secret()?;
    log::info!("preshared secret loaded");

    let http_store = http_server::HttpSessionStore::new(tun.clone(), psk_hash);
    let tunnel_state = Arc::new(TunnelState { tun, psk_hash });

    let app = http_server::add_routes(Router::new())
        .route("/ws", get(ws_handler))
        .route("/", get(web_handler))
        .route("/health", get(health_handler))
        .fallback(web_handler)
        .layer(axum::Extension(tunnel_state))
        .layer(axum::Extension(http_store));

    let addr: std::net::SocketAddr = format!("0.0.0.0:{}", config::SERVER_PORT).parse()?;
    log::info!("listening on {}", addr);

    match cert_mode {
        CertMode::Acme { domain } => {
            run_acme(app, addr, &domain).await?;
        }
        CertMode::SelfSigned {
            cert_path,
            key_path,
        } => {
            run_self_signed(app, addr, &cert_path, &key_path).await?;
        }
    }

    Ok(())
}

pub async fn run_plain(tun: TunDevice, port: u16) -> Result<()> {
    let psk_hash = crypto::load_preshared_secret()?;
    log::info!("preshared secret loaded");

    let http_store = http_server::HttpSessionStore::new(tun.clone(), psk_hash);
    let tunnel_state = Arc::new(TunnelState { tun, psk_hash });

    let app = http_server::add_routes(Router::new())
        .route("/ws", get(ws_handler))
        .route("/", get(web_handler))
        .route("/health", get(health_handler))
        .fallback(web_handler)
        .layer(axum::Extension(tunnel_state))
        .layer(axum::Extension(http_store));

    let addr: std::net::SocketAddr = format!("0.0.0.0:{}", port).parse()?;
    log::info!("listening without TLS on {}", addr);

    axum_server::bind(addr)
        .serve(app.into_make_service())
        .await
        .context("server error")?;

    Ok(())
}

async fn run_acme(
    app: Router,
    addr: std::net::SocketAddr,
    domain: &str,
) -> Result<()> {
    log::info!("using Let's Encrypt ACME for domain: {}", domain);

    let cache_path = config::cert_cache_path();
    let cache_str = cache_path
        .to_str()
        .context("non-UTF-8 cert cache path")?
        .to_string();

    let mut acme_state = rustls_acme::AcmeConfig::new(vec![domain.to_string()])
        .contact(vec!["mailto:noreply@example.com".to_string()])
        .cache_option(Some(rustls_acme::caches::DirCache::new(cache_str)))
        .directory_lets_encrypt(true)
        .state();

    let acceptor = acme_state.axum_acceptor(acme_state.default_rustls_config());

    tokio::spawn(async move {
        loop {
            match acme_state.next().await {
                Some(Ok(event)) => log::info!("ACME event: {:?}", event),
                Some(Err(e)) => log::error!("ACME error: {:?}", e),
                None => break,
            }
        }
    });

    axum_server::bind(addr)
        .acceptor(acceptor)
        .serve(app.into_make_service())
        .await
        .context("server error")?;

    Ok(())
}

async fn run_self_signed(
    app: Router,
    addr: std::net::SocketAddr,
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> Result<()> {
    log::info!(
        "using self-signed cert: {}, key: {}",
        cert_path.display(),
        key_path.display()
    );

    let config = RustlsConfig::from_pem_file(cert_path, key_path)
        .await
        .context("failed to load TLS certificates")?;

    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await
        .context("server error")?;

    Ok(())
}

#[derive(Clone)]
struct TunnelState {
    tun: TunDevice,
    psk_hash: [u8; 32],
}

async fn health_handler() -> impl IntoResponse {
    (axum::http::StatusCode::OK, "ok")
}

async fn web_handler() -> impl IntoResponse {
    axum::response::Html(web::SITE_HTML)
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    axum::Extension(state): axum::Extension<Arc<TunnelState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws(socket, state))
}

async fn handle_ws(mut socket: WebSocket, state: Arc<TunnelState>) {
    let key = match handshake(&mut socket, &state).await {
        Ok(k) => k,
        Err(e) => {
            log::error!("handshake failed: {}", e);
            return;
        }
    };

    log::info!("handshake complete, tunnel established");

    let (mut ws_write, mut ws_read) = socket.split();

    let tun = state.tun.clone();
    let (tun_tx, mut tun_rx) = mpsc::unbounded_channel::<Bytes>();

    let keepalive_tx = tun_tx.clone();
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

    let tun_reader = tokio::spawn(async move {
        let mut write_counter: u64 = 0;
        let mut buf = vec![0u8; config::MAX_FRAME_SIZE + 4];
        loop {
            match tun.recv_packet(&mut buf).await {
                Ok(len) if len >= 4 => {
                    let packet = Bytes::copy_from_slice(&buf[4..len]);
                    let encrypted = match crypto::encrypt(&key, write_counter, &packet) {
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
            Err(_) => break,
        };

        match msg {
            Message::Binary(data) => {
                let mut cursor = BytesMut::from(&data[..]);
                match tunnel::decode(&mut cursor) {
                    Ok(Some((frame_type, payload))) => match frame_type {
                        tunnel::FRAME_DATA => {
                            match crypto::decrypt(&key, read_counter, &payload) {
                                Ok(plaintext) => {
                                    if let Err(e) = state.tun.send_packet(&plaintext).await {
                                        log::warn!("tun send error: {}", e);
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
                    Err(e) => log::warn!("frame error: {}", e),
                }
            }
            Message::Ping(_) => {}
            Message::Close(_) => break,
            _ => {}
        }
    }

    keepalive_task.abort();
    tun_writer.abort();
    tun_reader.abort();
    log::info!("client disconnected");
}

async fn handshake(socket: &mut WebSocket, state: &TunnelState) -> Result<[u8; 32]> {
    let auth_msg = socket
        .recv()
        .await
        .context("expected auth message")?
        .context("ws recv error")?;

    let auth_data = match auth_msg {
        Message::Binary(data) => data,
        _ => anyhow::bail!("expected binary auth frame"),
    };

    let mut cursor = BytesMut::from(&auth_data[..]);
    let (frame_type, auth_payload) = tunnel::decode(&mut cursor)
        .context("decode auth frame")?
        .context("incomplete auth frame")?;

    anyhow::ensure!(
        frame_type == tunnel::FRAME_AUTH,
        "expected auth frame, got {}",
        frame_type
    );

    let peer_pub = crypto::verify_auth_payload(&auth_payload, &state.psk_hash)?;

    let mut server_handshake = crypto::Handshake::new();
    let key = server_handshake.derive_key(&peer_pub)?;

    let key_resp = tunnel::encode(tunnel::FRAME_KEY_EXCHANGE, server_handshake.public.as_bytes())?;

    socket
        .send(Message::Binary(key_resp.to_vec()))
        .await
        .context("send key exchange")?;

    Ok(key)
}
