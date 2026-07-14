use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use axum::{
    extract::Extension,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;
use tokio::sync::{mpsc, Mutex};
use uuid::Uuid;

use crate::config;
use crate::crypto;
use crate::tun::TunDevice;
use crate::tunnel;

const SESSION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(90);

struct HttpSession {
    key: [u8; 32],
    read_counter: u64,
    write_counter: u64,
    last_seen: Instant,
    stream_sender: Option<mpsc::UnboundedSender<Bytes>>,
}

pub struct HttpSessionStore {
    sessions: Mutex<HashMap<String, HttpSession>>,
    pub tun: TunDevice,
    pub psk_hash: [u8; 32],
}

impl HttpSessionStore {
    pub fn new(tun: TunDevice, psk_hash: [u8; 32]) -> Arc<Self> {
        let store = Arc::new(Self {
            sessions: Mutex::new(HashMap::new()),
            tun,
            psk_hash,
        });

        let cleanup_store = store.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                let mut sessions = cleanup_store.sessions.lock().await;
                let now = Instant::now();
                sessions.retain(|id, s| {
                    let keep = now.duration_since(s.last_seen) < SESSION_TIMEOUT;
                    if !keep {
                        log::info!("evicted stale http session: {}", id);
                    }
                    keep
                });
            }
        });

        let reader_store = store.clone();
        let tun = reader_store.tun.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; crate::config::MAX_FRAME_SIZE];
            loop {
                match tun.recv_packet(&mut buf).await {
                    Ok(len) if len > 0 => {
                        let packet = Bytes::copy_from_slice(&buf[..len]);
                        log::debug!("http tun reader: got {} bytes from TUN", len);
                        let mut sessions = reader_store.sessions.lock().await;
                        for (session_id, session) in sessions.iter_mut() {
                            if let Some(sender) = &session.stream_sender {
                                let encrypted = match crypto::encrypt(&session.key, session.write_counter, &packet) {
                                    Ok(v) => v,
                                    Err(e) => {
                                        log::warn!("encrypt error for session {}: {}", session_id, e);
                                        continue;
                                    }
                                };
                                session.write_counter += 1;
                                match tunnel::encode(tunnel::FRAME_DATA, &encrypted) {
                                    Ok(frame) => {
                                        let frame_len = frame.len();
                                        log::debug!("stream: sending frame {} bytes to session {}", frame_len, session_id);
                                        if sender.send(frame).is_err() {
                                            log::debug!("stream sender closed for session {}", session_id);
                                        }
                                    }
                                    Err(e) => log::warn!("encode error: {}", e),
                                }
                            }
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

        store
    }
}

pub fn add_routes(router: Router) -> Router {
    router
        .route("/http/init", post(init_handler))
        .route("/http/send", post(send_handler))
        .route("/http/stream", get(stream_handler))
}

async fn init_handler(
    Extension(store): Extension<Arc<HttpSessionStore>>,
    body: Bytes,
) -> impl IntoResponse {
    match do_init(&store, &body).await {
        Ok(resp) => (StatusCode::OK, resp),
        Err(e) => {
            log::error!("http init failed: {:?}", e);
            (StatusCode::UNAUTHORIZED, e.to_string().into_bytes())
        }
    }
}

async fn do_init(store: &HttpSessionStore, body: &[u8]) -> Result<Vec<u8>> {
    let mut cursor = BytesMut::from(body);
    let (frame_type, auth_payload) = tunnel::decode(&mut cursor)?
        .ok_or_else(|| anyhow::anyhow!("incomplete auth frame"))?;

    anyhow::ensure!(frame_type == tunnel::FRAME_AUTH, "expected auth frame");

    let peer_pub = crypto::verify_auth_payload(&auth_payload, &store.psk_hash)?;

    let mut server_handshake = crypto::Handshake::new();
    let key = server_handshake.derive_key(&peer_pub)?;

    let session_id = Uuid::new_v4().to_string();

    {
        let mut sessions = store.sessions.lock().await;
        sessions.insert(
            session_id.clone(),
            HttpSession {
                key,
                read_counter: 0,
                write_counter: 0,
                last_seen: Instant::now(),
                stream_sender: None,
            },
        );
    }

    let key_frame = tunnel::encode(tunnel::FRAME_KEY_EXCHANGE, server_handshake.public.as_bytes())?;

    let mut response = session_id.into_bytes();
    response.extend_from_slice(&key_frame);
    Ok(response)
}

async fn send_handler(
    Extension(store): Extension<Arc<HttpSessionStore>>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let session_id = match headers
        .get("x-session-id")
        .and_then(|v| v.to_str().ok())
    {
        Some(id) => id.to_string(),
        None => return (StatusCode::BAD_REQUEST, "missing x-session-id".to_string()),
    };

    let mut sessions = store.sessions.lock().await;
    let session = match sessions.get_mut(&session_id) {
        Some(s) => s,
        None => return (StatusCode::UNAUTHORIZED, "invalid session".to_string()),
    };

    session.last_seen = Instant::now();

    let mut cursor = BytesMut::from(&body[..]);
    let (frame_type, payload) = match tunnel::decode(&mut cursor) {
        Ok(Some(t)) => t,
        Ok(None) => return (StatusCode::BAD_REQUEST, "incomplete frame".to_string()),
        Err(e) => return (StatusCode::BAD_REQUEST, format!("frame error: {}", e)),
    };

    match frame_type {
        tunnel::FRAME_DATA => {
            match crypto::decrypt(&session.key, session.read_counter, &payload) {
                Ok(plaintext) => {
                    if let Err(e) = store.tun.send_packet(&plaintext).await {
                        log::warn!("tun send error ({} bytes): {}", plaintext.len(), e);
                    }
                    session.read_counter += 1;
                }
                Err(e) => log::warn!("decrypt error: {}", e),
            }
        }
        tunnel::FRAME_KEEPALIVE => {}
        t => log::warn!("unknown frame type: {}", t),
    }

    (StatusCode::OK, "ok".to_string())
}

async fn stream_handler(
    Extension(store): Extension<Arc<HttpSessionStore>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let session_id = match headers
        .get("x-session-id")
        .and_then(|v| v.to_str().ok())
    {
        Some(id) => id.to_string(),
        None => {
            return (StatusCode::BAD_REQUEST, "missing x-session-id").into_response();
        }
    };

    let _key = {
        let mut sessions = store.sessions.lock().await;
        let session = match sessions.get_mut(&session_id) {
            Some(s) => s,
            None => return (StatusCode::UNAUTHORIZED, "invalid session").into_response(),
        };
        session.last_seen = Instant::now();
        session.key
    };

    // Create a channel for this stream's frames
    let (frame_tx, frame_rx) = mpsc::unbounded_channel::<Bytes>();

    // Clone sender for keepalive task before registering
    let keepalive_tx = frame_tx.clone();

    // Register sender with session
    {
        let mut sessions = store.sessions.lock().await;
        if let Some(session) = sessions.get_mut(&session_id) {
            session.stream_sender = Some(frame_tx);
        }
    }

    // Spawn keepalive task for this stream
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(config::KEEPALIVE_INTERVAL);
        loop {
            interval.tick().await;
            if let Ok(frame) = tunnel::encode(tunnel::FRAME_KEEPALIVE, &[]) {
                if keepalive_tx.send(frame).is_err() {
                    break;
                }
            }
        }
});
    
    // Stream raw frames directly (no HTTP chunked encoding)
    let stream = tokio_stream::wrappers::UnboundedReceiverStream::new(frame_rx)
        .map(Ok::<_, std::convert::Infallible>);

    (
        StatusCode::OK,
        [
            ("Content-Type", "application/octet-stream"),
            ("Cache-Control", "no-cache"),
            ("Connection", "close"),
        ],
        axum::body::Body::from_stream(stream),
    )
        .into_response()
}