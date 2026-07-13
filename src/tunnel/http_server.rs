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

use crate::crypto;
use crate::tun::TunDevice;
use crate::tunnel;

const SESSION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(90);

struct HttpSession {
    key: [u8; 32],
    read_counter: u64,
    last_seen: Instant,
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
                last_seen: Instant::now(),
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

    let key = {
        let mut sessions = store.sessions.lock().await;
        let session = match sessions.get_mut(&session_id) {
            Some(s) => s,
            None => return (StatusCode::UNAUTHORIZED, "invalid session").into_response(),
        };
        session.last_seen = Instant::now();
        session.key
    };

    let (frame_tx, frame_rx) = mpsc::unbounded_channel::<Bytes>();

    let tun = store.tun.clone();
    let _tun_reader = tokio::spawn(async move {
        let mut write_counter: u64 = 0;
        let mut buf = vec![0u8; crate::config::MAX_FRAME_SIZE + 4];
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
                            if frame_tx.send(frame).is_err() {
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

    let stream = tokio_stream::wrappers::UnboundedReceiverStream::new(frame_rx)
        .map(Ok::<_, std::convert::Infallible>);

    (
        StatusCode::OK,
        [
            ("Content-Type", "application/octet-stream"),
            ("Cache-Control", "no-cache"),
        ],
        axum::body::Body::from_stream(stream),
    )
        .into_response()
}
