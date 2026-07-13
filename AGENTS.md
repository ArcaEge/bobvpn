# bobvpn — Agent Memory

## Objective
Rust VPN-over-HTTPS binary that tunnels over port 443 with a camouflage static site, NM desktop integration, ACME or self-signed certs, HTTP streaming fallback when WebSocket is blocked, and builds cleanly.

## Structure
```
src/
  main.rs       — CLI (clap), TUN creation, sysctl/iptables, entry points
  config.rs     — constants (IPs, ports, intervals), CertMode enum, path helpers
  crypto.rs     — X25519 + HKDF key exchange, ChaCha20-Poly1305 AEAD, PSK load/generate
  tun.rs        — TunDevice wrapper (Arc<AsyncDevice}), Clone, recv_packet/send_packet
  nm.rs         — NetworkManager integration via nmcli (best-effort, errors swallowed)
  web.rs        — Static file server for camouflage site
  tunnel/
    mod.rs      — Frame constants, encode/decode helpers
    client.rs   — WS client + HTTP fallback, auth handshake, keepalive (30s), tun<->WS bridge
    server.rs   — WS server + HTTP fallback routes, auth verify, key exchange, TLS/ACME
    http_fallback.rs — Client HTTP streaming transport (reqwest POST /http/init, POST /http/send, GET /http/stream)
    http_server.rs   — Server HTTP session store, POST/GET handlers, TUN reader per stream
```

## Conventions
- `RUST_LOG=info` / `RUST_LOG=debug` for logging
- `anyhow::Result` / `anyhow::Context` / `anyhow::bail!` everywhere
- `axum::Extension(state)` to pass shared state — NOT `with_state()` (keeps `Router<()>`)
- `pub const` for frame types, durations, IPs; `pub enum CertMode` for TLS config
- TUN reader spawns increment a `write_counter` (u64) for AEAD nonces
- Keepalive: separate tokio task writes `FRAME_KEEPALIVE` frames into shared mpsc channel
- No comments in code unless required

## Networking
- TUN subnet: `10.107.1.0/24`, server=`10.107.1.1`, client=`10.107.1.2`
- Server port: 443 with TLS, 8080 insecure (`--insecure` flag for both server & client)
- Client `--insecure`: replaces `wss://` → `ws://` (plain WS, no TLS)
- MTU: 1280, MAX_FRAME_SIZE: 1500
- Reconnect: exponential backoff 1s → 30s
- HTTP fallback:
  - Client tries WS first, falls back to HTTP streaming on failure
  - POST `/http/init` — auth + key exchange, returns session_id + key_exchange frame
  - POST `/http/send` — sends encrypted frames from client to server (decrypted → TUN)
  - GET `/http/stream` — persistent HTTP stream, TUN reader per session encrypts frames → response body
  - Cleanup: stale sessions evicted after 90s inactivity

## Crypto
- Auth: PSK (32B from file or auto-generated) + X25519 ephemeral → HKDF-SHA256 → AEAD key
- Frame encryption: ChaCha20-Poly1305, nonce = `counter.to_le_bytes()` (zero-padded to 12 bytes)
- Nonce counters: per-direction u64, monotonic (writer in tun_reader, reader in main loop)
- All crypto functions return `Result` (no panics)

## Known state
- All source files written, builds cleanly with zero warnings and zero clippy warnings
- No `.unwrap()` or `.expect()` calls in `src/` — all errors propagated via `anyhow` or logged
- Both client and server send `FRAME_KEEPALIVE` every 30s via a dedicated tokio task
- sysctl/iptables/ip-route failures logged as warnings instead of silently discarded
- Docker tests pass: WS handshake + keepalive (`test_docker.sh`), HTTP fallback handshake + keepalive (`test_http_fallback.sh` with `--force-http`)
- No CI configured
- `nm::register_tun` returns `()` — errors internal (expected for headless/CI)
