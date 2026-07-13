# Deploying bobvpn on Dokploy

## Prerequisites

- A VPS with **Docker** and **Dokploy** installed
- The **`tun` kernel module** loaded: `sudo modprobe tun`
- Confirm `/dev/net/tun` exists: `ls -la /dev/net/tun`
- **IP forwarding** enabled on the host: `sudo sysctl -w net.ipv4.ip_forward=1`

## Deployment

### 1. Push to Git

Push this repo to GitHub / GitLab.

### 2. Add service in Dokploy UI

1. Click **"Create Service"** → choose **"Docker Compose"**
2. Point to your repo URL (or paste the `docker-compose.yml` contents directly)
3. Add a **Domain** in the Dokploy UI → Dokploy's built-in Traefik automatically provisions a **Let's Encrypt** certificate
4. Set `PORT=8080` in the environment variables (if not using default)

### 3. Container requirements

Dokploy's Docker Compose mode handles `cap_add` and `devices` correctly. The `docker-compose.yml` in this repo already includes:

```yaml
cap_add:
  - NET_ADMIN
devices:
  - /dev/net/tun
```

No manual configuration needed.

### 4. How TLS works

- **Public side**: Dokploy's Traefik reverse proxy terminates HTTPS on port 443. Let's Encrypt certs are auto-provisioned.
- **Internal side**: Traefik forwards `wss://` traffic as plain `ws://` to the bobvpn container on **port 8080**.
- **bobvpn runs with `--insecure`** (plain WebSocket), so there's no double TLS.

### 5. Client connection

```bash
bobvpn client --server vpn.yourdomain.com
```

No `--insecure` flag needed — the client connects with `wss://` and verifies the Let's Encrypt cert.

## Alternative: ACME mode (server fetches own certs)

If you prefer the server to handle TLS directly instead of using Dokploy's Traefik proxy:

1. Expose port 443 in `docker-compose.yml`:
   ```yaml
   ports:
     - "443:443"
   ```
2. Disable Dokploy's domain management for this service
3. Run: `bobvpn server --domain vpn.yourdomain.com`

The server will fetch its own Let's Encrypt certificate and listen directly on 443.

## PSK Persistence

The preshared secret is stored in a Docker volume (`bobvpn-data:/root/.bobvpn`). It's generated automatically on first start and persists across restarts.

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `Cannot open TUN device` | Ensure `sudo modprobe tun` and `/dev/net/tun` exists |
| `Permission denied` on TUN | Container missing `cap_add: NET_ADMIN` |
| WebSocket connection fails | Verify Traefik is proxying `wss://` → container port correctly |
| Client cert error | If using Dokploy proxy, connect without `--insecure` |
