#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "=== Building Docker test image (multi-stage, Rust compiled inside) ==="
docker build -t bobvpn-test -f Dockerfile.test .

echo "=== Creating shared preshared secret ==="
SECRET_DIR=$(mktemp -d)
# 32 random bytes, hex-encoded
openssl rand -hex 32 > "$SECRET_DIR/secret"

echo "=== Running end-to-end test ==="
cleanup() {
    echo "=== Cleaning up ==="
    docker rm -f bobvpn-server bobvpn-client 2>/dev/null || true
    docker network rm bobvpn-test-net 2>/dev/null || true
    rm -rf "$SECRET_DIR"
}
trap cleanup EXIT

docker network create bobvpn-test-net

echo "--- Starting server ---"
docker run -d --name bobvpn-server \
    --cap-add NET_ADMIN \
    --device /dev/net/tun \
    --network bobvpn-test-net \
    -v "$SECRET_DIR/secret:/root/.bobvpn/secret:ro" \
    -e RUST_LOG=info \
    bobvpn-test \
    server --insecure

sleep 3
echo "=== Server logs ==="
docker logs bobvpn-server 2>&1 || true

if docker logs bobvpn-server 2>&1 | grep -qi "error.*panic\|error.*failed"; then
    echo "ERROR: Server reported errors"
    exit 1
fi
echo "Server started successfully"

echo "--- Starting client ---"
docker run -d --name bobvpn-client \
    --cap-add NET_ADMIN \
    --device /dev/net/tun \
    --network bobvpn-test-net \
    -v "$SECRET_DIR/secret:/root/.bobvpn/secret:ro" \
    -e RUST_LOG=info \
    bobvpn-test \
    client --server bobvpn-server --insecure

sleep 6

echo "=== Client logs ==="
docker logs bobvpn-client 2>&1 || true
echo ""
echo "=== Server logs ==="
docker logs bobvpn-server 2>&1 || true

if docker logs bobvpn-client 2>&1 | grep -qi "error.*reconnecting\|error.*panic"; then
    echo "ERROR: Client reported errors"
    exit 1
fi

if docker logs bobvpn-client 2>&1 | grep -q "tunnel established"; then
    echo "SUCCESS: Handshake completed!"
else
    echo "FAIL: No handshake completion detected"
    exit 1
fi

sleep 10

echo "=== Client logs after keepalive ==="
docker logs bobvpn-client 2>&1 || true
echo ""
echo "=== Server logs after keepalive ==="
docker logs bobvpn-server 2>&1 || true

if docker logs bobvpn-client 2>&1 | grep -q "tunnel established" &&
   docker ps --format '{{.Names}}' | grep -q bobvpn-client &&
   docker ps --format '{{.Names}}' | grep -q bobvpn-server; then
    echo "SUCCESS: Both processes still running after keepalive interval"
else
    echo "FAIL: One or both processes crashed"
    exit 1
fi

echo ""
echo "=== ALL TESTS PASSED ==="
