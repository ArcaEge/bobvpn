FROM rust:bookworm AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates wget iproute2 iptables procps && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/bobvpn /usr/local/bin/bobvpn
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD wget --no-verbose --tries=1 --spider http://localhost:${PORT:-8080}/health || exit 1
ENTRYPOINT ["bobvpn"]
CMD ["server", "--insecure"]
