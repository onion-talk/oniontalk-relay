FROM rust:slim-bookworm AS builder

WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config build-essential libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim

LABEL org.opencontainers.image.title="OnionTalk Federated Relay Node (Rust Native Tokio/Axum)" \
      org.opencontainers.image.version="1.5.7" \
      org.opencontainers.image.description="Zero-Trust Tor v3 Hidden Service & E2EE Gossip Relay for OnionTalk Messenger (oniontalk-relay-rs v1.5.7)" \
      org.opencontainers.image.authors="OnionTalk Core <security@oniontalk.org>"

RUN apt-get update && apt-get install -y --no-install-recommends \
    tor curl ca-certificates procps \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /data && chmod 777 /data

WORKDIR /app
COPY --from=builder /build/target/release/oniontalk-relay-rs /usr/local/bin/oniontalk-relay-rs
COPY entrypoint.sh /app/entrypoint.sh
RUN sed -i 's/\r$//' /app/entrypoint.sh \
    && chmod +x /usr/local/bin/oniontalk-relay-rs /app/entrypoint.sh \
    && chmod -R 755 /app

VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:${PORT:-8080}/health || exit 1

CMD ["/app/entrypoint.sh"]
