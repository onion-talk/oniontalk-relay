FROM rust:slim-bookworm AS builder

WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libc6-dev pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim

LABEL org.opencontainers.image.title="OnionTalk Federated Relay Node (Rust Native Tokio/Axum)"
LABEL org.opencontainers.image.description="Zero-Trust Tor v3 Hidden Service & E2EE Gossip Relay for OnionTalk Messenger (oniontalk-relay-rs)"
LABEL org.opencontainers.image.authors="OnionTalk Core <security@oniontalk.org>"

# Install GPG-verified Tor 0.4.9.x (Equi-X PoW enabled) from TorProject Bookworm repo + tini PID-1 reaper and non-root UID 10014
RUN export DEBIAN_FRONTEND=noninteractive && apt-get update && apt-get dist-upgrade -y && apt-get install -y --no-install-recommends \
    gnupg gpgv apt-transport-https tini curl ca-certificates procps libcap2 \
    && curl -fsSL https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc \
       | gpg --dearmor -o /usr/share/keyrings/deb.torproject.org-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/deb.torproject.org-keyring.gpg] https://deb.torproject.org/torproject.org bookworm main" \
       > /etc/apt/sources.list.d/tor.list \
    && apt-get update && apt-get install -y --no-install-recommends \
       tor deb.torproject.org-keyring tor-geoipdb \
    && apt-get purge -y --auto-remove gnupg \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 10014 oniontalk \
    && useradd -u 10014 -g 10014 -d /data -s /usr/sbin/nologin -M oniontalk \
    && mkdir -p /data /app \
    && chown -R 10014:10014 /data /app \
    && chmod 700 /data

WORKDIR /app
COPY --from=builder /build/target/release/oniontalk-relay-rs /usr/local/bin/oniontalk-relay-rs
COPY entrypoint.sh /app/entrypoint.sh
RUN sed -i 's/\r$//' /app/entrypoint.sh \
    && chmod 755 /usr/local/bin/oniontalk-relay-rs /app/entrypoint.sh

USER 10014:10014
VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=25s --retries=3 \
    CMD curl -fsS http://127.0.0.1:${PORT:-8080}/health >/dev/null && ( [ "${EXTERNAL_TOR:-0}" = "1" ] || [ -s "${DATA_DIR:-/data}/hidden_service/hostname" ] ) || exit 1

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/app/entrypoint.sh"]
