FROM python:3.12.8-slim-bookworm

LABEL org.opencontainers.image.title="OnionTalk Federated Relay Node (All-in-One)"
LABEL org.opencontainers.image.description="Zero-Trust Tor v3 Hidden Service & E2EE Gossip Relay for OnionTalk Messenger"
LABEL org.opencontainers.image.authors="Erik Tonon <security@oniontalk.org>"

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates procps libevent-2.1-7 libcap2 \
    && curl -sSL "https://deb.torproject.org/torproject.org/pool/main/t/tor/tor_0.4.9.14-1~d12.bookworm+1_amd64.deb" -o /tmp/tor.deb \
    && dpkg-deb -x /tmp/tor.deb /tmp/tor_pkg \
    && cp -a /tmp/tor_pkg/usr/* /usr/ \
    && rm -rf /tmp/tor.deb /tmp/tor_pkg /var/lib/apt/lists/* \
    && mkdir -p /data && chmod 777 /data

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY relay.py /app/relay.py
COPY entrypoint.sh /app/entrypoint.sh
RUN sed -i 's/\r$//' /app/entrypoint.sh && chmod +x /app/entrypoint.sh && chmod -R 755 /app

VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=25s --retries=3 \
    CMD curl -fsS http://127.0.0.1:${PORT:-8080}/health || exit 1

CMD ["/app/entrypoint.sh"]
