#!/bin/bash
set -e

PORT="${PORT:-8080}"
TOR_SOCKS_PORT="${TOR_SOCKS_PORT:-9050}"

DATA_DIR="${DATA_DIR:-/data}"
if ! mkdir -p "$DATA_DIR/tor_data" "$DATA_DIR/hidden_service" 2>/dev/null; then
    DATA_DIR="/tmp/oniontalk_data"
    mkdir -p "$DATA_DIR/tor_data" "$DATA_DIR/hidden_service"
fi
chown -R "$(id -u):$(id -g)" "$DATA_DIR/tor_data" "$DATA_DIR/hidden_service" 2>/dev/null || true
chmod 700 "$DATA_DIR/tor_data" "$DATA_DIR/hidden_service"
chmod 600 "$DATA_DIR/hidden_service/"* 2>/dev/null || true

# Support optional external Tor daemon (e.g. legacy multi-container compose)
if [ "${EXTERNAL_TOR:-0}" = "1" ]; then
    echo "[*] [ONIONTALK] Using external Tor daemon: ${TOR_SOCKS_PROXY:-socks5h://tor-daemon:9050}"
    exec gunicorn -w 1 --threads 64 --keep-alive 75 --timeout 90 -b "0.0.0.0:${PORT}" relay:app
fi

# Optional pre-provisioned Hidden Service v3 keys via environment variables
if [ -n "$TOR_HS_SECRET_B64" ] && [ -n "$TOR_HS_PUBLIC_B64" ] && [ -n "$TOR_HS_HOSTNAME" ]; then
    echo "$TOR_HS_SECRET_B64" | base64 -d > "$DATA_DIR/hidden_service/hs_ed25519_secret_key"
    echo "$TOR_HS_PUBLIC_B64" | base64 -d > "$DATA_DIR/hidden_service/hs_ed25519_public_key"
    printf "%s\n" "$TOR_HS_HOSTNAME" > "$DATA_DIR/hidden_service/hostname"
    chmod 600 "$DATA_DIR/hidden_service/"*
fi

cat << TOREOF > /tmp/torrc
DataDirectory ${DATA_DIR}/tor_data
PidFile /tmp/tor.pid
GeoIPFile /usr/share/tor/geoip
GeoIPv6File /usr/share/tor/geoip6
HiddenServiceDir ${DATA_DIR}/hidden_service/
HiddenServicePort 80 127.0.0.1:${PORT}
HiddenServiceVersion 3
HiddenServiceNumIntroductionPoints 5
SOCKSPort 127.0.0.1:${TOR_SOCKS_PORT}
KeepalivePeriod 30
NumEntryGuards 4
CircuitBuildTimeout 15
LearnCircuitBuildTimeout 1
SocksTimeout 15
MaxMemInQueues 64 MB
Log notice file /tmp/tor.log
TOREOF

if [ -n "$TOR_UPSTREAM_SOCKS5_PROXY" ]; then
    echo "Socks5Proxy ${TOR_UPSTREAM_SOCKS5_PROXY}" >> /tmp/torrc
fi

/usr/bin/tor -f /tmp/torrc --RunAsDaemon 1

# Background supervisor watchdog to keep Tor daemon alive
(
  while true; do
    sleep 15
    if ! pgrep -x tor >/dev/null 2>&1; then
      echo "[!] [WATCHDOG] Tor process not found, restarting daemon..."
      /usr/bin/tor -f /tmp/torrc --RunAsDaemon 1 || true
    fi
  done
) &

# Wait up to 20s for Tor to generate the v3 .onion hostname
for _ in $(seq 1 20); do
    if [ -s "$DATA_DIR/hidden_service/hostname" ]; then
        break
    fi
    sleep 1
done

ONION_ADDR="generating..."
if [ -s "$DATA_DIR/hidden_service/hostname" ]; then
    ONION_ADDR=$(tr -d '\r\n' < "$DATA_DIR/hidden_service/hostname")
fi

export TOR_HOSTNAME_FILE="${TOR_HOSTNAME_FILE:-$DATA_DIR/hidden_service/hostname}"
export TOR_SOCKS_PROXY="${TOR_SOCKS_PROXY:-socks5h://127.0.0.1:${TOR_SOCKS_PORT}}"
export RELAY_NODE_KEY_FILE="${RELAY_NODE_KEY_FILE:-$DATA_DIR/oniontalk_node_ed25519.key}"

echo "===================================================================="
echo "🧅 ONIONTALK ZERO-TRUST FEDERATED RELAY NODE (All-in-One)"
echo "--------------------------------------------------------------------"
echo "🌐 Hidden Service (.onion): ${ONION_ADDR}"
echo "🔌 Local Health / API Port: ${PORT}"
echo "🧦 Internal Tor SOCKS5:     127.0.0.1:${TOR_SOCKS_PORT}"
echo "💾 Persistent Data Dir:     ${DATA_DIR}"
echo "===================================================================="

exec gunicorn -w 1 --threads 64 --keep-alive 75 --timeout 90 -b "0.0.0.0:${PORT}" relay:app
