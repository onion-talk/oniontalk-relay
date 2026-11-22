#!/bin/bash
set -e

PORT="${PORT:-8080}"
TOR_SOCKS_PORT="${TOR_SOCKS_PORT:-9050}"

DATA_DIR="${DATA_DIR:-/data}"
if ! mkdir -p "$DATA_DIR/tor_data" "$DATA_DIR/hidden_service" 2>/dev/null; then
    DATA_DIR="/tmp/oniontalk_data"
    mkdir -p "$DATA_DIR/tor_data" "$DATA_DIR/hidden_service"
fi
chmod 700 "$DATA_DIR/tor_data" "$DATA_DIR/hidden_service" 2>/dev/null || true
chmod 600 "$DATA_DIR/hidden_service/"* 2>/dev/null || true

export RELAY_BIND_ADDR="${RELAY_BIND_ADDR:-0.0.0.0:${PORT}}"
export RELAY_NODE_KEY_FILE="${RELAY_NODE_KEY_FILE:-$DATA_DIR/oniontalk_node_ed25519.key}"
export RELAY_STATE_SNAPSHOT_FILE="${RELAY_STATE_SNAPSHOT_FILE:-$DATA_DIR/oniontalk_relay_state.json}"
export SPENT_NULLIFIERS_FILE="${SPENT_NULLIFIERS_FILE:-$DATA_DIR/oniontalk_spent_nullifiers_v154.json}"
export SEEN_CLIENT_TAGS_FILE="${SEEN_CLIENT_TAGS_FILE:-$DATA_DIR/oniontalk_seen_client_tags.json}"
export MESH_WATCH_FILE="${MESH_WATCH_FILE:-$DATA_DIR/oniontalk_mesh_watch_events.json}"
export AUTHORITY_CRL_FILE="${AUTHORITY_CRL_FILE:-$DATA_DIR/oniontalk_authority_crl.txt}"

# Support optional external Tor daemon (e.g. multi-container compose)
if [ "${EXTERNAL_TOR:-0}" = "1" ]; then
    echo "[*] [ONIONTALK-RELAY-RS] Using external Tor daemon: ${TOR_SOCKS_PROXY:-socks5h://tor-daemon:9050}"
    exec /usr/local/bin/oniontalk-relay-rs
fi

# Optional pre-provisioned Hidden Service v3 keys via environment variables or mounted secret file
if [ -n "$TOR_HS_SECRET_FILE" ] && [ -s "$TOR_HS_SECRET_FILE" ]; then
    cp "$TOR_HS_SECRET_FILE" "$DATA_DIR/hidden_service/hs_ed25519_secret_key"
    chmod 600 "$DATA_DIR/hidden_service/hs_ed25519_secret_key"
elif [ -n "$TOR_HS_SECRET_B64" ] && [ -n "$TOR_HS_PUBLIC_B64" ] && [ -n "$TOR_HS_HOSTNAME" ]; then
    echo "$TOR_HS_SECRET_B64" | base64 -d > "$DATA_DIR/hidden_service/hs_ed25519_secret_key"
    echo "$TOR_HS_PUBLIC_B64" | base64 -d > "$DATA_DIR/hidden_service/hs_ed25519_public_key"
    printf "%s\n" "$TOR_HS_HOSTNAME" > "$DATA_DIR/hidden_service/hostname"
    chmod 600 "$DATA_DIR/hidden_service/"*
fi

TORRC_FILE="${DATA_DIR}/torrc.runtime"
cat << TOREOF > "$TORRC_FILE"
DataDirectory ${DATA_DIR}/tor_data
PidFile ${DATA_DIR}/tor.pid
GeoIPFile /usr/share/tor/geoip
GeoIPv6File /usr/share/tor/geoip6
HiddenServiceDir ${DATA_DIR}/hidden_service/
HiddenServicePort 80 127.0.0.1:${PORT}
HiddenServiceVersion 3
HiddenServiceNumIntroductionPoints 5
HiddenServiceEnableIntroDoSDefense 1
HiddenServiceMaxStreams 64
HiddenServiceMaxStreamsCloseCircuit 1
SOCKSPort 127.0.0.1:${TOR_SOCKS_PORT} IsolateDestAddr IsolateSOCKSAuth
KeepalivePeriod 30
SocksTimeout 15
MaxMemInQueues 64 MB
NoExec 1
Log warn file ${DATA_DIR}/tor.log
TOREOF

# Enable Equi-X Proof-of-Work Hidden Service defense when compiled into the Tor binary (--enable-gpl)
if /usr/bin/tor --list-modules 2>/dev/null | grep -qi "pow: yes"; then
    echo "HiddenServicePoWDefensesEnabled 1" >> "$TORRC_FILE"
fi

if [ -n "$TOR_UPSTREAM_SOCKS5_PROXY" ]; then
    echo "Socks5Proxy ${TOR_UPSTREAM_SOCKS5_PROXY}" >> "$TORRC_FILE"
fi

/usr/bin/tor -f "$TORRC_FILE" --RunAsDaemon 1

# Background supervisor watchdog to keep Tor daemon alive
(
  while true; do
    sleep 15
    if ! pgrep -x tor >/dev/null 2>&1; then
      echo "[!] [WATCHDOG] Tor process not found, restarting daemon..."
      /usr/bin/tor -f "$TORRC_FILE" --RunAsDaemon 1 || true
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

echo "===================================================================="
echo "🦀 ONIONTALK ZERO-TRUST FEDERATED RELAY NODE (Rust Native v1.8.1)"
echo "--------------------------------------------------------------------"
echo "🌐 Hidden Service (.onion): ${ONION_ADDR}"
echo "🔌 Local Health / API Port: ${PORT}"
echo "🧦 Internal Tor SOCKS5:     127.0.0.1:${TOR_SOCKS_PORT}"
echo "💾 Persistent Data Dir:     ${DATA_DIR}"
echo "===================================================================="

exec /usr/local/bin/oniontalk-relay-rs
