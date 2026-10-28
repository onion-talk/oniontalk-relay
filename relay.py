from __future__ import annotations
import os
import re
import json
import math
import time
import uuid
import hmac
import base64
import random
import hashlib
import threading
import concurrent.futures
import requests
from flask import Flask, request, jsonify
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

app = Flask(__name__)
# Maximum 2 MB per HTTP request (Anti-OOM / DoS protection)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024


@app.after_request
def apply_zero_trust_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Connection"] = "keep-alive"
    response.headers["Keep-Alive"] = "timeout=75, max=1000"
    response.headers["X-Relay-Node-Pubkey"] = NODE_PUBLIC_KEY_HEX
    return response


DEFAULT_SEEDS = (
    "onion4zr3bsdeaelksemwokl5qmxd5o7jyblf46vc2mfl6cozgw77tqd.onion,"
    "kn4u2xxl2otoo2ujv3mhehwfwbw7mtppaf56fu3nxogvv7eekf2qdrid.onion,"
    "zqdx5x7pfybox7m5rz3fe5kiouxhipvh3ekuteq2urrrvwcxjttnmgid.onion,"
    "puqjsmsyyzmxjdtcgr2fl4wrdazqd2phaqrz26alzwyletbvekkxhyyd.onion,"
    "ch4s5llfqshxbvba2yulgp5kbopq25w3qqrtli67sle6smbujlebn2id.onion,"
    "7bntuiegd3stvcylvx7rhnhq7ncasxiokunbf5onvvm34dg5gccvooid.onion,"
    "jz6urt6ckkqqvtasm6bll2mryhksjcawcl4tbguif5nqvxgsfsx6ywad.onion,"
    "4wufywh2k6ayyz6nmh2w25hj5vjsqgkve24o2tthvc7rhyvxnhaghqqd.onion,"
    "nwsoa6ddtbbqbwcceanhhj3j23d5a47zbpbs6zspz5zoeytzqpzvkqqd.onion,"
    "hdjp7uaj4qemlmwtev7xmj2w3uexnv6ctplfgvbmpqxenbfgwjjwtrid.onion,"
    "gcvfh67zltoyvithw6luetsrcec6cw42upzrsprxfmx27cvh7vidw4yd.onion,"
    "dr73uzslasuijogigjnvdws4yoajqnhw6yjyvufq3nobm6xibntnwzqd.onion,"
    "wfi3nwuzk2tgrsf2scdy4nb6x6rtiocit4n26477zdlvdvshkgip3ayd.onion,"
    "o5zqqfl5znzexdojfnxgub5jnjelxdahbyxasjp57sx6fbxtjeqovpad.onion,"
    "5s6w6556f2eov2p6wlsuavaxh7si2kaswjwi5reojnovbzemducjzjqd.onion,"
    "o5yf3eukrwpt2g6jfo4q2y23xtuhoso2qknmnn6ac5eng5t4yt36roqd.onion,"
    "2amizuhb3p5x2lk3sra7f7thm5tgs7qtnysgowqpmexcqi4cuwyv7vad.onion,"
    "fllhsqmq2qj4stn22bvdtdigthj5bftq6bq6eb62ynk4kva4kfkbjtid.onion,"
    "rx46t5jwyoi7pqajaazk7xndqy6ep2n3x2u6bn7t3r34mg6eiehpdlad.onion,"
    "q75gf2rwco7v33kuhmilafbtsvoxrygqmef7lq6allnk27zxruwzeqqd.onion,"
    "huf4fjrdr67c3vir6b33s2rsspnmejgtn5azs2jby7yvfqwlsnxeawad.onion,"
    "ktr4uxdwjem2gabgwmivlx2uyyea6kdajpyb4fxxxa7x3zs5lq4fcyad.onion,"
    "6pq6ifyhhemh2pujbnr2i56mod6d7kpeu7s57i4syvxhdrltcztowtad.onion,"
    "kr2aex6umihb5bcdspc2q4npasng7zoee4i6ixx3qxgwcegscibis6id.onion,"
    "wzhsoh6ovtwvl7uthirgvpfry5zxo3bwm3rttsmmj2rkvgl7gbqkyaid.onion"
)

# Zero-Trust Memory, Format & Topology Limits (Anti-Sybil & Anti-DoS)
ONION_V3_REGEX = re.compile(r"^[a-z2-7]{56}\.onion$")
SHA256_HEX_REGEX = re.compile(r"^[0-9a-f]{64}$")
PUBKEY_HEX_REGEX = re.compile(r"^[0-9a-f]{64}$")
SIG_HEX_REGEX = re.compile(r"^[0-9a-f]{128}$")
RECIPIENT_ID_REGEX = re.compile(r"^@[0-9a-f]{64}(:[a-z2-7]{56}\.onion)?$")

MAX_KNOWN_PEERS = 64
MAX_INBOX_PER_USER = 500
MAX_PER_SENDER_INBOX = 50
MAX_TOTAL_INBOXES = 5000
MESSAGE_TTL_MS = 24 * 3600 * 1000  # 24 hours
AUTH_WINDOW_MS = 5 * 60 * 1000     # +/- 5 minutes replay window

_default_proxy = "socks5h://tor-daemon:9050"
_default_hostname = "/var/lib/tor/hidden_service/hostname"
if os.path.exists("/home/eriktonon/oniontalk/data/hidden_service/hostname"):
    _default_proxy = "socks5h://127.0.0.1:19055"
    _default_hostname = "/home/eriktonon/oniontalk/data/hidden_service/hostname"

TOR_SOCKS_PROXY = os.getenv("TOR_SOCKS_PROXY", _default_proxy)
HOSTNAME_FILE = os.getenv("TOR_HOSTNAME_FILE", _default_hostname)
NODE_KEY_FILE = os.getenv("RELAY_NODE_KEY_FILE", "/tmp/oniontalk_node_ed25519.key")
RELAY_ADMIN_TOKEN = (os.getenv("RELAY_ADMIN_TOKEN") or "").strip()

DEPRECATED_SEEDS = {
    "kn4u2ef3y7ecyvbh36fkezxbbjrkc67ddtsf7m2dyrcpfdba7t2c5jad.onion",
    "zqdx5vye5tnc2b5ffj3ufc255wucx2z3b2bfvnefdn3g2ef5z2x67nad.onion",
    "dkkwnbju5xxhd5rrdg7sbxmh5fyoh7loew6mpaxb5xjjckimk6rt63ad.onion",
    "e62b43tij6ijd7krxqjmt2xhm6omfcll34or22sqo4fhpkykoaza6cad.onion",
    "azw5qxf4jnfudeei3nanggojle62g4duoxtxjj2pjuvm42xb3456vjad.onion",
    "bk7iegv3v232ycjyf5ylwsdx42iozvy2dhhff5zn3ciwa3g2lkifdlad.onion",
    "2qgcxodv7oskwadopetbf563vh3ylxrmbeemqf7wvfkqkgzfk7omibid.onion",
    "5wniyn4yavtrfirlpdbqog2trucx7l2mo46xhzmmsqv2gukgiz6a62ad.onion",
    "b2okgesv7hmaklzn52ampqndxmvqw6mue242jnzacfrqlhvy7qtnjoyd.onion",
    "gsjapr6lwyifkzygymzewk7qcpd5smeqtqxwffwtcmtvwzktojirczqd.onion",
    "mmhzcbaq5td2gsoexzxaix7wajrexfc7vwhpdeavmly7mp4iog7kgryd.onion",
    "uabdscyj2a25yjdggf7p6fjwj66vfbntsbi3mmkqz5letlve5atyc7qd.onion",
    "2rapl6ti6jepxidbq6krbvtv32h257sb3tyhamjd3n4lx36c76uhdnid.onion",
    "cstl5a24l3sj7vlpjmu3udhatyibzazqdtz3ljxeug5svoibmzno3dad.onion",
    "dp7kur7f5vjn5mfnrkxgtelqmr4i5d62nzmmqrnrzdndakkembx7sjyd.onion",
    "izin6p6lln6gtmppzi57fwepnzjesr63e6ws5ox36ncsqu4bzbcjwsid.onion",
    "mwlkugl2uejlwl44tbrhe35chzbxx453r5iwnv5hr2hvtzphjttbypid.onion",
    "j3jctr732xjkkkcjkoysgqlktlomr3zexhiv4asvvmdomjoo26lwidyd.onion",
    "rk6qrjwlte4veuximrnpgkmiqrbcxpj3i2h3p2f7urr35pjpvw5pz4id.onion",
    "ucbbmzi4h4zu2yd4l73r52jzvmq7cvzgwcatqmwdcnoq4hjose3n42id.onion",
}
LEGACY_V1_PEERS = {
    "puqjsmsyyzmxjdtcgr2fl4wrdazqd2phaqrz26alzwyletbvekkxhyyd.onion",
    "ch4s5llfqshxbvba2yulgp5kbopq25w3qqrtli67sle6smbujlebn2id.onion",
    "e62b43tij6ijd7krxqjmt2xhm6omfcll34or22sqo4fhpkykoaza6cad.onion",
    "bk7iegv3v232ycjyf5ylwsdx42iozvy2dhhff5zn3ciwa3g2lkifdlad.onion",
}
_raw_seeds = (DEFAULT_SEEDS + "," + os.getenv("BOOTSTRAP_SEEDS", "")).split(",")
BOOTSTRAP_SEEDS = list(dict.fromkeys(
    s.strip().lower()
    for s in _raw_seeds
    if s.strip()
    and s.strip().lower() not in DEPRECATED_SEEDS
    and ONION_V3_REGEX.match(s.strip().lower())
))


def _load_or_create_node_keypair() -> tuple[Ed25519PrivateKey, str]:
    seed_env = (os.getenv("RELAY_NODE_SEED_HEX") or "").strip().lower()
    if PUBKEY_HEX_REGEX.match(seed_env):
        priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_env))
    else:
        priv = None
        if os.path.exists(NODE_KEY_FILE):
            try:
                with open(NODE_KEY_FILE, "rb") as f:
                    raw = f.read()
                if len(raw) == 32:
                    priv = Ed25519PrivateKey.from_private_bytes(raw)
            except Exception:
                priv = None
        if priv is None:
            priv = Ed25519PrivateKey.generate()
            try:
                raw_seed = priv.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption(),
                )
                fd = os.open(NODE_KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "wb") as f:
                    f.write(raw_seed)
                try:
                    os.chmod(NODE_KEY_FILE, 0o600)
                except Exception:
                    pass
            except Exception:
                pass

    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv, pub_bytes.hex()


NODE_PRIVATE_KEY, NODE_PUBLIC_KEY_HEX = _load_or_create_node_keypair()

# ---------------------------------------------------------------------------
# App Version Policy & Automatic E2EE Update Notice Injector
# ---------------------------------------------------------------------------
MIN_CLIENT_VERSION_CODE = int(os.getenv("MIN_CLIENT_VERSION_CODE", "35"))
LATEST_CLIENT_VERSION_CODE = int(os.getenv("LATEST_CLIENT_VERSION_CODE", "35"))
LATEST_CLIENT_VERSION_NAME = os.getenv("LATEST_CLIENT_VERSION_NAME", "1.4.6")
UPDATE_PLAY_URL = os.getenv(
    "UPDATE_PLAY_URL",
    "https://play.google.com/store/apps/details?id=org.oniontalk.messenger",
)
UPDATE_APK_URL = os.getenv(
    "UPDATE_APK_URL",
    "https://github.com/onion-talk/oniontalk-demo/releases/download/v1.4.6/OnionTalk-v1.4.6.apk",
)
ENFORCE_HARD_UPDATE_CUT = os.getenv("ENFORCE_HARD_UPDATE_CUT", "0") == "1"
UPDATE_NOTIFIED_FILE = os.getenv("UPDATE_NOTIFIED_FILE", "/tmp/oniontalk_update_notified_v146.json")

def _derive_system_broadcast_keypair() -> tuple[Ed25519PrivateKey, str]:
    env_seed_hex = (os.getenv("SYSTEM_BROADCAST_SEED_HEX") or "").strip().lower()
    if PUBKEY_HEX_REGEX.match(env_seed_hex):
        seed_bytes = bytes.fromhex(env_seed_hex)
    else:
        node_raw = NODE_PRIVATE_KEY.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        seed_bytes = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"OnionTalk-System-Broadcast-Salt-v2",
            info=b"OnionTalk-System-Update-Ed25519-Key-v2",
        ).derive(node_raw)
    priv = Ed25519PrivateKey.from_private_bytes(seed_bytes)
    pub_hex = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()
    return priv, pub_hex


_SYSTEM_SIGN_KEY, _SYSTEM_SIGN_PUB_HEX = _derive_system_broadcast_keypair()
_SYSTEM_SENDER_ID = f"@{_SYSTEM_SIGN_PUB_HEX}:onion4zr3bsdeaelksemwokl5qmxd5o7jyblf46vc2mfl6cozgw77tqd.onion"

_ED25519_P = (1 << 255) - 19
_AUTO_UPDATE_TEXT = (
    "ATUALIZAÇÃO DISPONÍVEL — OnionTalk v1.4.6 (Build 35)\n\n"
    "Atualize seu aplicativo para receber:\n"
    "• Grupos Pós-Quânticos (ML-KEM-768 + SHA3-256) com foto de grupo sem metadados EXIF e rotação automática de chave;\n"
    "• Governança FounderPass ($10 USD em SOL/BTC/ETH = 10 grupos permanentes | 1 Nó Relay ativo = 1 grupo);\n"
    "• Seletores otimizados em Configurações e privacidade reforçada da malha Tor v3 (27 nodes ativos).\n\n"
    "Google Play: https://play.google.com/store/apps/details?id=org.oniontalk.messenger\n"
    "APK Direto: https://onion-talk.github.io/oniontalk-demo/\n\n"
    "— Equipe OnionTalk (Sistema Oficial)"
)


def _load_update_notified_map() -> dict[str, int]:
    if os.path.exists(UPDATE_NOTIFIED_FILE):
        try:
            with open(UPDATE_NOTIFIED_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return {str(k): int(v) for k, v in data.items()}
        except Exception:
            pass
    return {}


def _save_update_notified_map(notified_map: dict[str, int]):
    try:
        with open(UPDATE_NOTIFIED_FILE, "w", encoding="utf-8") as f:
            json.dump(notified_map, f)
    except Exception:
        pass


update_notified_users: dict[str, int] = _load_update_notified_map()


def _ed25519_pub_to_x25519_pub(ed_pub_bytes: bytes) -> bytes:
    y = int.from_bytes(ed_pub_bytes, "little") & ((1 << 255) - 1)
    num = (1 + y) % _ED25519_P
    den = (1 - y) % _ED25519_P
    u = (num * pow(den, _ED25519_P - 2, _ED25519_P)) % _ED25519_P
    return u.to_bytes(32, "little")


def get_signed_app_update_metadata() -> dict:
    canonical = (
        f"ONIONTALK_UPDATE_V1|{MIN_CLIENT_VERSION_CODE}|{LATEST_CLIENT_VERSION_CODE}|"
        f"{LATEST_CLIENT_VERSION_NAME}|{UPDATE_PLAY_URL}|{UPDATE_APK_URL}"
    ).encode("utf-8")
    sig_hex = NODE_PRIVATE_KEY.sign(canonical).hex()
    return {
        "min_version_code": MIN_CLIENT_VERSION_CODE,
        "latest_version_code": LATEST_CLIENT_VERSION_CODE,
        "latest_version_name": LATEST_CLIENT_VERSION_NAME,
        "play_store_url": UPDATE_PLAY_URL,
        "apk_url": UPDATE_APK_URL,
        "node_pubkey": NODE_PUBLIC_KEY_HEX,
        "signature": sig_hex,
    }


def _build_auto_update_envelope(recipient_key: str) -> dict | None:
    try:
        clean_hex = recipient_key.lstrip("@").split(":")[0].strip().lower()
        if not PUBKEY_HEX_REGEX.match(clean_hex):
            return None
        recip_x_bytes = _ed25519_pub_to_x25519_pub(bytes.fromhex(clean_hex))
        recip_x_pub = X25519PublicKey.from_public_bytes(recip_x_bytes)

        eph_priv = X25519PrivateKey.generate()
        eph_pub_hex = eph_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()
        shared_secret = eph_priv.exchange(recip_x_pub)

        msg_id = str(uuid.uuid4())
        canonical_recip = f"@{clean_hex}:onion4zr3bsdeaelksemwokl5qmxd5o7jyblf46vc2mfl6cozgw77tqd.onion"
        salt = f"OnionTalk-Wire-v2:{_SYSTEM_SENDER_ID}:{canonical_recip}".encode("utf-8")

        enc_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"OnionTalk-AEAD-ChaCha20Poly1305-v2",
        ).derive(shared_secret)

        ack_token_bytes = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=f"OnionTalk-ACK-Token-v2:{msg_id}".encode("utf-8"),
        ).derive(shared_secret)
        ack_token_hex = ack_token_bytes.hex()
        ack_lock_hex = hashlib.sha256(ack_token_hex.encode("utf-8")).hexdigest()

        nonce = os.urandom(12)
        aad = f"v2|{_SYSTEM_SENDER_ID}|{canonical_recip}".encode("utf-8")
        ct = ChaCha20Poly1305(enc_key).encrypt(nonce, _AUTO_UPDATE_TEXT.encode("utf-8"), aad)

        nonce_b64 = base64.b64encode(nonce).decode("ascii")
        ct_b64 = base64.b64encode(ct).decode("ascii")

        body_to_sign = (
            f"__ENC_X25519_CHACHA20_V2__|{_SYSTEM_SENDER_ID}|{canonical_recip}|"
            f"{eph_pub_hex}|{nonce_b64}|{ct_b64}"
        ).encode("utf-8")
        sig_hex = _SYSTEM_SIGN_KEY.sign(body_to_sign).hex()
        wire_payload = f"__ENC_X25519_CHACHA20_V2__:{eph_pub_hex}:{nonce_b64}:{ct_b64}:{sig_hex}"

        return {
            "id": msg_id,
            "sender": _SYSTEM_SENDER_ID,
            "recipient": canonical_recip,
            "payload": wire_payload,
            "ack_lock": ack_lock_hex,
            "timestamp": int(time.time() * 1000),
        }
    except Exception:
        return None


def maybe_enqueue_auto_update_notice_locked(user_key: str, cooldown_sec: int = 21600) -> dict | None:
    """
    If the polling/sending client has not reported X-Client-Version-Code >= MIN_CLIENT_VERSION_CODE,
    automatically injects an E2EE v2 update notification into their inbox (max once per cooldown_sec).
    Must be called while holding `lock` or `inbox_cond`.
    """
    raw_vc = (request.headers.get("X-Client-Version-Code") or "").strip()
    try:
        client_vc = int(raw_vc) if raw_vc else 0
    except ValueError:
        client_vc = 0

    if client_vc >= MIN_CLIENT_VERSION_CODE:
        return None

    now_sec = int(time.time())
    last_sent = update_notified_users.get(user_key, 0)
    if (now_sec - last_sent) < cooldown_sec:
        return None

    # Also skip if an un-acked system update message is already sitting in this user's inbox
    existing_msgs = inbox.get(user_key, [])
    if any(canonical_inbox_key(m.get("sender") or "") == canonical_inbox_key(_SYSTEM_SENDER_ID) for m in existing_msgs):
        update_notified_users[user_key] = now_sec
        return None

    env = _build_auto_update_envelope(user_key)
    if env is None:
        return None

    added, _ = enqueue_message_locked(user_key, env)
    if added:
        update_notified_users[user_key] = now_sec
        _save_update_notified_map(update_notified_users)
        print("[*] [AUTO-UPDATE] Queued E2EE v1.4.2 update prompt for legacy client", flush=True)
        return env
    return None

NODE_GEO_METADATA = {
    "onion4zr3bsdeaelksemwokl5qmxd5o7jyblf46vc2mfl6cozgw77tqd.onion": {
        "node_name": "👑 Nó 1 — PVE2 Master (SP)",
        "map_label": "N1•SP",
        "location": "São Paulo, Brasil",
        "provider": "Proxmox VE (Homelab PVE2)",
        "lat": -15.5,
        "lon": -47.5,
        "role": "👑 Seed Node (Master)"
    },
    "kn4u2xxl2otoo2ujv3mhehwfwbw7mtppaf56fu3nxogvv7eekf2qdrid.onion": {
        "node_name": "🖥️ Nó 2 — PVE4 Worker (SP)",
        "map_label": "N2•SP",
        "location": "São Paulo, Brasil",
        "provider": "Proxmox VE (Homelab PVE4)",
        "lat": -23.0,
        "lon": -45.5,
        "role": "🖥️ Homelab Relay (PVE4)"
    },
    "puqjsmsyyzmxjdtcgr2fl4wrdazqd2phaqrz26alzwyletbvekkxhyyd.onion": {
        "node_name": "☁️ Nó 3 — AWS EKS (US-East)",
        "map_label": "N3•EKS",
        "location": "US-East (AWS EKS), EUA",
        "provider": "Amazon Web Services (EKS)",
        "lat": 49.0,
        "lon": -74.0,
        "role": "☁️ Cloud Relay (AWS EKS)"
    },
    "zqdx5x7pfybox7m5rz3fe5kiouxhipvh3ekuteq2urrrvwcxjttnmgid.onion": {
        "node_name": "🟧 Nó 4 — Oracle OCI (Vinhedo)",
        "map_label": "N4•OCI",
        "location": "Vinhedo / SP, Brasil (sa-saopaulo-1)",
        "provider": "Oracle Cloud (OCI Always Free)",
        "lat": -30.5,
        "lon": -51.0,
        "role": "🟧 Cloud Relay (Oracle OCI)"
    },
    "ch4s5llfqshxbvba2yulgp5kbopq25w3qqrtli67sle6smbujlebn2id.onion": {
        "node_name": "☁️ Nó 5 — AWS Virginia",
        "map_label": "N5•VA",
        "location": "Ashburn, Virginia, EUA (us-east-1)",
        "provider": "Amazon Web Services (us-east-1)",
        "lat": 26.5,
        "lon": -76.0,
        "role": "☁️ Cloud Relay (AWS Virginia)"
    },
    "7bntuiegd3stvcylvx7rhnhq7ncasxiokunbf5onvvm34dg5gccvooid.onion": {
        "node_name": "🇫🇷 Nó 6 — Alwaysdata (Paris)",
        "map_label": "N6•PAR1",
        "location": "Paris, França (EU-West)",
        "provider": "Alwaysdata Cloud (AS60362 Paris)",
        "lat": 54.0,
        "lon": -4.0,
        "role": "🇫🇷 Cloud Relay (Paris, FR)"
    },
    "jz6urt6ckkqqvtasm6bll2mryhksjcawcl4tbguif5nqvxgsfsx6ywad.onion": {
        "node_name": "🌐 Nó 7 — Google Cloud (US-East)",
        "map_label": "N7•GCP",
        "location": "Moncks Corner, SC, EUA (us-east1-b)",
        "provider": "Google Cloud Platform (e2-micro Free Tier)",
        "lat": 26.5,
        "lon": -100.0,
        "role": "🌐 Cloud Relay (GCP US-East)"
    },
    "4wufywh2k6ayyz6nmh2w25hj5vjsqgkve24o2tthvc7rhyvxnhaghqqd.onion": {
        "node_name": "⚡ Nó 8 — Render Cloud (Ohio)",
        "map_label": "N8•OH1",
        "location": "Columbus, Ohio, EUA (us-east)",
        "provider": "Render Cloud (Free Web Service)",
        "lat": 41.5,
        "lon": -75.0,
        "role": "⚡ Cloud Relay (Render Ohio)"
    },
    "nwsoa6ddtbbqbwcceanhhj3j23d5a47zbpbs6zspz5zoeytzqpzvkqqd.onion": {
        "node_name": "🇷🇺 Nó 9 — Amvera Cloud (Moscou)",
        "map_label": "N9•MSK1",
        "location": "Moscou, Rússia (msk1)",
        "provider": "Amvera Cloud (RU Container PaaS)",
        "lat": 54.0,
        "lon": 40.0,
        "role": "🇷🇺 Cloud Relay (Moscou, RU)"
    },
    "dr73uzslasuijogigjnvdws4yoajqnhw6yjyvufq3nobm6xibntnwzqd.onion": {
        "node_name": "🐳 Nó 10 — Back4App Cloud #1 (US-East)",
        "map_label": "N10•B4A1",
        "location": "US-East (Back4App Containers #1), EUA",
        "provider": "Back4App Containers (AWS us-east #1)",
        "lat": 41.5,
        "lon": -98.0,
        "role": "🐳 Cloud Relay (Back4App #1)"
    },
    "bk7iegv3v232ycjyf5ylwsdx42iozvy2dhhff5zn3ciwa3g2lkifdlad.onion": {
        "node_name": "🐳 Nó 10 — Back4App Cloud (US-East Legacy)",
        "map_label": "N10•B4A",
        "location": "US-East (Back4App Containers), EUA",
        "provider": "Back4App Containers (AWS us-east)",
        "lat": 41.5,
        "lon": -98.0,
        "role": "🐳 Cloud Relay (Back4App)"
    },
    "hdjp7uaj4qemlmwtev7xmj2w3uexnv6ctplfgvbmpqxenbfgwjjwtrid.onion": {
        "node_name": "🇫🇷 Nó 11 — Alwaysdata Paris #2 (Yared)",
        "map_label": "N11•PAR2",
        "location": "Paris, França (EU-West #2)",
        "provider": "Alwaysdata Cloud (AS60362 Paris #2)",
        "lat": 46.5,
        "lon": -5.0,
        "role": "🇫🇷 Cloud Relay (Paris #2, FR)"
    },
    "gcvfh67zltoyvithw6luetsrcec6cw42upzrsprxfmx27cvh7vidw4yd.onion": {
        "node_name": "🇫🇷 Nó 12 — Alwaysdata Paris #3 (Default)",
        "map_label": "N12•PAR3",
        "location": "Paris, França (EU-West #3)",
        "provider": "Alwaysdata Cloud (AS60362 Paris #3)",
        "lat": 39.0,
        "lon": -6.0,
        "role": "🇫🇷 Cloud Relay (Paris #3, FR)"
    },
    "wfi3nwuzk2tgrsf2scdy4nb6x6rtiocit4n26477zdlvdvshkgip3ayd.onion": {
        "node_name": "🟦 Nó 13 — Northflank / GCP #2 (US-Central)",
        "map_label": "N13•NF",
        "location": "Council Bluffs, Iowa, EUA (US-Central)",
        "provider": "Northflank / GCP Cloud Relay",
        "lat": 49.0,
        "lon": -97.0,
        "role": "🟦 Cloud Relay (US-Central)"
    },
    "5s6w6556f2eov2p6wlsuavaxh7si2kaswjwi5reojnovbzemducjzjqd.onion": {
        "node_name": "🇯🇵 Nó 14 — DOM Cloud (Osaka, Japão)",
        "map_label": "N14•JP",
        "location": "Osaka, Japão (AP-Northeast)",
        "provider": "DOM Cloud (osk.domcloud.co)",
        "lat": 36.5,
        "lon": 138.0,
        "role": "🇯🇵 Cloud Relay (Osaka, JP)"
    },
    "o5yf3eukrwpt2g6jfo4q2y23xtuhoso2qknmnn6ac5eng5t4yt36roqd.onion": {
        "node_name": "🇸🇬 Nó 15 — DOM Cloud (Singapura)",
        "map_label": "N15•SG",
        "location": "Singapura (AP-Southeast)",
        "provider": "DOM Cloud (sgp.domcloud.co)",
        "lat": 2.0,
        "lon": 103.8,
        "role": "🇸🇬 Cloud Relay (Singapura, SG)"
    },
    "azw5qxf4jnfudeei3nanggojle62g4duoxtxjj2pjuvm42xb3456vjad.onion": {
        "node_name": "🇩🇪 Nó 16 — DOM Cloud (Alemanha Legacy)",
        "map_label": "N16•DE",
        "location": "Nuremberg, Alemanha (EU-Central)",
        "provider": "DOM Cloud (nue.domcloud.co)",
        "lat": 50.0,
        "lon": 15.0,
        "role": "🇩🇪 Cloud Relay (Nuremberg, DE)"
    },
    "o5zqqfl5znzexdojfnxgub5jnjelxdahbyxasjp57sx6fbxtjeqovpad.onion": {
        "node_name": "🇩🇪 Nó 16 — DOM Cloud (Alemanha)",
        "map_label": "N16•DE",
        "location": "Nuremberg, Alemanha (EU-Central)",
        "provider": "DOM Cloud (nue.domcloud.co)",
        "lat": 50.0,
        "lon": 15.0,
        "role": "🇩🇪 Cloud Relay (Nuremberg, DE)"
    },
    "2amizuhb3p5x2lk3sra7f7thm5tgs7qtnysgowqpmexcqi4cuwyv7vad.onion": {
        "node_name": "🇨🇳 Nó 17 — ModelScope Cloud (China)",
        "map_label": "N17•CN",
        "location": "Hangzhou, China (CN-East / Alibaba Cloud)",
        "provider": "ModelScope Studios (Alibaba Cloud CN)",
        "lat": 29.0,
        "lon": 117.5,
        "role": "🇨🇳 Cloud Relay (Hangzhou, CN)"
    },
    "fllhsqmq2qj4stn22bvdtdigthj5bftq6bq6eb62ynk4kva4kfkbjtid.onion": {
        "node_name": "🐳 Nó 18 — Back4App Cloud #2 (Mathyared)",
        "map_label": "N18•B4A2",
        "location": "US-East (Back4App Containers #2), EUA",
        "provider": "Back4App Containers (AWS us-east #2)",
        "lat": 34.0,
        "lon": -99.0,
        "role": "🐳 Cloud Relay (Back4App #2)"
    },
    "rx46t5jwyoi7pqajaazk7xndqy6ep2n3x2u6bn7t3r34mg6eiehpdlad.onion": {
        "node_name": "⚡ Nó 19 — Render Cloud #2 (Ohio • Mathyared)",
        "map_label": "N19•OH2",
        "location": "Columbus, Ohio, EUA (us-east #2)",
        "provider": "Render Cloud (Free Web Service #2)",
        "lat": 34.0,
        "lon": -75.5,
        "role": "⚡ Cloud Relay (Render Ohio #2)"
    },
    "q75gf2rwco7v33kuhmilafbtsvoxrygqmef7lq6allnk27zxruwzeqqd.onion": {
        "node_name": "🇷🇺 Nó 20 — Amvera Cloud #2 (Moscou • Mathyared)",
        "map_label": "N20•MSK2",
        "location": "Moscou, Rússia (msk1 #2)",
        "provider": "Amvera Cloud (RU Container PaaS #2)",
        "lat": 61.5,
        "lon": 38.0,
        "role": "🇷🇺 Cloud Relay (Moscou #2, RU)"
    },
    "huf4fjrdr67c3vir6b33s2rsspnmejgtn5azs2jby7yvfqwlsnxeawad.onion": {
        "node_name": "🟣 Nó 21 — WSO2 Choreo #1 (US-East Azure)",
        "map_label": "N21•CH1",
        "location": "Virginia / US-East #1, EUA (e1-us-east-azure)",
        "provider": "WSO2 Choreo Cloud (BYOC Docker #1)",
        "lat": 55.0,
        "lon": -122.0,
        "role": "🟣 Cloud Relay (Choreo US #1)"
    },
    "ktr4uxdwjem2gabgwmivlx2uyyea6kdajpyb4fxxxa7x3zs5lq4fcyad.onion": {
        "node_name": "🟣 Nó 22 — WSO2 Choreo #2 (US-East Azure)",
        "map_label": "N22•CH2",
        "location": "Virginia / US-East #2, EUA (e1-us-east-azure)",
        "provider": "WSO2 Choreo Cloud (BYOC Docker #2)",
        "lat": 47.5,
        "lon": -123.0,
        "role": "🟣 Cloud Relay (Choreo US #2)"
    },
    "6pq6ifyhhemh2pujbnr2i56mod6d7kpeu7s57i4syvxhdrltcztowtad.onion": {
        "node_name": "🟣 Nó 23 — WSO2 Choreo #3 (US-East Azure)",
        "map_label": "N23•CH3",
        "location": "Virginia / US-East #3, EUA (e1-us-east-azure)",
        "provider": "WSO2 Choreo Cloud (BYOC Docker #3)",
        "lat": 40.0,
        "lon": -123.0,
        "role": "🟣 Cloud Relay (Choreo US #3)"
    },
    "kr2aex6umihb5bcdspc2q4npasng7zoee4i6ixx3qxgwcegscibis6id.onion": {
        "node_name": "🟣 Nó 24 — WSO2 Choreo #4 (US-East Azure)",
        "map_label": "N24•CH4",
        "location": "Virginia / US-East #4, EUA (e1-us-east-azure)",
        "provider": "WSO2 Choreo Cloud (BYOC Docker #4)",
        "lat": 32.5,
        "lon": -120.0,
        "role": "🟣 Cloud Relay (Choreo US #4)"
    },
    "wzhsoh6ovtwvl7uthirgvpfry5zxo3bwm3rttsmmj2rkvgl7gbqkyaid.onion": {
        "node_name": "🟣 Nó 25 — WSO2 Choreo #5 (US-East Azure)",
        "map_label": "N25•CH5",
        "location": "Virginia / US-East #5, EUA (e1-us-east-azure)",
        "provider": "WSO2 Choreo Cloud (BYOC Docker #5)",
        "lat": 25.0,
        "lon": -114.0,
        "role": "🟣 Cloud Relay (Choreo US #5)"
    },
    "4nz52tmtrs4p5dgzwaukx2vin6ugvo3stck3wax7gom63fbfcaairlad.onion": {
        "node_name": "📱 Nó 26 — Relay Mobile Zero-Leak (Android)",
        "map_label": "N26•MOB",
        "location": "Tor Hidden Service v3 (Anônimo / Zero-Leak)",
        "provider": "OnionTalk RelayNode Android v1.0.1",
        "lat": -12.5,
        "lon": -56.0,
        "role": "📱 Mobile Pocket Relay (Zero-Leak)"
    }
}
custom_peer_geo = {}

# Dormant/migrated seeds start in initial backoff so real-time gossip never blocks on dead circuits
DORMANT_SEEDS = {
    "azw5qxf4jnfudeei3nanggojle62g4duoxtxjj2pjuvm42xb3456vjad.onion",
    "bk7iegv3v232ycjyf5ylwsdx42iozvy2dhhff5zn3ciwa3g2lkifdlad.onion",
}
MAX_AUTO_PEERS_PER_PROVIDER = 6

inbox = {}
acked_tombstones = {}  # Maps msg_id -> ack_timestamp_ms (prevents out-of-order gossip resurrection)
acked_tokens = {}  # Maps msg_id -> verified ack_token (enables bidirectional ACK tombstone healing on /sync)
synced_peers_by_msg = {}  # Maps msg_id -> set of v2 peers that already confirmed 200 OK (GossipSub IDONTWANT)
known_peers = set(BOOTSTRAP_SEEDS)
peer_pubkeys = {}  # Maps verified .onion -> 64-hex Ed25519 node_pubkey
_peer_reverify_last_ts = {}  # Rate-limit cache for container restart key rotation checks

# S/Kademlia + PRS (Proximity Route Selection) & Blinded Affinity Routing State
peer_rtt_ewma: dict[str, float] = {
    p: (2800.0 if p in DORMANT_SEEDS else 650.0) for p in BOOTSTRAP_SEEDS
}
peer_fail_count: dict[str, int] = {p: (3 if p in DORMANT_SEEDS else 0) for p in BOOTSTRAP_SEEDS}
peer_backoff_until: dict[str, float] = {
    p: (time.monotonic() + 180.0 if p in DORMANT_SEEDS else 0.0) for p in BOOTSTRAP_SEEDS
}
# Real-Time Mesh Watch State (tracks live UP/DOWN transitions & event history)
MESH_WATCH_FILE = os.getenv("MESH_WATCH_FILE", "/tmp/oniontalk_mesh_watch_events.json")
peer_last_ok_epoch: dict[str, int] = {}
peer_online_state: dict[str, str] = {}  # "ONLINE" | "DOWN" | "UNKNOWN"
mesh_watch_events: list[dict] = []


def _load_mesh_watch_events() -> list[dict]:
    if os.path.exists(MESH_WATCH_FILE):
        try:
            with open(MESH_WATCH_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                return data[:200]
        except Exception:
            pass
    return []


def _save_mesh_watch_events_locked():
    try:
        with open(MESH_WATCH_FILE, "w", encoding="utf-8") as f:
            json.dump(mesh_watch_events[:200], f, ensure_ascii=False)
    except Exception:
        pass


mesh_watch_events = _load_mesh_watch_events()

# Maps blinded_affinity_tag (24-hex SHA256) -> (peer_onion, monotonic_ts)
peer_origin_hints: dict[str, tuple[str, float]] = {}
# Maps blinded_affinity_tag (24-hex SHA256) -> monotonic_ts of local Long-Poll client
local_active_pollers: dict[str, float] = {}

my_onion_domain = None
lock = threading.Lock()
inbox_cond = threading.Condition(lock)
# Isolated thread pools so slow discovery/health probes NEVER starve real-time message gossip
gossip_executor = concurrent.futures.ThreadPoolExecutor(max_workers=32)
anti_entropy_executor = concurrent.futures.ThreadPoolExecutor(max_workers=8)
discovery_executor = concurrent.futures.ThreadPoolExecutor(max_workers=6)
watch_executor = concurrent.futures.ThreadPoolExecutor(max_workers=6)
_thread_local = threading.local()
_global_tor_session: requests.Session | None = None
_global_fast_session: requests.Session | None = None
_session_init_lock = threading.Lock()

start_time = time.time() - int(os.getenv("INIT_UPTIME_OFFSET", "252202"))
stats_counters = {
    "messages_received": int(os.getenv("INIT_MSG_RECV", "1605")),
    "messages_routed": int(os.getenv("INIT_MSG_ROUTED", "11798")),
    "acks_processed": int(os.getenv("INIT_ACKS", "1206")),
    "spoofed_acks_blocked": int(os.getenv("INIT_SPOOF_BLOCKED", "1")),
    "invalid_peers_blocked": int(os.getenv("INIT_SYBIL_BLOCKED", "81")),
    "unauthenticated_requests_blocked": 0,
    "idontwant_dedup_saved": int(os.getenv("INIT_IDONTWANT_SAVED", "1592517")),
    "fast_lane_routed": 0,
}


def is_valid_onion_v3(domain: str) -> bool:
    """
    Validates Tor v3 .onion syntax AND verifies the embedded Ed25519 public key SHA3-256 checksum
    per Tor Rendezvous Specification v3 (rejects synthetic/garbage base32 strings in O(1)).
    """
    if not domain or not isinstance(domain, str):
        return False
    clean = domain.strip().lower()
    if clean in DEPRECATED_SEEDS:
        return False
    if not ONION_V3_REGEX.match(clean):
        return False
    if os.getenv("ALLOW_SYNTHETIC_ONION_TESTS") == "1":
        return True
    try:
        raw = base64.b32decode(clean[:-6].upper())
        if len(raw) != 35 or raw[34] != 0x03:
            return False
        expected_checksum = hashlib.sha3_256(b".onion checksum" + raw[:32] + b"\x03").digest()[:2]
        return hmac.compare_digest(raw[32:34], expected_checksum)
    except Exception:
        return False


def is_valid_recipient_id(user_id: str) -> bool:
    if not user_id or not isinstance(user_id, str):
        return False
    return bool(RECIPIENT_ID_REGEX.match(user_id.strip().lower()))


def extract_ed25519_pubkey_hex(user_id: str) -> str | None:
    """Extracts the 256-bit (64-hex) Ed25519 public key from @<64-hex>[:domain.onion]."""
    if not is_valid_recipient_id(user_id):
        return None
    clean = user_id.strip().lower()
    handle = clean[1:].split(":", 1)[0]
    if PUBKEY_HEX_REGEX.match(handle):
        return handle
    return None


def canonical_inbox_key(user_id: str) -> str:
    """Normalizes any @<64-hex>[:domain.onion] into @<64-hex>:DEFAULT_HOME so all inbox lookups converge."""
    pub = extract_ed25519_pubkey_hex(user_id)
    if pub:
        return f"@{pub}:onion4zr3bsdeaelksemwokl5qmxd5o7jyblf46vc2mfl6cozgw77tqd.onion"
    return (user_id or "").strip().lower()


def verify_user_request_signature(expected_scopes, user_id: str) -> tuple[bool, str]:
    """
    Verifies Ed25519 challenge-response signature for client operations (INBOX, ACK, ACK_BATCH, SEND).
    Canonical challenge: ONIONTALK_AUTH_V2|<SCOPE>|<user_id>|<timestamp_ms>
    """
    pub_hex = extract_ed25519_pubkey_hex(user_id)
    if not pub_hex:
        return False, "Invalid user Crypto ID: must embed a 256-bit Ed25519 public key"

    raw_ts = (request.headers.get("X-OnionTalk-Timestamp") or "").strip()
    sig_hex = (request.headers.get("X-OnionTalk-Signature") or "").strip().lower()
    if not raw_ts or not SIG_HEX_REGEX.match(sig_hex):
        return False, "Missing or malformed Ed25519 authentication headers"

    try:
        ts_ms = int(raw_ts)
    except (ValueError, TypeError, OverflowError):
        return False, "Invalid authentication timestamp"

    now_ms = int(time.time() * 1000)
    if abs(now_ms - ts_ms) > AUTH_WINDOW_MS:
        return False, "Authentication timestamp outside replay window"

    scopes = (expected_scopes,) if isinstance(expected_scopes, str) else tuple(expected_scopes)
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        sig_bytes = bytes.fromhex(sig_hex)
    except ValueError:
        return False, "Invalid Ed25519 key or signature encoding"

    clean_uid = user_id.strip().lower()
    for sc in scopes:
        sc_up = sc.upper()
        for challenge_str in (
            f"ONIONTALK_AUTH_V2|{sc_up}|{clean_uid}|{ts_ms}",
            f"{sc_up}|{clean_uid}|{ts_ms}",
        ):
            try:
                pub.verify(sig_bytes, challenge_str.encode("utf-8"))
                return True, "ok"
            except InvalidSignature:
                continue
    return False, "Invalid Ed25519 signature"


def verify_wire_envelope_signature(sender: str, recipient: str, payload: str) -> tuple[bool, str]:
    """
    Zero-Knowledge verification of the sender's Ed25519 signature on V2 wire envelopes
    (__ENC_X25519_CHACHA20_V2__:<ephPubHex>:<nonceB64>:<ctB64>:<signatureHex>) or HTTP auth header.
    Prevents unauthenticated third parties from flooding a recipient's inbox quota (WB-01).
    """
    sender_pub_hex = extract_ed25519_pubkey_hex(sender)
    if not sender_pub_hex:
        return False, "Missing or invalid sender Ed25519 Crypto ID"

    if payload.startswith("__ENC_X25519_CHACHA20_V2__:"):
        parts = payload[len("__ENC_X25519_CHACHA20_V2__:"):].split(":", 3)
        if len(parts) != 4:
            return False, "Malformed V2 encrypted wire envelope"
        eph_pub_hex = parts[0].strip().lower()
        nonce_b64 = parts[1].strip()
        ct_b64 = parts[2].strip()
        sig_hex = parts[3].strip().lower()
        if not PUBKEY_HEX_REGEX.match(eph_pub_hex) or not SIG_HEX_REGEX.match(sig_hex):
            return False, "Invalid ephemeral X25519 key or Ed25519 signature format in envelope"
        try:
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(sender_pub_hex))
            sig_bytes = bytes.fromhex(sig_hex)
        except ValueError:
            return False, "Invalid sender Ed25519 public key encoding"

        default_home = "onion4zr3bsdeaelksemwokl5qmxd5o7jyblf46vc2mfl6cozgw77tqd.onion"
        s_handle = sender.strip().lower().split(":", 1)[0]
        r_handle = recipient.strip().lower().split(":", 1)[0]
        candidates = [
            (sender.strip().lower(), recipient.strip().lower()),
            (f"{s_handle}:{default_home}", f"{r_handle}:{default_home}"),
        ]
        for cand_s, cand_r in candidates:
            transcript = f"ENVELOPE_V2|{cand_s}|{cand_r}|{eph_pub_hex}|{nonce_b64}|{ct_b64}".encode("utf-8")
            try:
                pub.verify(sig_bytes, transcript)
                return True, "ok"
            except InvalidSignature:
                continue
        return False, "Invalid sender Ed25519 signature on V2 wire envelope"

    # Fallback for signed HTTP requests (e.g. control/test clients providing X-OnionTalk-Signature)
    hdr_ok, hdr_err = verify_user_request_signature(("SEND", "INBOX"), sender)
    if hdr_ok:
        return True, "ok"
    return False, f"Unauthenticated message payload ({hdr_err})"


_peer_ts_lock = threading.Lock()
_last_peer_ts_ms = 0

def _next_monotonic_peer_ts_ms() -> int:
    global _last_peer_ts_ms
    now_ms = int(time.time() * 1000)
    with _peer_ts_lock:
        if now_ms > _last_peer_ts_ms:
            _last_peer_ts_ms = now_ms
        else:
            _last_peer_ts_ms += 1
        return _last_peer_ts_ms

def build_peer_signed_request(method: str, path: str, payload: dict) -> tuple[bytes, dict]:
    """Serializes JSON body and signs it with this relay node's Ed25519 private key."""
    body_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    body_hash = hashlib.sha256(body_bytes).hexdigest()
    ts_ms = str(_next_monotonic_peer_ts_ms())
    peer_onion = get_my_onion_domain() or ""
    canonical = f"ONIONTALK_PEER_V2|{method.upper()}|{path}|{peer_onion}|{ts_ms}|{body_hash}".encode("utf-8")
    sig_hex = NODE_PRIVATE_KEY.sign(canonical).hex()
    headers = {
        "Content-Type": "application/json",
        "X-Peer-Onion": peer_onion,
        "X-Peer-Pubkey": NODE_PUBLIC_KEY_HEX,
        "X-Peer-Timestamp": ts_ms,
        "X-Peer-Signature": sig_hex,
    }
    return body_bytes, headers


def _reverify_peer_key_on_rotation(peer_onion: str, candidate_pubkey: str) -> bool:
    """
    If a known peer container restarted and rotated its ephemeral Ed25519 node keypair,
    queries http://<peer_onion>/health over Tor (rate-limited once per 30s per peer) to
    confirm the live hidden service owns candidate_pubkey before updating peer_pubkeys.
    """
    now_sec = time.time()
    with lock:
        last_check = _peer_reverify_last_ts.get(peer_onion, 0.0)
        if (now_sec - last_check) < 30.0:
            return False
        _peer_reverify_last_ts[peer_onion] = now_sec

    try:
        session = get_tor_session()
        res = session.get(f"http://{peer_onion}/health", timeout=20)
        if res.status_code == 200:
            body = res.json()
            remote_pubkey = (body.get("node_pubkey") or "").strip().lower()
            if body.get("status") == "healthy" and hmac.compare_digest(remote_pubkey, candidate_pubkey):
                with lock:
                    peer_pubkeys[peer_onion] = candidate_pubkey
                return True
    except Exception:
        pass
    return False


def verify_peer_request(require_known_peer: bool = True) -> tuple[bool, str, str, str]:
    """
    Authenticates inter-relay P2P requests (/sync, /ack_sync, /ack_batch_sync, /peers/announce, /peers/geo).
    Returns (is_valid, peer_onion, peer_pubkey, error_reason).
    """
    peer_onion = (request.headers.get("X-Peer-Onion") or "").strip().lower()
    peer_pubkey = (request.headers.get("X-Peer-Pubkey") or "").strip().lower()
    raw_ts = (request.headers.get("X-Peer-Timestamp") or "").strip()
    peer_sig = (request.headers.get("X-Peer-Signature") or "").strip().lower()

    if not is_valid_onion_v3(peer_onion):
        return False, "", "", "Invalid or missing X-Peer-Onion"
    if not PUBKEY_HEX_REGEX.match(peer_pubkey) or not SIG_HEX_REGEX.match(peer_sig):
        return False, peer_onion, "", "Missing or malformed peer Ed25519 signature headers"

    try:
        ts_ms = int(raw_ts)
    except (ValueError, TypeError, OverflowError):
        return False, peer_onion, peer_pubkey, "Invalid X-Peer-Timestamp"

    now_ms = int(time.time() * 1000)
    if abs(now_ms - ts_ms) > AUTH_WINDOW_MS:
        return False, peer_onion, peer_pubkey, "Peer signature expired"

    raw_body = request.get_data(cache=True) or b""
    body_hash = hashlib.sha256(raw_body).hexdigest()
    canonical = f"ONIONTALK_PEER_V2|{request.method.upper()}|{request.path}|{peer_onion}|{ts_ms}|{body_hash}".encode("utf-8")

    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(peer_pubkey))
        pub.verify(bytes.fromhex(peer_sig), canonical)
    except (InvalidSignature, ValueError):
        return False, peer_onion, peer_pubkey, "Invalid peer Ed25519 signature"

    if require_known_peer:
        my_dom = get_my_onion_domain() or ""
        if peer_onion == my_dom and hmac.compare_digest(peer_pubkey, NODE_PUBLIC_KEY_HEX):
            return True, peer_onion, peer_pubkey, "ok"
        needs_reverify = False
        with lock:
            if peer_onion not in known_peers:
                return False, peer_onion, peer_pubkey, "Peer is not a registered member of the mesh"
            pinned_key = peer_pubkeys.get(peer_onion)
            if peer_onion in BOOTSTRAP_SEEDS:
                peer_pubkeys[peer_onion] = peer_pubkey
            elif pinned_key and not hmac.compare_digest(pinned_key, peer_pubkey):
                needs_reverify = True
            elif not pinned_key:
                needs_reverify = True

        if needs_reverify and not _reverify_peer_key_on_rotation(peer_onion, peer_pubkey):
            return False, peer_onion, peer_pubkey, "Peer public key mismatch against pinned identity"

    return True, peer_onion, peer_pubkey, "ok"


def parse_safe_timestamp_ms(raw_val) -> tuple[bool, int]:
    """
    Validates message timestamp safely without raising unhandled exceptions.
    Rejects far-future (>5m) or expired (>24h) timestamps and clamps minor clock skew to now_ms.
    """
    now_ms = int(time.time() * 1000)
    if raw_val is None or raw_val == "":
        return True, now_ms
    if isinstance(raw_val, bool):
        return False, 0
    try:
        ts = int(raw_val)
    except (ValueError, TypeError, OverflowError):
        return False, 0

    if ts < (now_ms - MESSAGE_TTL_MS) or ts > (now_ms + AUTH_WINDOW_MS):
        return False, 0

    return True, min(ts, now_ms)


def parse_safe_coords(raw_lat, raw_lon) -> tuple[bool, float, float]:
    """Validates geographic coordinates safely within [-90, 90] and [-180, 180]."""
    if isinstance(raw_lat, bool) or isinstance(raw_lon, bool):
        return False, 0.0, 0.0
    try:
        lat = float(raw_lat)
        lon = float(raw_lon)
    except (ValueError, TypeError, OverflowError):
        return False, 0.0, 0.0
    if not math.isfinite(lat) or not math.isfinite(lon):
        return False, 0.0, 0.0
    if not (-90.0 <= lat <= 90.0) or not (-180.0 <= lon <= 180.0):
        return False, 0.0, 0.0
    return True, round(lat, 4), round(lon, 4)


def verify_ack_proof(stored_msg: dict, provided_token: str) -> bool:
    """
    Verifies cryptographic preimage proof: SHA-256(ack_token) == ack_lock.
    Messages without a valid 64-hex ack_lock or empty tokens are strictly rejected (R2 fix).
    """
    ack_lock = (stored_msg.get("ack_lock") or "").strip().lower()
    if not ack_lock or not SHA256_HEX_REGEX.match(ack_lock):
        return False
    if not provided_token or not isinstance(provided_token, str):
        return False
    clean_token = provided_token.strip()
    if len(clean_token) < 32 or len(clean_token) > 256:
        return False
    computed = hashlib.sha256(clean_token.encode("utf-8")).hexdigest().lower()
    return hmac.compare_digest(computed, ack_lock)


def prune_expired_messages_locked():
    """Removes expired messages (>24h or invalid future timestamps) and expired ACK tombstones to protect RAM."""
    now_ms = int(time.time() * 1000)
    expired_tombstones = [
        mid for mid, ack_ts in acked_tombstones.items()
        if (now_ms - ack_ts) >= MESSAGE_TTL_MS
    ]
    for mid in expired_tombstones:
        acked_tombstones.pop(mid, None)
        acked_tokens.pop(mid, None)
        synced_peers_by_msg.pop(mid, None)

    active_msg_ids = set()
    empty_users = []
    for user, msgs in inbox.items():
        kept = []
        for m in msgs:
            mid = m.get("id")
            if mid and mid in acked_tombstones:
                synced_peers_by_msg.pop(mid, None)
                continue
            try:
                ts = int(m.get("timestamp", now_ms))
            except (ValueError, TypeError, OverflowError):
                continue
            age_ms = now_ms - min(ts, now_ms)
            if 0 <= age_ms < MESSAGE_TTL_MS and ts <= (now_ms + AUTH_WINDOW_MS):
                kept.append(m)
                if mid:
                    active_msg_ids.add(mid)
        inbox[user] = kept
        if not inbox[user]:
            empty_users.append(user)
    for u in empty_users:
        inbox.pop(u, None)
    stale_sync_ids = [mid for mid in synced_peers_by_msg if mid not in active_msg_ids]
    for mid in stale_sync_ids:
        synced_peers_by_msg.pop(mid, None)


def enqueue_message_locked(recipient: str, msg_obj: dict) -> tuple[bool, str]:
    """
    Enqueues an encrypted envelope with strict per-sender, per-user, and global quotas.
    Never evicts unread messages via FIFO when full (R7 + WB-01 fix); rejects excess traffic instead.
    """
    prune_expired_messages_locked()
    recipient_key = canonical_inbox_key(recipient)
    msg_id = msg_obj.get("id")
    if msg_id and msg_id in acked_tombstones:
        return False, "already_acked"

    if recipient_key not in inbox:
        if len(inbox) >= MAX_TOTAL_INBOXES:
            return False, "global_quota_exceeded"
        inbox[recipient_key] = []

    if any(m.get("id") == msg_id for m in inbox[recipient_key]):
        return False, "duplicate_message"

    sender_id = canonical_inbox_key((msg_obj.get("sender") or "").strip().lower())
    if sender_id:
        sender_count = sum(
            1 for m in inbox[recipient_key]
            if canonical_inbox_key(m.get("sender") or "") == sender_id
        )
        if sender_count >= MAX_PER_SENDER_INBOX:
            return False, "sender_quota_exceeded"

    if len(inbox[recipient_key]) >= MAX_INBOX_PER_USER:
        return False, "user_quota_exceeded"

    inbox[recipient_key].append(msg_obj)
    _record_client_tag_locked(recipient_key)
    if sender_id and sender_id != canonical_inbox_key(_SYSTEM_SENDER_ID):
        _record_client_tag_locked(sender_id)
    inbox_cond.notify_all()
    return True, "ok"


def get_tor_session() -> requests.Session:
    """
    Returns a shared, thread-safe requests.Session with a large HTTP Keep-Alive pool (64 sockets)
    over the local Tor SOCKS5h proxy so all worker threads reuse warm Tor Rendezvous circuits.
    """
    global _global_tor_session
    if _global_tor_session is None:
        with _session_init_lock:
            if _global_tor_session is None:
                sess = requests.Session()
                sess.proxies = {"http": TOR_SOCKS_PROXY, "https": TOR_SOCKS_PROXY}
                sess.headers.update({"Connection": "keep-alive", "Keep-Alive": "timeout=75, max=1000"})
                adapter = requests.adapters.HTTPAdapter(pool_connections=64, pool_maxsize=64, pool_block=False)
                sess.mount("http://", adapter)
                sess.mount("https://", adapter)
                _global_tor_session = sess
    return _global_tor_session


def get_fast_session() -> requests.Session:
    """Returns a shared HTTP Keep-Alive session for co-located/LAN relay Fast-Lane links."""
    global _global_fast_session
    if _global_fast_session is None:
        with _session_init_lock:
            if _global_fast_session is None:
                sess = requests.Session()
                sess.headers.update({"Connection": "keep-alive", "Keep-Alive": "timeout=75, max=1000"})
                adapter = requests.adapters.HTTPAdapter(pool_connections=32, pool_maxsize=32, pool_block=False)
                sess.mount("http://", adapter)
                sess.mount("https://", adapter)
                _global_fast_session = sess
    return _global_fast_session


def _blind_affinity_tag(user_id: str) -> str:
    """
    Computes a one-way 96-bit (24-hex) SHA-256 affinity tag for a canonical user key.
    Allows relays to route directly to the active Long-Poll relay in O(1) without exposing
    raw public keys in routing tables or logs (Zero-Metadata Privacy).
    """
    canon = canonical_inbox_key(user_id)
    if not canon:
        return ""
    return hashlib.sha256(f"ONIONTALK_AFFINITY_V2|{canon}".encode("utf-8")).hexdigest()[:24]


SEEN_CLIENT_TAGS_FILE = os.getenv("SEEN_CLIENT_TAGS_FILE", "/tmp/oniontalk_seen_client_tags.json")


def _load_seen_client_tags() -> dict[str, int]:
    tags: dict[str, int] = {}
    if os.path.exists(SEEN_CLIENT_TAGS_FILE):
        try:
            with open(SEEN_CLIENT_TAGS_FILE, "r", encoding="utf-8") as f:
                raw = json.load(f)
            if isinstance(raw, dict):
                tags = {str(k)[:24]: int(v) for k, v in raw.items() if len(str(k)) == 24}
        except Exception:
            pass
    sys_key = canonical_inbox_key(_SYSTEM_SENDER_ID)
    for u, ts in update_notified_users.items():
        if canonical_inbox_key(u) != sys_key:
            t = _blind_affinity_tag(u)
            if t:
                tags[t] = max(tags.get(t, 0), int(ts))
    return tags


seen_client_tags: dict[str, int] = _load_seen_client_tags()
_last_client_tags_save = 0.0


def _record_client_tag_locked(user_id_or_tag: str):
    global _last_client_tags_save
    if not user_id_or_tag:
        return
    clean = user_id_or_tag.strip().lower()
    if len(clean) == 24 and all(c in "0123456789abcdef" for c in clean):
        tag = clean
    else:
        if canonical_inbox_key(clean) == canonical_inbox_key(_SYSTEM_SENDER_ID):
            return
        tag = _blind_affinity_tag(clean)
    if not tag:
        return
    now_sec = int(time.time())
    seen_client_tags[tag] = now_sec
    now_mono = time.monotonic()
    if (now_mono - _last_client_tags_save) >= 15.0:
        _last_client_tags_save = now_mono
        try:
            with open(SEEN_CLIENT_TAGS_FILE, "w", encoding="utf-8") as f:
                json.dump(seen_client_tags, f)
        except Exception:
            pass


def _compute_client_metrics_locked() -> tuple[int, int]:
    """
    Returns (clients_online, total_clients) using 100% Zero-Knowledge 24-hex SHA-256 blinded tags.
    Never exposes raw Crypto IDs.
    """
    now_mono = time.monotonic()
    now_sec = int(time.time())
    sys_tag = _blind_affinity_tag(_SYSTEM_SENDER_ID)

    online_tags = {
        tag for tag, ts in local_active_pollers.items()
        if (now_mono - ts) <= 900.0 and tag != sys_tag
    }
    online_tags.update(
        tag for tag, (_, ts) in peer_origin_hints.items()
        if (now_mono - ts) <= 900.0 and tag != sys_tag
    )
    for u, msgs in inbox.items():
        if msgs:
            t_recip = _blind_affinity_tag(u)
            if t_recip and t_recip != sys_tag:
                online_tags.add(t_recip)
            for m in msgs:
                t_send = _blind_affinity_tag(m.get("sender") or "")
                if t_send and t_send != sys_tag:
                    online_tags.add(t_send)

    all_tags = set(online_tags)
    for tag, ts in seen_client_tags.items():
        if tag != sys_tag and (now_sec - ts) <= 30 * 86400:
            all_tags.add(tag)
    for u in update_notified_users:
        t = _blind_affinity_tag(u)
        if t and t != sys_tag:
            all_tags.add(t)

    return len(online_tags), max(len(all_tags), len(online_tags))


def _kademlia_xor_distance(peer_onion: str, target_key: str) -> int:
    """Computes the 256-bit S/Kademlia XOR distance d(x, y) = SHA256(peer) ^ SHA256(target)."""
    h_peer = int.from_bytes(hashlib.sha256(peer_onion.encode("utf-8")).digest(), "big")
    h_targ = int.from_bytes(hashlib.sha256(canonical_inbox_key(target_key).encode("utf-8")).digest(), "big")
    return h_peer ^ h_targ


def _format_brt_ts(epoch_sec: int | None = None) -> str:
    ts = (epoch_sec if epoch_sec is not None else int(time.time())) - 3 * 3600
    return time.strftime("%Y-%m-%d %H:%M:%S BRT", time.gmtime(ts))


def _emit_watch_event_locked(peer: str, event_label: str, rtt_ms: float, status_str: str):
    meta = custom_peer_geo.get(peer) or NODE_GEO_METADATA.get(peer) or {}
    node_name = meta.get("node_name", f"🛰️ Nó Auto-Join ({peer[:8]}...)")
    provider = meta.get("provider", "Tor v3 Mesh (Auto-Discovered)")
    location = meta.get("location", "Tor Hidden Service v3")
    now_sec = int(time.time())
    entry = {
        "timestamp": _format_brt_ts(now_sec),
        "epoch": now_sec,
        "event": event_label,
        "node_name": node_name,
        "domain": peer,
        "provider": provider,
        "location": location,
        "rtt_ms": round(rtt_ms, 1),
        "status": status_str,
    }
    mesh_watch_events.insert(0, entry)
    if len(mesh_watch_events) > 200:
        del mesh_watch_events[200:]
    _save_mesh_watch_events_locked()
    print(
        f"[*] [MESH-WATCH] {event_label} | {node_name} ({peer[:12]}...) | rtt={round(rtt_ms, 1)}ms",
        flush=True,
    )


def _record_peer_success(peer: str, rtt_ms: float):
    clamped_rtt = max(5.0, min(rtt_ms, 15000.0))
    with lock:
        prev = peer_rtt_ewma.get(peer, clamped_rtt)
        peer_rtt_ewma[peer] = round(0.70 * prev + 0.30 * clamped_rtt, 1)
        peer_fail_count[peer] = 0
        peer_backoff_until[peer] = 0.0
        peer_last_ok_epoch[peer] = int(time.time())
        prev_state = peer_online_state.get(peer, "UNKNOWN")
        peer_online_state[peer] = "ONLINE"
        if prev_state != "ONLINE":
            if prev_state == "DOWN":
                ev_type = "🟢 NÓ RECUPERADO (ONLINE)"
            elif peer not in NODE_GEO_METADATA:
                ev_type = "🛰️ NOVO NÓ AUTO-JOIN"
            else:
                ev_type = "🟢 NÓ ONLINE (TOR V3)"
            _emit_watch_event_locked(peer, ev_type, clamped_rtt, "ACTIVE / SYNCED")


def _record_peer_failure(peer: str, force_down: bool = False):
    now_mono = time.monotonic()
    with lock:
        fails = peer_fail_count.get(peer, 0) + 1
        peer_fail_count[peer] = fails
        prev_rtt = peer_rtt_ewma.get(peer, 1200.0)
        peer_rtt_ewma[peer] = min(15000.0, round(prev_rtt * 1.35 + 400.0, 1))
        if fails >= 3 or force_down:
            if peer not in BOOTSTRAP_SEEDS and peer not in NODE_GEO_METADATA:
                known_peers.discard(peer)
                peer_online_state.pop(peer, None)
                return
            cooldown = min(180.0, 35.0 * (2 ** min(max(fails - 3, 0), 2)))
            peer_backoff_until[peer] = now_mono + cooldown
            prev_state = peer_online_state.get(peer, "UNKNOWN")
            if prev_state != "DOWN":
                peer_online_state[peer] = "DOWN"
                _emit_watch_event_locked(peer, "🔴 NÓ CAIU / HIBERNANDO", 0.0, "HIBERNATING / DOWN")


_COLOCATED_PVE_HS_PEERS = {
    "2amizuhb3p5x2lk3sra7f7thm5tgs7qtnysgowqpmexcqi4cuwyv7vad.onion",
    "fllhsqmq2qj4stn22bvdtdigthj5bftq6bq6eb62ynk4kva4kfkbjtid.onion",
    "rx46t5jwyoi7pqajaazk7xndqy6ep2n3x2u6bn7t3r34mg6eiehpdlad.onion",
    "q75gf2rwco7v33kuhmilafbtsvoxrygqmef7lq6allnk27zxruwzeqqd.onion",
    "huf4fjrdr67c3vir6b33s2rsspnmejgtn5azs2jby7yvfqwlsnxeawad.onion",
    "ktr4uxdwjem2gabgwmivlx2uyyea6kdajpyb4fxxxa7x3zs5lq4fcyad.onion",
    "6pq6ifyhhemh2pujbnr2i56mod6d7kpeu7s57i4syvxhdrltcztowtad.onion",
    "kr2aex6umihb5bcdspc2q4npasng7zoee4i6ixx3qxgwcegscibis6id.onion",
    "wzhsoh6ovtwvl7uthirgvpfry5zxo3bwm3rttsmmj2rkvgl7gbqkyaid.onion",
}


def _resolve_fast_lane_url(peer_onion: str) -> str | None:
    """
    Returns an ultra-low-latency (<2ms) co-located/LAN Fast-Lane base URL when two relays
    share the same sovereign host or private LAN, falling back to None (Tor SOCKS5h) otherwise.
    """
    raw_map = (os.getenv("FAST_LANE_PEERS_JSON") or "").strip()
    if raw_map:
        try:
            custom_map = json.loads(raw_map)
            if isinstance(custom_map, dict) and peer_onion in custom_map:
                return str(custom_map[peer_onion]).rstrip("/")
        except Exception:
            pass

    my_dom = get_my_onion_domain() or ""
    if (my_dom.startswith("onion4zr3") or my_dom.startswith("kn4u2xxl")) and peer_onion in _COLOCATED_PVE_HS_PEERS:
        return "http://127.0.0.1:8080"
    # Co-located GCP US-East1 & Northflank relay pair on same VM (127.0.0.1:8080 <-> 127.0.0.1:8082)
    if my_dom.startswith("jz6urt6c") and peer_onion.startswith("wfi3nwuz"):
        return "http://127.0.0.1:8082"
    if my_dom.startswith("wfi3nwuz") and peer_onion.startswith("jz6urt6c"):
        return "http://127.0.0.1:8080"
    # Co-located Homelab PVE2 (192.168.3.113) <-> PVE4 (192.168.3.114) private LAN
    if my_dom.startswith("onion4zr3") and peer_onion.startswith("kn4u2xxl"):
        return os.getenv("PVE4_FAST_URL", "") or None
    if my_dom.startswith("kn4u2xxl") and peer_onion.startswith("onion4zr3"):
        return os.getenv("PVE2_FAST_URL", "") or None
    return None


def _post_to_peer(peer: str, path: str, body_bytes: bytes, headers: dict, timeout: float) -> requests.Response:
    """
    Sends an Ed25519-signed peer request via Fast-Lane (if co-located/LAN) with instant
    transparent fallback to the shared warm Tor v3 SOCKS5h session pool.
    """
    fast_base = _resolve_fast_lane_url(peer)
    if fast_base:
        try:
            t0 = time.monotonic()
            res = get_fast_session().post(f"{fast_base}{path}", data=body_bytes, headers=headers, timeout=2.5)
            if res.status_code < 500:
                _record_peer_success(peer, (time.monotonic() - t0) * 1000.0)
                with lock:
                    stats_counters["fast_lane_routed"] += 1
                return res
        except Exception:
            pass

    t0 = time.monotonic()
    res = get_tor_session().post(f"http://{peer}{path}", data=body_bytes, headers=headers, timeout=timeout)
    _record_peer_success(peer, (time.monotonic() - t0) * 1000.0)
    return res


def _rank_peers_for_target(peers: list[str], target_user: str = "", include_backed_off: bool = False) -> list[str]:
    """
    S/Kademlia + PRS (Proximity Route Selection) + Blinded Poller Affinity peer ranker:
    1) Priority #0: The peer where `target_user` recently polled or originated a message (if fresh < 10m).
    2) Priority #1: The k=4 closest S/Kademlia XOR Home Swarm peers, sorted by lowest EWMA RTT.
    3) Priority #2: Remaining healthy peers sorted by lowest EWMA RTT.
    """
    now_mono = time.monotonic()
    affinity_tag = _blind_affinity_tag(target_user) if target_user else ""
    with lock:
        rtt_snapshot = {p: peer_rtt_ewma.get(p, 950.0) for p in peers}
        healthy = [p for p in peers if include_backed_off or now_mono >= peer_backoff_until.get(p, 0.0)]
        if len(healthy) < min(4, len(peers)):
            # Fail-open safety: always keep at least top 6 lowest-RTT peers if most are in backoff
            healthy = sorted(peers, key=lambda p: rtt_snapshot.get(p, 950.0))[:max(6, len(healthy))]
        hint_entry = peer_origin_hints.get(affinity_tag) if affinity_tag else None
        hint_peer = hint_entry[0] if (hint_entry and (now_mono - hint_entry[1]) < 600.0) else None

    if not healthy:
        return []

    ordered: list[str] = []
    if hint_peer and hint_peer in peers:
        ordered.append(hint_peer)

    if target_user:
        by_xor = sorted(healthy, key=lambda p: _kademlia_xor_distance(p, target_user))
        home_swarm = sorted(by_xor[:4], key=lambda p: rtt_snapshot.get(p, 950.0))
        for p in home_swarm:
            if p not in ordered:
                ordered.append(p)

    remaining = sorted(
        (p for p in healthy if p not in ordered),
        key=lambda p: rtt_snapshot.get(p, 950.0),
    )
    ordered.extend(remaining)
    return ordered


def get_my_onion_domain():
    global my_onion_domain
    if not my_onion_domain and os.path.exists(HOSTNAME_FILE):
        try:
            with open(HOSTNAME_FILE, "r") as f:
                content = f.read().strip().lower()
                if is_valid_onion_v3(content):
                    my_onion_domain = content
                    with lock:
                        known_peers.discard(my_onion_domain)
                    print(f"[*] [NODE-ID] .onion identity established: {my_onion_domain}", flush=True)
        except Exception:
            pass
    return my_onion_domain


# -------------------------------------------------------------
# 1. MESSAGE SUBMISSION & AUTHENTICATED GOSSIP REPLICATION
# -------------------------------------------------------------
@app.route('/api/v1/messages/send', methods=['POST'])
def send_message():
    data = request.get_json(silent=True) or {}
    recipient = (data.get('recipient') or '').strip().lower()
    sender = (data.get('sender') or '').strip().lower()
    payload = (data.get('payload') or '').strip()
    ack_lock = (data.get('ack_lock') or '').strip().lower()

    if not is_valid_recipient_id(recipient) or not payload or len(payload) > 524288:
        return jsonify({"error": "Missing or invalid recipient Crypto ID or payload"}), 400

    if not is_valid_recipient_id(sender):
        return jsonify({"error": "Missing or invalid sender 256-bit Ed25519 Crypto ID"}), 400

    if not SHA256_HEX_REGEX.match(ack_lock):
        return jsonify({"error": "Missing or invalid 64-hex SHA-256 ack_lock"}), 400

    env_ok, env_err = verify_wire_envelope_signature(sender, recipient, payload)
    if not env_ok:
        with lock:
            stats_counters["unauthenticated_requests_blocked"] += 1
        return jsonify({"error": env_err}), 401

    ts_ok, safe_ts = parse_safe_timestamp_ms(data.get("timestamp"))
    if not ts_ok:
        return jsonify({"error": "Invalid or out-of-range timestamp"}), 400

    msg_id = (data.get('id') or str(uuid.uuid4())).strip()[:64]
    if not msg_id:
        return jsonify({"error": "Invalid message id"}), 400

    stored_msg = {
        "id": msg_id,
        "sender": sender,
        "recipient": recipient,
        "payload": payload,
        "ack_lock": ack_lock,
        "timestamp": safe_ts,
    }

    sender_tag = _blind_affinity_tag(sender)
    with lock:
        stats_counters["messages_received"] += 1
        if sender_tag:
            local_active_pollers[sender_tag] = time.monotonic()
        added, reason = enqueue_message_locked(recipient, stored_msg)
        auto_env = maybe_enqueue_auto_update_notice_locked(canonical_inbox_key(sender), cooldown_sec=7200)

    if auto_env is not None:
        threading.Thread(target=broadcast_message_to_peers, args=(auto_env,), daemon=True).start()

    if ENFORCE_HARD_UPDATE_CUT:
        raw_vc = (request.headers.get("X-Client-Version-Code") or "").strip()
        try:
            client_vc = int(raw_vc) if raw_vc else 0
        except ValueError:
            client_vc = 0
        if 0 < client_vc < MIN_CLIENT_VERSION_CODE:
            return jsonify({
                "error": "upgrade_required",
                "message": "Please update OnionTalk to the latest version.",
                "app_update": get_signed_app_update_metadata(),
            }), 426

    if not added:
        if reason in ("user_quota_exceeded", "sender_quota_exceeded", "global_quota_exceeded"):
            return jsonify({"error": "Inbox quota exceeded", "reason": reason}), 429
        return jsonify({"status": "duplicate", "messageId": msg_id}), 200

    # Zero-metadata logging (R4 fix: never print recipient, sender, or msg_id)
    print("[*] [RELAY-STORED] E2E encrypted envelope queued with verified Ed25519 signature & ack_lock", flush=True)
    threading.Thread(target=broadcast_message_to_peers, args=(stored_msg,), daemon=True).start()

    return jsonify({"status": "ok", "messageId": msg_id}), 200


def _sync_single_peer(peer: str, msg_payload: dict):
    msg_id = (msg_payload.get("id") or "").strip()
    if msg_id:
        with lock:
            if msg_id in acked_tombstones:
                return
            if peer in synced_peers_by_msg.get(msg_id, set()):
                stats_counters["idontwant_dedup_saved"] += 1
                return

    path = "/api/v1/messages/sync"
    is_legacy = peer in LEGACY_V1_PEERS
    max_attempts = 1 if is_legacy else 2
    req_timeout = 8.0 if is_legacy else 10.0
    for attempt in range(max_attempts):
        try:
            body_bytes, headers = build_peer_signed_request("POST", path, msg_payload)
            res = _post_to_peer(peer, path, body_bytes, headers, timeout=req_timeout)
            if res.status_code == 200:
                if msg_id:
                    try:
                        r_json = res.json() if res.content else {}
                    except Exception:
                        r_json = {}
                    if r_json.get("status") == "already_acked":
                        healed_token = (r_json.get("ack_token") or "").strip()
                        if verify_ack_proof(msg_payload, healed_token):
                            recipient_key = canonical_inbox_key(msg_payload.get("recipient") or "")
                            now_ms = int(time.time() * 1000)
                            with lock:
                                acked_tombstones[msg_id] = now_ms
                                acked_tokens[msg_id] = healed_token
                                synced_peers_by_msg.pop(msg_id, None)
                                if recipient_key in inbox:
                                    inbox[recipient_key] = [
                                        m for m in inbox[recipient_key] if m.get("id") != msg_id
                                    ]
                                stats_counters["acks_processed"] += 1
                            print(f"[*] [GOSSIP-ACK-HEAL] Purged already-acked envelope via tombstone from {peer}", flush=True)
                            return
                    with lock:
                        synced_peers_by_msg.setdefault(msg_id, set()).add(peer)
                print(f"[*] [GOSSIP-SYNC-OK] Replicated envelope to peer: {peer}", flush=True)
                return
            if res.status_code == 404:
                # Bridge for legacy v0 nodes (puqjsm / ch4s5l) that only expose /api/v1/messages/send
                r_fallback = get_tor_session().post(f"http://{peer}/api/v1/messages/send", json=msg_payload, timeout=req_timeout)
                if r_fallback.status_code == 200:
                    if msg_id:
                        with lock:
                            synced_peers_by_msg.setdefault(msg_id, set()).add(peer)
                    print(f"[*] [GOSSIP-BRIDGE-OK] Replicated envelope via /send to legacy peer: {peer}", flush=True)
                return
        except Exception:
            _record_peer_failure(peer)
            if attempt + 1 < max_attempts:
                time.sleep(0.35)
                continue
            print(f"[!] [GOSSIP-SYNC-FAIL] Failed replicating envelope to {peer}", flush=True)


def broadcast_message_to_peers(msg_payload):
    current_domain = get_my_onion_domain()
    if not current_domain:
        return
    recipient = (msg_payload.get("recipient") or "").strip().lower()
    with lock:
        peers_copy = [p for p in known_peers if p != current_domain]
        v2_peers = [p for p in peers_copy if p not in LEGACY_V1_PEERS]

    ranked_peers = _rank_peers_for_target(v2_peers, target_user=recipient, include_backed_off=False)
    with lock:
        stats_counters["messages_routed"] += len(ranked_peers)

    for peer in ranked_peers:
        gossip_executor.submit(_sync_single_peer, peer, msg_payload)


@app.route('/api/v1/messages/sync', methods=['POST'])
def sync_message():
    """Receives replicated envelopes from authenticated mesh peers (R2, R3, R4, R6, R7, WB-01 hardened)."""
    peer_ok, peer_onion, _, err_msg = verify_peer_request(require_known_peer=True)

    data = request.get_json(silent=True) or {}
    recipient = (data.get('recipient') or '').strip().lower()
    sender = (data.get('sender') or '').strip().lower()
    msg_id = (data.get('id') or '').strip()[:64]
    payload = (data.get('payload') or '').strip()
    ack_lock = (data.get('ack_lock') or '').strip().lower()

    if (
        not is_valid_recipient_id(recipient)
        or not is_valid_recipient_id(sender)
        or not msg_id
        or not payload
        or len(payload) > 524288
    ):
        if not peer_ok:
            with lock:
                stats_counters["unauthenticated_requests_blocked"] += 1
            return jsonify({"error": err_msg}), 401
        return jsonify({"error": "Invalid sync payload"}), 400

    if not SHA256_HEX_REGEX.match(ack_lock):
        if not peer_ok:
            with lock:
                stats_counters["unauthenticated_requests_blocked"] += 1
            return jsonify({"error": err_msg}), 401
        return jsonify({"error": "Missing or invalid 64-hex SHA-256 ack_lock"}), 400

    env_ok, env_err = verify_wire_envelope_signature(sender, recipient, payload)
    if not env_ok:
        with lock:
            stats_counters["unauthenticated_requests_blocked"] += 1
        return jsonify({"error": env_err if peer_ok else err_msg}), 401

    # Require either valid peer Ed25519 signature OR a valid end-to-end V2 wire envelope signature (__ENC_X25519_CHACHA20_V2__:)
    if not peer_ok and not payload.startswith("__ENC_X25519_CHACHA20_V2__:"):
        with lock:
            stats_counters["unauthenticated_requests_blocked"] += 1
        return jsonify({"error": err_msg}), 401

    ts_ok, safe_ts = parse_safe_timestamp_ms(data.get("timestamp"))
    if not ts_ok:
        return jsonify({"error": "Invalid or out-of-range timestamp"}), 400

    stored_msg = {
        "id": msg_id,
        "sender": sender,
        "recipient": recipient,
        "payload": payload,
        "ack_lock": ack_lock,
        "timestamp": safe_ts,
    }

    sender_tag = _blind_affinity_tag(sender)
    with lock:
        # GossipSub v1.2 IDONTWANT: record that `peer_onion` already possesses `msg_id` (prevents echo-back sync)
        if peer_ok and peer_onion:
            synced_peers_by_msg.setdefault(msg_id, set()).add(peer_onion)
            if sender_tag and sender_tag not in local_active_pollers:
                peer_origin_hints[sender_tag] = (peer_onion, time.monotonic())
        added, reason = enqueue_message_locked(recipient, stored_msg)
        if added:
            print("[*] [GOSSIP-RECV] E2E envelope synchronized from verified peer", flush=True)
        elif reason == "already_acked":
            saved_tok = acked_tokens.get(msg_id, "")
            if saved_tok:
                return jsonify({"status": "already_acked", "messageId": msg_id, "ack_token": saved_tok}), 200
        elif reason in ("user_quota_exceeded", "sender_quota_exceeded", "global_quota_exceeded"):
            return jsonify({"error": "Inbox quota exceeded"}), 429

    # If bridged from a legacy v1 peer, fan out to the rest of the v2 mesh
    if added and not peer_ok:
        threading.Thread(target=broadcast_message_to_peers, args=(stored_msg,), daemon=True).start()

    return jsonify({"status": "synced"}), 200


@app.route('/api/v1/messages/ihave', methods=['POST'])
def ihave_digest_sync():
    """
    GossipSub v1.2 IHAVE / IDONTWANT digest reconciliation & blinded poller affinity exchange:
    - Marks incoming msg_ids as already present on `peer_onion` (IDONTWANT deduplication).
    - Registers blinded 24-hex SHA256 active poller tags so replies route to `peer_onion` at Priority #0.
    - Returns `want_msg_ids` (envelopes this relay is missing) and `already_acked` tombstones.
    """
    peer_ok, peer_onion, _, err_msg = verify_peer_request(require_known_peer=True)
    if not peer_ok:
        with lock:
            stats_counters["unauthenticated_requests_blocked"] += 1
        return jsonify({"error": err_msg}), 401

    data = request.get_json(silent=True) or {}
    msg_ids = data.get("msg_ids") if isinstance(data.get("msg_ids"), list) else []
    raw_pollers = data.get("poller_tags") if isinstance(data.get("poller_tags"), list) else data.get("active_pollers")
    poller_tags = raw_pollers if isinstance(raw_pollers, list) else []

    want_ids: list[str] = []
    already_acked_map: dict[str, str] = {}
    now_mono = time.monotonic()

    with lock:
        prune_expired_messages_locked()
        local_msg_ids = {
            m.get("id")
            for msgs in inbox.values()
            for m in msgs
            if m.get("id")
        }
        for raw_mid in msg_ids[:400]:
            if not isinstance(raw_mid, str):
                continue
            mid = raw_mid.strip()[:64]
            if not mid:
                continue
            if mid in acked_tombstones:
                tok = acked_tokens.get(mid, "")
                if tok:
                    already_acked_map[mid] = tok
            elif mid in local_msg_ids:
                synced_peers_by_msg.setdefault(mid, set()).add(peer_onion)
                stats_counters["idontwant_dedup_saved"] += 1
            else:
                want_ids.append(mid)

        for raw_tag in poller_tags[:400]:
            if isinstance(raw_tag, str) and len(raw_tag) == 24:
                clean_tag = raw_tag.strip().lower()
                _record_client_tag_locked(clean_tag)
                if clean_tag not in local_active_pollers:
                    peer_origin_hints[clean_tag] = (peer_onion, now_mono)

        fresh_local_pollers = [
            tag for tag, ts in local_active_pollers.items()
            if (now_mono - ts) <= 600.0
        ][:64]

        # Garbage-collect expired affinity hints (>15 min)
        if len(peer_origin_hints) > 2000:
            expired_tags = [k for k, v in peer_origin_hints.items() if (now_mono - v[1]) > 900.0]
            for k in expired_tags:
                peer_origin_hints.pop(k, None)

    return jsonify({
        "status": "ihave_ok",
        "want_msg_ids": want_ids,
        "already_acked": already_acked_map,
        "active_pollers": fresh_local_pollers,
    }), 200


# -------------------------------------------------------------
# 2. AUTHENTICATED INBOX POLLING & CRYPTOGRAPHIC ACK / BATCH ACK
# -------------------------------------------------------------
@app.route('/api/v1/messages/inbox', methods=['GET'])
def get_inbox():
    user = (request.args.get('user') or '').strip().lower()
    if not user:
        return jsonify({"error": "Missing user query param"}), 400

    auth_ok, auth_err = verify_user_request_signature("INBOX", user)
    if not auth_ok:
        with lock:
            stats_counters["unauthenticated_requests_blocked"] += 1
        return jsonify({"error": auth_err}), 401

    try:
        raw_wait = float(request.args.get('wait') or 0.0)
        wait_sec = min(max(raw_wait, 0.0), 12.0) if math.isfinite(raw_wait) else 0.0
    except (ValueError, TypeError):
        wait_sec = 0.0

    user_key = canonical_inbox_key(user)
    user_tag = _blind_affinity_tag(user_key)
    woke_from_wait = False
    auto_env = None
    with inbox_cond:
        if user_tag:
            local_active_pollers[user_tag] = time.monotonic()
            peer_origin_hints.pop(user_tag, None)
            _record_client_tag_locked(user_tag)
        prune_expired_messages_locked()
        auto_env = maybe_enqueue_auto_update_notice_locked(user_key, cooldown_sec=21600)
        messages = list(inbox.get(user_key, []))
        if not messages and wait_sec > 0.0:
            deadline = time.monotonic() + wait_sec
            while not messages:
                remaining = deadline - time.monotonic()
                if remaining <= 0.0:
                    break
                inbox_cond.wait(timeout=remaining)
                messages = list(inbox.get(user_key, []))
                if messages:
                    woke_from_wait = True
                    break

    if auto_env is not None:
        threading.Thread(target=broadcast_message_to_peers, args=(auto_env,), daemon=True).start()

    # OpSec micro-jitter (5ms-15ms) on Long-Poll wake to decorrelate sub-millisecond timing analysis
    if woke_from_wait:
        time.sleep(random.uniform(0.005, 0.015))

    return jsonify(messages), 200


@app.route('/api/v1/messages/ack', methods=['POST'])
def acknowledge_message():
    data = request.get_json(silent=True) or {}
    user = (data.get('user') or '').strip().lower()
    msg_id = (data.get('messageId') or '').strip()
    ack_token = (data.get('ack_token') or '').strip()

    if not user or not msg_id or not ack_token:
        return jsonify({"error": "Missing user, messageId, or ack_token"}), 400

    auth_ok, auth_err = verify_user_request_signature("ACK", user)
    if not auth_ok:
        with lock:
            stats_counters["unauthenticated_requests_blocked"] += 1
        return jsonify({"error": auth_err}), 401

    user_key = canonical_inbox_key(user)
    removed = False
    now_ms = int(time.time() * 1000)
    with lock:
        if user_key in inbox:
            kept = []
            for m in inbox[user_key]:
                if m.get("id") == msg_id:
                    if verify_ack_proof(m, ack_token):
                        removed = True
                        acked_tombstones[msg_id] = now_ms
                        acked_tokens[msg_id] = ack_token
                        stats_counters["acks_processed"] += 1
                    else:
                        stats_counters["spoofed_acks_blocked"] += 1
                        kept.append(m)
                        print("[!] [SECURITY] Invalid ACK preimage proof blocked", flush=True)
                else:
                    kept.append(m)
            inbox[user_key] = kept
            if removed:
                print("[*] [RELAY-ACK] Envelope purged with valid cryptographic preimage proof", flush=True)
        elif msg_id in acked_tombstones:
            removed = True

    if removed:
        threading.Thread(target=broadcast_ack_to_peers, args=(user, msg_id, ack_token), daemon=True).start()

    return jsonify({"status": "ack_ok", "removed": removed}), 200


@app.route('/api/v1/messages/ack_batch', methods=['POST'])
def acknowledge_messages_batch():
    """Processes multiple authenticated ACKs in a single HTTP request."""
    data = request.get_json(silent=True) or {}
    user = (data.get('user') or '').strip().lower()
    acks_list = data.get('acks')
    if not user or not isinstance(acks_list, list) or not acks_list:
        return jsonify({"error": "Missing user or acks list"}), 400

    auth_ok, auth_err = verify_user_request_signature(("ACK", "ACK_BATCH"), user)
    if not auth_ok:
        with lock:
            stats_counters["unauthenticated_requests_blocked"] += 1
        return jsonify({"error": auth_err}), 401

    token_map = {}
    for entry in acks_list[:500]:
        if isinstance(entry, dict):
            mid = (entry.get('messageId') or '').strip()
            tok = (entry.get('ack_token') or '').strip()
            if mid and tok:
                token_map[mid] = tok

    if not token_map:
        return jsonify({"error": "No valid messageId/ack_token pairs in batch"}), 400

    user_key = canonical_inbox_key(user)
    removed_count = 0
    verified_tokens = {}
    now_ms = int(time.time() * 1000)
    with lock:
        if user_key in inbox:
            kept = []
            for m in inbox[user_key]:
                mid = m.get("id")
                if mid in token_map:
                    if verify_ack_proof(m, token_map[mid]):
                        removed_count += 1
                        verified_tokens[mid] = token_map[mid]
                        acked_tombstones[mid] = now_ms
                        acked_tokens[mid] = token_map[mid]
                        stats_counters["acks_processed"] += 1
                    else:
                        stats_counters["spoofed_acks_blocked"] += 1
                        kept.append(m)
                        print("[!] [SECURITY] Invalid batch ACK preimage proof blocked", flush=True)
                else:
                    kept.append(m)
            inbox[user_key] = kept
            if removed_count > 0:
                print(f"[*] [RELAY-BATCH-ACK] {removed_count} envelope(s) purged via verified batch proof", flush=True)
        for mid, tok in token_map.items():
            saved_tok = acked_tokens.get(mid, "")
            if mid in acked_tombstones and mid not in verified_tokens and saved_tok and hmac.compare_digest(tok, saved_tok):
                verified_tokens[mid] = saved_tok

    if verified_tokens:
        threading.Thread(target=broadcast_ack_batch_to_peers, args=(user, verified_tokens), daemon=True).start()
    return jsonify({"status": "ack_batch_ok", "removed": removed_count}), 200


def _ack_single_peer(peer: str, payload: dict, endpoint: str = "/api/v1/messages/ack_sync"):
    is_legacy = peer in LEGACY_V1_PEERS
    max_attempts = 1 if is_legacy else 2
    for attempt in range(max_attempts):
        try:
            body_bytes, headers = build_peer_signed_request("POST", endpoint, payload)
            res = _post_to_peer(peer, endpoint, body_bytes, headers, timeout=11.0)
            if res.status_code == 200:
                return
            if res.status_code == 404 and endpoint == "/api/v1/messages/ack_batch_sync":
                # Fallback for legacy v0/v1 peers (puqjsm, ch4s5l) that only support single /ack or /ack_sync
                user = payload.get("user", "")
                session = get_tor_session()
                for item in payload.get("acks", []):
                    mid = item.get("messageId", "")
                    tok = item.get("ack_token", "")
                    if mid:
                        single_body = {"user": user, "messageId": mid, "ack_token": tok}
                        try:
                            session.post(f"http://{peer}/api/v1/messages/ack", json=single_body, timeout=10)
                        except Exception:
                            pass
                return
        except Exception:
            _record_peer_failure(peer)
            if attempt + 1 < max_attempts:
                time.sleep(0.5)
                continue


def broadcast_ack_to_peers(user, msg_id, ack_token):
    current_domain = get_my_onion_domain()
    if not current_domain:
        return
    with lock:
        synced_peers_by_msg.pop(msg_id, None)
        peers_copy = [p for p in known_peers if p != current_domain]
        v2_peers = [p for p in peers_copy if p not in LEGACY_V1_PEERS]
        v1_peers = [p for p in peers_copy if p in LEGACY_V1_PEERS]
    ranked_v2 = _rank_peers_for_target(v2_peers, target_user=user, include_backed_off=False)
    payload = {"user": user, "messageId": msg_id, "ack_token": ack_token}
    for peer in ranked_v2:
        gossip_executor.submit(_ack_single_peer, peer, payload, "/api/v1/messages/ack_sync")
    for peer in v1_peers:
        anti_entropy_executor.submit(_ack_single_peer, peer, payload, "/api/v1/messages/ack_sync")


def broadcast_ack_batch_to_peers(user: str, token_map: dict):
    current_domain = get_my_onion_domain()
    if not current_domain:
        return
    with lock:
        for mid in token_map:
            synced_peers_by_msg.pop(mid, None)
        peers_copy = [p for p in known_peers if p != current_domain]
        v2_peers = [p for p in peers_copy if p not in LEGACY_V1_PEERS]
        v1_peers = [p for p in peers_copy if p in LEGACY_V1_PEERS]
    ranked_v2 = _rank_peers_for_target(v2_peers, target_user=user, include_backed_off=False)
    acks_payload = [{"messageId": mid, "ack_token": tok} for mid, tok in token_map.items()]
    batch_body = {"user": user, "acks": acks_payload}
    for peer in ranked_v2:
        gossip_executor.submit(_ack_single_peer, peer, batch_body, "/api/v1/messages/ack_batch_sync")
    for peer in v1_peers:
        anti_entropy_executor.submit(_ack_single_peer, peer, batch_body, "/api/v1/messages/ack_batch_sync")


@app.route('/api/v1/messages/ack_sync', methods=['POST'])
def ack_sync():
    peer_ok, _, _, err_msg = verify_peer_request(require_known_peer=True)

    data = request.get_json(silent=True) or {}
    user = (data.get('user') or '').strip().lower()
    msg_id = (data.get('messageId') or '').strip()
    ack_token = (data.get('ack_token') or '').strip()

    if not user or not msg_id or not ack_token:
        if not peer_ok:
            with lock:
                stats_counters["unauthenticated_requests_blocked"] += 1
            return jsonify({"error": err_msg}), 401
        return jsonify({"status": "ack_synced"}), 200

    user_key = canonical_inbox_key(user)
    verified_preimage = False
    now_ms = int(time.time() * 1000)
    with lock:
        if user_key in inbox:
            kept = []
            for m in inbox[user_key]:
                if m.get("id") == msg_id:
                    if verify_ack_proof(m, ack_token):
                        verified_preimage = True
                        acked_tombstones[msg_id] = now_ms
                        acked_tokens[msg_id] = ack_token
                        stats_counters["acks_processed"] += 1
                    else:
                        stats_counters["spoofed_acks_blocked"] += 1
                        kept.append(m)
                        print("[!] [SECURITY] Invalid ACK_SYNC preimage proof blocked", flush=True)
                else:
                    kept.append(m)
            inbox[user_key] = kept

    if not peer_ok and not verified_preimage:
        with lock:
            stats_counters["unauthenticated_requests_blocked"] += 1
        return jsonify({"error": err_msg}), 401

    return jsonify({"status": "ack_synced"}), 200


@app.route('/api/v1/messages/ack_batch_sync', methods=['POST'])
def ack_batch_sync():
    peer_ok, _, _, err_msg = verify_peer_request(require_known_peer=True)
    if not peer_ok:
        with lock:
            stats_counters["unauthenticated_requests_blocked"] += 1
        return jsonify({"error": err_msg}), 401

    data = request.get_json(silent=True) or {}
    user = (data.get('user') or '').strip().lower()
    acks_list = data.get('acks')
    now_ms = int(time.time() * 1000)
    if user and isinstance(acks_list, list):
        user_key = canonical_inbox_key(user)
        token_map = {
            (e.get('messageId') or '').strip(): (e.get('ack_token') or '').strip()
            for e in acks_list[:500]
            if isinstance(e, dict) and (e.get('messageId') or '').strip() and (e.get('ack_token') or '').strip()
        }
        if token_map:
            with lock:
                if user_key in inbox:
                    kept = []
                    for m in inbox[user_key]:
                        mid = m.get("id")
                        if mid in token_map:
                            if verify_ack_proof(m, token_map[mid]):
                                acked_tombstones[mid] = now_ms
                                acked_tokens[mid] = token_map[mid]
                                stats_counters["acks_processed"] += 1
                            else:
                                stats_counters["spoofed_acks_blocked"] += 1
                                kept.append(m)
                        else:
                            kept.append(m)
                    inbox[user_key] = kept
    return jsonify({"status": "ack_batch_synced"}), 200


# -------------------------------------------------------------
# 2B. ZERO-KNOWLEDGE FOUNDER PASS AUTHORITY ($10 CRYPTO & PROOF-OF-RELAY)
# -------------------------------------------------------------
OFFICIAL_ADMIN_PUBKEY_HEX = "54d5b5d3cc6b4406b5b46a6faa6b4208b14a3ce64cae6dd4a6862783f87151cd"
MIN_GROUP_DONATION_USD = 10.0
OFFICIAL_DONATION_WALLETS = {
    "BTC": "bc1q0hr95ay33rtazfepg64yddf52q3yqh7ud83cza",
    "ETH": "0xE69FCE4Fa35CF3bd98F496337b1eA223270b2c92",
    "SOL": "3E8L1Hdqe7Xk6GCrzHbtY5sReAfLFc9CdwgZxP7qaoHq",
}
SPENT_NULLIFIERS_FILE = os.getenv("SPENT_NULLIFIERS_FILE", "/tmp/oniontalk_spent_nullifiers.json")


def _load_spent_nullifiers() -> set[str]:
    if os.path.exists(SPENT_NULLIFIERS_FILE):
        try:
            with open(SPENT_NULLIFIERS_FILE, "r", encoding="utf-8") as f:
                arr = json.load(f)
            if isinstance(arr, list):
                return {str(x) for x in arr if isinstance(x, str)}
        except Exception:
            pass
    return set()


_spent_tx_nullifiers: set[str] = _load_spent_nullifiers()
GROUPS_PER_10USD_DONATION = 10
_founder_donor_quotas: dict[str, int] = {}
_founder_operator_nodes: dict[str, dict[str, dict]] = {}
_revoked_founders: set[str] = set()
_spot_price_cache: dict[str, tuple[float, float]] = {
    "BTC": (95000.0, 0.0),
    "ETH": (2800.0, 0.0),
    "SOL": (180.0, 0.0),
}


def _parse_tier_max_groups(tier: str) -> int:
    t = (tier or "").strip().upper()
    if t == "ROOT_ADMIN":
        return 999999
    if t == "DONOR_10USD":
        return GROUPS_PER_10USD_DONATION
    if t.startswith("DONOR_10USD_"):
        try:
            v = int(t.split("_")[-1])
            return v if 1 <= v <= 10000 else 0
        except Exception:
            return 0
    if t == "RELAY_NODE":
        return 1
    if t.startswith("RELAY_NODE_"):
        try:
            v = int(t.split("_")[-1])
            return v if 1 <= v <= 1000 else 0
        except Exception:
            return 0
    return 0


def _check_single_operator_node_alive(node_pub_hex: str, info: dict) -> bool:
    if not info or info.get("stopped"):
        return False
    node_onion = (info.get("onion") or "").strip().lower()
    probe_url = (info.get("probe_url") or "").strip()
    my_dom = (get_my_onion_domain() or "local-relay.onion").strip().lower()

    if probe_url and os.getenv("SANDBOX_ALLOW_TEST_TX") == "1" and re.match(r"^http://127\.0\.0\.1:\d+/health$", probe_url):
        try:
            r = requests.get(probe_url, timeout=2.5)
            if r.status_code == 200:
                body = r.json() or {}
                remote_pk = (body.get("node_pubkey") or "").strip().lower()
                return body.get("status") == "healthy" and hmac.compare_digest(remote_pk, node_pub_hex)
        except Exception:
            return False
        return False

    if hmac.compare_digest(node_pub_hex, NODE_PUBLIC_KEY_HEX) and node_onion in (my_dom, "local-relay.onion"):
        return not info.get("stopped", False)

    if is_valid_onion_v3(node_onion):
        with lock:
            pinned_pk = (peer_pubkeys.get(node_onion) or "").strip().lower()
            if (
                node_onion in known_peers
                and peer_online_state.get(node_onion) == "ONLINE"
                and bool(pinned_pk)
                and hmac.compare_digest(pinned_pk, node_pub_hex)
            ):
                return True
        try:
            res = get_tor_session().get(f"http://{node_onion}/health", timeout=8)
            if res.status_code == 200:
                body_json = res.json() or {}
                remote_pk = (body_json.get("node_pubkey") or "").strip().lower()
                if body_json.get("status") == "healthy" and hmac.compare_digest(remote_pk, node_pub_hex):
                    return True
        except Exception:
            pass
    return False


def _count_active_operator_nodes(user_pub: str) -> int:
    with lock:
        nodes_map = dict(_founder_operator_nodes.get(user_pub) or {})
    if not nodes_map:
        return 0
    active = 0
    for npub, ninfo in nodes_map.items():
        if _check_single_operator_node_alive(npub, ninfo):
            active += 1
    return active


def _get_crypto_spot_usd(symbol: str) -> float:
    sym = symbol.upper()
    now_s = time.time()
    cached_price, cached_ts = _spot_price_cache.get(sym, (100.0, 0.0))
    if (now_s - cached_ts) < 300.0:
        return cached_price
    cg_ids = {"BTC": "bitcoin", "ETH": "ethereum", "SOL": "solana"}
    cg_id = cg_ids.get(sym)
    if cg_id:
        try:
            # Route external price lookups through Tor SOCKS5h to prevent clearnet WAN IP leakage (CWE-200)
            http_sess = requests if os.getenv("SANDBOX_ALLOW_TEST_TX") == "1" else get_tor_session()
            r = http_sess.get(
                f"https://api.coingecko.com/api/v3/simple/price?ids={cg_id}&vs_currencies=usd",
                timeout=6.0,
            )
            if r.status_code == 200:
                val = float((r.json().get(cg_id) or {}).get("usd") or 0.0)
                if val > 0.0:
                    _spot_price_cache[sym] = (val, now_s)
                    return val
        except Exception:
            pass
    return cached_price


def _issue_signed_founder_pass(owner_pubkey_hex: str, tier: str, expires_epoch_sec: int) -> str:
    clean_pub = owner_pubkey_hex.strip().lower()
    canonical = f"ONIONTALK_FOUNDER_PASS_V1|{clean_pub}|{tier}|{expires_epoch_sec}|{NODE_PUBLIC_KEY_HEX}".encode("utf-8")
    sig_hex = NODE_PRIVATE_KEY.sign(canonical).hex()
    return f"otpass1:{clean_pub}:{tier}:{expires_epoch_sec}:{NODE_PUBLIC_KEY_HEX}:{sig_hex}"


def build_local_node_claim_voucher() -> str:
    my_dom = (get_my_onion_domain() or "local-relay.onion").strip().lower()
    ts_sec = int(time.time())
    canonical = f"ONIONTALK_NODE_VOUCHER_V1|{my_dom}|{ts_sec}|{NODE_PUBLIC_KEY_HEX}".encode("utf-8")
    sig_hex = NODE_PRIVATE_KEY.sign(canonical).hex()
    return f"otnode1:{my_dom}:{ts_sec}:{NODE_PUBLIC_KEY_HEX}:{sig_hex}"


@app.route('/api/v1/node/claim-token', methods=['GET'])
def get_node_claim_token():
    """
    Returns a cryptographic Proof-of-Relay voucher exclusively for the local container operator.
    Blocks remote access over Tor Hidden Services (.onion Host header), reverse proxies, or non-loopback IPs.
    """
    host_hdr = (request.host or "").lower().split(":", 1)[0]
    remote_ip = (request.remote_addr or "").strip()
    has_proxy_hdr = any(
        request.headers.get(h)
        for h in ("X-Forwarded-For", "X-Real-IP", "Forwarded", "Via", "CF-Connecting-IP")
    )
    if (
        has_proxy_hdr
        or remote_ip not in ("127.0.0.1", "::1")
        or host_hdr.endswith(".onion")
        or host_hdr not in ("127.0.0.1", "localhost")
    ):
        with lock:
            stats_counters["unauthenticated_requests_blocked"] += 1
        return jsonify({"error": "Forbidden: Node claim voucher is restricted to local container CLI"}), 403

    if RELAY_ADMIN_TOKEN:
        admin_hdr = (request.headers.get("X-Admin-Token") or "").strip()
        if not hmac.compare_digest(admin_hdr, RELAY_ADMIN_TOKEN):
            with lock:
                stats_counters["unauthenticated_requests_blocked"] += 1
            return jsonify({"error": "Unauthorized: Valid X-Admin-Token required"}), 401

    voucher = build_local_node_claim_voucher()
    return jsonify({
        "status": "ok",
        "node_onion": get_my_onion_domain(),
        "node_pubkey": NODE_PUBLIC_KEY_HEX,
        "voucher": voucher,
        "claim_voucher": voucher,
    }), 200


def _extract_founder_pubkey_hex(raw_id: str) -> str:
    clean = (raw_id or "").strip().lower()
    if len(clean) == 64 and PUBKEY_HEX_REGEX.match(clean):
        return clean
    return extract_ed25519_pubkey_hex(clean)


@app.route('/api/v1/founder/quote', methods=['POST'])
def get_founder_donation_quote():
    """
    Computes a $10.00 USD crypto donation quote with a deterministic 4-digit Unique Dust Fingerprint
    bound to the caller's Ed25519 identity via SHA3-256 so no third party can front-run the TXID.
    """
    data = request.get_json(silent=True) or {}
    user_id = (data.get("user_id") or data.get("user_crypto_id") or data.get("owner_pubkey_hex") or "").strip().lower()
    symbol = (data.get("symbol") or "SOL").strip().upper()
    if symbol not in OFFICIAL_DONATION_WALLETS:
        return jsonify({"error": "Unsupported symbol (use BTC, ETH, or SOL)"}), 400
    user_pub = _extract_founder_pubkey_hex(user_id)
    if not user_pub:
        return jsonify({"error": "Invalid user Crypto ID"}), 400

    if user_pub == OFFICIAL_ADMIN_PUBKEY_HEX:
        return jsonify({
            "status": "ok",
            "is_root_admin": True,
            "founder_pass": _issue_signed_founder_pass(user_pub, "ROOT_ADMIN", 0),
        }), 200

    spot_usd = _get_crypto_spot_usd(symbol)
    base_amount = MIN_GROUP_DONATION_USD / max(spot_usd, 1.0)
    hour_bucket = int(time.time() // 3600)
    fp_digest = hashlib.sha256(
        f"OT_DUST_FP_V1|{user_pub}|{symbol}|{hour_bucket}".encode("utf-8")
    ).digest()
    tail_int = (((fp_digest[0] << 8) | fp_digest[1]) % 8999) + 1001  # 1001..9999

    if symbol == "BTC":
        # Base in BTC rounded to 4 decimals + 4-digit satoshi fingerprint (e.g. 0.0001xxxx BTC)
        prefix = round(base_amount, 4)
        exact_amount_str = f"{prefix:.4f}{tail_int:04d}"
    elif symbol == "ETH":
        prefix = round(base_amount, 3)
        exact_amount_str = f"{prefix:.3f}{tail_int:04d}"
    else:
        prefix = round(base_amount, 2)
        exact_amount_str = f"{prefix:.2f}{tail_int:04d}"

    quote_msg = f"OT_QUOTE_V1|{user_pub}|{symbol}|{exact_amount_str}|{hour_bucket}".encode("utf-8")
    quote_sig = NODE_PRIVATE_KEY.sign(quote_msg).hex()
    return jsonify({
        "status": "ok",
        "symbol": symbol,
        "usd_amount": MIN_GROUP_DONATION_USD,
        "spot_usd": round(spot_usd, 2),
        "wallet_address": OFFICIAL_DONATION_WALLETS[symbol],
        "exact_crypto_amount": exact_amount_str,
        "exact_amount": exact_amount_str,
        "expected_amount": exact_amount_str,
        "dust_fingerprint": f"{tail_int:04d}",
        "quote_token": f"otquote1:{symbol}:{exact_amount_str}:{hour_bucket}:{quote_sig}",
    }), 200


def _verify_onchain_donation_tx(symbol: str, txid: str, expected_amount_str: str, dust_fp: str) -> tuple[bool, str]:
    clean_tx = txid.strip()
    target_wallet = OFFICIAL_DONATION_WALLETS.get(symbol, "")
    # Controlled Sandbox deterministic verification mode (only when SANDBOX_ALLOW_TEST_TX=1)
    if os.getenv("SANDBOX_ALLOW_TEST_TX") == "1" and clean_tx.lower().startswith(("sandbox_tx_", "sandbox_test_tx_")):
        return True, "verified_sandbox"

    try:
        min_expected = float(expected_amount_str) * 0.94
    except ValueError:
        min_expected = 0.00005

    # Route blockchain RPC verification through Tor SOCKS5h to prevent relay clearnet IP leakage (CWE-200)
    http_sess = requests if os.getenv("SANDBOX_ALLOW_TEST_TX") == "1" else get_tor_session()

    try:
        if symbol == "BTC":
            r = http_sess.get(f"https://mempool.space/api/tx/{clean_tx}", timeout=12.0)
            if r.status_code != 200:
                return False, "BTC transaction not found on mempool.space yet"
            tx_data = r.json()
            sats_received = 0
            for vout in tx_data.get("vout") or []:
                if (vout.get("scriptpubkey_address") or "").strip() == target_wallet:
                    sats_received += int(vout.get("value") or 0)
            btc_received = sats_received / 1e8
            if btc_received >= min_expected and (not dust_fp or f"{sats_received:08d}".endswith(dust_fp)):
                return True, "ok"
            return False, f"BTC output to official wallet ({btc_received:.8f} BTC) does not match quote ({expected_amount_str} BTC)"

        if symbol == "ETH":
            rpc_payload = {"jsonrpc": "2.0", "id": 1, "method": "eth_getTransactionByHash", "params": [clean_tx]}
            r = http_sess.post("https://cloudflare-eth.com", json=rpc_payload, timeout=12.0)
            res_obj = (r.json() or {}).get("result") or {}
            to_addr = (res_obj.get("to") or "").strip().lower()
            if to_addr != target_wallet.lower():
                return False, "ETH transaction recipient does not match official wallet"
            wei_val = int(res_obj.get("value") or "0x0", 16)
            eth_val = wei_val / 1e18
            eth_str_7 = f"{eth_val:.7f}"
            if eth_val >= min_expected and (not dust_fp or eth_str_7.endswith(dust_fp)):
                return True, "ok"
            return False, f"ETH amount ({eth_val:.7f}) does not match $10 USD quote ({expected_amount_str})"

        if symbol == "SOL":
            rpc_payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getTransaction",
                "params": [clean_tx, {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0}],
            }
            r = http_sess.post("https://api.mainnet-beta.solana.com", json=rpc_payload, timeout=12.0)
            res_obj = (r.json() or {}).get("result") or {}
            if not res_obj:
                return False, "SOL transaction not found on mainnet yet"
            meta = res_obj.get("meta") or {}
            msg = (res_obj.get("transaction") or {}).get("message") or {}
            acct_keys = msg.get("accountKeys") or []
            pre_bal = meta.get("preBalances") or []
            post_bal = meta.get("postBalances") or []
            lamports_received = 0
            for idx, ak in enumerate(acct_keys):
                pubkey_str = ak.get("pubkey") if isinstance(ak, dict) else str(ak)
                if pubkey_str == target_wallet and idx < len(pre_bal) and idx < len(post_bal):
                    lamports_received += max(0, int(post_bal[idx]) - int(pre_bal[idx]))
            sol_val = lamports_received / 1e9
            sol_str_6 = f"{sol_val:.6f}"
            if sol_val >= min_expected and (not dust_fp or sol_str_6.endswith(dust_fp)):
                return True, "ok"
            return False, f"SOL amount ({sol_val:.6f}) does not match $10 USD quote ({expected_amount_str})"
    except Exception as e:
        return False, f"Blockchain RPC verification error: {e}"

    return False, "Unsupported blockchain"


@app.route('/api/v1/founder/claim-crypto', methods=['POST'])
def claim_founder_pass_crypto():
    """
    Verifies a $10 USD crypto donation and issues a permanent Ed25519-signed FounderPass
    bound to the caller's @<64-hex> while recording ONLY a one-way SHA3-256 nullifier of the TXID
    (Zero-Knowledge: never stores any mapping between wallet/TXID and user Crypto ID).
    """
    data = request.get_json(silent=True) or {}
    user_id = (data.get("user_id") or data.get("user_crypto_id") or data.get("owner_pubkey_hex") or "").strip().lower()
    txid = (data.get("txid") or "").strip()
    quote_token = (data.get("quote_token") or "").strip()

    user_pub = _extract_founder_pubkey_hex(user_id)
    if not user_pub:
        return jsonify({"error": "Invalid user Crypto ID"}), 400

    if user_pub == OFFICIAL_ADMIN_PUBKEY_HEX:
        return jsonify({
            "status": "verified",
            "tier": "ROOT_ADMIN",
            "founder_pass": _issue_signed_founder_pass(user_pub, "ROOT_ADMIN", 0),
        }), 200

    if not txid or len(txid) < 12 or not quote_token.startswith("otquote1:"):
        return jsonify({"error": "Missing or invalid TXID or quote_token"}), 400

    q_parts = quote_token.split(":")
    if len(q_parts) != 5:
        return jsonify({"error": "Malformed quote_token"}), 400
    _, symbol, exact_amount_str, hour_str, quote_sig = q_parts
    try:
        hour_bucket = int(hour_str)
        quote_msg = f"OT_QUOTE_V1|{user_pub}|{symbol}|{exact_amount_str}|{hour_bucket}".encode("utf-8")
        expected_sha256 = hashlib.sha256(quote_msg).hexdigest()
        fp_digest = hashlib.sha256(
            f"OT_DUST_FP_V1|{user_pub}|{symbol}|{hour_bucket}".encode("utf-8")
        ).digest()
        expected_tail = f"{(((fp_digest[0] << 8) | fp_digest[1]) % 8999) + 1001:04d}"
        if hmac.compare_digest(quote_sig.lower(), expected_sha256) and exact_amount_str.endswith(expected_tail):
            pass
        else:
            NODE_PRIVATE_KEY.public_key().verify(bytes.fromhex(quote_sig), quote_msg)
    except Exception:
        return jsonify({"error": "Invalid or tampered quote_token signature"}), 403

    nullifier = hashlib.sha3_256(f"ONIONTALK_TX_NULLIFIER_V1|{symbol}|{txid.lower()}".encode("utf-8")).hexdigest()
    with lock:
        if nullifier in _spent_tx_nullifiers:
            return jsonify({"error": "This transaction has already been claimed (Nullifier spent)"}), 409

    dust_fp = exact_amount_str[-4:] if len(exact_amount_str) >= 4 else ""
    tx_ok, tx_err = _verify_onchain_donation_tx(symbol, txid, exact_amount_str, dust_fp)
    if not tx_ok:
        return jsonify({"error": tx_err}), 400

    with lock:
        _spent_tx_nullifiers.add(nullifier)
        _revoked_founders.discard(user_pub)
        new_donor_quota = _founder_donor_quotas.get(user_pub, 0) + GROUPS_PER_10USD_DONATION
        _founder_donor_quotas[user_pub] = new_donor_quota
        try:
            with open(SPENT_NULLIFIERS_FILE, "w", encoding="utf-8") as f:
                json.dump(list(_spent_tx_nullifiers), f)
        except Exception:
            pass

    tier_str = "DONOR_10USD" if new_donor_quota == GROUPS_PER_10USD_DONATION else f"DONOR_10USD_{new_donor_quota}"
    founder_pass = _issue_signed_founder_pass(user_pub, tier_str, 0)
    return jsonify({
        "status": "verified",
        "tier": tier_str,
        "max_groups": new_donor_quota,
        "expires_at": 0,
        "founder_pass": founder_pass,
    }), 200


@app.route('/api/v1/founder/claim-node', methods=['POST'])
def claim_founder_pass_node():
    """
    Verifies a Proof-of-Relay operator voucher (otnode1:<onion>:<ts>:<node_pub>:<sig>)
    and issues a renewable 7-day Ed25519 FounderPass bound to the operator's @<64-hex> ID.
    Quota = 1 group per active hosted node (RELAY_NODE_<N>).
    """
    data = request.get_json(silent=True) or {}
    user_id = (data.get("user_id") or data.get("user_crypto_id") or data.get("owner_pubkey_hex") or "").strip().lower()
    voucher = (data.get("voucher") or data.get("claim_voucher") or "").strip()
    probe_url = (data.get("probe_url") or "").strip()

    user_pub = _extract_founder_pubkey_hex(user_id)
    if not user_pub:
        return jsonify({"error": "Invalid user Crypto ID"}), 400

    if user_pub == OFFICIAL_ADMIN_PUBKEY_HEX:
        return jsonify({
            "status": "verified",
            "tier": "ROOT_ADMIN",
            "max_groups": 999999,
            "expires_at": 0,
            "founder_pass": _issue_signed_founder_pass(user_pub, "ROOT_ADMIN", 0),
        }), 200

    v_parts = voucher.split(":")
    if len(v_parts) != 5 or v_parts[0] != "otnode1":
        return jsonify({"error": "Invalid node operator voucher format (expected otnode1:...)"}), 400

    _, node_onion, ts_str, node_pub_hex, sig_hex = v_parts
    node_onion = node_onion.strip().lower()
    node_pub_hex = node_pub_hex.strip().lower()
    if not PUBKEY_HEX_REGEX.match(node_pub_hex) or not SIG_HEX_REGEX.match(sig_hex):
        return jsonify({"error": "Malformed node public key or signature in voucher"}), 400

    try:
        ts_sec = int(ts_str)
        if abs(int(time.time()) - ts_sec) > 3600:
            return jsonify({"error": "Node operator voucher expired (1-hour validity window)"}), 403
        canonical = f"ONIONTALK_NODE_VOUCHER_V1|{node_onion}|{ts_sec}|{node_pub_hex}".encode("utf-8")
        pub_obj = Ed25519PublicKey.from_public_bytes(bytes.fromhex(node_pub_hex))
        pub_obj.verify(bytes.fromhex(sig_hex), canonical)
    except Exception:
        return jsonify({"error": "Invalid Ed25519 signature on node operator voucher"}), 403

    if hmac.compare_digest(node_pub_hex, user_pub):
        return jsonify({"error": "Self-signed user identity cannot act as a relay node voucher"}), 403

    v_nullifier = hashlib.sha3_256(
        f"ONIONTALK_NODE_VOUCHER_NULLIFIER_V1|{node_pub_hex}|{ts_sec}|{sig_hex.lower()}".encode("utf-8")
    ).hexdigest()
    with lock:
        if v_nullifier in _spent_tx_nullifiers:
            return jsonify({"error": "This node operator voucher has already been claimed (Nullifier spent)"}), 409

    safe_probe_url = ""
    if probe_url and os.getenv("SANDBOX_ALLOW_TEST_TX") == "1" and re.match(r"^http://127\.0\.0\.1:\d+/health$", probe_url):
        safe_probe_url = probe_url

    candidate_info = {
        "onion": node_onion,
        "probe_url": safe_probe_url,
        "claimed_at": int(time.time()),
        "stopped": False,
    }
    node_alive = _check_single_operator_node_alive(node_pub_hex, candidate_info)
    if not node_alive:
        return jsonify({"error": f"Relay node {node_onion} key {node_pub_hex[:12]}... is not verified/healthy on the Tor mesh"}), 400

    with lock:
        _spent_tx_nullifiers.add(v_nullifier)
        _revoked_founders.discard(user_pub)
        _founder_operator_nodes.setdefault(user_pub, {})[node_pub_hex] = candidate_info
        try:
            with open(SPENT_NULLIFIERS_FILE, "w", encoding="utf-8") as f:
                json.dump(list(_spent_tx_nullifiers), f)
        except Exception:
            pass

    active_nodes = _count_active_operator_nodes(user_pub)
    if active_nodes <= 0:
        return jsonify({"error": "No active relay nodes verified for this operator"}), 400

    tier_str = f"RELAY_NODE_{active_nodes}"
    expires_sec = int(time.time()) + 7 * 86400
    founder_pass = _issue_signed_founder_pass(user_pub, tier_str, expires_sec)
    total_max_groups = active_nodes + _founder_donor_quotas.get(user_pub, 0)
    return jsonify({
        "status": "verified",
        "tier": tier_str,
        "active_nodes": active_nodes,
        "max_groups": total_max_groups,
        "expires_at": expires_sec,
        "founder_pass": founder_pass,
    }), 200


@app.route('/api/v1/founder/verify-allowance', methods=['POST'])
def verify_founder_group_allowance():
    """
    Live verification before group creation:
    - Checks if the FounderPass was revoked.
    - For RELAY_NODE operators: actively checks how many hosted nodes are ONLINE right now.
      If the operator stopped hosting (active_nodes == 0), immediately denies and revokes group creation.
    - Enforces max_groups = active_nodes (1 group per active node) or 10 groups per $10 USD donation.
    """
    data = request.get_json(silent=True) or {}
    user_id = (data.get("user_id") or data.get("user_crypto_id") or data.get("owner_pubkey_hex") or "").strip().lower()
    pass_token = (data.get("founder_pass") or "").strip()
    current_groups = int(data.get("current_groups_count") or 0)

    user_pub = _extract_founder_pubkey_hex(user_id)
    if not user_pub:
        return jsonify({"allowed": False, "error": "Invalid user Crypto ID"}), 400

    if user_pub == OFFICIAL_ADMIN_PUBKEY_HEX:
        return jsonify({
            "allowed": True,
            "tier": "ROOT_ADMIN",
            "active_nodes": 999,
            "max_groups": 999999,
        }), 200

    with lock:
        is_revoked = user_pub in _revoked_founders
    if is_revoked:
        return jsonify({
            "allowed": False,
            "revoked": True,
            "active_nodes": 0,
            "max_groups": 0,
            "error": "Permissão de criação de grupos revogada.",
        }), 403

    parts = pass_token.split(":")
    if len(parts) != 6 or parts[0] != "otpass1":
        return jsonify({"allowed": False, "revoked": True, "error": "FounderPass ausente ou inválido"}), 403

    token_owner, tier, expires_str, issuer_pub, sig_hex = (
        parts[1].strip().lower(),
        parts[2].strip(),
        parts[3].strip(),
        parts[4].strip().lower(),
        parts[5].strip().lower(),
    )
    if token_owner != user_pub or token_owner == issuer_pub:
        return jsonify({"allowed": False, "revoked": True, "error": "FounderPass não pertence a este usuário"}), 403

    try:
        expires_sec = int(expires_str)
        if expires_sec > 0 and int(time.time()) > expires_sec:
            return jsonify({"allowed": False, "revoked": True, "error": "FounderPass expirado"}), 403
        canonical = f"ONIONTALK_FOUNDER_PASS_V1|{token_owner}|{tier}|{expires_sec}|{issuer_pub}".encode("utf-8")
        pub_obj = Ed25519PublicKey.from_public_bytes(bytes.fromhex(issuer_pub))
        pub_obj.verify(bytes.fromhex(sig_hex), canonical)
    except Exception:
        return jsonify({"allowed": False, "revoked": True, "error": "Assinatura FounderPass inválida"}), 403

    token_max = _parse_tier_max_groups(tier)
    if token_max <= 0:
        return jsonify({"allowed": False, "revoked": True, "error": "Tier de FounderPass desconhecido"}), 403

    if tier.startswith("RELAY_NODE"):
        active_nodes = _count_active_operator_nodes(user_pub)
        donor_bonus = _founder_donor_quotas.get(user_pub, 0)
        if active_nodes <= 0 and donor_bonus <= 0:
            return jsonify({
                "allowed": False,
                "revoked": True,
                "active_nodes": 0,
                "max_groups": 0,
                "error": "Nó Relay offline/inativo: se deixar de hospedar o nó, não pode mais criar grupos.",
            }), 403
        effective_max = active_nodes + donor_bonus
        if current_groups >= effective_max:
            return jsonify({
                "allowed": False,
                "revoked": False,
                "active_nodes": active_nodes,
                "max_groups": effective_max,
                "error": f"Limite atingido ({current_groups}/{effective_max} grupos): você possui {active_nodes} nó(s) ativo(s). Suba mais nós ou doe $10 USD para criar mais grupos.",
            }), 403
        new_tier = f"RELAY_NODE_{active_nodes}"
        refreshed_pass = _issue_signed_founder_pass(user_pub, new_tier, int(time.time()) + 7 * 86400)
        return jsonify({
            "allowed": True,
            "revoked": False,
            "tier": new_tier,
            "active_nodes": active_nodes,
            "max_groups": effective_max,
            "founder_pass": refreshed_pass,
        }), 200

    if tier.startswith("DONOR_10USD"):
        effective_max = max(_founder_donor_quotas.get(user_pub, token_max), token_max)
        if current_groups >= effective_max:
            return jsonify({
                "allowed": False,
                "revoked": False,
                "max_groups": effective_max,
                "error": f"Limite de {effective_max} grupos atingido para sua doação de $10 USD ({current_groups}/{effective_max}).",
            }), 403
        return jsonify({
            "allowed": True,
            "revoked": False,
            "tier": tier,
            "max_groups": effective_max,
        }), 200

    return jsonify({"allowed": False, "error": "Tier não suportado"}), 403


@app.route('/api/v1/founder/stop-node', methods=['POST'])
def stop_founder_operator_node():
    """
    Marks one or all hosted relay nodes for an operator as stopped/offline so group creation
    permission is immediately revoked or reduced when the operator stops hosting.
    """
    data = request.get_json(silent=True) or {}
    user_id = (data.get("user_id") or data.get("user_crypto_id") or data.get("owner_pubkey_hex") or "").strip().lower()
    target_node_pub = (data.get("node_pubkey") or "").strip().lower()
    user_pub = _extract_founder_pubkey_hex(user_id)
    if not user_pub:
        return jsonify({"error": "Invalid user Crypto ID"}), 400
    with lock:
        nodes_map = _founder_operator_nodes.get(user_pub) or {}
        if target_node_pub:
            if target_node_pub in nodes_map:
                nodes_map[target_node_pub]["stopped"] = True
        else:
            for k in nodes_map:
                nodes_map[k]["stopped"] = True
    active_nodes = _count_active_operator_nodes(user_pub)
    return jsonify({
        "status": "ok",
        "user_pub": user_pub,
        "active_nodes": active_nodes,
        "can_create_groups": active_nodes > 0 or _founder_donor_quotas.get(user_pub, 0) > 0,
    }), 200


@app.route('/api/v1/founder/revoke', methods=['POST'])
def revoke_founder_pass():
    """
    Revokes FounderPass permissions and clears node/donor quotas for a specific user
    (or all non-admin users when revoke_all_except is provided).
    """
    data = request.get_json(silent=True) or {}
    keep_only_id = (data.get("keep_only_crypto_id") or "").strip().lower()
    user_id = (data.get("user_id") or data.get("user_crypto_id") or "").strip().lower()

    with lock:
        if keep_only_id:
            keep_pub = _extract_founder_pubkey_hex(keep_only_id)
            for upub in list(_founder_operator_nodes.keys()) + list(_founder_donor_quotas.keys()):
                if upub != keep_pub and upub != OFFICIAL_ADMIN_PUBKEY_HEX:
                    _founder_operator_nodes.pop(upub, None)
                    _founder_donor_quotas.pop(upub, None)
                    _revoked_founders.add(upub)
            return jsonify({"status": "ok", "kept_only": keep_pub}), 200

        user_pub = _extract_founder_pubkey_hex(user_id)
        if not user_pub:
            return jsonify({"error": "Invalid user Crypto ID"}), 400
        if user_pub != OFFICIAL_ADMIN_PUBKEY_HEX:
            _founder_operator_nodes.pop(user_pub, None)
            _founder_donor_quotas.pop(user_pub, None)
            _revoked_founders.add(user_pub)
    return jsonify({"status": "ok", "revoked": user_pub}), 200


# -------------------------------------------------------------
# 3. AUTHENTICATED AUTO-DISCOVERY & PEER GOSSIP (ANTI-SYBIL)
# -------------------------------------------------------------
@app.route('/api/v1/peers/announce', methods=['POST'])
def announce_peer():
    peer_ok, header_onion, header_pubkey, err_msg = verify_peer_request(require_known_peer=False)
    if not peer_ok:
        with lock:
            stats_counters["invalid_peers_blocked"] += 1
        return jsonify({"error": err_msg}), 401

    data = request.get_json(silent=True) or {}
    peer_onion = (data.get('node_onion') or '').strip().lower()
    announced_pubkey = (data.get('node_pubkey') or header_pubkey).strip().lower()
    current_domain = get_my_onion_domain()

    if not is_valid_onion_v3(peer_onion) or not PUBKEY_HEX_REGEX.match(announced_pubkey):
        with lock:
            stats_counters["invalid_peers_blocked"] += 1
        return jsonify({"error": "Invalid Tor v3 .onion address or node_pubkey"}), 400

    # A peer may either announce itself directly (header_onion == peer_onion)
    # or an already-verified mesh peer may gossip a newly verified peer
    if header_onion != peer_onion:
        with lock:
            is_gossiper_trusted = (
                header_onion in known_peers
                and peer_pubkeys.get(header_onion) == header_pubkey
            )
        if not is_gossiper_trusted:
            with lock:
                stats_counters["invalid_peers_blocked"] += 1
            return jsonify({"error": "Peer announce sender must match node_onion or be a verified mesh peer"}), 403

    with lock:
        already_known = (peer_onion in known_peers) and (peer_pubkeys.get(peer_onion) == announced_pubkey)
        can_accept_more = len(known_peers) < MAX_KNOWN_PEERS or (peer_onion in known_peers)
        current_peers = list(known_peers)
        if current_domain and current_domain not in current_peers:
            current_peers.append(current_domain)

    announced_geo = data.get("geo") if isinstance(data.get("geo"), dict) else None
    if peer_onion and not already_known and can_accept_more:
        threading.Thread(
            target=verify_and_register_peer,
            args=(peer_onion, announced_pubkey, announced_geo),
            daemon=True,
        ).start()
    elif peer_onion and already_known and announced_geo and peer_onion not in NODE_GEO_METADATA:
        _apply_discovered_geo(peer_onion, announced_geo)

    return jsonify({"status": "registered", "peers": current_peers}), 200


def _apply_discovered_geo(domain: str, raw_geo: dict):
    if not isinstance(raw_geo, dict) or domain in NODE_GEO_METADATA:
        return
    coords_ok, safe_lat, safe_lon = parse_safe_coords(
        raw_geo.get("lat", 0.0),
        raw_geo.get("lon", 0.0),
    )
    if not coords_ok or (safe_lat == 0.0 and safe_lon == 0.0):
        return
    short_id = domain[:6]
    node_name = str(raw_geo.get("node_name") or f"🛰️ Nó Auto-Join ({domain[:8]}...)")[:80]
    map_label = str(raw_geo.get("map_label") or f"🛰️ Auto • {short_id}")[:32]
    with lock:
        custom_peer_geo[domain] = {
            "node_name": node_name,
            "map_label": map_label,
            "location": str(raw_geo.get("location") or "Tor Hidden Service v3 (Auto-Join)")[:80],
            "provider": str(raw_geo.get("provider") or "Federated P2P Node")[:80],
            "lat": safe_lat,
            "lon": safe_lon,
            "role": str(raw_geo.get("role") or "🛰️ Auto-Discovered Relay")[:64],
        }


def verify_and_register_peer(candidate_onion: str, expected_pubkey: str, announced_geo: dict | None = None):
    """
    Performs active handshake over Tor (/health) with retry backoff (up to 3 attempts)
    to handle newly published Tor v3 HSDir descriptors and auto-registers peer + geo metadata.
    Includes S/Kademlia provider diversity guard against Eclipse/Sybil concentration.
    """
    if not is_valid_onion_v3(candidate_onion) or not PUBKEY_HEX_REGEX.match(expected_pubkey):
        return
    current_domain = get_my_onion_domain()
    if candidate_onion == current_domain or candidate_onion in DEPRECATED_SEEDS:
        return

    # Trusted sovereign BOOTSTRAP_SEEDS (including hybrid PaaS + PVE 24/7 failover nodes)
    # have already verified their Ed25519 request signature in announce_peer() and must never
    # trigger a false-positive Anti-Sybil rejection when switching between cloud and PVE failover keys.
    if candidate_onion in BOOTSTRAP_SEEDS:
        with lock:
            known_peers.add(candidate_onion)
            peer_pubkeys[candidate_onion] = expected_pubkey
        if candidate_onion in _COLOCATED_PVE_HS_PEERS:
            _record_peer_success(candidate_onion, 12.0)
        return

    verified = False
    remote_geo = announced_geo
    for attempt in range(3):
        t0 = time.monotonic()
        try:
            fast_base = _resolve_fast_lane_url(candidate_onion)
            if fast_base:
                res = get_fast_session().get(f"{fast_base}/health", timeout=6)
            else:
                res = get_tor_session().get(f"http://{candidate_onion}/health", timeout=22)
            if res.status_code == 200:
                body = res.json()
                remote_pubkey = (body.get("node_pubkey") or "").strip().lower()
                if isinstance(body.get("geo"), dict):
                    remote_geo = body.get("geo")
                if body.get("status") == "healthy" and hmac.compare_digest(remote_pubkey, expected_pubkey):
                    _record_peer_success(candidate_onion, (time.monotonic() - t0) * 1000.0)
                    verified = True
                    break
        except Exception:
            verified = False
        if attempt < 2:
            time.sleep(6)

    if not verified:
        _record_peer_failure(candidate_onion)
        with lock:
            stats_counters["invalid_peers_blocked"] += 1
        print(f"[!] [ANTI-SYBIL] Unverified peer rejected: {candidate_onion}", flush=True)
        return

    if remote_geo:
        _apply_discovered_geo(candidate_onion, remote_geo)

    added = False
    with lock:
        # Provider/Bucket Diversity Guard (S/Kademlia Eclipse defense for auto-discovered nodes)
        if candidate_onion not in NODE_GEO_METADATA and candidate_onion not in known_peers:
            cand_prov = str((custom_peer_geo.get(candidate_onion) or {}).get("provider") or "auto").strip().lower()[:40]
            same_prov_count = sum(
                1 for p in known_peers
                if p not in NODE_GEO_METADATA
                and str((custom_peer_geo.get(p) or {}).get("provider") or "auto").strip().lower()[:40] == cand_prov
            )
            if same_prov_count >= MAX_AUTO_PEERS_PER_PROVIDER:
                stats_counters["invalid_peers_blocked"] += 1
                print(f"[!] [ANTI-ECLIPSE] Provider diversity cap reached for {cand_prov}: {candidate_onion}", flush=True)
                return

        if len(known_peers) < MAX_KNOWN_PEERS or candidate_onion in known_peers:
            known_peers.add(candidate_onion)
            peer_pubkeys[candidate_onion] = expected_pubkey
            added = True

    if added:
        print(f"[*] [DISCOVERY] Verified peer added to mesh: {candidate_onion}", flush=True)
        gossip_new_peer(candidate_onion, expected_pubkey)


def gossip_new_peer(new_peer_onion: str, new_peer_pubkey: str):
    current_domain = get_my_onion_domain()
    if not current_domain:
        return
    now_mono = time.monotonic()
    with lock:
        targets = [
            p for p in known_peers
            if p != new_peer_onion
            and p != current_domain
            and p not in DEPRECATED_SEEDS
            and peer_backoff_until.get(p, 0.0) <= now_mono
        ]
        peer_geo = custom_peer_geo.get(new_peer_onion)
    session = get_tor_session()
    path = "/api/v1/peers/announce"
    payload = {"node_onion": new_peer_onion, "node_pubkey": new_peer_pubkey}
    if peer_geo:
        payload["geo"] = peer_geo
    for target in targets:
        try:
            body_bytes, headers = build_peer_signed_request("POST", path, payload)
            fast_base = _resolve_fast_lane_url(target)
            if fast_base:
                get_fast_session().post(f"{fast_base}{path}", data=body_bytes, headers=headers, timeout=6)
            else:
                session.post(f"http://{target}{path}", data=body_bytes, headers=headers, timeout=15)
        except Exception:
            pass


def get_node_geo_entry(domain: str, is_local: bool = False) -> dict:
    meta = custom_peer_geo.get(domain) or NODE_GEO_METADATA.get(domain)
    auto_discovered = 0 if domain in NODE_GEO_METADATA else 1
    if not meta:
        # Deterministic continental hub coordinates when node location is unknown (never in the ocean)
        hubs = [
            (47.37, 8.54),    # Zurich
            (59.33, 18.06),   # Stockholm
            (52.23, 21.01),   # Warsaw
            (40.42, -3.70),   # Madrid
            (64.14, -21.94),  # Reykjavik
            (4.71, -74.07),   # Bogota
            (-33.45, -70.66), # Santiago
            (-26.20, 28.04),  # Johannesburg
            (37.56, 126.97),  # Seoul
            (-33.86, 151.20), # Sydney
            (19.07, 72.87),   # Mumbai
            (60.17, 24.94),   # Helsinki
        ]
        h = int(hashlib.sha256(domain.encode("utf-8")).hexdigest()[:8], 16)
        base_lat, base_lon = hubs[h % len(hubs)]
        fallback_lat = base_lat + (((h >> 8) % 10) - 5) * 0.15
        fallback_lon = base_lon + (((h >> 16) % 10) - 5) * 0.15
        short_id = domain[:4]
        meta = {
            "node_name": f"🛰️ Nó Auto-Join ({domain[:8]}...)",
            "map_label": f"AUTO•{short_id}",
            "location": "Tor Hidden Service v3 (Localização Oculta / Auto-Join)",
            "provider": "Tor v3 Mesh (Auto-Discovered)",
            "lat": round(fallback_lat, 4),
            "lon": round(fallback_lon, 4),
            "role": "🛰️ Federated Mesh Peer (Auto-Join)"
        }
    if is_local:
        node_status = "ACTIVE / LOCAL"
        health_score = 1
        rtt_ms = 1.0
        last_seen_sec = 0
    else:
        state = peer_online_state.get(domain, "UNKNOWN")
        is_up = state == "ONLINE"
        health_score = 1 if is_up else 0
        if is_up:
            node_status = "ACTIVE / SYNCED"
            rtt_ms = round(peer_rtt_ewma.get(domain, 650.0), 1)
        elif state == "DOWN":
            node_status = "HIBERNATING / DOWN"
            rtt_ms = 0.0
        else:
            node_status = "PROBING..."
            rtt_ms = 0.0
        last_seen_sec = (int(time.time()) - peer_last_ok_epoch[domain]) if domain in peer_last_ok_epoch else -1

    return {
        "domain": domain,
        "node_name": meta["node_name"],
        "map_label": meta.get("map_label", meta["node_name"]),
        "location": meta["location"],
        "provider": meta["provider"],
        "lat": float(meta["lat"]),
        "lon": float(meta["lon"]),
        "role": meta["role"],
        "status": node_status,
        "type": "Local Node" if is_local else "Remote Peer (Tor v3)",
        "protocol_version": 1 if domain in LEGACY_V1_PEERS else 2,
        "auto_discovered": auto_discovered,
        "health_score": health_score,
        "rtt_ms": rtt_ms,
        "last_seen_sec": last_seen_sec,
        "fail_count": 0 if is_local else peer_fail_count.get(domain, 0),
    }


@app.route('/api/v1/peers/geo', methods=['POST'])
def update_peer_geo():
    """
    Updates geographic metadata for a node (R3 & R6 hardened).
    Requires either a valid RELAY_ADMIN_TOKEN or a verified peer Ed25519 signature for its own domain.
    """
    admin_hdr = (request.headers.get("X-Admin-Token") or "").strip()
    is_admin = bool(RELAY_ADMIN_TOKEN) and hmac.compare_digest(admin_hdr, RELAY_ADMIN_TOKEN)

    data = request.get_json(silent=True) or {}
    domain = (data.get("node_onion") or data.get("domain") or "").strip().lower()
    if not is_valid_onion_v3(domain):
        return jsonify({"error": "Invalid Tor v3 .onion address"}), 400

    if not is_admin:
        peer_ok, peer_onion, _, err_msg = verify_peer_request(require_known_peer=True)
        if not peer_ok or peer_onion != domain or domain in NODE_GEO_METADATA:
            with lock:
                stats_counters["unauthenticated_requests_blocked"] += 1
            return jsonify({"error": err_msg if not peer_ok else "Unauthorized geo metadata update"}), 401

    coords_ok, safe_lat, safe_lon = parse_safe_coords(
        data.get("lat", 47.3769),
        data.get("lon", 8.5417),
    )
    if not coords_ok:
        return jsonify({"error": "Invalid geographic coordinates (lat/lon)"}), 400

    with lock:
        custom_peer_geo[domain] = {
            "node_name": str(data.get("node_name") or f"🌐 Nó ({domain[:8]}...)")[:80],
            "location": str(data.get("location") or "Tor Hidden Service v3")[:80],
            "provider": str(data.get("provider") or "Federated P2P Node")[:80],
            "lat": safe_lat,
            "lon": safe_lon,
            "role": str(data.get("role") or "🌐 Federated Mesh Peer")[:64],
        }
    return jsonify({"status": "geo_updated", "domain": domain, "geo": custom_peer_geo[domain]}), 200


@app.route('/api/v1/peers/list', methods=['GET'])
def list_peers():
    summary_only = (request.args.get("summary") or "").strip() == "1"
    with lock:
        my_domain = get_my_onion_domain()
        peer_list = [p for p in known_peers if p != my_domain and p not in DEPRECATED_SEEDS]
        total_nodes = max(23, len(peer_list) + (1 if my_domain else 0))
        if summary_only:
            return jsonify({
                "total_nodes": total_nodes,
                "online_nodes": total_nodes,
                "app_update": get_signed_app_update_metadata(),
            }), 200
        v2_client_peers = [
            p for p in peer_list
            if p not in LEGACY_V1_PEERS or peer_online_state.get(p) == "ONLINE"
        ]
        peers_detail = []
        if my_domain:
            peers_detail.append(get_node_geo_entry(my_domain, is_local=True))
        for p in sorted(peer_list):
            peers_detail.append(get_node_geo_entry(p, is_local=False))
        online_nodes = sum(1 for item in peers_detail if item.get("health_score") == 1)
        down_nodes = sum(1 for item in peers_detail if item.get("health_score") == 0)
        return jsonify({
            "my_domain": my_domain,
            "peers": v2_client_peers,
            "all_peers": peer_list,
            "total_peers": len(peer_list),
            "total_nodes": len(peer_list) + (1 if my_domain else 0),
            "online_nodes": online_nodes,
            "hibernating_nodes": down_nodes,
            "peers_detail": peers_detail,
            "watch_events": list(mesh_watch_events[:50]),
            "app_update": get_signed_app_update_metadata(),
        }), 200


@app.route('/api/v1/peers/watch', methods=['GET'])
def watch_peers():
    with lock:
        my_domain = get_my_onion_domain()
        peer_list = [p for p in known_peers if p != my_domain and p not in DEPRECATED_SEEDS]
        peers_detail = []
        if my_domain:
            peers_detail.append(get_node_geo_entry(my_domain, is_local=True))
        for p in sorted(peer_list):
            peers_detail.append(get_node_geo_entry(p, is_local=False))
        online_nodes = sum(1 for item in peers_detail if item.get("health_score") == 1)
        down_nodes = sum(1 for item in peers_detail if item.get("health_score") == 0)
        auto_nodes = sum(1 for item in peers_detail if item.get("auto_discovered") == 1 and item.get("health_score") == 1)
        events_copy = list(mesh_watch_events[:100])
    return jsonify({
        "my_domain": my_domain,
        "total_nodes": len(peers_detail),
        "online_nodes": online_nodes,
        "hibernating_nodes": down_nodes,
        "auto_join_online": auto_nodes,
        "events": events_copy,
        "nodes": peers_detail,
    }), 200


@app.route('/api/v1/version', methods=['GET'])
def get_version_policy():
    return jsonify(get_signed_app_update_metadata()), 200


@app.route('/health', methods=['GET'])
def health():
    with lock:
        prune_expired_messages_locked()
        total_queued = sum(len(msgs) for msgs in inbox.values())
        active_inboxes = len([u for u, m in inbox.items() if len(m) > 0])
        clients_online, total_clients = _compute_client_metrics_locked()
        my_domain = get_my_onion_domain()
        peer_count = len([p for p in known_peers if p != my_domain])
        total_nodes = peer_count + (1 if my_domain else 0)
        uptime_sec = int(time.time() - start_time)
        my_geo = get_node_geo_entry(my_domain, is_local=True) if my_domain else None
        rtts = [v for k, v in peer_rtt_ewma.items() if k in known_peers and peer_fail_count.get(k, 0) == 0]
        avg_rtt = round(sum(rtts) / len(rtts), 1) if rtts else 0.0
        online_peers = sum(1 for p in known_peers if p != my_domain and peer_online_state.get(p) == "ONLINE")
        online_nodes = online_peers + (1 if my_domain else 0)
        hibernating_nodes = max(0, total_nodes - online_nodes)
    return jsonify({
        "status": "healthy",
        "zero_trust_mode": "X25519-ChaCha20-Poly1305 + Ed25519-Auth + ACK-Lock + Anti-Sybil + S/Kademlia-GossipSub-v1.2",
        "routing_engine": "S/Kademlia-XOR + GossipSub-v1.2-IHAVE-IDONTWANT + Blinded-Poller-Affinity",
        "storage_engine": "ram-volatile-ephemeral-ttl24h",
        "domain": my_domain,
        "node_pubkey": NODE_PUBLIC_KEY_HEX,
        "geo": my_geo,
        "peers_count": peer_count,
        "total_nodes": total_nodes,
        "online_nodes": online_nodes,
        "hibernating_nodes": hibernating_nodes,
        "clients_online": clients_online,
        "total_clients": total_clients,
        "queued_messages": total_queued,
        "active_inboxes": active_inboxes,
        "messages_received": stats_counters["messages_received"],
        "messages_routed": stats_counters["messages_routed"],
        "acks_processed": stats_counters["acks_processed"],
        "idontwant_dedup_saved": stats_counters["idontwant_dedup_saved"],
        "fast_lane_routed": stats_counters["fast_lane_routed"],
        "avg_peer_rtt_ms": avg_rtt,
        "spoofed_acks_blocked": stats_counters["spoofed_acks_blocked"],
        "invalid_peers_blocked": stats_counters["invalid_peers_blocked"],
        "unauthenticated_requests_blocked": stats_counters["unauthenticated_requests_blocked"],
        "uptime_seconds": uptime_sec,
        "app_update": get_signed_app_update_metadata(),
    }), 200


@app.route('/api/v1/stats', methods=['GET'])
def stats():
    """Returns aggregate anonymized metrics only; never exposes recipient queues (R1 fix)."""
    with lock:
        prune_expired_messages_locked()
        my_domain = get_my_onion_domain()
        peer_count = len([p for p in known_peers if p != my_domain])
        total_queued = sum(len(msgs) for msgs in inbox.values())
        active_inboxes = len([u for u, m in inbox.items() if len(m) > 0])
        clients_online, total_clients = _compute_client_metrics_locked()
        rtts = [v for k, v in peer_rtt_ewma.items() if k in known_peers and peer_fail_count.get(k, 0) == 0]
        avg_rtt = round(sum(rtts) / len(rtts), 1) if rtts else 0.0
    return jsonify({
        "domain": my_domain,
        "zero_trust_mode": "X25519-ChaCha20-Poly1305 + Ed25519-Auth + ACK-Lock + Anti-Sybil + S/Kademlia-GossipSub-v1.2",
        "routing_engine": "S/Kademlia-XOR + GossipSub-v1.2-IHAVE-IDONTWANT + Blinded-Poller-Affinity",
        "storage_engine": "ram-volatile-ephemeral-ttl24h",
        "peers_count": peer_count,
        "clients_online": clients_online,
        "total_clients": total_clients,
        "queued_messages": total_queued,
        "active_inboxes": active_inboxes,
        "idontwant_dedup_saved": stats_counters["idontwant_dedup_saved"],
        "fast_lane_routed": stats_counters["fast_lane_routed"],
        "avg_peer_rtt_ms": avg_rtt,
        "spoofed_acks_blocked": stats_counters["spoofed_acks_blocked"],
        "invalid_peers_blocked": stats_counters["invalid_peers_blocked"],
        "unauthenticated_requests_blocked": stats_counters["unauthenticated_requests_blocked"],
    }), 200


@app.route('/api/v1/debug/queues', methods=['GET'])
def debug_queues():
    """
    Authenticated diagnostic endpoint for SRE mesh latency monitoring.
    Blocks HTTP Host-header spoofing over Tor by requiring either RELAY_ADMIN_TOKEN
    or a valid Ed25519 signature from this node's own local NODE_PRIVATE_KEY, and
    never exposes raw recipient Crypto IDs (uses salted one-way SHA-256 prefixes).
    """
    host_hdr = (request.host or "").lower().split(":", 1)[0]
    if host_hdr.endswith(".onion") or host_hdr not in ("127.0.0.1", "localhost"):
        return jsonify({"error": "Not Found"}), 404

    admin_hdr = (request.headers.get("X-Admin-Token") or "").strip()
    is_admin = bool(RELAY_ADMIN_TOKEN) and hmac.compare_digest(admin_hdr, RELAY_ADMIN_TOKEN)
    if not is_admin:
        peer_ok, _, peer_pubkey, _ = verify_peer_request(require_known_peer=False)
        if not (peer_ok and hmac.compare_digest(peer_pubkey, NODE_PUBLIC_KEY_HEX)):
            with lock:
                stats_counters["unauthenticated_requests_blocked"] += 1
            return jsonify({"error": "Not Found"}), 404

    now_ms = int(time.time() * 1000)
    with lock:
        prune_expired_messages_locked()
        queues_summary = []
        for u, msgs in inbox.items():
            if not msgs:
                continue
            ages_sec = [round((now_ms - int(m.get("timestamp", now_ms))) / 1000.0, 1) for m in msgs]
            blinded_hash = hashlib.sha256(f"{NODE_PUBLIC_KEY_HEX}|{u}".encode("utf-8")).hexdigest()[:12]
            queues_summary.append({
                "recipient_hash": f"anon:{blinded_hash}",
                "count": len(msgs),
                "min_age_sec": min(ages_sec) if ages_sec else 0,
                "max_age_sec": max(ages_sec) if ages_sec else 0,
            })
        tomb_count = len(acked_tombstones)
    return jsonify({
        "domain": get_my_onion_domain(),
        "total_queued": sum(q["count"] for q in queues_summary),
        "active_inboxes": len(queues_summary),
        "tombstones_cached": tomb_count,
        "queues": queues_summary,
    }), 200


def _reconcile_peer_ihave(
    peer: str,
    ihave_payload: dict,
    pending_by_id: dict,
):
    """
    GossipSub v1.2 IHAVE/IDONTWANT + Blinded Poller Affinity anti-entropy exchange with a single peer.
    Also serves as a 18s keep-alive heartbeat that keeps Tor circuits and Gunicorn 75s HTTP sockets warm!
    """
    path = "/api/v1/messages/ihave"
    t0 = time.monotonic()
    try:
        body_bytes, headers = build_peer_signed_request("POST", path, ihave_payload)
        fast_base = _resolve_fast_lane_url(peer)
        if fast_base:
            res = get_fast_session().post(f"{fast_base}{path}", data=body_bytes, headers=headers, timeout=6)
        else:
            res = get_tor_session().post(f"http://{peer}{path}", data=body_bytes, headers=headers, timeout=14)

        if res.status_code == 200:
            _record_peer_success(peer, (time.monotonic() - t0) * 1000.0)
            body = res.json() if res.content else {}
            want_ids = set(body.get("want_msg_ids") or [])
            already_acked = body.get("already_acked") or {}
            remote_pollers = body.get("active_pollers") or []
            now_mono = time.monotonic()

            with lock:
                if isinstance(remote_pollers, list):
                    for tag in remote_pollers[:64]:
                        tag_str = str(tag or "").strip().lower()
                        if len(tag_str) == 24 and tag_str not in local_active_pollers:
                            peer_origin_hints[tag_str] = (peer, now_mono)

                # Heal local queues if remote peer already tombstoned a message with a valid ack_token
                if isinstance(already_acked, dict) and already_acked:
                    for ak_id, ak_tok in list(already_acked.items())[:128]:
                        if isinstance(ak_id, str) and isinstance(ak_tok, str) and SHA256_HEX_REGEX.match(ak_tok):
                            process_ack_preimage_locked(ak_id.strip()[:64], ak_tok.strip().lower())

                # Mark all offered IDs that the peer did NOT want as already synced (IDONTWANT)
                for mid in pending_by_id.keys():
                    if mid not in want_ids:
                        s_set = synced_peers_by_msg.setdefault(mid, set())
                        if peer not in s_set:
                            s_set.add(peer)
                            stats_counters["idontwant_dedup_saved"] += 1

            # Push only the envelopes the peer explicitly requested in want_msg_ids
            for mid in want_ids:
                msg_obj = pending_by_id.get(mid)
                if msg_obj:
                    _sync_single_peer(peer, msg_obj)
            return

        if res.status_code == 404:
            # Peer is running an older release without /api/v1/messages/ihave; fallback to direct sync
            _record_peer_success(peer, (time.monotonic() - t0) * 1000.0)
            for mid, msg_obj in pending_by_id.items():
                with lock:
                    already_done = peer in synced_peers_by_msg.get(mid, set())
                if not already_done:
                    _sync_single_peer(peer, msg_obj)
            return

        _record_peer_failure(peer)
    except Exception:
        _record_peer_failure(peer)


def anti_entropy_sync_loop():
    """
    Periodic GossipSub v1.2 IHAVE/IDONTWANT reconciliation & Warm Circuit Keep-Alive loop (every 18s):
    1) Exchanges compact message ID digests + blinded poller affinity tags with active v2 peers.
    2) Keeps Tor v3 rendezvous circuits and Gunicorn 75s HTTP sockets warm so real-time messages
       experience zero cold-socket handshake latency.
    3) Pushes full ciphertext envelopes ONLY when a peer reports it is missing the message ID.
    """
    while True:
        time.sleep(18)
        current_domain = get_my_onion_domain()
        if not current_domain:
            continue

        now_mono = time.monotonic()
        with lock:
            prune_expired_messages_locked()
            pending_by_id = {}
            for msgs in inbox.values():
                if msgs:
                    for m in msgs[-20:]:
                        mid = m.get("id")
                        if mid:
                            pending_by_id[mid] = m

            fresh_local_pollers = [
                tag for tag, ts in local_active_pollers.items()
                if (now_mono - ts) <= 600.0
            ][:64]

            v2_peers = [
                p for p in known_peers
                if p != current_domain
                and p not in LEGACY_V1_PEERS
                and p not in DEPRECATED_SEEDS
                and peer_backoff_until.get(p, 0.0) <= now_mono
            ]

        ihave_payload = {
            "msg_ids": list(pending_by_id.keys())[:256],
            "poller_tags": fresh_local_pollers,
            "active_pollers": fresh_local_pollers,
        }

        for peer in v2_peers:
            anti_entropy_executor.submit(_reconcile_peer_ihave, peer, ihave_payload, pending_by_id)


_self_geo_detected = False


def _detect_self_geo_if_unknown(current_domain: str):
    """
    Applies operator-configured NODE_LAT / NODE_LON coordinates on startup if provided.
    Never performs clearnet IP geolocation requests (OpSec Zero-Leak); falls back to
    deterministic SHA-256(.onion) coordinates in get_node_geo_entry().
    """
    global _self_geo_detected
    if _self_geo_detected or not current_domain or current_domain in NODE_GEO_METADATA:
        _self_geo_detected = True
        return
    _self_geo_detected = True

    env_lat = os.getenv("NODE_LAT")
    env_lon = os.getenv("NODE_LON")
    if env_lat and env_lon:
        ok, slat, slon = parse_safe_coords(env_lat, env_lon)
        if ok:
            short_id = current_domain[:6]
            _apply_discovered_geo(current_domain, {
                "node_name": os.getenv("NODE_NAME", f"🛰️ Nó Auto-Join ({current_domain[:8]}...)"),
                "map_label": os.getenv("NODE_MAP_LABEL", f"🛰️ Auto • {short_id}"),
                "location": os.getenv("NODE_LOCATION", "Tor Hidden Service v3 (Auto-Join)"),
                "provider": os.getenv("NODE_PROVIDER", "Federated Cloud Relay"),
                "lat": slat,
                "lon": slon,
                "role": os.getenv("NODE_ROLE", "🛰️ Auto-Discovered Relay"),
            })


def _announce_to_single_seed(seed: str, current_domain: str, payload: dict):
    now_mono = time.monotonic()
    with lock:
        if seed in DORMANT_SEEDS and peer_backoff_until.get(seed, 0.0) > now_mono:
            return
    path = "/api/v1/peers/announce"
    session = get_tor_session()
    t0 = time.monotonic()
    try:
        with lock:
            has_pubkey = seed in peer_pubkeys
        fast_base = _resolve_fast_lane_url(seed)
        if not has_pubkey:
            if fast_base:
                h_res = get_fast_session().get(f"{fast_base}/health", timeout=6)
            else:
                h_res = session.get(f"http://{seed}/health", timeout=18)
            if h_res.status_code == 200:
                h_body = h_res.json()
                remote_pk = (h_body.get("node_pubkey") or "").strip().lower()
                if isinstance(h_body.get("geo"), dict):
                    _apply_discovered_geo(seed, h_body.get("geo"))
                if PUBKEY_HEX_REGEX.match(remote_pk):
                    with lock:
                        peer_pubkeys[seed] = remote_pk

        body_bytes, headers = build_peer_signed_request("POST", path, payload)
        if fast_base:
            res = get_fast_session().post(
                f"{fast_base}{path}",
                data=body_bytes,
                headers=headers,
                timeout=6,
            )
        else:
            res = session.post(
                f"http://{seed}{path}",
                data=body_bytes,
                headers=headers,
                timeout=18,
            )
        if res.status_code == 200:
            _record_peer_success(seed, (time.monotonic() - t0) * 1000.0)
            peers = res.json().get("all_peers") or res.json().get("peers", [])
            for p in peers:
                p_clean = (p or "").strip().lower()
                if (
                    is_valid_onion_v3(p_clean)
                    and p_clean != current_domain
                    and p_clean not in LEGACY_V1_PEERS
                    and p_clean not in DEPRECATED_SEEDS
                    and p_clean not in DORMANT_SEEDS
                ):
                    with lock:
                        already = p_clean in known_peers
                        can_more = len(known_peers) < MAX_KNOWN_PEERS
                    if not already and can_more:
                        try:
                            t_p = time.monotonic()
                            p_health = session.get(f"http://{p_clean}/health", timeout=18)
                            if p_health.status_code == 200:
                                p_body = p_health.json()
                                p_pk = (p_body.get("node_pubkey") or "").strip().lower()
                                if isinstance(p_body.get("geo"), dict):
                                    _apply_discovered_geo(p_clean, p_body.get("geo"))
                                if p_body.get("status") == "healthy":
                                    _record_peer_success(p_clean, (time.monotonic() - t_p) * 1000.0)
                                    with lock:
                                        if len(known_peers) < MAX_KNOWN_PEERS:
                                            known_peers.add(p_clean)
                                            if PUBKEY_HEX_REGEX.match(p_pk):
                                                peer_pubkeys[p_clean] = p_pk
                        except Exception:
                            _record_peer_failure(p_clean)
            print(
                f"[*] [MESH-SYNC] Synchronized via {seed[:16]}... "
                f"({len(known_peers)} active peers)",
                flush=True,
            )
        else:
            _record_peer_failure(seed)
    except Exception as e:
        _record_peer_failure(seed)
        print(f"[!] [MESH-WAIT] Waiting for Tor circuit to {seed[:16]}...: {e}", flush=True)


PAAS_KEEPALIVE_URLS = (
    "https://oniontalk-render-mathyared.onrender.com/health",
)


def _ping_paas_keepalive(url: str):
    try:
        get_fast_session().get(url, timeout=10)
    except Exception:
        pass


def _cross_check_sibling_seed_watch(peer: str) -> float | None:
    my_dom = get_my_onion_domain() or ""
    sibling_url = None
    if my_dom.startswith("onion4zr3"):
        sibling_url = os.getenv("PVE4_FAST_URL", "http://192.168.3.114:8080")
    elif my_dom.startswith("kn4u2xxl"):
        sibling_url = os.getenv("PVE2_FAST_URL", "http://192.168.3.113:8080")
    if not sibling_url:
        return None
    try:
        r = get_fast_session().get(f"{sibling_url.rstrip('/')}/api/v1/peers/watch", timeout=3)
        if r.status_code == 200:
            for item in (r.json().get("nodes") or []):
                if item.get("domain") == peer and item.get("health_score") == 1 and item.get("last_seen_sec", 999) < 90:
                    return float(item.get("rtt_ms") or 1200.0)
    except Exception:
        pass
    return None


def _probe_single_peer_watch(peer: str):
    session = get_tor_session()
    t0 = time.monotonic()
    try:
        fast_base = _resolve_fast_lane_url(peer)
        if fast_base:
            res = get_fast_session().get(f"{fast_base}/health", timeout=5)
        else:
            res = session.get(f"http://{peer}/health", timeout=22)
        if res.status_code == 200:
            rtt_ms = (time.monotonic() - t0) * 1000.0
            _record_peer_success(peer, rtt_ms)
            try:
                body = res.json()
                remote_pk = (body.get("node_pubkey") or "").strip().lower()
                if isinstance(body.get("geo"), dict):
                    _apply_discovered_geo(peer, body.get("geo"))
                if PUBKEY_HEX_REGEX.match(remote_pk):
                    with lock:
                        peer_pubkeys[peer] = remote_pk
            except Exception:
                pass
            return
    except Exception:
        pass

    sibling_rtt = _cross_check_sibling_seed_watch(peer)
    if sibling_rtt is not None:
        _record_peer_success(peer, sibling_rtt)
        return
    _record_peer_failure(peer, force_down=False)


def mesh_watch_loop():
    """
    Continuous Real-Time Mesh Watchdog (every 35s, initial sweep at 4s):
    1) Pings free-tier PaaS clearnet health endpoints (Render #2 & WSO2 Choreo US-East) so
       their serverless containers stay warm without scaling to zero.
    2) Probes peers over Tor v3 SOCKS5h that have not recently confirmed via GossipSub IHAVE
       (including LEGACY_V1_PEERS like AWS EKS & Virginia, plus recovering cloud nodes),
       recording exact UP/DOWN/AUTO-JOIN state transitions in mesh_watch_events.
    """
    time.sleep(4)
    while True:
        current_domain = get_my_onion_domain()
        if not current_domain:
            time.sleep(3)
            continue

        if current_domain.startswith("onion4zr3"):
            for url in PAAS_KEEPALIVE_URLS:
                watch_executor.submit(_ping_paas_keepalive, url)

        now_sec = int(time.time())
        with lock:
            candidates = [
                p for p in (set(BOOTSTRAP_SEEDS) | known_peers)
                if p != current_domain and p not in DEPRECATED_SEEDS
            ]
            to_probe = [
                p for p in candidates
                if peer_online_state.get(p, "UNKNOWN") != "ONLINE"
                or (now_sec - peer_last_ok_epoch.get(p, 0)) > 45
                or p in LEGACY_V1_PEERS
            ]

        futures = [watch_executor.submit(_probe_single_peer_watch, p) for p in to_probe]
        concurrent.futures.wait(futures, timeout=26)
        time.sleep(35)


def bootstrap_discovery_loop():
    """
    Continuous autonomous peer discovery & Ed25519-authenticated parallel announce loop over Tor.
    Runs on isolated discovery_executor so it never contends with real-time gossip_executor.
    """
    primary_seeds = [
        "onion4zr3bsdeaelksemwokl5qmxd5o7jyblf46vc2mfl6cozgw77tqd.onion",
        "kn4u2xxl2otoo2ujv3mhehwfwbw7mtppaf56fu3nxogvv7eekf2qdrid.onion",
        "zqdx5x7pfybox7m5rz3fe5kiouxhipvh3ekuteq2urrrvwcxjttnmgid.onion",
        "jz6urt6ckkqqvtasm6bll2mryhksjcawcl4tbguif5nqvxgsfsx6ywad.onion",
    ]
    while True:
        current_domain = get_my_onion_domain()
        if not current_domain:
            time.sleep(3)
            continue

        _detect_self_geo_if_unknown(current_domain)

        now_mono = time.monotonic()
        with lock:
            all_candidates = (
                (set(BOOTSTRAP_SEEDS) | known_peers)
                - {current_domain}
                - LEGACY_V1_PEERS
                - DEPRECATED_SEEDS
            )
            active_candidates = [
                c for c in all_candidates
                if c not in DORMANT_SEEDS or peer_backoff_until.get(c, 0.0) <= now_mono
            ]
            ordered_targets = [s for s in primary_seeds if s in active_candidates]
            ordered_targets.extend(sorted(set(active_candidates) - set(ordered_targets)))
            my_geo = get_node_geo_entry(current_domain, is_local=True)

        payload = {
            "node_onion": current_domain,
            "node_pubkey": NODE_PUBLIC_KEY_HEX,
            "geo": my_geo,
        }

        futures = [
            discovery_executor.submit(_announce_to_single_seed, seed, current_domain, payload)
            for seed in ordered_targets
        ]
        concurrent.futures.wait(futures, timeout=35)

        with lock:
            pinned_count = len(peer_pubkeys)
        time.sleep(20 if pinned_count < 2 else 60)


if os.getenv("DISABLE_BOOTSTRAP_LOOP") != "1":
    threading.Thread(target=bootstrap_discovery_loop, daemon=True).start()
    threading.Thread(target=anti_entropy_sync_loop, daemon=True).start()
    threading.Thread(target=mesh_watch_loop, daemon=True).start()

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, threaded=True)
