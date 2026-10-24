<div align="center">
  <img src="https://raw.githubusercontent.com/onion-talk/.github/main/assets/oniontalk-icon-512.png" alt="OnionTalk Logo" width="110" height="110" />
  <h1>OnionTalk Relay Node</h1>
  <p><strong>Zero-Knowledge Tor v3 Hidden Service Relay with Ed25519-Authenticated Peer Exchange (PEX) & Cryptographic ACK Preimage Lock</strong></p>

  <p>
    <a href="https://play.google.com/store/apps/details?id=org.oniontalk.messenger">
      <img src="https://img.shields.io/badge/Google_Play-OnionTalk_–_Apps_no_Google_Play-3DDC84?style=for-the-badge&logo=google-play&logoColor=black" alt="OnionTalk – Apps no Google Play" />
    </a>
    <a href="https://github.com/sponsors/eriktonon">
      <img src="https://img.shields.io/badge/Sponsor-OnionTalk-ea4aaa?style=for-the-badge&logo=githubsponsors&logoColor=white" alt="Sponsor on GitHub" />
    </a>
    <a href="#-sponsor--donate">
      <img src="https://img.shields.io/badge/Donate-BTC_%7C_ETH_%7C_SOL-F7931A?style=for-the-badge&logo=bitcoin&logoColor=white" alt="Donate Crypto" />
    </a>
  </p>
</div>

---

## 🚀 What's New in `v1.4.4` (`versionCode = 28` / Build 28) & Relay Mesh `v=27` — Post-Quantum Hybrid Encryption (`ML-KEM-768`), Dual Warm Socket Pool (~1.13s E2E), S/Kademlia XOR Routing & GossipSub v1.2

- **📦 Direct Signed APK Downloads (`v1.4.4` — Latest Release Build 28)**:
  - **Main Messenger APK (`org.oniontalk.messenger` `v1.4.4` Build 28)**: [**Download `OnionTalk-v1.4.4.apk`**](https://github.com/onion-talk/oniontalk-demo/releases/download/v1.4.4-demo/OnionTalk-v1.4.4.apk) (`SHA-256: 02290a3e1d2b1719c7736aee898f6dcd0244fc5206d9e749770b1319615ab1ba`)
  - **Standalone Android Relay Node APK (`org.oniontalk.relaynode` `v1.4.3` Build 7)**: [**Download `OnionTalk-RelayNode-v1.4.3.apk`**](https://github.com/onion-talk/oniontalk-demo/releases/download/v1.4.4-demo/OnionTalk-RelayNode-v1.4.3.apk) (`SHA-256: 14cb0acbff19947312af12df7ba092c7245084e432ffafb4b06c9008e838b4e4`)
- **🛡️ Key Cryptographic & P2P Mesh Breakthroughs in `v1.4.4` (`Build 28`)**:
  1. **Hybrid Post-Quantum Cryptography (`__ENC_PQC_KYBER768_X25519_V3__`)**: Combines classical **Dual X25519 ECDH** with **NIST FIPS 203 ML-KEM-768 (`Kyber-768`)** key encapsulation via `HKDF-SHA256` + `ChaCha20-Poly1305 AEAD` + `Ed25519` outer envelope signatures to protect against *Harvest Now, Decrypt Later* quantum adversaries.
  2. **Ultra-Fast E2E Delivery (`1.139s – 1.244s`, avg `1.20s`)**: Upgraded **Dual Warm Socket Pool** (`minWarmSockets = 2` per `.onion` gateway, `70s/75s` Keep-Alive) achieving **100% pre-warmed Tor circuit reuse (`0ms` SOCKS5 handshake)** alongside a `250ms` speculative *Hedged Send*.
  3. **S/Kademlia XOR Distance Routing & Blinded Poller Affinity (`v=27`)**: All 17 global `.onion` v3 relays now route by XOR distance (`SHA-256(peer_onion) ^ SHA-256(recipient_hash)`) with zero-knowledge RAM-only rendezvous affinity (`active_pollers`, `TTL 90s`, zero logs).
  4. **GossipSub v1.2 `IHAVE` / `IDONTWANT` Deduplication**: Relays announce `POST /gossip/ihave` metadata before forwarding payloads `> 1024 bytes`, cutting redundant Tor mesh bandwidth by **~70%**.
  5. **Continuous `10s–12s` Long-Polling & Mandatory `SHA-256` Media Integrity**: Eliminates dead intervals between poll cycles and verifies `SHA-256` Merkle hashes on all voice notes, images, and attachments prior to rendering.

---
## 🚀 What's New in `v1.4.1` (`versionCode = 18` / Internal `vc17`) — Password-Locked Messages & Chats, Unified Long-Press Menu, Profile Photo Privacy, 15s Auto-Lock & Official Video Suite

- **📦 Direct Signed APK Downloads (`v1.4.1` — Latest Fixed Build 18)**:
  - **Main Messenger APK (`org.oniontalk.messenger` `v1.4.1` Build 18)**: [**Download `OnionTalk-v1.4.1.apk`**](https://github.com/onion-talk/oniontalk-demo/releases/download/v1.4.4-demo/OnionTalk-v1.4.4.apk) (`SHA-256: 68f3d5785919acaf0820c238f93f5db0cb02df5986db457ec783d573dbc652a8`)
  - **Release Build 18 APK (`versionCode = 18`)**: [**Download `OnionTalk-v1.4.1-b18-release.apk`**](https://github.com/onion-talk/oniontalk-demo/releases/download/v1.4.1-demo/OnionTalk-v1.4.1-b18-release.apk)
  - **Internal Test Track Build 17 APK (`versionCode = 17`)**: [**Download `OnionTalk-v1.4.1-b17-internal.apk`**](https://github.com/onion-talk/oniontalk-demo/releases/download/v1.4.1-demo/OnionTalk-v1.4.1-b17-internal.apk) (`SHA-256: b110ff9db1b75bf4ec6229284a6dd2f47040175003974f8a50bfe9ef2f100c5c`)
  - **Standalone Android Relay Node APK (`org.oniontalk.relaynode` `v1.4.1` Build 3)**: [**Download `OnionTalk-RelayNode-v1.4.2.apk`**](https://github.com/onion-talk/oniontalk-demo/releases/download/v1.4.1-demo/OnionTalk-RelayNode-v1.4.2.apk) (`SHA-256: befe94bcf2e66a2fe067b47b2114af9f226cf3405292df7e67ab5e29782f3f1b`)
- **🎬 New Official `v1.4.1` Promotional & Feature Walkthrough Videos**:
  - [**▶ Watch Official Promo v1.4.1 (Português 1080p)**](https://github.com/onion-talk/oniontalk-demo/raw/main/video/OnionTalk-v1.4.1-Promo-Oficial-PT.mp4)
  - [**▶ Watch Official Promo v1.4.1 (English 1080p)**](https://github.com/onion-talk/oniontalk-demo/raw/main/video/OnionTalk-v1.4.1-Promo-Official-EN.mp4)
  - [**▶ Watch Complete Feature & Messaging Walkthrough v1.4.1 (PT-BR 1080p)**](https://github.com/onion-talk/oniontalk-demo/raw/main/video/OnionTalk-v1.4.1-Demo-Funcoes-PT.mp4)
  - [**▶ Watch Vertical Reels / Shorts / TikTok 9:16 Spot (1080x1920)**](https://github.com/onion-talk/oniontalk-demo/raw/main/video/OnionTalk-v1.4.1-Reels-Shorts-PT.mp4)
- **🔐 Key Security & UX Improvements in `v1.4.1` (`Build 18`)**:
  1. **Password-Protected Individual Messages (`__LOCKED_MSG_V1__`)**: Lock any message in a conversation with a dedicated secret password (`PBKDF2-HMAC-SHA256` + `AES-256-GCM`) and reliable first-try session caching (`unlockedMessageCache`) so unlocked messages stay readable throughout the active chat session.
  2. **Password-Protected Conversations**: Lock entire conversations with a dedicated password, masking message previews on the Home screen (`🔒 Conversa trancada com senha`).
  3. **Clean Conversation Rows & Unified Long-Press Action Menu**: Removed external star and pencil icons from conversation rows; long-pressing any conversation opens a unified action menu to **Favorite / Pin to Top (`📌`)**, **Rename Contact (`✏️`)**, or trigger **Bilateral Anti-Forensic Burn (`🔥`)**.
  4. **Instant Add Contact Dismissal & Navigation**: Adding a `.onion` contact now dismisses the modal prior to navigation so the dialog never lingers when returning to the Home screen.
  5. **Single-Flight Hardware Biometrics (`AtomicBoolean`)**: Eliminates duplicate fingerprint prompts when unlocking the vault or resuming from background (`ON_START`).
  6. **Granular Profile Photo Visibility (`Public / Contacts / Friends / Private`)**: Control who receives your sanitized avatar, plus fixed 4-tab Settings navigation (`Modifier.weight(1f)`) and responsive Crypto Donation cards (`BTC`, `ETH`, `SOL`).
  7. **15-Second Auto-Lock (Even After App Closed)**: Persists inactivity timestamps and evaluates elapsed background time immediately on process start so the vault locks strictly after `15s`.

| **1. Password-Locked Message (`v1.4.1`)** | **2. Instant Message Unlock Modal** | **3. Clean List & Long-Press Favorites (`📌`)** |
| :---: | :---: | :---: |
| <img src="https://raw.githubusercontent.com/onion-talk/.github/main/assets/screenshots/11-locked-message-e2ee.png" width="260" alt="Password Locked Message Bubble" /> | <img src="https://raw.githubusercontent.com/onion-talk/.github/main/assets/screenshots/12-unlock-message-modal.png" width="260" alt="Unlock Message Modal" /> | <img src="https://raw.githubusercontent.com/onion-talk/.github/main/assets/screenshots/13-locked-chat-pin-home.png" width="260" alt="Clean Home Pinned & Locked Chat" /> |
| *Per-message AES-256-GCM password lock inside E2EE Tor v3 chat.* | *Unlocks on the first try with incognito keyboard and session cache.* | *Clean conversation list with pinned favorites and locked chat masking.* |

| **4. Lock Entire Conversation Modal** | **5. Profile Photo Privacy (`Build 18`)** | **6. 15s Auto-Lock & Single Biometrics** |
| :---: | :---: | :---: |
| <img src="https://raw.githubusercontent.com/onion-talk/.github/main/assets/screenshots/14-lock-conversation-modal.png" width="260" alt="Lock Conversation with Password" /> | <img src="https://raw.githubusercontent.com/onion-talk/.github/main/assets/screenshots/15-profile-photo-privacy.png" width="260" alt="Profile Photo Visibility Settings" /> | <img src="https://raw.githubusercontent.com/onion-talk/.github/main/assets/screenshots/16-autolock-15s-security.png" width="260" alt="15s Auto-Lock and Biometric Security" /> |
| *Dedicated conversation password hides Home previews and blocks unauthorized access.* | *4 fixed Settings tabs (`Build 18`) and Public / Contacts / Friends / Private avatar visibility.* | *15s inactivity lock enforced even after app closure + single-flight fingerprint prompt.* |

---

## 🚀 What's New in `v1.4.0` (`versionCode = 14`) — 17-Node Global Mesh (8 Countries), Selective `FLAG_SECURE`, Instant Tor Auto-Heal & GZIP File Transfers

- **📦 Direct Signed APK Downloads (`v1.4.0`)**:
  - **Main Messenger APK (`org.oniontalk.messenger`)**: [**Download `OnionTalk-v1.4.0.apk`**](https://github.com/onion-talk/oniontalk-demo/releases/download/v1.4.4-demo/OnionTalk-v1.4.4.apk) (`SHA-256: d11ee5629b6bffa32658d80e2d22cd5582e37c84d3b69bd85dffc424793688c4`)
  - **Standalone Android Relay Node APK (`org.oniontalk.relaynode`)**: [**Download `OnionTalk-RelayNode-v1.4.2.apk`**](https://github.com/onion-talk/oniontalk-demo/releases/download/v1.4.1-demo/OnionTalk-RelayNode-v1.4.2.apk) (`SHA-256: befe94bcf2e66a2fe067b47b2114af9f226cf3405292df7e67ab5e29782f3f1b`)
- **🌐 17 Active Tor v3 Relays Across 8 Countries (`BR`, `US`, `FR`, `DE`, `RU`, `SG`, `JP`, `CN`)**:
  - Added **Node 16 (DOM Cloud Nuremberg, Germany)**: `o5zqqfl5znzexdojfnxgub5jnjelxdahbyxasjp57sx6fbxtjeqovpad.onion`
  - Added **Node 17 (ModelScope Cloud Hangzhou, China — GFW Bypass)**: `2amizuhb3p5x2lk3sra7f7thm5tgs7qtnysgowqpmexcqi4cuwyv7vad.onion`
  - Added **Zero-Touch Auto-Join & 100% Zero-Leak Synthetic Coordinates (Zero IP / Zero Geo Exposure)** so any Docker or Android Relay Node joins the mesh in `<15s`.
- **🛡️ Selective `FLAG_SECURE` by Route**:
  - Enforces `WindowManager.LayoutParams.FLAG_SECURE` **100% of the time** on **Conversations (`CHAT_DETAIL`)**, **Active Chats (`CHAT_LIST`)**, and **Contacts Library (`CONTACTS_LIBRARY`)**, while dynamically allowing screenshots on **Settings / QR Code (`SETTINGS`)** for frictionless identity sharing.
- **⚡ 2-Hour Large-Scale Soak & Chaos Engineering Certification (`23:50–01:50`, 60 Waves, 3 Android 15 Emulators)**:
  - **0 crashes, 0 ANRs, 0 frozen process warnings** (`PSS: 62.5 MB – 94.9 MB`).
  - **Online P2P Delivery Latency**: `p50 = 1,147.1 ms` (`1.15s`), `p95 = 5,039.5 ms`.
  - **Encrypted File Transfers (`16 KB`–`256 KB`)**: `15/15` (`100%`) delivered with transparent **GZIP pre-compression (`gz=true`)** and adaptive read timeouts (`25s`).
  - **Bilateral Anti-Forensic Burn (`__CTRL_BURN_V1__`)**: `15/15` (`100%`) confirmed in `p50 = 1,846.5 ms`.
  - **Instant Network Auto-Recovery (`ConnectivityManager.NetworkCallback`)**: Foreground & background `NetworkCallback` + `3.5s` partial wake-lock on incoming batches recovers offline backlogs in `700.8 ms – 849.9 ms`.
- **🎨 Visual Privacy & UI Polish**:
  - Added **Blur / Unblur Contact Photo** (`blurAvatarBitmap`) per contact, removed bubble reply clutter and header shield icon, and placed the `✅ Atualizado` confirmation directly inside the Tor Status card.

| # | Country / Region | Tor v3 Hidden Service Address (`.onion`) | Role |
| :-: | :--- | :--- | :--- |
| 1 | 🇧🇷 Brazil (São Paulo #1) | `onion4zr3bsdeaelksemwokl5qmxd5o7jyblf46vc2mfl6cozgw77tqd.onion` | Master Vanity Seed (PVE2) |
| 2 | 🇧🇷 Brazil (São Paulo #2) | `kn4u2xxl2otoo2ujv3mhehwfwbw7mtppaf56fu3nxogvv7eekf2qdrid.onion` | Homelab Core Seed (PVE4) |
| 3 | 🇺🇸 USA (US-East) | `puqjsmsyyzmxjdtcgr2fl4wrdazqd2phaqrz26alzwyletbvekkxhyyd.onion` | AWS EKS Relay |
| 4 | 🇧🇷 Brazil (Vinhedo) | `zqdx5x7pfybox7m5rz3fe5kiouxhipvh3ekuteq2urrrvwcxjttnmgid.onion` | Oracle Cloud OCI Relay |
| 5 | 🇺🇸 USA (Virginia) | `ch4s5llfqshxbvba2yulgp5kbopq25w3qqrtli67sle6smbujlebn2id.onion` | AWS Virginia Relay |
| 6 | 🇫🇷 France (Paris #1) | `7bntuiegd3stvcylvx7rhnhq7ncasxiokunbf5onvvm34dg5gccvooid.onion` | Alwaysdata EU Relay #1 |
| 7 | 🇺🇸 USA (South Carolina) | `jz6urt6ckkqqvtasm6bll2mryhksjcawcl4tbguif5nqvxgsfsx6ywad.onion` | Google Cloud US-East Relay |
| 8 | 🇺🇸 USA (Ohio) | `4wufywh2k6ayyz6nmh2w25hj5vjsqgkve24o2tthvc7rhyvxnhaghqqd.onion` | Render Cloud Ohio Relay |
| 9 | 🇷🇺 Russia (Moscow) | `nwsoa6ddtbbqbwcceanhhj3j23d5a47zbpbs6zspz5zoeytzqpzvkqqd.onion` | Amvera Cloud Eurasia Relay |
| 10 | 🇺🇸 USA (US-East) | `bk7iegv3v232ycjyf5ylwsdx42iozvy2dhhff5zn3ciwa3g2lkifdlad.onion` | Back4App Container Relay |
| 11 | 🇫🇷 France (Paris #2) | `hdjp7uaj4qemlmwtev7xmj2w3uexnv6ctplfgvbmpqxenbfgwjjwtrid.onion` | Alwaysdata EU Relay #2 |
| 12 | 🇫🇷 France (Paris #3) | `gcvfh67zltoyvithw6luetsrcec6cw42upzrsprxfmx27cvh7vidw4yd.onion` | Alwaysdata EU Relay #3 |
| 13 | 🇺🇸 USA (Iowa, US-Central) | `wfi3nwuzk2tgrsf2scdy4nb6x6rtiocit4n26477zdlvdvshkgip3ayd.onion` | Northflank US-Central Relay |
| 14 | 🇯🇵 Japan (Osaka) | `5s6w6556f2eov2p6wlsuavaxh7si2kaswjwi5reojnovbzemducjzjqd.onion` | DOM Cloud Asia-Pacific East |
| 15 | 🇸🇬 Singapore | `o5yf3eukrwpt2g6jfo4q2y23xtuhoso2qknmnn6ac5eng5t4yt36roqd.onion` | DOM Cloud Southeast Asia Hub |
| 16 | 🇩🇪 Germany (Nuremberg) | `o5zqqfl5znzexdojfnxgub5jnjelxdahbyxasjp57sx6fbxtjeqovpad.onion` | DOM Cloud Central Europe |
| 17 | 🇨🇳 China (Hangzhou) | `2amizuhb3p5x2lk3sra7f7thm5tgs7qtnysgowqpmexcqi4cuwyv7vad.onion` | ModelScope CN / GFW Bypass |

---

## 🎯 Overview

`oniontalk-relay` is the federated RAM-only store-and-forward node that powers the **OnionTalk** decentralized messaging mesh.

- **Works Behind CGNAT & Home Routers (Zero Open Clearnet Ports)**: Because the relay operates strictly as a **Tor v3 Hidden Service (`.onion`)** and binds its local inspection port solely to `127.0.0.1`, the container establishes outbound circuits into the Tor network. No port forwarding, static IP, or public DNS is required.
- **Zero-Knowledge RAM-Only Store-and-Forward**: The relay stores encrypted envelopes (`__ENC_X25519_CHACHA20_V2__`: `X25519 ECDH` + `HKDF-SHA256` + `ChaCha20-Poly1305 AEAD` + `Ed25519 Signature`) exclusively in volatile RAM (`ram-volatile-ephemeral-ttl24h`), requires `Ed25519` challenge signatures (`X-OnionTalk-Signature`) on `/inbox` and `/ack`, and purges envelopes upon verifying a 256-bit cryptographic preimage proof (`SHA-256(ack_token) == ack_lock`).
- **Authenticated Peer Discovery (Ed25519 Gossip PEX)**: On startup, the relay generates its `.onion` v3 hidden service and `Ed25519` node signing key (`node_pubkey`), announcing itself to the mesh bootstrap seeds and verifying peer keys over Tor (`/health`) before accepting gossip replication.

---

## 🚀 Quick Start (1 Command)

```bash
git clone https://github.com/onion-talk/oniontalk-relay.git
cd oniontalk-relay
docker compose up -d --build
```

### Check Your Relay `.onion` Identity & Mesh Health

```bash
curl http://127.0.0.1:8080/health
```

Example output once Tor circuits are established (30–90 seconds after first boot):

```json
{
  "status": "healthy",
  "zero_trust_mode": "X25519-ChaCha20-Poly1305 + Ed25519-Auth + ACK-Lock + Anti-Sybil",
  "storage_engine": "ram-volatile-ephemeral-ttl24h",
  "domain": "your_generated_56_character_ed25519_address.onion",
  "node_pubkey": "64_character_hex_ed25519_public_key",
  "peers_count": 5,
  "total_nodes": 6,
  "queued_messages": 0,
  "active_inboxes": 0,
  "messages_received": 42,
  "messages_routed": 168,
  "acks_processed": 42
}
```

### Inspect Connected Mesh Peers & Geo-Distribution

```bash
curl http://127.0.0.1:8080/api/v1/peers/list
```

---

## 📂 Repository Structure

```text
oniontalk-relay/
├── docker-compose.yml   # Orchestrates Tor v3 Hidden Service + Gunicorn Relay API (127.0.0.1 bind)
├── Dockerfile           # Pinned Python 3.12-slim-bookworm + Gunicorn container image
├── relay.py             # Zero-knowledge RAM routing engine, Ed25519 auth, PEX gossip & ACK lock
├── requirements.txt     # Pinned dependencies (Flask, Gunicorn, Requests[socks], Cryptography)
├── torrc                # Tor v3 HiddenServiceVersion 3 + SOCKS5h configuration
└── README.md            # Deployment and operations guide
```

---

## ⚙️ Optional Configuration

To change the localhost HTTP inspection port (default `127.0.0.1:8080`) without affecting Tor hidden service routing (which always uses virtual port `80` inside the `.onion` circuit):

```bash
RELAY_PORT=8090 docker compose up -d
```

> **Important**: Your node's Ed25519 `.onion` private key is persisted in the `tor_keys` Docker volume. Avoid running `docker compose down -v` unless you intentionally want to rotate your `.onion` address.

---

## 💖 Sponsor & Donate

Help us keep independent Tor v3 bootstrap relays running across multiple global jurisdictions:

- **GitHub Sponsors**: [github.com/sponsors/eriktonon](https://github.com/sponsors/eriktonon)
- **Bitcoin (BTC)**: `bc1q0hr95ay33rtazfepg64yddf52q3yqh7ud83cza`
- **Ethereum (ETH / ERC-20)**: `0xE69FCE4Fa35CF3bd98F496337b1eA223270b2c92`
- **Solana (SOL)**: `3E8L1Hdqe7Xk6GCrzHbtY5sReAfLFc9CdwgZxP7qaoHq`
