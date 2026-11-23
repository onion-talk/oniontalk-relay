# OnionTalk Wire Protocol Specification (`ENVELOPE_V3`)

> **Canonical Specification Notice**: This document is the single authoritative wire protocol specification for the **OnionTalk** decentralized messaging mesh. The legacy standalone repository `onion-talk/oniontalk-protocol` has been archived and consolidated here so protocol documentation stays directly coupled to the production Rust relay implementation (`src/crypto.rs`, `src/main.rs`, `src/founder.rs`).

> **Source Code Availability Disclaimer / Aviso sobre o Código-Fonte**:
> - **Open Source (MIT — Publicly Auditable)**: This federated Tor v3 Rust Relay (`oniontalk-relay`) and this Wire Protocol Specification (`docs/PROTOCOL.md` & `docs/MANIFESTO.md`) are fully open-source under the MIT License.
> - **Temporarily Restricted Source Code (Clients)**: The source code for the client applications (`org.oniontalk.messenger` for Android, `onion-talk-web`, and iOS) is **temporarily closed / restricted for now** while active cryptographic hardening, architectural stabilization, and pre-audit reviews are in progress. Signed binaries continue to be distributed via Google Play Store, GitHub Releases (`SHA256SUMS.txt`), and Docker Hub.
> - *(PT-BR)*: **O código-fonte dos aplicativos clientes (`org.oniontalk.messenger`, `onion-talk-web` e iOS) encontra-se bloqueado/fechado temporariamente** durante a fase atual de hardening de segurança e estabilização pré-auditoria, enquanto o servidor Relay em Rust (`oniontalk-relay`) e a especificação formal do protocolo `ENVELOPE_V3` permanecem abertos sob licença MIT.

---

## 1. Design Principles & Threat Model

OnionTalk is engineered for **zero-metadata, censorship-resistant, end-to-end encrypted communication** under a zero-trust relay model:

1. **Zero PII Identities**: No phone number, SIM card, email, or central account registry. An identity is a 256-bit **Ed25519** public key (`@<64-hex-ed25519-pubkey>:<relay-domain>.onion`), birationally mapped to **X25519** (`RFC 7748` / `RFC 8032`).
2. **Untrusted Relays (Blind Store-and-Forward)**: Relays hold encrypted envelopes strictly in volatile RAM (`DashMap`, 24h TTL; 30s TTL for voice frames), never see plaintext or private keys, cannot spoof sender envelopes, cannot list inboxes without Ed25519 authentication, and cannot purge messages without cryptographic proof of decryption (`ACK Preimage Lock`).
3. **Zero Clearnet / Zero DNS Leaks**: All client-to-relay and relay-to-relay transport traverses **Tor v3 Hidden Services** (`56-char base32 .onion`) via `SOCKS5h` (`127.0.0.1:9050`, `IsolateDestAddr`, `IsolateSOCKSAuth`), with local relay ports bound solely to `127.0.0.1`.
4. **Post-Quantum Defense-in-Depth**: Combines classical **Dual X25519 ECDH** with **NIST FIPS 203 ML-KEM-768 (`CRYSTALS-Kyber-768`)** to mitigate *Harvest Now, Decrypt Later* adversaries.

---

## 2. The 4-Layer Protocol Stack (`ENVELOPE_V3`)

### Layer 1 — Tor v3 Transport & Anti-DoS Hardening (`torrc`)
- **Hidden Service v3**: Ed25519 `.onion` addresses (`^[a-z2-7]{56}\.onion$`), virtual port `80` routed internally to the non-root Rust relay (`UID 10014:10014`).
- **Introduction & DoS Defenses**:
  - `HiddenServiceNumIntroductionPoints 5`
  - `HiddenServiceEnableIntroDoSDefense 1`
  - `HiddenServicePoWDefensesEnabled 1` (**Tor 0.4.9 Equi-X Proof-of-Work**)
  - `HiddenServiceMaxStreams 64` + `HiddenServiceMaxStreamsCloseCircuit 1`
  - `NoExec 1` & `KeepalivePeriod 45`
- **Zero-Master Blind RTT Gateway Selection**: Clients probe relay `/health` endpoints over Tor circuits and maintain an EWMA RTT score without ever querying GPS, GeoIP, locale, or carrier telemetry. Voice calls negotiate dynamic single-hop rendezvous relays (`reply_relay` + `backup_relay`) inside the encrypted `RING:` control frame, pinned against verified relays.

### Layer 2 — Authenticated Peer Exchange (`Auto-Gossip PEX`), S/Kademlia XOR Routing & GossipSub v1.2
- **Peer Authentication (`ONIONTALK_PEER_V2`)**: Relays sign peer-to-peer requests (`/api/v1/peers/announce`, `/api/v1/messages/sync`, `/api/v1/messages/ihave`, `/api/v1/messages/ack_sync`, `/api/v1/messages/ack_batch_sync`) with their `Ed25519` node key using canonical transcript:
  ```text
  ONIONTALK_PEER_V2|<METHOD>|<PATH>|<SOURCE_ONION>|<TIMESTAMP_MS>|<BODY_SHA256_HEX>
  ```
- **Active Anti-Sybil Verification**: Before admitting a candidate peer (`MAX_KNOWN_PEERS = 64`, `MAX_AUTO_PEERS_PER_PROVIDER = 6`), the receiving relay opens a reverse Tor circuit to `GET http://<candidate>.onion/health` and verifies that `node_pubkey` matches the announcement signature.
- **S/Kademlia XOR Distance Routing**:
  ```text
  distance(peer_onion, target_key) = SHA-256(peer_onion) XOR SHA-256(target_key)
  ```
- **Blinded Poller Affinity**: Relays advertise locally connected recipients without exposing raw public keys via a domain-separated blinded tag:
  ```text
  affinity_tag = SHA-256("ONIONTALK_AFFINITY_V2|" || canonical_inbox_key)
  ```
- **GossipSub v1.2 Anti-Entropy (`IHAVE` / `IDONTWANT`)**: Every 18 seconds (and prior to forwarding large envelopes), relays exchange compact message digests and active blinded poller tags over `POST /api/v1/messages/ihave`, preventing redundant Tor mesh forwarding.

### Layer 3 — Volatile RAM Queues, Inbox Challenge Auth & Cryptographic ACK Preimage Lock
- **RAM-Only Bounded Quotas (`src/crypto.rs`, `src/main.rs`)**:
  - `MESSAGE_TTL_MS = 24 * 3600 * 1000` (`24h`)
  - `VOICE_MESSAGE_TTL_MS = 30 * 1000` (`30s`)
  - `MAX_INBOX_PER_USER = 500`, `MAX_PER_SENDER_INBOX = 150`, `MAX_TOTAL_INBOXES = 5000`
  - Atomic `0600` persistence on `/data` is restricted strictly to node keys, anti-replay nullifiers, and CRL state — **never message plaintext or decrypted envelopes**.
- **Client Request Authentication (`ONIONTALK_AUTH_V2`)**:
  - Requests to `/api/v1/messages/inbox`, `/api/v1/voice/stream`, `/api/v1/messages/ack`, and `/api/v1/messages/ack_batch` require `X-OnionTalk-Timestamp` (within `AUTH_WINDOW_MS = 5 min`) and `X-OnionTalk-Signature` (Ed25519 over):
    ```text
    ONIONTALK_AUTH_V2|<SCOPE>|<CANONICAL_USER_ID>|<TIMESTAMP_MS>
    ```
- **Cryptographic ACK Preimage Lock**:
  - The sender generates a 256-bit CSPRNG `ack_token`, seals it inside the E2EE ciphertext, and attaches only `ack_lock = SHA-256(ack_token)` to the outer envelope.
  - Only the legitimate recipient can decrypt the envelope, recover `ack_token`, and issue an authenticated `ACK`. Relays verify `SHA-256(ack_token) == ack_lock` in constant time (`constant_time_eq`) before purging the message from RAM and propagating `ack_sync` / `ack_batch_sync`.

### Layer 4 — End-to-End Hybrid Post-Quantum Cryptography (`ENVELOPE_V3` + `ML-KEM-768`)
- **Outer Authenticated Wire Format (`ENVELOPE_V3`)**:
  ```text
  __ENC_X25519_CHACHA20_V3__:<msgId>:<timestampMs>:<ackLockHex>:<ephPubHex>:<nonceB64>:<ciphertextB64>:<ed25519SigHex>
  ```
- **Bound Ed25519 Outer Signature Transcript (`src/crypto.rs::verify_envelope_v3_transcript`)**:
  ```text
  ENVELOPE_V3|<sender>|<recipient>|<msgId>|<timestampMs>|<ackLockHex>|<ephPubHex>|<nonceB64>|<ciphertextB64>
  ```
  Binding `msgId`, `timestampMs`, and `ack_lock` inside both the Ed25519 signature and AEAD associated data prevents malicious relays from substituting `ack_lock` values, replaying envelopes across timestamps, or mutating envelope metadata.
- **Outer Symmetric Key Derivation**:
  - Fresh ephemeral X25519 keypair per message (`eph_priv`, `eph_pub`).
  - Dual ECDH: `ECDH(eph_priv, recipient_x25519_pub) || ECDH(sender_x25519_priv, recipient_x25519_pub)`.
  - `HKDF-SHA256` -> 256-bit AEAD key -> **ChaCha20-Poly1305** (`96-bit nonce`, `128-bit Poly1305 tag`) with AAD binding `ENVELOPE_V3|<sender>|<recipient>|<msgId>|<timestampMs>|<ackLockHex>|<ephPubHex>`.
- **Inner Post-Quantum Layer (`ML-KEM-768` / NIST FIPS 203)**:
  - Handshake negotiation via `__CTRL_PQC_KEM_V1__` (`INIT` / `ACK`) carrying deterministic `ML-KEM-768` public keys.
  - Inner ciphertext framing: `__PQC_MLKEM768_V1__:` with `OT_PQC_CAPSULE_V2|` domain-separated `HKDF-SHA256` + `ChaCha20-Poly1305`.
  - Sovereign PQC Groups combine `ML-KEM-768` + `SHA3-256` + `ChaCha20-Poly1305` with dual-stack `Ed25519` founder roster manifests (`V2` + `V3` SHA-256 roster binding).
- **Local Vault & Encrypted Backup at Rest**:
  - **SQLCipher AES-256** keyed via **Argon2id (`19 MiB` / `19,456 KiB`, `t = 2`, `p = 1`)** (`argon2id$v19$`).
  - Encrypted backup format **`OTBK3`**: `OTBK3` header + 16-byte salt + `AES-256-GCM(Argon2id)`.
  - Anti-forensic protections: mandatory `FLAG_SECURE`, 5-strike duress wipe (`DoD 5220.22-M`), bilateral synchronized burn (`__CTRL_BURN_V1__`) with monotonic burn watermarks, and SQLCipher persistent anti-replay nullifiers.

---

## 3. Offline Root CA PKI & Signed Authority CRL (`otcrl1:`)

To eliminate single-key governance risk and support instant revocation without central online CAs, relays and clients enforce pinned Offline Root CAs (`OFFLINE_ROOT_CA_PUBKEYS`) and mandatory token expiration (`MAX_AUTHORITY_TOKEN_TTL_SEC = 35 days`):

- **Signed Revocation & Delegation Token (`otcrl1:`)**:
  ```text
  otcrl1:<epoch_sec>:<revoked_csv>:<delegated_csv>:<root_pubkey_hex>:<ed25519_sig_hex>
  ```
- **Canonical CRL Signature Transcript (`src/founder.rs`)**:
  ```text
  ONIONTALK_AUTHORITY_CRL_V1|<epoch_sec>|<revoked_csv>|<delegated_csv>|<root_pubkey_hex>
  ```
- **Verification Rules**:
  1. `root_pubkey_hex` must belong to the compile-time pinned `OFFLINE_ROOT_CA_PUBKEYS` set.
  2. `epoch_sec` must be strictly monotonic (`> current_crl_epoch`) and within `MAX_CRL_FUTURE_SKEW_SEC = 300s`.
  3. Ed25519 signature must validate cleanly before updating the in-memory and atomically persisted CRL state.

---

## 4. Relay HTTP API Endpoints (Over Tor v3 Virtual Port `80`)

| Method | Endpoint | Auth / Purpose |
| :--- | :--- | :--- |
| `GET` | `/health` | Public node health, `.onion` domain, `node_pubkey`, synthetic topology metadata, and `zero_trust_mode`. |
| `GET` | `/api/v1/peers/list` | Returns verified `.onion` peers in the mesh. |
| `POST` | `/api/v1/peers/announce` | `ONIONTALK_PEER_V2` Ed25519-signed peer announcement + reverse `/health` handshake. |
| `POST` | `/api/v1/messages/send` | Client envelope submission (`ENVELOPE_V3` verified before queuing & gossip). |
| `POST` | `/api/v1/messages/sync` | `ONIONTALK_PEER_V2` relay-to-relay envelope replication. |
| `POST` | `/api/v1/messages/ihave` | `ONIONTALK_PEER_V2` GossipSub v1.2 digest exchange & blinded `active_pollers` affinity sync. |
| `GET` | `/api/v1/messages/inbox` | `ONIONTALK_AUTH_V2` Ed25519-authenticated inbox fetch & long-polling. |
| `GET` | `/api/v1/voice/stream` | `ONIONTALK_AUTH_V2` isochronous chunked stream for PQC voice frames (`30s` TTL). |
| `POST` | `/api/v1/messages/ack` | `ONIONTALK_AUTH_V2` + `SHA-256(ack_token) == ack_lock` purge proof. |
| `POST` | `/api/v1/messages/ack_batch` | `ONIONTALK_AUTH_V2` batch preimage purge proof. |
| `POST` | `/api/v1/messages/ack_sync` | `ONIONTALK_PEER_V2` single ACK propagation across the mesh. |
| `POST` | `/api/v1/messages/ack_batch_sync` | `ONIONTALK_PEER_V2` batch ACK propagation across the mesh. |

---

## 5. Further Reading

- [**OnionTalk Manifesto (`docs/MANIFESTO.md`)**](./MANIFESTO.md) — Architectural thesis, anti-censorship engineering, and cypherpunk design foundations.
- [**Relay Source Implementation (`src/crypto.rs` & `src/main.rs`)**](../src/) — Production Rust reference implementation (`Tokio` / `Axum` / `DashMap` / `ed25519-dalek`).
