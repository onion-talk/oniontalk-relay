use crate::geo::{DEFAULT_HOME_ONION, DEPRECATED_SEEDS};
use data_encoding::BASE32;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use sha3::Sha3_256;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub const AUTH_WINDOW_MS: i64 = 5 * 60 * 1000;
pub const MESSAGE_TTL_MS: i64 = 24 * 3600 * 1000;
pub const VOICE_MESSAGE_TTL_MS: i64 = 30 * 1000;

static LAST_PEER_TS_MS: AtomicI64 = AtomicI64::new(0);

pub fn now_epoch_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub fn now_epoch_sec() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn next_monotonic_peer_ts_ms() -> i64 {
    let now = now_epoch_ms();
    loop {
        let prev = LAST_PEER_TS_MS.load(Ordering::SeqCst);
        let next = if now > prev { now } else { prev + 1 };
        if LAST_PEER_TS_MS
            .compare_exchange(prev, next, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            return next;
        }
    }
}

pub fn is_lower_hex_len(s: &str, expected_len: usize) -> bool {
    s.len() == expected_len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub fn is_valid_onion_v3(domain: &str) -> bool {
    let clean = domain.trim().to_ascii_lowercase();
    if clean.len() != 62 || !clean.ends_with(".onion") {
        return false;
    }
    if DEPRECATED_SEEDS.contains(&clean.as_str()) {
        return false;
    }
    let host_part = &clean[..56];
    if !host_part.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7')) {
        return false;
    }
    if std::env::var("ALLOW_SYNTHETIC_ONION_TESTS").as_deref() == Ok("1") {
        return true;
    }
    let upper = host_part.to_ascii_uppercase();
    let Ok(raw) = BASE32.decode(upper.as_bytes()) else {
        return false;
    };
    if raw.len() != 35 || raw[34] != 0x03 {
        return false;
    }
    let mut hasher = Sha3_256::new();
    hasher.update(b".onion checksum");
    hasher.update(&raw[..32]);
    hasher.update([0x03]);
    let digest = hasher.finalize();
    constant_time_eq(&raw[32..34], &digest[..2])
}

pub fn is_valid_recipient_id(user_id: &str) -> bool {
    let clean = user_id.trim().to_ascii_lowercase();
    if !clean.starts_with('@') {
        return false;
    }
    let rest = &clean[1..];
    if let Some((pub_part, dom_part)) = rest.split_once(':') {
        is_lower_hex_len(pub_part, 64) && is_valid_onion_v3(dom_part)
    } else {
        is_lower_hex_len(rest, 64)
    }
}

pub fn extract_ed25519_pubkey_hex(user_id: &str) -> Option<String> {
    if !is_valid_recipient_id(user_id) {
        return None;
    }
    let clean = user_id.trim().to_ascii_lowercase();
    let handle = clean[1..].split(':').next()?;
    if is_lower_hex_len(handle, 64) {
        Some(handle.to_string())
    } else {
        None
    }
}

pub fn canonical_inbox_key(user_id: &str) -> String {
    if let Some(pub_hex) = extract_ed25519_pubkey_hex(user_id) {
        format!("@{}:{}", pub_hex, DEFAULT_HOME_ONION)
    } else {
        user_id.trim().to_ascii_lowercase()
    }
}

pub fn blind_affinity_tag(user_id: &str) -> String {
    let canon = canonical_inbox_key(user_id);
    if canon.is_empty() {
        return String::new();
    }
    let digest = Sha256::digest(format!("ONIONTALK_AFFINITY_V2|{}", canon).as_bytes());
    hex::encode(&digest[..12])
}

pub fn kademlia_xor_distance(peer_onion: &str, target_key: &str) -> [u8; 32] {
    let h_peer = Sha256::digest(peer_onion.as_bytes());
    let canon_target = canonical_inbox_key(target_key);
    let h_targ = Sha256::digest(canon_target.as_bytes());
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = h_peer[i] ^ h_targ[i];
    }
    out
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn write_file_atomic_0600(target_path: &str, data: &[u8]) -> std::io::Result<()> {
    if target_path.trim().is_empty() {
        return Ok(());
    }
    let path = Path::new(target_path);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = fs::create_dir_all(parent);
        }
    }
    let tmp_path = format!("{}.tmp.{}", target_path, std::process::id());
    {
        use std::io::Write;
        let mut f = fs::File::create(&tmp_path)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600));
    }
    fs::rename(&tmp_path, target_path)
}

pub fn resolve_default_data_file(filename: &str) -> String {
    if let Ok(dir) = std::env::var("DATA_DIR") {
        let trimmed = dir.trim().trim_end_matches('/').trim_end_matches('\\');
        if !trimmed.is_empty() && Path::new(trimmed).exists() {
            return format!("{}/{}", trimmed, filename);
        }
    }
    if Path::new("/data").exists() {
        return format!("/data/{}", filename);
    }
    format!("/tmp/{}", filename)
}

pub fn load_or_create_node_keypair(key_file: &str) -> (SigningKey, String) {
    if let Ok(seed_env) = std::env::var("RELAY_NODE_SEED_HEX") {
        let clean = seed_env.trim().to_ascii_lowercase();
        if is_lower_hex_len(&clean, 64) {
            if let Ok(bytes) = hex::decode(&clean) {
                if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
                    let sk = SigningKey::from_bytes(&arr);
                    let pk_hex = hex::encode(sk.verifying_key().to_bytes());
                    return (sk, pk_hex);
                }
            }
        }
    }

    let path = Path::new(key_file);
    if path.exists() {
        if let Ok(raw) = fs::read(path) {
            if let Ok(arr) = <[u8; 32]>::try_from(raw.as_slice()) {
                let sk = SigningKey::from_bytes(&arr);
                let pk_hex = hex::encode(sk.verifying_key().to_bytes());
                return (sk, pk_hex);
            }
        }
    }

    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let sk = SigningKey::from_bytes(&seed);
    let _ = write_file_atomic_0600(key_file, &sk.to_bytes());
    let pk_hex = hex::encode(sk.verifying_key().to_bytes());
    (sk, pk_hex)
}

pub fn verify_user_request_signature(
    expected_scopes: &[&str],
    user_id: &str,
    raw_ts: &str,
    raw_sig_hex: &str,
) -> Result<(), &'static str> {
    let Some(pub_hex) = extract_ed25519_pubkey_hex(user_id) else {
        return Err("Invalid user Crypto ID: must embed a 256-bit Ed25519 public key");
    };
    let sig_hex = raw_sig_hex.trim().to_ascii_lowercase();
    if raw_ts.trim().is_empty() || !is_lower_hex_len(&sig_hex, 128) {
        return Err("Missing or malformed Ed25519 authentication headers");
    }
    let Ok(ts_ms) = raw_ts.trim().parse::<i64>() else {
        return Err("Invalid authentication timestamp");
    };
    let now_ms = now_epoch_ms();
    if (now_ms - ts_ms).abs() > AUTH_WINDOW_MS {
        return Err("Authentication timestamp outside replay window");
    }

    let Ok(pub_bytes) = hex::decode(&pub_hex) else {
        return Err("Invalid Ed25519 key encoding");
    };
    let Ok(pub_arr) = <[u8; 32]>::try_from(pub_bytes.as_slice()) else {
        return Err("Invalid Ed25519 key length");
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&pub_arr) else {
        return Err("Invalid Ed25519 public key point");
    };
    let Ok(sig_bytes) = hex::decode(&sig_hex) else {
        return Err("Invalid Ed25519 signature hex");
    };
    let Ok(sig) = Signature::from_slice(&sig_bytes) else {
        return Err("Invalid Ed25519 signature length");
    };

    let clean_uid = user_id.trim().to_ascii_lowercase();
    for sc in expected_scopes {
        let sc_up = sc.to_ascii_uppercase();
        let c1 = format!("ONIONTALK_AUTH_V2|{}|{}|{}", sc_up, clean_uid, ts_ms);
        if verifying_key.verify(c1.as_bytes(), &sig).is_ok() {
            return Ok(());
        }
        let c2 = format!("{}|{}|{}", sc_up, clean_uid, ts_ms);
        if verifying_key.verify(c2.as_bytes(), &sig).is_ok() {
            return Ok(());
        }
    }
    Err("Invalid Ed25519 signature")
}

#[allow(clippy::too_many_arguments)]
pub fn verify_envelope_v3_transcript(
    verifying_key: &VerifyingKey,
    sender: &str,
    recipient: &str,
    msg_id: &str,
    ts_ms: i64,
    ack_lock: &str,
    eph_pub_hex: &str,
    nonce_b64: &str,
    ct_b64: &str,
    sig: &Signature,
) -> bool {
    let s_clean = sender.trim().to_ascii_lowercase();
    let r_clean = recipient.trim().to_ascii_lowercase();
    let s_handle = s_clean.split(':').next().unwrap_or(&s_clean);
    let r_handle = r_clean.split(':').next().unwrap_or(&r_clean);
    let id_clean = msg_id.trim();
    let lock_clean = ack_lock.trim().to_ascii_lowercase();

    let t1 = format!(
        "ENVELOPE_V3|{}|{}|{}|{}|{}|{}|{}|{}",
        s_clean, r_clean, id_clean, ts_ms, lock_clean, eph_pub_hex, nonce_b64, ct_b64
    );
    if verifying_key.verify(t1.as_bytes(), sig).is_ok() {
        return true;
    }
    let t2 = format!(
        "ENVELOPE_V3|{}:{}|{}:{}|{}|{}|{}|{}|{}|{}",
        s_handle, DEFAULT_HOME_ONION, r_handle, DEFAULT_HOME_ONION, id_clean, ts_ms, lock_clean, eph_pub_hex, nonce_b64, ct_b64
    );
    verifying_key.verify(t2.as_bytes(), sig).is_ok()
}

#[allow(clippy::too_many_arguments)]
pub fn verify_wire_envelope_signature_bound(
    sender: &str,
    recipient: &str,
    msg_id: &str,
    ts_ms: i64,
    ack_lock: &str,
    payload: &str,
    detached_v3_sig: Option<&str>,
    require_v3_binding: bool,
    raw_ts_hdr: &str,
    raw_sig_hdr: &str,
) -> Result<(), &'static str> {
    let Some(sender_pub_hex) = extract_ed25519_pubkey_hex(sender) else {
        return Err("Missing or invalid sender Ed25519 Crypto ID");
    };

    if let Some(rest) = payload.strip_prefix("__ENC_X25519_CHACHA20_V3__:") {
        let parts: Vec<&str> = rest.splitn(7, ':').collect();
        if parts.len() != 7 {
            return Err("Malformed V3 encrypted wire envelope");
        }
        let env_id = parts[0].trim();
        let Ok(env_ts) = parts[1].trim().parse::<i64>() else {
            return Err("Invalid timestamp in V3 wire envelope");
        };
        let env_lock = parts[2].trim().to_ascii_lowercase();
        let eph_pub_hex = parts[3].trim().to_ascii_lowercase();
        let nonce_b64 = parts[4].trim();
        let ct_b64 = parts[5].trim();
        let sig_hex = parts[6].trim().to_ascii_lowercase();

        if env_id.is_empty()
            || env_ts <= 0
            || !is_lower_hex_len(&env_lock, 64)
            || !is_lower_hex_len(&eph_pub_hex, 64)
            || !is_lower_hex_len(&sig_hex, 128)
        {
            return Err("Invalid field format in V3 wire envelope");
        }
        if !msg_id.trim().is_empty() && msg_id.trim() != env_id {
            return Err("Outer JSON id does not match signed V3 envelope id");
        }
        if ts_ms > 0 && ts_ms != env_ts {
            return Err("Outer JSON timestamp does not match signed V3 envelope timestamp");
        }
        if !ack_lock.trim().is_empty() && ack_lock.trim().to_ascii_lowercase() != env_lock {
            return Err("Outer JSON ack_lock does not match signed V3 envelope ack_lock");
        }

        let Ok(pub_bytes) = hex::decode(&sender_pub_hex) else {
            return Err("Invalid sender Ed25519 public key encoding");
        };
        let Ok(pub_arr) = <[u8; 32]>::try_from(pub_bytes.as_slice()) else {
            return Err("Invalid sender Ed25519 public key encoding");
        };
        let Ok(verifying_key) = VerifyingKey::from_bytes(&pub_arr) else {
            return Err("Invalid sender Ed25519 public key encoding");
        };
        let Ok(sig_bytes) = hex::decode(&sig_hex) else {
            return Err("Invalid sender Ed25519 signature encoding");
        };
        let Ok(sig) = Signature::from_slice(&sig_bytes) else {
            return Err("Invalid sender Ed25519 signature encoding");
        };

        if verify_envelope_v3_transcript(
            &verifying_key,
            sender,
            recipient,
            env_id,
            env_ts,
            &env_lock,
            &eph_pub_hex,
            nonce_b64,
            ct_b64,
            &sig,
        ) {
            return Ok(());
        }
        return Err("Invalid sender Ed25519 signature on V3 wire envelope");
    }

    if let Some(rest) = payload.strip_prefix("__ENC_X25519_CHACHA20_V2__:") {
        let parts: Vec<&str> = rest.splitn(4, ':').collect();
        if parts.len() != 4 {
            return Err("Malformed V2 encrypted wire envelope");
        }
        let eph_pub_hex = parts[0].trim().to_ascii_lowercase();
        let nonce_b64 = parts[1].trim();
        let ct_b64 = parts[2].trim();
        let sig_hex = parts[3].trim().to_ascii_lowercase();
        if !is_lower_hex_len(&eph_pub_hex, 64) || !is_lower_hex_len(&sig_hex, 128) {
            return Err("Invalid ephemeral X25519 key or Ed25519 signature format in envelope");
        }
        let Ok(pub_bytes) = hex::decode(&sender_pub_hex) else {
            return Err("Invalid sender Ed25519 public key encoding");
        };
        let Ok(pub_arr) = <[u8; 32]>::try_from(pub_bytes.as_slice()) else {
            return Err("Invalid sender Ed25519 public key encoding");
        };
        let Ok(verifying_key) = VerifyingKey::from_bytes(&pub_arr) else {
            return Err("Invalid sender Ed25519 public key encoding");
        };
        let Ok(sig_bytes) = hex::decode(&sig_hex) else {
            return Err("Invalid sender Ed25519 signature encoding");
        };
        let Ok(sig) = Signature::from_slice(&sig_bytes) else {
            return Err("Invalid sender Ed25519 signature encoding");
        };

        let s_clean = sender.trim().to_ascii_lowercase();
        let r_clean = recipient.trim().to_ascii_lowercase();
        let s_handle = s_clean.split(':').next().unwrap_or(&s_clean);
        let r_handle = r_clean.split(':').next().unwrap_or(&r_clean);

        let t1 = format!(
            "ENVELOPE_V2|{}|{}|{}|{}|{}",
            s_clean, r_clean, eph_pub_hex, nonce_b64, ct_b64
        );
        let t2 = format!(
            "ENVELOPE_V2|{}:{}|{}:{}|{}|{}|{}",
            s_handle, DEFAULT_HOME_ONION, r_handle, DEFAULT_HOME_ONION, eph_pub_hex, nonce_b64, ct_b64
        );
        if verifying_key.verify(t1.as_bytes(), &sig).is_err()
            && verifying_key.verify(t2.as_bytes(), &sig).is_err()
        {
            return Err("Invalid sender Ed25519 signature on V2 wire envelope");
        }

        let clean_v3_sig = detached_v3_sig.map(|s| s.trim().to_ascii_lowercase()).unwrap_or_default();
        if !clean_v3_sig.is_empty() {
            if !is_lower_hex_len(&clean_v3_sig, 128) || msg_id.trim().is_empty() || ts_ms <= 0 {
                return Err("Malformed detached ENVELOPE_V3 binding signature or metadata");
            }
            let Ok(v3_bytes) = hex::decode(&clean_v3_sig) else {
                return Err("Invalid detached ENVELOPE_V3 signature hex");
            };
            let Ok(v3_sig_obj) = Signature::from_slice(&v3_bytes) else {
                return Err("Invalid detached ENVELOPE_V3 signature length");
            };
            if !verify_envelope_v3_transcript(
                &verifying_key,
                sender,
                recipient,
                msg_id,
                ts_ms,
                ack_lock,
                &eph_pub_hex,
                nonce_b64,
                ct_b64,
                &v3_sig_obj,
            ) {
                return Err("Detached ENVELOPE_V3 signature rejected (ack_lock, id or timestamp tampered)");
            }
        } else if require_v3_binding {
            return Err("Client v1.8.0+ must include ENVELOPE_V3 binding signature (v3_sig)");
        }
        return Ok(());
    }

    if require_v3_binding {
        return Err("Unencrypted or legacy envelope rejected for v1.8.0+ client");
    }
    verify_user_request_signature(&["SEND", "INBOX"], sender, raw_ts_hdr, raw_sig_hdr)
}

#[allow(dead_code)]
pub fn verify_wire_envelope_signature(
    sender: &str,
    recipient: &str,
    payload: &str,
    raw_ts_hdr: &str,
    raw_sig_hdr: &str,
) -> Result<(), &'static str> {
    verify_wire_envelope_signature_bound(
        sender,
        recipient,
        "",
        0,
        "",
        payload,
        None,
        false,
        raw_ts_hdr,
        raw_sig_hdr,
    )
}

pub fn verify_ack_proof(ack_lock: &str, provided_token: &str) -> bool {
    let lock_clean = ack_lock.trim().to_ascii_lowercase();
    if !is_lower_hex_len(&lock_clean, 64) {
        return false;
    }
    let tok_clean = provided_token.trim();
    if tok_clean.len() < 32 || tok_clean.len() > 256 {
        return false;
    }
    let computed = hex::encode(Sha256::digest(tok_clean.as_bytes()));
    constant_time_eq(computed.as_bytes(), lock_clean.as_bytes())
}

pub fn parse_safe_timestamp_ms(raw_val: Option<&serde_json::Value>) -> Option<i64> {
    let now_ms = now_epoch_ms();
    let Some(val) = raw_val else {
        return Some(now_ms);
    };
    if val.is_null() {
        return Some(now_ms);
    }
    if val.is_boolean() {
        return None;
    }
    let ts = if let Some(i) = val.as_i64() {
        i
    } else if let Some(u) = val.as_u64() {
        u as i64
    } else if let Some(f) = val.as_f64() {
        f as i64
    } else {
        let s = val.as_str()?;
        if s.trim().is_empty() {
            return Some(now_ms);
        }
        s.trim().parse::<i64>().ok()?
    };

    if ts < (now_ms - MESSAGE_TTL_MS) || ts > (now_ms + AUTH_WINDOW_MS) {
        return None;
    }
    // Preserve exact client-signed timestamp within AUTH_WINDOW_MS so ENVELOPE_V3 signature
    // remains byte-for-byte valid across slight NTP clock drift and multi-hop relay gossip.
    Some(ts)
}

pub fn build_peer_signed_request(
    signing_key: &SigningKey,
    node_pub_hex: &str,
    my_onion: &str,
    method: &str,
    path: &str,
    payload: &serde_json::Value,
) -> (Vec<u8>, Vec<(String, String)>) {
    let body_bytes = serde_json::to_vec(payload).unwrap_or_default();
    let body_hash = hex::encode(Sha256::digest(&body_bytes));
    let ts_ms = next_monotonic_peer_ts_ms().to_string();
    let canonical = format!(
        "ONIONTALK_PEER_V2|{}|{}|{}|{}|{}",
        method.to_ascii_uppercase(),
        path,
        my_onion,
        ts_ms,
        body_hash
    );
    let sig = signing_key.sign(canonical.as_bytes());
    let sig_hex = hex::encode(sig.to_bytes());
    let headers = vec![
        ("Content-Type".to_string(), "application/json".to_string()),
        ("X-Peer-Onion".to_string(), my_onion.to_string()),
        ("X-Peer-Pubkey".to_string(), node_pub_hex.to_string()),
        ("X-Peer-Timestamp".to_string(), ts_ms),
        ("X-Peer-Signature".to_string(), sig_hex),
    ];
    (body_bytes, headers)
}

pub fn is_retired_system_broadcast_envelope(sender: &str, payload: &str, sys_sender_canon: &str) -> bool {
    let sender_raw = sender.trim().to_ascii_lowercase();
    if sender_raw.is_empty() {
        return false;
    }
    let sender_clean = canonical_inbox_key(&sender_raw);
    if !sys_sender_canon.is_empty() && sender_clean == sys_sender_canon {
        return true;
    }
    let p_trim = payload.trim();
    if p_trim.starts_with("__ENC_X25519_CHACHA20_V2__:")
        && (p_trim.len() == 1670 || p_trim.len() == 1178)
        && sender_raw.ends_with(":onion4zr3bsdeaelksemwokl5qmxd5o7jyblf46vc2mfl6cozgw77tqd.onion")
    {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_v3_detached_and_native_reject_ack_lock_id_and_ts_tampering() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pub_hex = hex::encode(sk.verifying_key().to_bytes());
        let sender = format!("@{}:{}", pub_hex, DEFAULT_HOME_ONION);
        let recipient = format!("@{}:{}", "22".repeat(32), DEFAULT_HOME_ONION);
        let eph_hex = "33".repeat(32);
        let nonce_b64 = "AAAAAAAAAAAAAAAA";
        let ct_b64 = "BBBBBBBBBBBBBBBBBBBBBBBB";
        let msg_id = "msg-v3-001";
        let ts_ms = 1_763_600_000_000i64;
        let ack_lock = "44".repeat(32);

        let v2_transcript = format!(
            "ENVELOPE_V2|{}|{}|{}|{}|{}",
            sender, recipient, eph_hex, nonce_b64, ct_b64
        );
        let v2_sig = hex::encode(sk.sign(v2_transcript.as_bytes()).to_bytes());
        let v2_payload = format!(
            "__ENC_X25519_CHACHA20_V2__:{}:{}:{}:{}",
            eph_hex, nonce_b64, ct_b64, v2_sig
        );

        let v3_transcript = format!(
            "ENVELOPE_V3|{}|{}|{}|{}|{}|{}|{}|{}",
            sender, recipient, msg_id, ts_ms, ack_lock, eph_pub_hex_ref(&eph_hex), nonce_b64, ct_b64
        );
        let v3_sig = hex::encode(sk.sign(v3_transcript.as_bytes()).to_bytes());

        // 1. Valid dual-stack V2 + detached v3_sig passes with require_v3_binding = true
        assert!(verify_wire_envelope_signature_bound(
            &sender,
            &recipient,
            msg_id,
            ts_ms,
            &ack_lock,
            &v2_payload,
            Some(&v3_sig),
            true,
            "",
            "",
        )
        .is_ok());

        // 2. Relay/peer swaps ack_lock -> MUST FAIL
        let forged_lock = "55".repeat(32);
        assert!(verify_wire_envelope_signature_bound(
            &sender,
            &recipient,
            msg_id,
            ts_ms,
            &forged_lock,
            &v2_payload,
            Some(&v3_sig),
            true,
            "",
            "",
        )
        .is_err());

        // 3. Relay/peer swaps message id or timestamp -> MUST FAIL
        assert!(verify_wire_envelope_signature_bound(
            &sender,
            &recipient,
            "forged-id-999",
            ts_ms,
            &ack_lock,
            &v2_payload,
            Some(&v3_sig),
            true,
            "",
            "",
        )
        .is_err());
        assert!(verify_wire_envelope_signature_bound(
            &sender,
            &recipient,
            msg_id,
            ts_ms + 1,
            &ack_lock,
            &v2_payload,
            Some(&v3_sig),
            true,
            "",
            "",
        )
        .is_err());

        // 4. Downgrade stripping v3_sig when client_vc >= 72 (require_v3_binding = true) -> MUST FAIL
        assert!(verify_wire_envelope_signature_bound(
            &sender,
            &recipient,
            msg_id,
            ts_ms,
            &ack_lock,
            &v2_payload,
            None,
            true,
            "",
            "",
        )
        .is_err());

        // 5. Native __ENC_X25519_CHACHA20_V3__ wire format passes when untampered and fails on ack_lock mismatch
        let native_v3 = format!(
            "__ENC_X25519_CHACHA20_V3__:{}:{}:{}:{}:{}:{}:{}",
            msg_id, ts_ms, ack_lock, eph_hex, nonce_b64, ct_b64, v3_sig
        );
        assert!(verify_wire_envelope_signature_bound(
            &sender,
            &recipient,
            msg_id,
            ts_ms,
            &ack_lock,
            &native_v3,
            None,
            true,
            "",
            "",
        )
        .is_ok());
        assert!(verify_wire_envelope_signature_bound(
            &sender,
            &recipient,
            msg_id,
            ts_ms,
            &forged_lock,
            &native_v3,
            None,
            true,
            "",
            "",
        )
        .is_err());
    }

    fn eph_pub_hex_ref(s: &str) -> &str {
        s
    }
}
