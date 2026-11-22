use crate::crypto::{
    build_peer_signed_request, constant_time_eq, extract_ed25519_pubkey_hex, is_lower_hex_len,
    is_valid_onion_v3, now_epoch_ms, now_epoch_sec, AUTH_WINDOW_MS,
};
use crate::geo::{DEPRECATED_SEEDS, LEGACY_V1_PEERS};
use crate::AppState;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sha3::Sha3_256;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

pub const OFFLINE_ROOT_CA_PUBKEYS: &[&str] = &[
    "412de9f7e67d42239cc1e6641fad86d8edc90c11558a6758316d1cfa95ddd58a",
    "7d91eda8859db144410318ef7137032bacec4f543f0c75d22f96322a44ac8179",
];

pub const OPERATIONAL_SUB_ISSUER_PUBKEYS: &[&str] = &[
    "f264b56baf2938e6c19103d932bafc0c45ab0b73af472d222355c3d4bb0f941f", // Master BR-Master
    "95e679efef897cb46eff5da9de5622eb03624b98985bfaa21363c96f743acdd2", // Worker BR-Worker
];

pub const MIN_GROUP_DONATION_USD: f64 = 10.0;
pub const GROUPS_PER_10USD_DONATION: i64 = 10;
pub const FOUNDER_PASS_DONOR_TTL_SEC: i64 = 30 * 86400;
pub const FOUNDER_PASS_NODE_TTL_SEC: i64 = 7 * 86400;
pub const MAX_AUTHORITY_TOKEN_TTL_SEC: i64 = 35 * 86400;
pub const MAX_CRL_FUTURE_SKEW_SEC: u64 = 300;

pub fn official_donation_wallet(symbol: &str) -> Option<&'static str> {
    match symbol {
        "BTC" => Some("bc1q0hr95ay33rtazfepg64yddf52q3yqh7ud83cza"),
        "ETH" => Some("0xE69FCE4Fa35CF3bd98F496337b1eA223270b2c92"),
        "SOL" => Some("3E8L1Hdqe7Xk6GCrzHbtY5sReAfLFc9CdwgZxP7qaoHq"),
        _ => None,
    }
}

pub fn extract_founder_pubkey_hex(raw_id: &str) -> Option<String> {
    let clean = raw_id.trim().to_ascii_lowercase();
    if is_lower_hex_len(&clean, 64) {
        return Some(clean);
    }
    extract_ed25519_pubkey_hex(&clean)
}

pub fn issue_signed_founder_pass(
    state: &AppState,
    owner_pubkey_hex: &str,
    tier: &str,
    expires_epoch_sec: i64,
) -> String {
    let clean_pub = owner_pubkey_hex.trim().to_ascii_lowercase();
    let canonical = format!(
        "ONIONTALK_FOUNDER_PASS_V1|{}|{}|{}|{}",
        clean_pub, tier, expires_epoch_sec, state.node_public_key_hex
    );
    let sig = state.node_signing_key.sign(canonical.as_bytes());
    format!(
        "otpass1:{}:{}:{}:{}:{}",
        clean_pub,
        tier,
        expires_epoch_sec,
        state.node_public_key_hex,
        hex::encode(sig.to_bytes())
    )
}

/// Env-gated test/sandbox helper: issues a 30-day `DONOR_10USD` FounderPass ONLY when both
/// `RELAY_SANDBOX_MODE=1` and `ONIONTALK_TEST_GRANT_DONOR_10USD=1` are explicitly enabled.
pub fn sandbox_grant_donor_10usd(state: &AppState, owner_pubkey_hex: &str) -> Option<String> {
    if std::env::var("RELAY_SANDBOX_MODE").as_deref() != Ok("1")
        || std::env::var("ONIONTALK_TEST_GRANT_DONOR_10USD").as_deref() != Ok("1")
    {
        return None;
    }
    let clean_pub = extract_founder_pubkey_hex(owner_pubkey_hex)?;
    if constant_time_eq(clean_pub.as_bytes(), state.node_public_key_hex.as_bytes()) {
        return None;
    }
    let expires_sec = now_epoch_sec() + FOUNDER_PASS_DONOR_TTL_SEC;
    Some(issue_signed_founder_pass(
        state,
        &clean_pub,
        "DONOR_10USD",
        expires_sec,
    ))
}

pub fn build_local_node_claim_voucher(state: &AppState) -> String {
    let my_dom = state
        .get_my_onion_domain()
        .unwrap_or_else(|| "local-relay.onion".to_string())
        .to_ascii_lowercase();
    let ts_sec = now_epoch_sec();
    let canonical = format!(
        "ONIONTALK_NODE_VOUCHER_V1|{}|{}|{}",
        my_dom, ts_sec, state.node_public_key_hex
    );
    let sig = state.node_signing_key.sign(canonical.as_bytes());
    format!(
        "otnode1:{}:{}:{}:{}",
        my_dom,
        ts_sec,
        state.node_public_key_hex,
        hex::encode(sig.to_bytes())
    )
}

pub fn issue_signed_node_certificate(
    state: &AppState,
    node_onion: &str,
    node_pubkey_hex: &str,
    provider_group: &str,
    expires_epoch_sec: i64,
) -> String {
    let clean_onion = node_onion.trim().to_ascii_lowercase();
    let clean_pub = node_pubkey_hex.trim().to_ascii_lowercase();
    let clean_prov = provider_group.trim().to_ascii_uppercase().replace(':', "_");
    let prov = if clean_prov.is_empty() {
        "COMMUNITY"
    } else {
        clean_prov.as_str()
    };
    let canonical = format!(
        "ONIONTALK_NODE_CERT_V1|{}|{}|{}|{}|{}",
        clean_onion, clean_pub, prov, expires_epoch_sec, state.node_public_key_hex
    );
    let sig = state.node_signing_key.sign(canonical.as_bytes());
    format!(
        "otnode1:{}:{}:{}:{}:{}:{}",
        clean_onion,
        clean_pub,
        prov,
        expires_epoch_sec,
        state.node_public_key_hex,
        hex::encode(sig.to_bytes())
    )
}

pub fn verify_node_certificate(
    state: &AppState,
    node_onion: &str,
    node_pubkey_hex: &str,
    cert_token: &str,
) -> bool {
    let clean_onion = node_onion.trim().to_ascii_lowercase();
    let clean_pub = node_pubkey_hex.trim().to_ascii_lowercase();
    if !is_valid_onion_v3(&clean_onion) || !is_lower_hex_len(&clean_pub, 64) {
        return false;
    }
    let clean_tok = cert_token.trim();
    if !clean_tok.starts_with("otnode1:") {
        return false;
    }
    let parts: Vec<&str> = clean_tok.split(':').collect();
    if parts.len() != 7 {
        return false;
    }
    let tok_onion = parts[1].trim().to_ascii_lowercase();
    let tok_pub = parts[2].trim().to_ascii_lowercase();
    let prov = parts[3].trim().to_ascii_uppercase();
    let Ok(expires_sec) = parts[4].trim().parse::<i64>() else {
        return false;
    };
    let issuer_pub = parts[5].trim().to_ascii_lowercase();
    let sig_hex = parts[6].trim().to_ascii_lowercase();

    if tok_onion != clean_onion || tok_pub != clean_pub || prov.is_empty() || issuer_pub == tok_pub
    {
        return false;
    }
    let now_sec = now_epoch_sec();
    if expires_sec <= now_sec || expires_sec > now_sec + MAX_AUTHORITY_TOKEN_TTL_SEC {
        return false;
    }
    if !state.is_trusted_authority_issuer(&issuer_pub) || !is_lower_hex_len(&sig_hex, 128) {
        return false;
    }
    let Ok(pk_bytes) = hex::decode(&issuer_pub) else {
        return false;
    };
    let Ok(pk_arr) = <[u8; 32]>::try_from(pk_bytes.as_slice()) else {
        return false;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&pk_arr) else {
        return false;
    };
    let Ok(sig_bytes) = hex::decode(&sig_hex) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(&sig_bytes) else {
        return false;
    };
    let canonical = format!(
        "ONIONTALK_NODE_CERT_V1|{}|{}|{}|{}|{}",
        tok_onion, tok_pub, prov, expires_sec, issuer_pub
    );
    verifying_key.verify(canonical.as_bytes(), &sig).is_ok()
}

pub(crate) fn verify_and_apply_authority_crl_internal(
    state: &AppState,
    crl_token: &str,
    persist_after: bool,
) -> Result<u64, &'static str> {
    let clean_tok = crl_token.trim();
    if clean_tok.is_empty() || clean_tok.len() > 16_384 || !clean_tok.starts_with("otcrl1:") {
        return Err("Malformed otcrl1 token format");
    }
    let parts: Vec<&str> = clean_tok.split(':').collect();
    if parts.len() != 6 || parts[0] != "otcrl1" {
        return Err("Malformed otcrl1 token structure (expected 6 colon-delimited fields)");
    }
    let Ok(epoch_sec) = parts[1].trim().parse::<u64>() else {
        return Err("Invalid CRL epoch_sec");
    };
    if epoch_sec == 0 {
        return Err("CRL epoch_sec must be > 0");
    }
    let now_u64 = now_epoch_sec().max(0) as u64;
    if epoch_sec > now_u64.saturating_add(MAX_CRL_FUTURE_SKEW_SEC) {
        return Err("CRL epoch_sec exceeds maximum future clock skew (300s)");
    }

    let revoked_csv = parts[2].trim().to_ascii_lowercase();
    let delegated_csv = parts[3].trim().to_ascii_lowercase();
    let root_pubkey_hex = parts[4].trim().to_ascii_lowercase();
    let sig_hex = parts[5].trim().to_ascii_lowercase();

    if !is_lower_hex_len(&root_pubkey_hex, 64) || !is_lower_hex_len(&sig_hex, 128) {
        return Err("Invalid Offline Root CA pubkey or signature hex encoding");
    }

    let is_pinned_root = OFFLINE_ROOT_CA_PUBKEYS.contains(&root_pubkey_hex.as_str()) || {
        #[cfg(test)]
        {
            state
                .test_root_ca_pubkey
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .as_deref()
                == Some(root_pubkey_hex.as_str())
        }
        #[cfg(not(test))]
        {
            false
        }
    };
    if !is_pinned_root {
        return Err("Signer is not an authorized Offline Root CA");
    }

    let mut new_revoked = HashSet::new();
    if !revoked_csv.is_empty() {
        for raw_pk in revoked_csv.split(',') {
            let pk = raw_pk.trim();
            if !is_lower_hex_len(pk, 64) || new_revoked.len() >= 256 {
                return Err("Invalid Ed25519 pubkey hex in revoked_csv");
            }
            new_revoked.insert(pk.to_string());
        }
    }

    let mut new_delegated = HashSet::new();
    if !delegated_csv.is_empty() {
        for raw_pk in delegated_csv.split(',') {
            let pk = raw_pk.trim();
            if !is_lower_hex_len(pk, 64) || new_delegated.len() >= 256 {
                return Err("Invalid Ed25519 pubkey hex in delegated_csv");
            }
            let Ok(pk_bytes) = hex::decode(pk) else {
                return Err("Invalid Ed25519 pubkey hex in delegated_csv");
            };
            let Ok(pk_arr) = <[u8; 32]>::try_from(pk_bytes.as_slice()) else {
                return Err("Invalid Ed25519 pubkey length in delegated_csv");
            };
            if VerifyingKey::from_bytes(&pk_arr).is_err() {
                return Err("Invalid Ed25519 curve point in delegated_csv");
            }
            if !new_revoked.contains(pk) {
                new_delegated.insert(pk.to_string());
            }
        }
    }

    let canonical = format!(
        "ONIONTALK_AUTHORITY_CRL_V1|{}|{}|{}|{}",
        epoch_sec, revoked_csv, delegated_csv, root_pubkey_hex
    );
    let Ok(root_bytes) = hex::decode(&root_pubkey_hex) else {
        return Err("Invalid Offline Root CA pubkey encoding");
    };
    let Ok(root_arr) = <[u8; 32]>::try_from(root_bytes.as_slice()) else {
        return Err("Invalid Offline Root CA pubkey length");
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&root_arr) else {
        return Err("Invalid Offline Root CA curve point");
    };
    let Ok(sig_bytes) = hex::decode(&sig_hex) else {
        return Err("Invalid CRL Ed25519 signature hex");
    };
    let Ok(sig) = Signature::from_slice(&sig_bytes) else {
        return Err("Invalid CRL Ed25519 signature length");
    };
    if verifying_key.verify(canonical.as_bytes(), &sig).is_err() {
        return Err("Invalid Offline Root CA Ed25519 signature on otcrl1 token");
    }

    let normalized_crl = format!(
        "otcrl1:{}:{}:{}:{}:{}",
        epoch_sec, revoked_csv, delegated_csv, root_pubkey_hex, sig_hex
    );

    {
        let _write_guard = state
            .authority_crl_write_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let current_epoch = state.authority_crl_epoch.load(Ordering::SeqCst);
        if epoch_sec <= current_epoch {
            return Err("Stale or replayed CRL epoch_sec (must be > current_crl_epoch)");
        }
        *state
            .revoked_authority_pubkeys
            .write()
            .unwrap_or_else(|e| e.into_inner()) = new_revoked;
        *state
            .delegated_authority_pubkeys
            .write()
            .unwrap_or_else(|e| e.into_inner()) = new_delegated;
        *state
            .latest_authority_crl_token
            .write()
            .unwrap_or_else(|e| e.into_inner()) = Some(normalized_crl);
        state.authority_crl_epoch.store(epoch_sec, Ordering::SeqCst);
    }

    if persist_after && !state.state_snapshot_file.is_empty() {
        state.save_persistent_files();
    }

    Ok(epoch_sec)
}

pub fn verify_and_apply_authority_crl(
    state: &AppState,
    crl_token: &str,
) -> Result<u64, &'static str> {
    verify_and_apply_authority_crl_internal(state, crl_token, true)
}

fn spawn_gossip_authority_crl(state: Arc<AppState>, crl_token: String) {
    if std::env::var("DISABLE_BOOTSTRAP_LOOP").as_deref() == Ok("1") || state.known_peers.is_empty()
    {
        return;
    }
    tokio::spawn(async move {
        let Some(my_dom) = state.get_my_onion_domain() else {
            return;
        };
        let peers: Vec<String> = state
            .known_peers
            .iter()
            .map(|e| e.key().clone())
            .filter(|p| {
                p != &my_dom
                    && !LEGACY_V1_PEERS.contains(&p.as_str())
                    && !DEPRECATED_SEEDS.contains(&p.as_str())
            })
            .collect();
        let payload = json!({ "crl": crl_token });
        let endpoint = "/api/v1/authority/crl";
        for peer in peers {
            let st = state.clone();
            let my_onion = my_dom.clone();
            let body_json = payload.clone();
            tokio::spawn(async move {
                let (bytes, headers) = build_peer_signed_request(
                    &st.node_signing_key,
                    &st.node_public_key_hex,
                    &my_onion,
                    "POST",
                    endpoint,
                    &body_json,
                );
                let _ = st.post_to_peer(&peer, endpoint, bytes, headers, 12).await;
            });
        }
    });
}

pub async fn handle_get_authority_crl(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut revoked: Vec<String> = state
        .revoked_authority_pubkeys
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .cloned()
        .collect();
    revoked.sort();
    let mut delegated: Vec<String> = state
        .delegated_authority_pubkeys
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .cloned()
        .collect();
    delegated.sort();
    let latest_crl = state.get_latest_authority_crl();
    (
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "epoch": state.authority_crl_epoch.load(Ordering::SeqCst),
            "authority_crl": latest_crl,
            "crl": latest_crl,
            "offline_root_ca_pubkeys": OFFLINE_ROOT_CA_PUBKEYS,
            "revoked_pubkeys": revoked,
            "delegated_pubkeys": delegated,
            "active_trusted_issuers": state.get_active_trusted_issuers(),
        })),
    )
}

pub async fn handle_post_authority_crl(
    State(state): State<Arc<AppState>>,
    Json(data): Json<Value>,
) -> impl IntoResponse {
    let raw_crl = data
        .get("crl")
        .or_else(|| data.get("authority_crl"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if raw_crl.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Missing crl field (expected otcrl1:...)"})),
        );
    }
    match verify_and_apply_authority_crl(&state, raw_crl) {
        Ok(epoch) => {
            let latest = state.get_latest_authority_crl();
            if let Some(ref tok) = latest {
                spawn_gossip_authority_crl(state.clone(), tok.clone());
            }
            let mut revoked: Vec<String> = state
                .revoked_authority_pubkeys
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .cloned()
                .collect();
            revoked.sort();
            let mut delegated: Vec<String> = state
                .delegated_authority_pubkeys
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .cloned()
                .collect();
            delegated.sort();
            (
                StatusCode::OK,
                Json(json!({
                    "status": "applied",
                    "epoch": epoch,
                    "authority_crl": latest,
                    "revoked_pubkeys": revoked,
                    "delegated_pubkeys": delegated,
                })),
            )
        }
        Err(err_msg) => {
            let status = if err_msg.starts_with("Malformed") {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::FORBIDDEN
            };
            (status, Json(json!({"error": err_msg})))
        }
    }
}

fn verify_founder_endpoint_auth(
    headers: &HeaderMap,
    target_pub_hex: &str,
    raw_user_id: &str,
) -> Result<(), &'static str> {
    if !is_lower_hex_len(target_pub_hex, 64) {
        return Err("Invalid target Ed25519 public key");
    }

    let raw_ts = headers
        .get("x-oniontalk-timestamp")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim();
    let sig_hex = headers
        .get("x-oniontalk-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();

    if raw_ts.is_empty() || !is_lower_hex_len(&sig_hex, 128) {
        return Err("Missing or malformed Ed25519 authentication headers (X-OnionTalk-Timestamp / X-OnionTalk-Signature)");
    }

    let Ok(ts_ms) = raw_ts.parse::<i64>() else {
        return Err("Invalid X-OnionTalk-Timestamp");
    };
    if (now_epoch_ms() - ts_ms).abs() > AUTH_WINDOW_MS {
        return Err("Authentication timestamp outside replay window");
    }

    let Ok(sig_bytes) = hex::decode(&sig_hex) else {
        return Err("Invalid signature hex");
    };
    let Ok(sig) = Signature::from_slice(&sig_bytes) else {
        return Err("Invalid signature length");
    };

    let Ok(pk_bytes) = hex::decode(target_pub_hex) else {
        return Err("Invalid target Ed25519 key encoding");
    };
    let Ok(pk_arr) = <[u8; 32]>::try_from(pk_bytes.as_slice()) else {
        return Err("Invalid target Ed25519 key length");
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&pk_arr) else {
        return Err("Invalid target Ed25519 public key point");
    };

    let raw_clean = raw_user_id.trim().to_ascii_lowercase();
    let mut uid_variants = vec![format!("@{}", target_pub_hex), target_pub_hex.to_string()];
    if !raw_clean.is_empty()
        && !uid_variants.contains(&raw_clean)
        && extract_founder_pubkey_hex(&raw_clean).as_deref() == Some(target_pub_hex)
    {
        uid_variants.push(raw_clean);
    }

    for uid_v in &uid_variants {
        for sc in ["FOUNDER", "SEND", "INBOX"] {
            let m1 = format!("ONIONTALK_AUTH_V2|{}|{}|{}", sc, uid_v, ts_ms);
            if verifying_key.verify(m1.as_bytes(), &sig).is_ok() {
                return Ok(());
            }
            let m2 = format!("{}|{}|{}", sc, uid_v, ts_ms);
            if verifying_key.verify(m2.as_bytes(), &sig).is_ok() {
                return Ok(());
            }
        }
    }
    Err("Invalid Ed25519 signature for Founder operation")
}

pub fn parse_tier_max_groups(tier: &str) -> i64 {
    let t = tier.trim().to_ascii_uppercase();
    if t == "ROOT_ADMIN" {
        return 0;
    }
    if t == "DONOR_10USD" {
        return GROUPS_PER_10USD_DONATION;
    }
    if let Some(rest) = t.strip_prefix("DONOR_10USD_") {
        if let Ok(v) = rest.parse::<i64>() {
            if (1..=100).contains(&v) {
                return v;
            }
        }
        return 0;
    }
    if t == "RELAY_NODE" {
        return 1;
    }
    if let Some(rest) = t.strip_prefix("RELAY_NODE_") {
        if let Ok(v) = rest.parse::<i64>() {
            if (1..=20).contains(&v) {
                return v;
            }
        }
        return 0;
    }
    0
}

async fn check_single_operator_node_alive(
    state: &AppState,
    node_pub_hex: &str,
    info: &Value,
) -> bool {
    if info.get("stopped").and_then(|v| v.as_bool()).unwrap_or(false) {
        return false;
    }
    let node_onion = info
        .get("onion")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let probe_url = info
        .get("probe_url")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let my_dom = state
        .get_my_onion_domain()
        .unwrap_or_else(|| "local-relay.onion".to_string())
        .to_ascii_lowercase();

    if !probe_url.is_empty()
        && std::env::var("SANDBOX_ALLOW_TEST_TX").as_deref() == Ok("1")
        && probe_url.starts_with("http://127.0.0.1:")
        && probe_url.ends_with("/health")
    {
        if let Ok(r) = state.fast_client.get(probe_url).send().await {
            if r.status() == StatusCode::OK {
                if let Ok(body) = r.json::<Value>().await {
                    let remote_pk = body
                        .get("node_pubkey")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .trim()
                        .to_ascii_lowercase();
                    let status_ok = body.get("status").and_then(|v| v.as_str()) == Some("healthy");
                    return status_ok
                        && constant_time_eq(remote_pk.as_bytes(), node_pub_hex.as_bytes());
                }
            }
        }
        return false;
    }

    if constant_time_eq(node_pub_hex.as_bytes(), state.node_public_key_hex.as_bytes())
        && (node_onion == my_dom || node_onion == "local-relay.onion")
    {
        return !info.get("stopped").and_then(|v| v.as_bool()).unwrap_or(false);
    }

    if is_valid_onion_v3(&node_onion) {
        if state.known_peers.contains_key(&node_onion)
            && state
                .peer_online_state
                .get(&node_onion)
                .map(|v| v.value() == "ONLINE")
                .unwrap_or(false)
        {
            if let Some(pinned_pk) = state.peer_pubkeys.get(&node_onion) {
                if constant_time_eq(pinned_pk.value().as_bytes(), node_pub_hex.as_bytes()) {
                    return true;
                }
            }
        }
        let url = format!("http://{}/health", node_onion);
        if let Ok(res) = state
            .tor_client
            .get(&url)
            .timeout(std::time::Duration::from_secs(8))
            .send()
            .await
        {
            if res.status() == StatusCode::OK {
                if let Ok(body) = res.json::<Value>().await {
                    let remote_pk = body
                        .get("node_pubkey")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .trim()
                        .to_ascii_lowercase();
                    if body.get("status").and_then(|v| v.as_str()) == Some("healthy")
                        && constant_time_eq(remote_pk.as_bytes(), node_pub_hex.as_bytes())
                    {
                        return true;
                    }
                }
            }
        }
    }
    false
}

async fn count_active_operator_nodes(state: &AppState, user_pub: &str) -> i64 {
    let nodes_snapshot: Vec<(String, Value)> = state
        .founder_operator_nodes
        .get(user_pub)
        .map(|entry| {
            entry
                .value()
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        })
        .unwrap_or_default();
    let mut active = 0i64;
    for (npub, ninfo) in nodes_snapshot {
        if check_single_operator_node_alive(state, &npub, &ninfo).await {
            active += 1;
        }
    }
    active
}

pub async fn handle_node_claim_token(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let host_hdr = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    let host_only = host_hdr.split(':').next().unwrap_or("");
    let has_proxy_hdr = [
        "x-forwarded-for",
        "x-real-ip",
        "forwarded",
        "via",
        "cf-connecting-ip",
    ]
    .iter()
    .any(|h| headers.contains_key(*h));
    let ip = addr.ip();
    if has_proxy_hdr
        || !ip.is_loopback()
        || host_only.ends_with(".onion")
        || (host_only != "127.0.0.1" && host_only != "localhost")
    {
        state.inc_unauthenticated();
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Forbidden: Node claim voucher is restricted to local container CLI"})),
        );
    }

    if !state.relay_admin_token.is_empty() {
        let admin_hdr = headers
            .get("x-admin-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .trim();
        if !constant_time_eq(admin_hdr.as_bytes(), state.relay_admin_token.as_bytes()) {
            state.inc_unauthenticated();
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Unauthorized: Valid X-Admin-Token required"})),
            );
        }
    }

    let voucher = build_local_node_claim_voucher(&state);
    (
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "node_onion": state.get_my_onion_domain(),
            "node_pubkey": state.node_public_key_hex,
            "voucher": voucher,
            "claim_voucher": voucher,
        })),
    )
}

pub async fn handle_founder_quote(
    State(state): State<Arc<AppState>>,
    Json(data): Json<Value>,
) -> impl IntoResponse {
    let user_id = data
        .get("user_id")
        .or_else(|| data.get("user_crypto_id"))
        .or_else(|| data.get("owner_pubkey_hex"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let symbol = data
        .get("symbol")
        .and_then(|v| v.as_str())
        .unwrap_or("SOL")
        .trim()
        .to_ascii_uppercase();
    let Some(wallet) = official_donation_wallet(&symbol) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Unsupported symbol (use BTC, ETH, or SOL)"})),
        );
    };
    let Some(user_pub) = extract_founder_pubkey_hex(&user_id) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid user Crypto ID"})),
        );
    };

    let spot_usd = match symbol.as_str() {
        "BTC" => 95000.0,
        "ETH" => 2800.0,
        _ => 180.0,
    };
    let base_amount = MIN_GROUP_DONATION_USD / spot_usd;
    let hour_bucket = now_epoch_sec() / 3600;
    let fp_digest = Sha256::digest(
        format!("OT_DUST_FP_V1|{}|{}|{}", user_pub, symbol, hour_bucket).as_bytes(),
    );
    let tail_int = (((fp_digest[0] as u32) << 8 | (fp_digest[1] as u32)) % 8999) + 1001;
    let exact_amount_str = match symbol.as_str() {
        "BTC" => format!("{:.4}{:04}", (base_amount * 10000.0).round() / 10000.0, tail_int),
        "ETH" => format!("{:.3}{:04}", (base_amount * 1000.0).round() / 1000.0, tail_int),
        _ => format!("{:.2}{:04}", (base_amount * 100.0).round() / 100.0, tail_int),
    };
    let quote_msg = format!(
        "OT_QUOTE_V1|{}|{}|{}|{}",
        user_pub, symbol, exact_amount_str, hour_bucket
    );
    let quote_sig = hex::encode(state.node_signing_key.sign(quote_msg.as_bytes()).to_bytes());
    (
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "symbol": symbol,
            "usd_amount": MIN_GROUP_DONATION_USD,
            "spot_usd": spot_usd,
            "wallet_address": wallet,
            "exact_crypto_amount": exact_amount_str,
            "exact_amount": exact_amount_str,
            "expected_amount": exact_amount_str,
            "dust_fingerprint": format!("{:04}", tail_int),
            "quote_token": format!("otquote1:{}:{}:{}:{}", symbol, exact_amount_str, hour_bucket, quote_sig),
        })),
    )
}

pub async fn handle_founder_claim_crypto(
    State(state): State<Arc<AppState>>,
    Json(data): Json<Value>,
) -> impl IntoResponse {
    let user_id = data
        .get("user_id")
        .or_else(|| data.get("user_crypto_id"))
        .or_else(|| data.get("owner_pubkey_hex"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let txid = data
        .get("txid")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let quote_token = data
        .get("quote_token")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();

    let Some(user_pub) = extract_founder_pubkey_hex(&user_id) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid user Crypto ID"})),
        );
    };

    if txid.len() < 12 || !quote_token.starts_with("otquote1:") {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Missing or invalid TXID or quote_token"})),
        );
    }
    let q_parts: Vec<&str> = quote_token.split(':').collect();
    if q_parts.len() != 5 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Malformed quote_token"})),
        );
    }
    let (symbol, exact_amount_str, hour_str, quote_sig) =
        (q_parts[1], q_parts[2], q_parts[3], q_parts[4]);
    let Ok(hour_bucket) = hour_str.parse::<i64>() else {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Invalid quote_token hour_bucket"})),
        );
    };
    let quote_msg = format!(
        "OT_QUOTE_V1|{}|{}|{}|{}",
        user_pub, symbol, exact_amount_str, hour_bucket
    );
    let expected_sha256 = hex::encode(Sha256::digest(quote_msg.as_bytes()));
    let fp_digest = Sha256::digest(
        format!("OT_DUST_FP_V1|{}|{}|{}", user_pub, symbol, hour_bucket).as_bytes(),
    );
    let expected_tail = format!(
        "{:04}",
        (((fp_digest[0] as u32) << 8 | (fp_digest[1] as u32)) % 8999) + 1001
    );

    let sig_valid = if constant_time_eq(
        quote_sig.to_ascii_lowercase().as_bytes(),
        expected_sha256.as_bytes(),
    ) && exact_amount_str.ends_with(&expected_tail)
    {
        true
    } else if let Ok(sig_bytes) = hex::decode(quote_sig) {
        if let Ok(sig) = Signature::from_slice(&sig_bytes) {
            state
                .node_signing_key
                .verifying_key()
                .verify(quote_msg.as_bytes(), &sig)
                .is_ok()
        } else {
            false
        }
    } else {
        false
    };
    if !sig_valid {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Invalid or tampered quote_token signature"})),
        );
    }

    let nullifier = hex::encode(Sha3_256::digest(
        format!(
            "ONIONTALK_TX_NULLIFIER_V1|{}|{}",
            symbol,
            txid.to_ascii_lowercase()
        )
        .as_bytes(),
    ));
    if state.spent_tx_nullifiers.contains_key(&nullifier) {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": "This transaction has already been claimed (Nullifier spent)"})),
        );
    }

    let sandbox_env_enabled = std::env::var("SANDBOX_ALLOW_TEST_TX").as_deref() == Ok("1")
        || (std::env::var("RELAY_SANDBOX_MODE").as_deref() == Ok("1")
            && std::env::var("ONIONTALK_TEST_GRANT_DONOR_10USD").as_deref() == Ok("1"));
    let sandbox_ok = sandbox_env_enabled
        && (txid.to_ascii_lowercase().starts_with("sandbox_tx_")
            || txid.to_ascii_lowercase().starts_with("sandbox_test_tx_"));
    if !sandbox_ok {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Transaction not confirmed on-chain yet"})),
        );
    }

    state.spent_tx_nullifiers.insert(nullifier, ());
    state.revoked_founders.remove(&user_pub);
    let new_quota = {
        let mut entry = state.founder_donor_quotas.entry(user_pub.clone()).or_insert(0);
        *entry = (*entry + GROUPS_PER_10USD_DONATION).min(100);
        *entry
    };
    let tier_str = if new_quota == GROUPS_PER_10USD_DONATION {
        "DONOR_10USD".to_string()
    } else {
        format!("DONOR_10USD_{}", new_quota)
    };
    let expires_sec = now_epoch_sec() + FOUNDER_PASS_DONOR_TTL_SEC;
    let founder_pass = issue_signed_founder_pass(&state, &user_pub, &tier_str, expires_sec);
    (
        StatusCode::OK,
        Json(json!({
            "status": "verified",
            "tier": tier_str,
            "max_groups": new_quota,
            "expires_at": expires_sec,
            "founder_pass": founder_pass,
        })),
    )
}

pub async fn handle_founder_claim_node(
    State(state): State<Arc<AppState>>,
    Json(data): Json<Value>,
) -> impl IntoResponse {
    let user_id = data
        .get("user_id")
        .or_else(|| data.get("user_crypto_id"))
        .or_else(|| data.get("owner_pubkey_hex"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let voucher = data
        .get("voucher")
        .or_else(|| data.get("claim_voucher"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let probe_url = data
        .get("probe_url")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();

    let Some(user_pub) = extract_founder_pubkey_hex(&user_id) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid user Crypto ID"})),
        );
    };

    let v_parts: Vec<&str> = voucher.split(':').collect();
    if v_parts.len() != 5 || v_parts[0] != "otnode1" {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid node operator voucher format (expected otnode1:...)"})),
        );
    }
    let node_onion = v_parts[1].trim().to_ascii_lowercase();
    let ts_str = v_parts[2].trim();
    let node_pub_hex = v_parts[3].trim().to_ascii_lowercase();
    let sig_hex = v_parts[4].trim().to_ascii_lowercase();
    if !is_lower_hex_len(&node_pub_hex, 64) || !is_lower_hex_len(&sig_hex, 128) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Malformed node public key or signature in voucher"})),
        );
    }
    let Ok(ts_sec) = ts_str.parse::<i64>() else {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Invalid voucher timestamp"})),
        );
    };
    if (now_epoch_sec() - ts_sec).abs() > 3600 {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Node operator voucher expired (1-hour validity window)"})),
        );
    }
    let canonical = format!(
        "ONIONTALK_NODE_VOUCHER_V1|{}|{}|{}",
        node_onion, ts_sec, node_pub_hex
    );
    let sig_ok = (|| -> Option<bool> {
        let pk_bytes = hex::decode(&node_pub_hex).ok()?;
        let pk_arr = <[u8; 32]>::try_from(pk_bytes.as_slice()).ok()?;
        let vk = VerifyingKey::from_bytes(&pk_arr).ok()?;
        let sb = hex::decode(&sig_hex).ok()?;
        let sig = Signature::from_slice(&sb).ok()?;
        Some(vk.verify(canonical.as_bytes(), &sig).is_ok())
    })()
    .unwrap_or(false);
    if !sig_ok {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Invalid Ed25519 signature on node operator voucher"})),
        );
    }
    if constant_time_eq(node_pub_hex.as_bytes(), user_pub.as_bytes()) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Self-signed user identity cannot act as a relay node voucher"})),
        );
    }

    let v_nullifier = hex::encode(Sha3_256::digest(
        format!(
            "ONIONTALK_NODE_VOUCHER_NULLIFIER_V1|{}|{}|{}",
            node_pub_hex, ts_sec, sig_hex
        )
        .as_bytes(),
    ));
    if state.spent_tx_nullifiers.contains_key(&v_nullifier) {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": "This node operator voucher has already been claimed (Nullifier spent)"})),
        );
    }

    let safe_probe = if !probe_url.is_empty()
        && std::env::var("SANDBOX_ALLOW_TEST_TX").as_deref() == Ok("1")
        && probe_url.starts_with("http://127.0.0.1:")
        && probe_url.ends_with("/health")
    {
        probe_url
    } else {
        ""
    };
    let candidate_info = json!({
        "onion": node_onion,
        "probe_url": safe_probe,
        "claimed_at": now_epoch_sec(),
        "stopped": false,
    });
    if !check_single_operator_node_alive(&state, &node_pub_hex, &candidate_info).await {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("Relay node {} is not verified/healthy on the Tor mesh", node_onion)})),
        );
    }

    state.spent_tx_nullifiers.insert(v_nullifier, ());
    state.revoked_founders.remove(&user_pub);
    state
        .founder_operator_nodes
        .entry(user_pub.clone())
        .or_default()
        .insert(node_pub_hex, candidate_info);

    let active_nodes = count_active_operator_nodes(&state, &user_pub).await;
    if active_nodes <= 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "No active relay nodes verified for this operator"})),
        );
    }
    let capped_nodes = active_nodes.min(20);
    let tier_str = format!("RELAY_NODE_{}", capped_nodes);
    let expires_sec = now_epoch_sec() + FOUNDER_PASS_NODE_TTL_SEC;
    let founder_pass = issue_signed_founder_pass(&state, &user_pub, &tier_str, expires_sec);
    let donor_bonus = state
        .founder_donor_quotas
        .get(&user_pub)
        .map(|v| *v.value())
        .unwrap_or(0)
        .min(100);
    (
        StatusCode::OK,
        Json(json!({
            "status": "verified",
            "tier": tier_str,
            "active_nodes": capped_nodes,
            "max_groups": capped_nodes + donor_bonus,
            "expires_at": expires_sec,
            "founder_pass": founder_pass,
        })),
    )
}

pub async fn handle_founder_verify_allowance(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(data): Json<Value>,
) -> impl IntoResponse {
    let user_id = data
        .get("user_id")
        .or_else(|| data.get("user_crypto_id"))
        .or_else(|| data.get("owner_pubkey_hex"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let pass_token = data
        .get("founder_pass")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let current_groups_client = data
        .get("current_groups_count")
        .and_then(|v| v.as_i64())
        .unwrap_or(0)
        .max(0);
    let group_id_req = data
        .get("group_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();

    let Some(user_pub) = extract_founder_pubkey_hex(&user_id) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"allowed": false, "error": "Invalid user Crypto ID"})),
        );
    };
    if let Err(err_msg) = verify_founder_endpoint_auth(&headers, &user_pub, &user_id) {
        state.inc_unauthenticated();
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"allowed": false, "error": err_msg})),
        );
    }

    if state.revoked_founders.contains_key(&user_pub) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "allowed": false,
                "revoked": true,
                "active_nodes": 0,
                "max_groups": 0,
                "error": "Permissão de criação de grupos revogada.",
            })),
        );
    }

    let parts: Vec<&str> = pass_token.split(':').collect();
    if parts.len() != 6 || parts[0] != "otpass1" {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"allowed": false, "revoked": true, "error": "FounderPass ausente ou inválido"})),
        );
    }
    let token_owner = parts[1].trim().to_ascii_lowercase();
    let tier = parts[2].trim();
    let expires_str = parts[3].trim();
    let issuer_pub = parts[4].trim().to_ascii_lowercase();
    let sig_hex = parts[5].trim().to_ascii_lowercase();

    if token_owner != user_pub || token_owner == issuer_pub {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"allowed": false, "revoked": true, "error": "FounderPass não pertence a este usuário"})),
        );
    }
    let Ok(expires_sec) = expires_str.parse::<i64>() else {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"allowed": false, "revoked": true, "error": "Assinatura FounderPass inválida"})),
        );
    };
    let now_sec = now_epoch_sec();
    if expires_sec <= now_sec || expires_sec > now_sec + MAX_AUTHORITY_TOKEN_TTL_SEC {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"allowed": false, "revoked": true, "error": "FounderPass expirado ou fora da janela máxima de validade"})),
        );
    }
    if !state.is_trusted_authority_issuer(&issuer_pub) || !is_lower_hex_len(&sig_hex, 128) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"allowed": false, "revoked": true, "error": "Emissor de FounderPass revogado ou não autorizado"})),
        );
    }

    let canonical = format!(
        "ONIONTALK_FOUNDER_PASS_V1|{}|{}|{}|{}",
        token_owner, tier, expires_sec, issuer_pub
    );
    let sig_ok = (|| -> Option<bool> {
        let pk_bytes = hex::decode(&issuer_pub).ok()?;
        let pk_arr = <[u8; 32]>::try_from(pk_bytes.as_slice()).ok()?;
        let vk = VerifyingKey::from_bytes(&pk_arr).ok()?;
        let sb = hex::decode(&sig_hex).ok()?;
        let sig = Signature::from_slice(&sb).ok()?;
        Some(vk.verify(canonical.as_bytes(), &sig).is_ok())
    })()
    .unwrap_or(false);
    if !sig_ok {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"allowed": false, "revoked": true, "error": "Assinatura FounderPass inválida"})),
        );
    }

    let token_max = parse_tier_max_groups(tier);
    if token_max <= 0 {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"allowed": false, "revoked": true, "error": "Tier de FounderPass desconhecido ou revogado"})),
        );
    }

    let server_groups_count = state
        .founder_created_groups
        .get(&user_pub)
        .map(|set| {
            let len = set.value().len() as i64;
            if !group_id_req.is_empty() && set.value().contains(&group_id_req) {
                (len - 1).max(0)
            } else {
                len
            }
        })
        .unwrap_or(0);
    let current_groups = current_groups_client.max(server_groups_count);

    if tier.starts_with("RELAY_NODE") {
        let active_nodes = count_active_operator_nodes(&state, &user_pub).await.min(20);
        let donor_bonus = state
            .founder_donor_quotas
            .get(&user_pub)
            .map(|v| *v.value())
            .unwrap_or(0)
            .min(100);
        if active_nodes <= 0 && donor_bonus <= 0 {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "allowed": false,
                    "revoked": true,
                    "active_nodes": 0,
                    "max_groups": 0,
                    "error": "Nó Relay offline/inativo: se deixar de hospedar o nó, não pode mais criar grupos.",
                })),
            );
        }
        let effective_max = active_nodes + donor_bonus;
        if current_groups >= effective_max {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "allowed": false,
                    "revoked": false,
                    "active_nodes": active_nodes,
                    "max_groups": effective_max,
                    "error": format!("Limite atingido ({}/{} grupos): você possui {} nó(s) ativo(s).", current_groups, effective_max, active_nodes),
                })),
            );
        }
        if !group_id_req.is_empty() {
            state
                .founder_created_groups
                .entry(user_pub.clone())
                .or_default()
                .insert(group_id_req);
        }
        let new_tier = if active_nodes > 0 {
            format!("RELAY_NODE_{}", active_nodes)
        } else if donor_bonus == GROUPS_PER_10USD_DONATION {
            "DONOR_10USD".to_string()
        } else {
            format!("DONOR_10USD_{}", donor_bonus)
        };
        let ttl = if active_nodes > 0 {
            FOUNDER_PASS_NODE_TTL_SEC
        } else {
            FOUNDER_PASS_DONOR_TTL_SEC
        };
        let (refreshed_pass, refreshed_exp) =
            if state.is_trusted_authority_issuer(&state.node_public_key_hex) {
                let exp = now_epoch_sec() + ttl;
                (
                    issue_signed_founder_pass(&state, &user_pub, &new_tier, exp),
                    exp,
                )
            } else {
                (pass_token.to_string(), expires_sec)
            };
        return (
            StatusCode::OK,
            Json(json!({
                "allowed": true,
                "revoked": false,
                "tier": new_tier,
                "active_nodes": active_nodes,
                "max_groups": effective_max,
                "expires_at": refreshed_exp,
                "founder_pass": refreshed_pass,
            })),
        );
    }

    if tier.starts_with("DONOR_10USD") {
        let donor_q = state
            .founder_donor_quotas
            .get(&user_pub)
            .map(|v| *v.value())
            .unwrap_or(token_max)
            .min(100);
        let effective_max = donor_q.max(token_max).min(100);
        if current_groups >= effective_max {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "allowed": false,
                    "revoked": false,
                    "max_groups": effective_max,
                    "error": format!("Limite de {} grupos atingido para sua doação de $10 USD ({}/{}).", effective_max, current_groups, effective_max),
                })),
            );
        }
        if !group_id_req.is_empty() {
            state
                .founder_created_groups
                .entry(user_pub.clone())
                .or_default()
                .insert(group_id_req);
        }
        let refreshed_tier = if effective_max == GROUPS_PER_10USD_DONATION {
            "DONOR_10USD".to_string()
        } else {
            format!("DONOR_10USD_{}", effective_max)
        };
        let (refreshed_pass, refreshed_exp) =
            if state.is_trusted_authority_issuer(&state.node_public_key_hex) {
                let exp = now_epoch_sec() + FOUNDER_PASS_DONOR_TTL_SEC;
                (
                    issue_signed_founder_pass(&state, &user_pub, &refreshed_tier, exp),
                    exp,
                )
            } else {
                (pass_token.to_string(), expires_sec)
            };
        return (
            StatusCode::OK,
            Json(json!({
                "allowed": true,
                "revoked": false,
                "tier": refreshed_tier,
                "max_groups": effective_max,
                "expires_at": refreshed_exp,
                "founder_pass": refreshed_pass,
            })),
        );
    }

    (
        StatusCode::FORBIDDEN,
        Json(json!({"allowed": false, "error": "Tier não suportado"})),
    )
}

pub async fn handle_founder_stop_node(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(data): Json<Value>,
) -> impl IntoResponse {
    let user_id = data
        .get("user_id")
        .or_else(|| data.get("user_crypto_id"))
        .or_else(|| data.get("owner_pubkey_hex"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let target_node_pub = data
        .get("node_pubkey")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let Some(user_pub) = extract_founder_pubkey_hex(&user_id) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid user Crypto ID"})),
        );
    };
    if let Err(err_msg) = verify_founder_endpoint_auth(&headers, &user_pub, &user_id) {
        state.inc_unauthenticated();
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": err_msg})));
    }

    if let Some(mut nodes_map) = state.founder_operator_nodes.get_mut(&user_pub) {
        if !target_node_pub.is_empty() {
            if let Some(info) = nodes_map.get_mut(&target_node_pub) {
                if let Some(obj) = info.as_object_mut() {
                    obj.insert("stopped".to_string(), json!(true));
                }
            }
        } else {
            for info in nodes_map.values_mut() {
                if let Some(obj) = info.as_object_mut() {
                    obj.insert("stopped".to_string(), json!(true));
                }
            }
        }
    }
    let active_nodes = count_active_operator_nodes(&state, &user_pub).await;
    let donor_q = state
        .founder_donor_quotas
        .get(&user_pub)
        .map(|v| *v.value())
        .unwrap_or(0);
    (
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "user_pub": user_pub,
            "active_nodes": active_nodes,
            "can_create_groups": active_nodes > 0 || donor_q > 0,
        })),
    )
}

pub async fn handle_founder_revoke(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(data): Json<Value>,
) -> impl IntoResponse {
    let has_bulk_revoke_param = data
        .get("keep_only_crypto_id")
        .and_then(|v| v.as_str())
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);
    if has_bulk_revoke_param {
        state.inc_unauthenticated();
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Bulk founder revocation is disabled; callers may only revoke their own FounderPass"})),
        );
    }

    let user_id = data
        .get("user_id")
        .or_else(|| data.get("user_crypto_id"))
        .or_else(|| data.get("owner_pubkey_hex"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();

    let Some(target_pub) = extract_founder_pubkey_hex(&user_id) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid user Crypto ID"})),
        );
    };
    if let Err(err_msg) = verify_founder_endpoint_auth(&headers, &target_pub, &user_id) {
        state.inc_unauthenticated();
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": err_msg})));
    }

    state.founder_operator_nodes.remove(&target_pub);
    state.founder_donor_quotas.remove(&target_pub);
    state.founder_created_groups.remove(&target_pub);
    state.revoked_founders.insert(target_pub.clone(), ());
    (
        StatusCode::OK,
        Json(json!({"status": "ok", "revoked": target_pub})),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::is_retired_system_broadcast_envelope;
    use crate::geo::DEFAULT_HOME_ONION;
    use crate::relay_security_tests::build_test_state;
    use axum::http::HeaderValue;
    use axum::routing::{get, post};
    use axum::Router;
    use ed25519_dalek::SigningKey;
    use std::fs;
    use uuid::Uuid;

    fn sign_founder_headers(sk: &SigningKey, uid: &str) -> HeaderMap {
        let ts_ms = now_epoch_ms().to_string();
        let msg = format!("ONIONTALK_AUTH_V2|FOUNDER|{}|{}", uid, ts_ms);
        let sig_hex = hex::encode(sk.sign(msg.as_bytes()).to_bytes());
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-oniontalk-timestamp",
            HeaderValue::from_str(&ts_ms).unwrap(),
        );
        headers.insert(
            "x-oniontalk-signature",
            HeaderValue::from_str(&sig_hex).unwrap(),
        );
        headers
    }

    fn sign_founder_pass_with_key(
        issuer_sk: &SigningKey,
        owner_pub_hex: &str,
        tier: &str,
        expires_sec: i64,
    ) -> String {
        let issuer_pub_hex = hex::encode(issuer_sk.verifying_key().to_bytes());
        let canonical = format!(
            "ONIONTALK_FOUNDER_PASS_V1|{}|{}|{}|{}",
            owner_pub_hex, tier, expires_sec, issuer_pub_hex
        );
        let sig = hex::encode(issuer_sk.sign(canonical.as_bytes()).to_bytes());
        format!(
            "otpass1:{}:{}:{}:{}:{}",
            owner_pub_hex, tier, expires_sec, issuer_pub_hex, sig
        )
    }

    fn sign_node_cert_with_key(
        issuer_sk: &SigningKey,
        node_onion: &str,
        node_pub_hex: &str,
        prov: &str,
        expires_sec: i64,
    ) -> String {
        let issuer_pub_hex = hex::encode(issuer_sk.verifying_key().to_bytes());
        let canonical = format!(
            "ONIONTALK_NODE_CERT_V1|{}|{}|{}|{}|{}",
            node_onion, node_pub_hex, prov, expires_sec, issuer_pub_hex
        );
        let sig = hex::encode(issuer_sk.sign(canonical.as_bytes()).to_bytes());
        format!(
            "otnode1:{}:{}:{}:{}:{}:{}",
            node_onion, node_pub_hex, prov, expires_sec, issuer_pub_hex, sig
        )
    }

    fn sign_otcrl1_token(
        root_sk: &SigningKey,
        epoch_sec: u64,
        revoked_csv: &str,
        delegated_csv: &str,
    ) -> String {
        let root_pub_hex = hex::encode(root_sk.verifying_key().to_bytes());
        let canonical = format!(
            "ONIONTALK_AUTHORITY_CRL_V1|{}|{}|{}|{}",
            epoch_sec, revoked_csv, delegated_csv, root_pub_hex
        );
        let sig_hex = hex::encode(root_sk.sign(canonical.as_bytes()).to_bytes());
        format!(
            "otcrl1:{}:{}:{}:{}:{}",
            epoch_sec, revoked_csv, delegated_csv, root_pub_hex, sig_hex
        )
    }

    fn valid_test_onion_from_key(sk: &SigningKey) -> String {
        let pk_bytes = sk.verifying_key().to_bytes();
        let mut hasher = Sha3_256::new();
        hasher.update(b".onion checksum");
        hasher.update(pk_bytes);
        hasher.update([0x03]);
        let digest = hasher.finalize();
        let mut raw = [0u8; 35];
        raw[..32].copy_from_slice(&pk_bytes);
        raw[32] = digest[0];
        raw[33] = digest[1];
        raw[34] = 0x03;
        format!(
            "{}.onion",
            data_encoding::BASE32.encode(&raw).to_ascii_lowercase()
        )
    }

    #[tokio::test]
    async fn wave1_a_rejects_root_admin_and_retired_admin_pubkey_and_bulk_revoke() {
        let dir = std::env::temp_dir().join(format!("ot_founder_w1a_{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let state = Arc::new(build_test_state(&dir));

        // 1. Tier bounds strictly reject ROOT_ADMIN and out-of-range donor/relay tiers
        assert_eq!(parse_tier_max_groups("ROOT_ADMIN"), 0);
        assert_eq!(parse_tier_max_groups("DONOR_10USD"), 10);
        assert_eq!(parse_tier_max_groups("DONOR_10USD_100"), 100);
        assert_eq!(parse_tier_max_groups("DONOR_10USD_101"), 0);
        assert_eq!(parse_tier_max_groups("DONOR_10USD_10000"), 0);
        assert_eq!(parse_tier_max_groups("RELAY_NODE"), 1);
        assert_eq!(parse_tier_max_groups("RELAY_NODE_20"), 20);
        assert_eq!(parse_tier_max_groups("RELAY_NODE_21"), 0);

        // 2. Reconstruct retired admin pubkey from raw bytes (zero literal privileges)
        let retired_key_bytes: [u8; 32] = [
            0xbb, 0xac, 0x48, 0xf9, 0x9e, 0xd4, 0x53, 0x6c, 0xe9, 0x13, 0x4d, 0xf1, 0x6c, 0xc4,
            0x9d, 0xbe, 0xd2, 0xd9, 0x10, 0x9e, 0xd3, 0x51, 0x71, 0x0d, 0x18, 0x1d, 0x86, 0xc2,
            0x8f, 0x34, 0xef, 0xd9,
        ];
        let retired_pub_hex = hex::encode(retired_key_bytes);
        assert!(!state.is_trusted_authority_issuer(&retired_pub_hex));

        // Quote endpoint returns normal crypto quote, never is_root_admin / DONOR_10USD_10000
        let (q_status, q_body) = {
            let resp = handle_founder_quote(
                State(state.clone()),
                Json(json!({ "user_id": format!("@{}", retired_pub_hex), "symbol": "SOL" })),
            )
            .await
            .into_response();
            let status = resp.status();
            let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
            (status, serde_json::from_slice::<Value>(&bytes).unwrap())
        };
        assert_eq!(q_status, StatusCode::OK);
        assert!(q_body.get("is_root_admin").is_none());
        assert!(q_body.get("founder_pass").is_none());
        assert!(q_body.get("quote_token").is_some());

        // Claim-crypto endpoint rejects missing TXID/quote for retired pubkey
        let claim_resp = handle_founder_claim_crypto(
            State(state.clone()),
            Json(json!({ "user_id": format!("@{}", retired_pub_hex) })),
        )
        .await
        .into_response();
        assert_eq!(claim_resp.status(), StatusCode::BAD_REQUEST);

        // 3. Even if a trusted issuer signed a ROOT_ADMIN pass, verify-allowance rejects it
        let issuer_sk = SigningKey::from_bytes(&[0x31; 32]);
        let issuer_pub = hex::encode(issuer_sk.verifying_key().to_bytes());
        state
            .delegated_authority_pubkeys
            .write()
            .unwrap()
            .insert(issuer_pub);

        let user_sk = SigningKey::from_bytes(&[0x41; 32]);
        let user_pub = hex::encode(user_sk.verifying_key().to_bytes());
        let user_uid = format!("@{}", user_pub);
        let root_pass = sign_founder_pass_with_key(
            &issuer_sk,
            &user_pub,
            "ROOT_ADMIN",
            now_epoch_sec() + 86400,
        );
        let allow_resp = handle_founder_verify_allowance(
            State(state.clone()),
            sign_founder_headers(&user_sk, &user_uid),
            Json(json!({
                "user_id": user_uid,
                "founder_pass": root_pass,
                "current_groups_count": 0
            })),
        )
        .await
        .into_response();
        assert_eq!(allow_resp.status(), StatusCode::FORBIDDEN);

        // 4. Bulk revocation (keep_only_crypto_id) and cross-user revocation (even with x-admin-token) are rejected
        let attacker_sk = SigningKey::from_bytes(&[0x51; 32]);
        let attacker_uid = format!("@{}", hex::encode(attacker_sk.verifying_key().to_bytes()));
        let mut bulk_hdrs = sign_founder_headers(&attacker_sk, &attacker_uid);
        bulk_hdrs.insert(
            "x-admin-token",
            HeaderValue::from_static("test-admin-secret"),
        );
        let bulk_resp = handle_founder_revoke(
            State(state.clone()),
            bulk_hdrs.clone(),
            Json(json!({ "keep_only_crypto_id": attacker_uid })),
        )
        .await
        .into_response();
        assert_eq!(bulk_resp.status(), StatusCode::FORBIDDEN);

        let cross_revoke_resp = handle_founder_revoke(
            State(state.clone()),
            bulk_hdrs,
            Json(json!({ "user_id": user_uid })),
        )
        .await
        .into_response();
        assert_eq!(cross_revoke_resp.status(), StatusCode::UNAUTHORIZED);

        // 5. Retired system broadcast filter now catches retired admin sender too
        let retired_sender = format!("@{}:{}", retired_pub_hex, DEFAULT_HOME_ONION);
        let prefix = "__ENC_X25519_CHACHA20_V2__:";
        let retired_payload = format!("{}{}", prefix, "a".repeat(1670 - prefix.len()));
        assert!(is_retired_system_broadcast_envelope(
            &retired_sender,
            &retired_payload,
            ""
        ));

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn wave1_b_rejects_eternal_zero_expiry_and_excessive_ttl_tokens() {
        let dir = std::env::temp_dir().join(format!("ot_founder_w1b_{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let state = Arc::new(build_test_state(&dir));

        let issuer_sk = SigningKey::from_bytes(&[0x32; 32]);
        let issuer_pub = hex::encode(issuer_sk.verifying_key().to_bytes());
        state
            .delegated_authority_pubkeys
            .write()
            .unwrap()
            .insert(issuer_pub);

        let user_sk = SigningKey::from_bytes(&[0x42; 32]);
        let user_pub = hex::encode(user_sk.verifying_key().to_bytes());
        let user_uid = format!("@{}", user_pub);
        let now = now_epoch_sec();

        // Eternal (0), negative (-1), already expired (now - 10), and >35 days (now + 36d) MUST all fail
        for bad_exp in [0i64, -1, now - 10, now, now + 36 * 86400] {
            let pass = sign_founder_pass_with_key(&issuer_sk, &user_pub, "DONOR_10USD", bad_exp);
            let resp = handle_founder_verify_allowance(
                State(state.clone()),
                sign_founder_headers(&user_sk, &user_uid),
                Json(json!({
                    "user_id": user_uid,
                    "founder_pass": pass,
                    "current_groups_count": 0
                })),
            )
            .await
            .into_response();
            assert_eq!(
                resp.status(),
                StatusCode::FORBIDDEN,
                "FounderPass with expires_sec={} must be rejected",
                bad_exp
            );
        }

        // Same strict TTL bounds on otnode1: node certificates
        let peer_sk = SigningKey::from_bytes(&[0x62; 32]);
        let peer_pub = hex::encode(peer_sk.verifying_key().to_bytes());
        let peer_onion = valid_test_onion_from_key(&peer_sk);
        for bad_exp in [0i64, -5, now - 1, now, now + 36 * 86400] {
            let cert =
                sign_node_cert_with_key(&issuer_sk, &peer_onion, &peer_pub, "COMMUNITY", bad_exp);
            assert!(
                !verify_node_certificate(&state, &peer_onion, &peer_pub, &cert),
                "Node cert with expires_sec={} must be rejected",
                bad_exp
            );
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn wave1_c_valid_30_day_donor_10usd_issuance_and_verification() {
        let dir = std::env::temp_dir().join(format!("ot_founder_w1c_{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let state = Arc::new(build_test_state(&dir));

        // Delegate the relay's node_public_key_hex as an authorized sub-issuer
        state
            .delegated_authority_pubkeys
            .write()
            .unwrap()
            .insert(state.node_public_key_hex.clone());

        let donor_sk = SigningKey::from_bytes(&[0x43; 32]);
        let donor_pub = hex::encode(donor_sk.verifying_key().to_bytes());
        let donor_uid = format!("@{}", donor_pub);

        // 1. Issue a valid 30-day DONOR_10USD FounderPass via handle_founder_quote -> handle_founder_claim_crypto
        std::env::set_var("SANDBOX_ALLOW_TEST_TX", "1");
        let before_sec = now_epoch_sec();
        let quote_resp = handle_founder_quote(
            State(state.clone()),
            Json(json!({ "user_id": donor_uid, "symbol": "SOL" })),
        )
        .await
        .into_response();
        assert_eq!(quote_resp.status(), StatusCode::OK);
        let quote_json: Value = serde_json::from_slice(
            &axum::body::to_bytes(quote_resp.into_body(), 65536)
                .await
                .unwrap(),
        )
        .unwrap();
        let quote_tok = quote_json["quote_token"].as_str().unwrap();

        let claim_resp = handle_founder_claim_crypto(
            State(state.clone()),
            Json(json!({
                "user_id": donor_uid,
                "txid": format!("sandbox_tx_{}", Uuid::new_v4()),
                "quote_token": quote_tok
            })),
        )
        .await
        .into_response();
        assert_eq!(claim_resp.status(), StatusCode::OK);
        let claim_json: Value = serde_json::from_slice(
            &axum::body::to_bytes(claim_resp.into_body(), 65536)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(claim_json["tier"], "DONOR_10USD");
        assert_eq!(claim_json["max_groups"], 10);
        let claim_exp = claim_json["expires_at"].as_i64().unwrap();
        assert!(claim_exp >= before_sec + FOUNDER_PASS_DONOR_TTL_SEC);
        assert!(claim_exp <= now_epoch_sec() + MAX_AUTHORITY_TOKEN_TTL_SEC);
        let donor_pass = claim_json["founder_pass"].as_str().unwrap().to_string();
        let issued_exp = claim_exp;

        // Ensure issued token embeds positive 30-day expiry, never 0
        let parts: Vec<&str> = donor_pass.split(':').collect();
        let parsed_exp: i64 = parts[3].parse().unwrap();
        assert_eq!(parsed_exp, claim_exp);
        assert!(parsed_exp >= before_sec + 30 * 86400);
        assert!(parsed_exp <= now_epoch_sec() + MAX_AUTHORITY_TOKEN_TTL_SEC);

        // 2. Verify allowance succeeds and returns refreshed 30-day rolling FounderPass
        let resp = handle_founder_verify_allowance(
            State(state.clone()),
            sign_founder_headers(&donor_sk, &donor_uid),
            Json(json!({
                "user_id": donor_uid,
                "founder_pass": donor_pass,
                "current_groups_count": 0,
                "group_id": "group-alpha-001"
            })),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_slice(
            &axum::body::to_bytes(resp.into_body(), 65536).await.unwrap(),
        )
        .unwrap();
        assert_eq!(body["allowed"], true);
        assert_eq!(body["tier"], "DONOR_10USD");
        assert_eq!(body["max_groups"], 10);
        let refreshed_exp = body["expires_at"].as_i64().unwrap();
        assert!(refreshed_exp >= before_sec + 30 * 86400);
        let refreshed_pass = body["founder_pass"].as_str().unwrap();
        assert!(refreshed_pass.starts_with("otpass1:"));
        assert!(!refreshed_pass.contains(":0:"));

        // 3. Untrusted random issuer MUST be rejected even with valid 30-day expiry
        let rogue_sk = SigningKey::from_bytes(&[0x99; 32]);
        let rogue_pass =
            sign_founder_pass_with_key(&rogue_sk, &donor_pub, "DONOR_10USD", issued_exp);
        let rogue_resp = handle_founder_verify_allowance(
            State(state.clone()),
            sign_founder_headers(&donor_sk, &donor_uid),
            Json(json!({
                "user_id": donor_uid,
                "founder_pass": rogue_pass,
                "current_groups_count": 1
            })),
        )
        .await
        .into_response();
        assert_eq!(rogue_resp.status(), StatusCode::FORBIDDEN);

        // 4. Quota enforcement at 10 groups
        let cap_resp = handle_founder_verify_allowance(
            State(state.clone()),
            sign_founder_headers(&donor_sk, &donor_uid),
            Json(json!({
                "user_id": donor_uid,
                "founder_pass": refreshed_pass,
                "current_groups_count": 10
            })),
        )
        .await
        .into_response();
        assert_eq!(cap_resp.status(), StatusCode::FORBIDDEN);

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn wave1_d_live_otcrl1_revokes_f264b5_and_delegates_rotated_issuer_via_offline_root_ca() {
        let dir = std::env::temp_dir().join(format!("ot_founder_w1d_{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let state = Arc::new(build_test_state(&dir));

        let target_revoked = "f264b56baf2938e6c19103d932bafc0c45ab0b73af472d222355c3d4bb0f941f";
        assert!(
            state.is_trusted_authority_issuer(target_revoked),
            "Operational sub-issuer f264b5... starts trusted before CRL"
        );

        // Rotated sub-issuer keypair starts UNTRUSTED before CRL delegation
        let rotated_sk = SigningKey::from_bytes(&[0x77; 32]);
        let rotated_pub = hex::encode(rotated_sk.verifying_key().to_bytes());
        assert!(!state.is_trusted_authority_issuer(&rotated_pub));

        let user_sk = SigningKey::from_bytes(&[0x44; 32]);
        let user_pub = hex::encode(user_sk.verifying_key().to_bytes());
        let user_uid = format!("@{}", user_pub);
        let exp_30d = now_epoch_sec() + FOUNDER_PASS_DONOR_TTL_SEC;
        let rotated_pass =
            sign_founder_pass_with_key(&rotated_sk, &user_pub, "DONOR_10USD", exp_30d);

        // Before CRL: rotated_pass MUST fail verification
        let pre_resp = handle_founder_verify_allowance(
            State(state.clone()),
            sign_founder_headers(&user_sk, &user_uid),
            Json(json!({ "user_id": user_uid, "founder_pass": rotated_pass })),
        )
        .await
        .into_response();
        assert_eq!(pre_resp.status(), StatusCode::FORBIDDEN);

        // Non-root signer attempting to forge otcrl1 MUST fail (strict OFFLINE_ROOT_CA_PUBKEYS check)
        let non_root_sk = SigningKey::from_bytes(&[0x88; 32]);
        let forged_crl = sign_otcrl1_token(
            &non_root_sk,
            now_epoch_sec() as u64,
            target_revoked,
            &rotated_pub,
        );
        assert!(verify_and_apply_authority_crl(&state, &forged_crl).is_err());

        // Pin deterministic test Offline Root CA keypair in test_root_ca_pubkey
        let offline_root_sk = SigningKey::from_bytes(&[0xA5; 32]);
        let offline_root_pub = hex::encode(offline_root_sk.verifying_key().to_bytes());
        *state.test_root_ca_pubkey.write().unwrap() = Some(offline_root_pub);

        // Future-skewed CRL (> now + 300s) MUST fail
        let future_crl = sign_otcrl1_token(
            &offline_root_sk,
            (now_epoch_sec() as u64) + 600,
            target_revoked,
            &rotated_pub,
        );
        assert!(verify_and_apply_authority_crl(&state, &future_crl).is_err());

        // Live HTTP router test for POST/GET /api/v1/authority/crl and GET /api/v1/peers/list
        let app = Router::new()
            .route(
                "/api/v1/authority/crl",
                get(handle_get_authority_crl).post(handle_post_authority_crl),
            )
            .route("/api/v1/peers/list", get(crate::handle_list_peers))
            .route(
                "/api/v1/founder/verify-allowance",
                post(handle_founder_verify_allowance),
            )
            .with_state(state.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let client = reqwest::Client::new();
        let base = format!("http://{}", addr);

        let crl_epoch = now_epoch_sec() as u64;
        let valid_crl =
            sign_otcrl1_token(&offline_root_sk, crl_epoch, target_revoked, &rotated_pub);

        // 1. Apply CRL over HTTP POST /api/v1/authority/crl
        let post_res = client
            .post(format!("{}/api/v1/authority/crl", base))
            .json(&json!({ "crl": valid_crl }))
            .send()
            .await
            .unwrap();
        assert_eq!(post_res.status(), StatusCode::OK);

        // 2. f264b5... is now REVOKED and rotated_pub is now DELEGATED & TRUSTED
        assert!(!state.is_trusted_authority_issuer(target_revoked));
        assert!(state.is_authority_revoked(target_revoked));
        assert!(state.is_trusted_authority_issuer(&rotated_pub));

        // 3. Replaying same epoch or older epoch MUST fail with 403
        let replay_res = client
            .post(format!("{}/api/v1/authority/crl", base))
            .json(&json!({ "crl": valid_crl }))
            .send()
            .await
            .unwrap();
        assert_eq!(replay_res.status(), StatusCode::FORBIDDEN);

        // 4. Token claiming revoked f264b5... issuer MUST be rejected
        let fake_f264_pass = format!(
            "otpass1:{}:DONOR_10USD:{}:{}:{}",
            user_pub,
            exp_30d,
            target_revoked,
            "11".repeat(64)
        );
        let ts_ms = now_epoch_ms().to_string();
        let sig_f264 = hex::encode(
            user_sk
                .sign(format!("ONIONTALK_AUTH_V2|FOUNDER|{}|{}", user_uid, ts_ms).as_bytes())
                .to_bytes(),
        );
        let rev_check = client
            .post(format!("{}/api/v1/founder/verify-allowance", base))
            .header("X-OnionTalk-Timestamp", &ts_ms)
            .header("X-OnionTalk-Signature", &sig_f264)
            .json(&json!({ "user_id": user_uid, "founder_pass": fake_f264_pass }))
            .send()
            .await
            .unwrap();
        assert_eq!(rev_check.status(), StatusCode::FORBIDDEN);

        // 5. Rotated issuer's 30-day DONOR_10USD FounderPass & otnode1 cert now SUCCEED!
        let ts_ms2 = (now_epoch_ms() + 1).to_string();
        let sig_rot = hex::encode(
            user_sk
                .sign(format!("ONIONTALK_AUTH_V2|FOUNDER|{}|{}", user_uid, ts_ms2).as_bytes())
                .to_bytes(),
        );
        let rot_check = client
            .post(format!("{}/api/v1/founder/verify-allowance", base))
            .header("X-OnionTalk-Timestamp", &ts_ms2)
            .header("X-OnionTalk-Signature", &sig_rot)
            .json(&json!({ "user_id": user_uid, "founder_pass": rotated_pass }))
            .send()
            .await
            .unwrap();
        assert_eq!(rot_check.status(), StatusCode::OK);
        let rot_json: Value = rot_check.json().await.unwrap();
        assert_eq!(rot_json["allowed"], true);
        assert_eq!(rot_json["max_groups"], 10);

        let peer_sk = SigningKey::from_bytes(&[0x66; 32]);
        let peer_pub = hex::encode(peer_sk.verifying_key().to_bytes());
        let peer_onion = valid_test_onion_from_key(&peer_sk);
        let rot_cert =
            sign_node_cert_with_key(&rotated_sk, &peer_onion, &peer_pub, "COMMUNITY", exp_30d);
        assert!(verify_node_certificate(
            &state,
            &peer_onion,
            &peer_pub,
            &rot_cert
        ));

        // 6. GET /api/v1/authority/crl and GET /api/v1/peers/list (summary=1 and full) sync authority_crl
        let get_crl_json: Value = client
            .get(format!("{}/api/v1/authority/crl", base))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(get_crl_json["authority_crl"].as_str(), Some(valid_crl.as_str()));

        let peers_sum_json: Value = client
            .get(format!("{}/api/v1/peers/list?summary=1", base))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(
            peers_sum_json["authority_crl"].as_str(),
            Some(valid_crl.as_str())
        );

        let peers_full_json: Value = client
            .get(format!("{}/api/v1/peers/list", base))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(
            peers_full_json["authority_crl"].as_str(),
            Some(valid_crl.as_str())
        );

        // 7. Snapshot persistence restores CRL revocations/delegations across restart
        let state_reloaded = build_test_state(&dir);
        *state_reloaded.test_root_ca_pubkey.write().unwrap() =
            Some(hex::encode(offline_root_sk.verifying_key().to_bytes()));
        state_reloaded.load_persistent_files();
        assert_eq!(state_reloaded.authority_crl_epoch.load(Ordering::SeqCst), crl_epoch);
        assert!(state_reloaded.is_authority_revoked(target_revoked));
        assert!(state_reloaded.is_trusted_authority_issuer(&rotated_pub));

        srv.abort();
        let _ = fs::remove_dir_all(&dir);
    }
}
