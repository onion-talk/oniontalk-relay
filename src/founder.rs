use crate::crypto::{
    constant_time_eq, extract_ed25519_pubkey_hex, is_lower_hex_len, is_valid_onion_v3,
    now_epoch_ms, now_epoch_sec, AUTH_WINDOW_MS,
};
use crate::AppState;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sha3::Sha3_256;
use std::net::SocketAddr;
use std::sync::Arc;

pub const OFFICIAL_ADMIN_PUBKEY_HEX: &str =
    "bbac48f99ed4536ce9134df16cc49dbed2d9109ed351710d181d86c28f34efd9";
pub const MIN_GROUP_DONATION_USD: f64 = 10.0;
pub const GROUPS_PER_10USD_DONATION: i64 = 10;

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

fn verify_founder_endpoint_auth(
    state: &AppState,
    headers: &HeaderMap,
    target_pub_hex: &str,
    raw_user_id: &str,
    allow_admin_override: bool,
) -> Result<(), &'static str> {
    if !state.relay_admin_token.is_empty() {
        if let Some(admin_hdr) = headers.get("x-admin-token").and_then(|v| v.to_str().ok()) {
            let clean_hdr = admin_hdr.trim();
            if !clean_hdr.is_empty()
                && constant_time_eq(clean_hdr.as_bytes(), state.relay_admin_token.as_bytes())
            {
                return Ok(());
            }
        }
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

    let mut candidate_pubs = Vec::new();
    if is_lower_hex_len(target_pub_hex, 64) {
        candidate_pubs.push(target_pub_hex.to_string());
    }
    if allow_admin_override && !candidate_pubs.iter().any(|p| p == OFFICIAL_ADMIN_PUBKEY_HEX) {
        candidate_pubs.push(OFFICIAL_ADMIN_PUBKEY_HEX.to_string());
    }

    let raw_clean = raw_user_id.trim().to_ascii_lowercase();
    for cand_pub in candidate_pubs {
        let Ok(pk_bytes) = hex::decode(&cand_pub) else {
            continue;
        };
        let Ok(pk_arr) = <[u8; 32]>::try_from(pk_bytes.as_slice()) else {
            continue;
        };
        let Ok(verifying_key) = VerifyingKey::from_bytes(&pk_arr) else {
            continue;
        };
        let mut uid_variants = vec![format!("@{}", cand_pub), cand_pub.clone()];
        if !raw_clean.is_empty() && !uid_variants.contains(&raw_clean) {
            uid_variants.push(raw_clean.clone());
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
    }
    Err("Invalid Ed25519 signature for Founder operation")
}

fn parse_tier_max_groups(tier: &str) -> i64 {
    let t = tier.trim().to_ascii_uppercase();
    if t == "ROOT_ADMIN" {
        return 999999;
    }
    if t == "DONOR_10USD" {
        return GROUPS_PER_10USD_DONATION;
    }
    if let Some(rest) = t.strip_prefix("DONOR_10USD_") {
        if let Ok(v) = rest.parse::<i64>() {
            if (1..=10000).contains(&v) {
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
            if (1..=1000).contains(&v) {
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
    let has_proxy_hdr = ["x-forwarded-for", "x-real-ip", "forwarded", "via", "cf-connecting-ip"]
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

    if user_pub == OFFICIAL_ADMIN_PUBKEY_HEX {
        return (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "is_root_admin": true,
                "tier": "DONOR_10USD_10000",
                "max_groups": 10000,
                "expires_at": 0,
                "founder_pass": issue_signed_founder_pass(&state, &user_pub, "DONOR_10USD_10000", 0),
            })),
        );
    }

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

    if user_pub == OFFICIAL_ADMIN_PUBKEY_HEX {
        return (
            StatusCode::OK,
            Json(json!({
                "status": "verified",
                "is_root_admin": true,
                "tier": "DONOR_10USD_10000",
                "max_groups": 10000,
                "expires_at": 0,
                "founder_pass": issue_signed_founder_pass(&state, &user_pub, "DONOR_10USD_10000", 0),
            })),
        );
    }

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

    let sig_valid = if constant_time_eq(quote_sig.to_ascii_lowercase().as_bytes(), expected_sha256.as_bytes())
        && exact_amount_str.ends_with(&expected_tail)
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
        format!("ONIONTALK_TX_NULLIFIER_V1|{}|{}", symbol, txid.to_ascii_lowercase()).as_bytes(),
    ));
    if state.spent_tx_nullifiers.contains_key(&nullifier) {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": "This transaction has already been claimed (Nullifier spent)"})),
        );
    }

    let sandbox_ok = std::env::var("SANDBOX_ALLOW_TEST_TX").as_deref() == Ok("1")
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
        *entry += GROUPS_PER_10USD_DONATION;
        *entry
    };
    let tier_str = if new_quota == GROUPS_PER_10USD_DONATION {
        "DONOR_10USD".to_string()
    } else {
        format!("DONOR_10USD_{}", new_quota)
    };
    let founder_pass = issue_signed_founder_pass(&state, &user_pub, &tier_str, 0);
    (
        StatusCode::OK,
        Json(json!({
            "status": "verified",
            "tier": tier_str,
            "max_groups": new_quota,
            "expires_at": 0,
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

    if user_pub == OFFICIAL_ADMIN_PUBKEY_HEX {
        return (
            StatusCode::OK,
            Json(json!({
                "status": "verified",
                "is_root_admin": true,
                "tier": "DONOR_10USD_10000",
                "max_groups": 10000,
                "expires_at": 0,
                "founder_pass": issue_signed_founder_pass(&state, &user_pub, "DONOR_10USD_10000", 0),
            })),
        );
    }

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
    let tier_str = format!("RELAY_NODE_{}", active_nodes);
    let expires_sec = now_epoch_sec() + 7 * 86400;
    let founder_pass = issue_signed_founder_pass(&state, &user_pub, &tier_str, expires_sec);
    let donor_bonus = state
        .founder_donor_quotas
        .get(&user_pub)
        .map(|v| *v.value())
        .unwrap_or(0);
    (
        StatusCode::OK,
        Json(json!({
            "status": "verified",
            "tier": tier_str,
            "active_nodes": active_nodes,
            "max_groups": active_nodes + donor_bonus,
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
    if let Err(err_msg) = verify_founder_endpoint_auth(&state, &headers, &user_pub, &user_id, true)
    {
        state.inc_unauthenticated();
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"allowed": false, "error": err_msg})),
        );
    }

    if user_pub == OFFICIAL_ADMIN_PUBKEY_HEX {
        return (
            StatusCode::OK,
            Json(json!({
                "allowed": true,
                "tier": "ROOT_ADMIN",
                "active_nodes": 999,
                "max_groups": 999999,
            })),
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
    if expires_sec > 0 && now_epoch_sec() > expires_sec {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"allowed": false, "revoked": true, "error": "FounderPass expirado"})),
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
            Json(json!({"allowed": false, "revoked": true, "error": "Tier de FounderPass desconhecido"})),
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
        let active_nodes = count_active_operator_nodes(&state, &user_pub).await;
        let donor_bonus = state
            .founder_donor_quotas
            .get(&user_pub)
            .map(|v| *v.value())
            .unwrap_or(0);
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
        let new_tier = format!("RELAY_NODE_{}", active_nodes);
        let refreshed_pass =
            issue_signed_founder_pass(&state, &user_pub, &new_tier, now_epoch_sec() + 7 * 86400);
        return (
            StatusCode::OK,
            Json(json!({
                "allowed": true,
                "revoked": false,
                "tier": new_tier,
                "active_nodes": active_nodes,
                "max_groups": effective_max,
                "founder_pass": refreshed_pass,
            })),
        );
    }

    if tier.starts_with("DONOR_10USD") {
        let donor_q = state
            .founder_donor_quotas
            .get(&user_pub)
            .map(|v| *v.value())
            .unwrap_or(token_max);
        let effective_max = donor_q.max(token_max);
        if current_groups < effective_max && !group_id_req.is_empty() {
            state
                .founder_created_groups
                .entry(user_pub.clone())
                .or_default()
                .insert(group_id_req);
        }
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
        return (
            StatusCode::OK,
            Json(json!({
                "allowed": true,
                "revoked": false,
                "tier": tier,
                "max_groups": effective_max,
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
    if let Err(err_msg) = verify_founder_endpoint_auth(&state, &headers, &user_pub, &user_id, true)
    {
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
    let keep_only_id = data
        .get("keep_only_crypto_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let user_id = data
        .get("user_id")
        .or_else(|| data.get("user_crypto_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();

    if !keep_only_id.is_empty() {
        let admin_uid = format!("@{}", OFFICIAL_ADMIN_PUBKEY_HEX);
        if let Err(err_msg) = verify_founder_endpoint_auth(
            &state,
            &headers,
            OFFICIAL_ADMIN_PUBKEY_HEX,
            &admin_uid,
            true,
        ) {
            state.inc_unauthenticated();
            return (StatusCode::UNAUTHORIZED, Json(json!({"error": err_msg})));
        }
        let Some(keep_pub) = extract_founder_pubkey_hex(&keep_only_id) else {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Invalid keep_only_crypto_id"})),
            );
        };
        let mut all_users: Vec<String> = state
            .founder_operator_nodes
            .iter()
            .map(|e| e.key().clone())
            .collect();
        for e in state.founder_donor_quotas.iter() {
            if !all_users.contains(e.key()) {
                all_users.push(e.key().clone());
            }
        }
        for upub in all_users {
            if upub != keep_pub && upub != OFFICIAL_ADMIN_PUBKEY_HEX {
                state.founder_operator_nodes.remove(&upub);
                state.founder_donor_quotas.remove(&upub);
                state.founder_created_groups.remove(&upub);
                state.revoked_founders.insert(upub, ());
            }
        }
        return (
            StatusCode::OK,
            Json(json!({"status": "ok", "kept_only": keep_pub})),
        );
    }

    let Some(target_pub) = extract_founder_pubkey_hex(&user_id) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid user Crypto ID"})),
        );
    };
    if let Err(err_msg) = verify_founder_endpoint_auth(&state, &headers, &target_pub, &user_id, true)
    {
        state.inc_unauthenticated();
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": err_msg})));
    }
    if target_pub != OFFICIAL_ADMIN_PUBKEY_HEX {
        state.founder_operator_nodes.remove(&target_pub);
        state.founder_donor_quotas.remove(&target_pub);
        state.founder_created_groups.remove(&target_pub);
        state.revoked_founders.insert(target_pub.clone(), ());
    }
    (
        StatusCode::OK,
        Json(json!({"status": "ok", "revoked": target_pub})),
    )
}
