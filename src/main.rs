pub mod crypto;
pub mod founder;
pub mod geo;

use crate::crypto::{
    blind_affinity_tag, build_peer_signed_request, canonical_inbox_key, constant_time_eq,
    is_lower_hex_len, is_retired_system_broadcast_envelope,
    is_valid_onion_v3, is_valid_recipient_id, kademlia_xor_distance, load_or_create_node_keypair,
    now_epoch_ms, now_epoch_sec, parse_safe_timestamp_ms, verify_ack_proof,
    verify_user_request_signature, verify_wire_envelope_signature, AUTH_WINDOW_MS, MESSAGE_TTL_MS,
    VOICE_MESSAGE_TTL_MS,
};
use crate::geo::{
    build_node_geo_detail, resolve_fast_lane_url, static_node_geo_map, GeoMeta, BOOTSTRAP_SEEDS,
    COLOCATED_PVE_HS_PEERS, DEPRECATED_SEEDS, DORMANT_SEEDS, LEGACY_V1_PEERS,
};
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode, Uri};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{FixedOffset, TimeZone};
use dashmap::DashMap;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::Notify;
use tokio_stream::wrappers::ReceiverStream;
use uuid::Uuid;

const MAX_KNOWN_PEERS: usize = 64;
const MAX_INBOX_PER_USER: usize = 500;
const MAX_PER_SENDER_INBOX: usize = 150;
const MAX_TOTAL_INBOXES: usize = 5000;
const MAX_AUTO_PEERS_PER_PROVIDER: usize = 6;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredMessage {
    pub id: String,
    pub sender: String,
    pub recipient: String,
    pub payload: String,
    pub ack_lock: String,
    pub timestamp: i64,
    #[serde(default)]
    pub _voice: bool,
    #[serde(skip)]
    pub claim_until: Option<Instant>,
}

impl StoredMessage {
    pub fn to_wire_json(&self) -> Value {
        json!({
            "id": self.id,
            "sender": self.sender,
            "recipient": self.recipient,
            "payload": self.payload,
            "ack_lock": self.ack_lock,
            "timestamp": self.timestamp,
        })
    }
}

pub struct UserMailbox {
    pub messages: Mutex<Vec<StoredMessage>>,
    pub notify: Notify,
    pub active_voice_streams: AtomicU64,
}

impl UserMailbox {
    pub fn new() -> Self {
        Self {
            messages: Mutex::new(Vec::new()),
            notify: Notify::new(),
            active_voice_streams: AtomicU64::new(0),
        }
    }
}

struct VoiceStreamGuard {
    mailbox: Arc<UserMailbox>,
}

impl Drop for VoiceStreamGuard {
    fn drop(&mut self) {
        self.mailbox
            .active_voice_streams
            .fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchEvent {
    pub timestamp: String,
    pub epoch: i64,
    pub event: String,
    pub node_name: String,
    pub domain: String,
    pub provider: String,
    pub location: String,
    pub rtt_ms: f64,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct RelaySnapshot {
    #[serde(default)]
    inbox: HashMap<String, Vec<StoredMessage>>,
    #[serde(default)]
    acked_tombstones: HashMap<String, i64>,
    #[serde(default)]
    acked_tokens: HashMap<String, String>,
    #[serde(default)]
    peer_pubkeys: HashMap<String, String>,
    #[serde(default)]
    known_peers: Vec<String>,
    #[serde(default)]
    peer_online_state: HashMap<String, String>,
    #[serde(default)]
    peer_rtt_ewma: HashMap<String, f64>,
    #[serde(default)]
    custom_peer_geo: HashMap<String, GeoMeta>,
    #[serde(default)]
    stats: HashMap<String, u64>,
}

pub struct AppState {
    pub node_signing_key: SigningKey,
    pub node_public_key_hex: String,
    pub hostname_file: String,
    pub my_onion_domain: RwLock<Option<String>>,
    pub relay_admin_token: String,
    pub min_client_version_code: i64,
    pub latest_client_version_code: i64,
    pub latest_client_version_name: String,
    pub update_play_url: String,
    pub update_apk_url: String,
    pub enforce_hard_update_cut: bool,
    pub start_time_sec: i64,
    pub state_snapshot_file: String,
    pub seen_client_tags_file: String,
    pub mesh_watch_file: String,
    pub spent_nullifiers_file: String,

    pub mailboxes: DashMap<String, Arc<UserMailbox>>,
    pub acked_tombstones: DashMap<String, i64>,
    pub acked_tokens: DashMap<String, String>,
    pub synced_peers_by_msg: DashMap<String, HashSet<String>>,
    pub known_peers: DashMap<String, ()>,
    pub peer_pubkeys: DashMap<String, String>,
    pub peer_reverify_last_ts: DashMap<String, Instant>,
    pub peer_rtt_ewma: DashMap<String, f64>,
    pub peer_fail_count: DashMap<String, u32>,
    pub peer_backoff_until: DashMap<String, Instant>,
    pub peer_last_ok_epoch: DashMap<String, i64>,
    pub peer_last_fail_mono: DashMap<String, Instant>,
    pub peer_online_state: DashMap<String, String>,
    pub custom_peer_geo: DashMap<String, GeoMeta>,
    pub mesh_watch_events: Mutex<Vec<WatchEvent>>,

    pub peer_origin_hints: DashMap<String, (String, Instant)>,
    pub local_active_pollers: DashMap<String, Instant>,
    pub local_voice_stream_pollers: DashMap<String, Instant>,
    pub seen_client_tags: DashMap<String, i64>,

    pub spent_tx_nullifiers: DashMap<String, ()>,
    pub founder_donor_quotas: DashMap<String, i64>,
    pub founder_operator_nodes: DashMap<String, HashMap<String, Value>>,
    pub revoked_founders: DashMap<String, ()>,
    pub founder_created_groups: DashMap<String, HashSet<String>>,

    pub messages_received: AtomicU64,
    pub messages_routed: AtomicU64,
    pub acks_processed: AtomicU64,
    pub spoofed_acks_blocked: AtomicU64,
    pub invalid_peers_blocked: AtomicU64,
    pub unauthenticated_requests_blocked: AtomicU64,
    pub idontwant_dedup_saved: AtomicU64,
    pub fast_lane_routed: AtomicU64,

    pub tor_client: reqwest::Client,
    pub fast_client: reqwest::Client,
}

impl AppState {
    pub fn inc_unauthenticated(&self) {
        self.unauthenticated_requests_blocked
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_my_onion_domain(&self) -> Option<String> {
        if let Ok(guard) = self.my_onion_domain.read() {
            if let Some(dom) = guard.as_ref() {
                return Some(dom.clone());
            }
        }
        if Path::new(&self.hostname_file).exists() {
            if let Ok(raw) = fs::read_to_string(&self.hostname_file) {
                let clean = raw.trim().to_ascii_lowercase();
                if is_valid_onion_v3(&clean) {
                    self.known_peers.remove(&clean);
                    if let Ok(mut w) = self.my_onion_domain.write() {
                        *w = Some(clean.clone());
                    }
                    println!("[*] [NODE-ID] .onion identity established: {}", clean);
                    return Some(clean);
                }
            }
        }
        None
    }

    pub fn get_signed_app_update_metadata(&self) -> Value {
        let canonical = format!(
            "ONIONTALK_UPDATE_V1|{}|{}|{}|{}|{}",
            self.min_client_version_code,
            self.latest_client_version_code,
            self.latest_client_version_name,
            self.update_play_url,
            self.update_apk_url
        );
        let sig = self.node_signing_key.sign(canonical.as_bytes());
        json!({
            "min_version_code": self.min_client_version_code,
            "latest_version_code": self.latest_client_version_code,
            "latest_version_name": self.latest_client_version_name,
            "play_store_url": self.update_play_url,
            "apk_url": self.update_apk_url,
            "node_pubkey": self.node_public_key_hex,
            "signature": hex::encode(sig.to_bytes()),
        })
    }

    pub fn get_or_create_mailbox(&self, user_key: &str) -> Option<Arc<UserMailbox>> {
        if let Some(existing) = self.mailboxes.get(user_key) {
            return Some(existing.value().clone());
        }
        if self.mailboxes.len() >= MAX_TOTAL_INBOXES {
            return None;
        }
        let mb = Arc::new(UserMailbox::new());
        let entry = self
            .mailboxes
            .entry(user_key.to_string())
            .or_insert_with(|| mb);
        Some(entry.value().clone())
    }

    pub fn record_client_tag(&self, user_id_or_tag: &str) {
        let clean = user_id_or_tag.trim().to_ascii_lowercase();
        if clean.is_empty() {
            return;
        }
        let tag = if is_lower_hex_len(&clean, 24) {
            clean
        } else {
            blind_affinity_tag(&clean)
        };
        if !tag.is_empty() {
            self.seen_client_tags.insert(tag, now_epoch_sec());
        }
    }

    pub fn enqueue_message(&self, recipient: &str, msg_obj: StoredMessage) -> (bool, &'static str) {
        let recipient_key = canonical_inbox_key(recipient);
        if is_retired_system_broadcast_envelope(&msg_obj.sender, &msg_obj.payload, "") {
            self.acked_tombstones
                .insert(msg_obj.id.clone(), now_epoch_ms());
            return (false, "already_acked");
        }
        if self.acked_tombstones.contains_key(&msg_obj.id) {
            return (false, "already_acked");
        }
        let Some(mailbox) = self.get_or_create_mailbox(&recipient_key) else {
            return (false, "global_quota_exceeded");
        };

        let sender_id = canonical_inbox_key(&msg_obj.sender);
        let now_ms = now_epoch_ms();
        {
            let mut list = mailbox.messages.lock().unwrap();
            list.retain(|m| {
                if self.acked_tombstones.contains_key(&m.id) {
                    return false;
                }
                let age = now_ms - m.timestamp.min(now_ms);
                let ttl = if m._voice {
                    VOICE_MESSAGE_TTL_MS
                } else {
                    MESSAGE_TTL_MS
                };
                age >= 0 && age < ttl && m.timestamp <= (now_ms + AUTH_WINDOW_MS)
            });

            if list.iter().any(|m| m.id == msg_obj.id) {
                return (false, "duplicate_message");
            }

            if !sender_id.is_empty() {
                let sender_count = list
                    .iter()
                    .filter(|m| canonical_inbox_key(&m.sender) == sender_id)
                    .count();
                if sender_count >= MAX_PER_SENDER_INBOX {
                    if msg_obj._voice {
                        if let Some(idx) = list
                            .iter()
                            .position(|m| m._voice && canonical_inbox_key(&m.sender) == sender_id)
                        {
                            list.remove(idx);
                        } else {
                            return (false, "sender_quota_exceeded");
                        }
                    } else {
                        return (false, "sender_quota_exceeded");
                    }
                }
            }

            if list.len() >= MAX_INBOX_PER_USER {
                return (false, "user_quota_exceeded");
            }

            list.push(msg_obj);
        }

        // O(1) targeted wake-up ONLY for this user's active long-poll / stream tasks!
        mailbox.notify.notify_waiters();

        self.record_client_tag(&recipient_key);
        if !sender_id.is_empty() {
            self.record_client_tag(&sender_id);
        }
        (true, "ok")
    }

    pub fn prune_expired_messages(&self) {
        let now_ms = now_epoch_ms();
        self.acked_tombstones
            .retain(|_, ack_ts| (now_ms - *ack_ts) < MESSAGE_TTL_MS);
        self.acked_tokens
            .retain(|mid, _| self.acked_tombstones.contains_key(mid));

        let mut active_msg_ids = HashSet::new();
        let mut empty_users = Vec::new();
        for entry in self.mailboxes.iter() {
            let user = entry.key().clone();
            let mb = entry.value();
            let mut list = mb.messages.lock().unwrap();
            list.retain(|m| {
                if is_retired_system_broadcast_envelope(&m.sender, &m.payload, "") {
                    self.acked_tombstones.insert(m.id.clone(), now_ms);
                    return false;
                }
                if self.acked_tombstones.contains_key(&m.id) {
                    return false;
                }
                let age = now_ms - m.timestamp.min(now_ms);
                let ttl = if m._voice {
                    VOICE_MESSAGE_TTL_MS
                } else {
                    MESSAGE_TTL_MS
                };
                let keep = age >= 0 && age < ttl && m.timestamp <= (now_ms + AUTH_WINDOW_MS);
                if keep {
                    active_msg_ids.insert(m.id.clone());
                }
                keep
            });
            if list.is_empty() {
                empty_users.push(user);
            }
        }
        for u in empty_users {
            // Only remove if still empty
            if let Some(mb) = self.mailboxes.get(&u) {
                if mb.messages.lock().unwrap().is_empty() {
                    drop(mb);
                    self.mailboxes.remove(&u);
                }
            }
        }
        self.synced_peers_by_msg
            .retain(|mid, _| active_msg_ids.contains(mid));
    }

    pub fn compute_client_metrics(&self) -> (usize, usize) {
        let now_mono = Instant::now();
        let now_sec = now_epoch_sec();
        let mut online_tags = HashSet::new();
        for entry in self.local_active_pollers.iter() {
            if now_mono.duration_since(*entry.value()).as_secs() <= 900 {
                online_tags.insert(entry.key().clone());
            }
        }
        for entry in self.peer_origin_hints.iter() {
            if now_mono.duration_since(entry.value().1).as_secs() <= 900 {
                online_tags.insert(entry.key().clone());
            }
        }
        for entry in self.mailboxes.iter() {
            let list = entry.value().messages.lock().unwrap();
            if !list.is_empty() {
                let t_recip = blind_affinity_tag(entry.key());
                if !t_recip.is_empty() {
                    online_tags.insert(t_recip);
                }
                for m in list.iter() {
                    let t_send = blind_affinity_tag(&m.sender);
                    if !t_send.is_empty() {
                        online_tags.insert(t_send);
                    }
                }
            }
        }
        let mut all_tags = online_tags.clone();
        for entry in self.seen_client_tags.iter() {
            if (now_sec - *entry.value()) <= 30 * 86400 {
                all_tags.insert(entry.key().clone());
            }
        }
        let online_len = online_tags.len();
        let total_len = all_tags.len().max(online_len);
        (online_len, total_len)
    }

    pub fn emit_watch_event(&self, peer: &str, event_label: &str, rtt_ms: f64, status_str: &str) {
        let static_map = static_node_geo_map();
        let custom = self.custom_peer_geo.get(peer).map(|v| v.value().clone());
        let (node_name, provider, location) = if let Some(c) = custom {
            (c.node_name, c.provider, c.location)
        } else if let Some(s) = static_map.get(peer) {
            (
                s.node_name.clone(),
                s.provider.clone(),
                s.location.clone(),
            )
        } else {
            let short8: String = peer.chars().take(8).collect();
            (
                format!("🛰️ Nó Auto-Join ({}...)", short8),
                "Tor v3 Mesh (Auto-Discovered)".to_string(),
                "Tor Hidden Service v3".to_string(),
            )
        };
        let now_sec = now_epoch_sec();
        let brt_offset = FixedOffset::west_opt(3 * 3600).unwrap();
        let ts_str = brt_offset
            .timestamp_opt(now_sec, 0)
            .single()
            .map(|dt| format!("{} BRT", dt.format("%Y-%m-%d %H:%M:%S")))
            .unwrap_or_else(|| format!("{} BRT", now_sec));
        let rtt_round = (rtt_ms * 10.0).round() / 10.0;
        let entry = WatchEvent {
            timestamp: ts_str,
            epoch: now_sec,
            event: event_label.to_string(),
            node_name: node_name.clone(),
            domain: peer.to_string(),
            provider,
            location,
            rtt_ms: rtt_round,
            status: status_str.to_string(),
        };
        if let Ok(mut events) = self.mesh_watch_events.lock() {
            events.insert(0, entry);
            if events.len() > 200 {
                events.truncate(200);
            }
        }
        let short12: String = peer.chars().take(12).collect();
        println!(
            "[*] [MESH-WATCH] {} | {} ({}...) | rtt={}ms",
            event_label, node_name, short12, rtt_round
        );
    }

    pub fn record_peer_success(&self, peer: &str, rtt_ms: f64) {
        let clamped = rtt_ms.clamp(5.0, 15000.0);
        let prev = self
            .peer_rtt_ewma
            .get(peer)
            .map(|v| *v.value())
            .unwrap_or(clamped);
        let new_rtt = ((0.70 * prev + 0.30 * clamped) * 10.0).round() / 10.0;
        self.peer_rtt_ewma.insert(peer.to_string(), new_rtt);
        self.peer_fail_count.insert(peer.to_string(), 0);
        self.peer_backoff_until.remove(peer);
        self.peer_last_ok_epoch
            .insert(peer.to_string(), now_epoch_sec());
        let prev_state = self
            .peer_online_state
            .get(peer)
            .map(|v| v.value().clone())
            .unwrap_or_else(|| "UNKNOWN".to_string());
        self.peer_online_state
            .insert(peer.to_string(), "ONLINE".to_string());
        if prev_state != "ONLINE" {
            let ev_type = if prev_state == "DOWN" {
                "🟢 NÓ RECUPERADO (ONLINE)"
            } else if !static_node_geo_map().contains_key(peer) {
                "🛰️ NOVO NÓ AUTO-JOIN"
            } else {
                "🟢 NÓ ONLINE (TOR V3)"
            };
            self.emit_watch_event(peer, ev_type, clamped, "ACTIVE / SYNCED");
        }
    }

    pub fn record_peer_failure(&self, peer: &str, force_down: bool) {
        let now_mono = Instant::now();
        let now_sec = now_epoch_sec();
        if !force_down {
            if let Some(last_ok) = self.peer_last_ok_epoch.get(peer) {
                if (now_sec - *last_ok.value()) < 45 {
                    return;
                }
            }
            if let Some(last_fail) = self.peer_last_fail_mono.get(peer) {
                if now_mono.duration_since(*last_fail.value()).as_secs() < 15 {
                    return;
                }
            }
        }
        self.peer_last_fail_mono.insert(peer.to_string(), now_mono);
        let fails = self
            .peer_fail_count
            .get(peer)
            .map(|v| *v.value() + 1)
            .unwrap_or(1);
        self.peer_fail_count.insert(peer.to_string(), fails);
        let prev_rtt = self
            .peer_rtt_ewma
            .get(peer)
            .map(|v| *v.value())
            .unwrap_or(1200.0);
        let next_rtt = ((prev_rtt * 1.35 + 400.0) * 10.0).round() / 10.0;
        self.peer_rtt_ewma
            .insert(peer.to_string(), next_rtt.min(15000.0));
        if fails >= 4 || force_down {
            if !BOOTSTRAP_SEEDS.contains(&peer) && !static_node_geo_map().contains_key(peer) {
                self.known_peers.remove(peer);
                self.peer_online_state.remove(peer);
                return;
            }
            let exp = (fails.saturating_sub(4)).min(2);
            let cooldown_secs = (35u64 * (1u64 << exp)).min(180);
            self.peer_backoff_until.insert(
                peer.to_string(),
                now_mono + Duration::from_secs(cooldown_secs),
            );
            let prev_state = self
                .peer_online_state
                .get(peer)
                .map(|v| v.value().clone())
                .unwrap_or_else(|| "UNKNOWN".to_string());
            if prev_state != "DOWN" {
                self.peer_online_state
                    .insert(peer.to_string(), "DOWN".to_string());
                self.emit_watch_event(peer, "🔴 NÓ CAIU / HIBERNANDO", 0.0, "HIBERNATING / DOWN");
            }
        }
    }

    pub fn rank_peers_for_target(
        &self,
        peers: &[String],
        target_user: &str,
        include_backed_off: bool,
    ) -> Vec<String> {
        let now_mono = Instant::now();
        let affinity_tag = if !target_user.is_empty() {
            blind_affinity_tag(target_user)
        } else {
            String::new()
        };
        let mut rtt_snapshot = HashMap::new();
        let mut healthy = Vec::new();
        for p in peers {
            let rtt = self
                .peer_rtt_ewma
                .get(p)
                .map(|v| *v.value())
                .unwrap_or(950.0);
            rtt_snapshot.insert(p.clone(), rtt);
            let backed_off = self
                .peer_backoff_until
                .get(p)
                .map(|until| now_mono < *until.value())
                .unwrap_or(false);
            if include_backed_off || !backed_off {
                healthy.push(p.clone());
            }
        }
        if healthy.len() < peers.len().min(4) {
            let mut sorted_all = peers.to_vec();
            sorted_all.sort_by(|a, b| {
                let ra = rtt_snapshot.get(a).copied().unwrap_or(950.0);
                let rb = rtt_snapshot.get(b).copied().unwrap_or(950.0);
                ra.partial_cmp(&rb).unwrap_or(std::cmp::Ordering::Equal)
            });
            sorted_all.truncate(6.max(healthy.len()));
            healthy = sorted_all;
        }
        if healthy.is_empty() {
            return Vec::new();
        }

        let mut ordered = Vec::new();
        if !affinity_tag.is_empty() {
            if let Some(hint) = self.peer_origin_hints.get(&affinity_tag) {
                if now_mono.duration_since(hint.value().1).as_secs() < 600
                    && peers.contains(&hint.value().0)
                {
                    ordered.push(hint.value().0.clone());
                }
            }
        }

        if !target_user.is_empty() {
            let mut by_xor = healthy.clone();
            by_xor.sort_by_key(|p| kademlia_xor_distance(p, target_user));
            let mut home_swarm: Vec<String> = by_xor.into_iter().take(4).collect();
            home_swarm.sort_by(|a, b| {
                let ra = rtt_snapshot.get(a).copied().unwrap_or(950.0);
                let rb = rtt_snapshot.get(b).copied().unwrap_or(950.0);
                ra.partial_cmp(&rb).unwrap_or(std::cmp::Ordering::Equal)
            });
            for p in home_swarm {
                if !ordered.contains(&p) {
                    ordered.push(p);
                }
            }
        }

        let mut remaining: Vec<String> = healthy
            .into_iter()
            .filter(|p| !ordered.contains(p))
            .collect();
        remaining.sort_by(|a, b| {
            let ra = rtt_snapshot.get(a).copied().unwrap_or(950.0);
            let rb = rtt_snapshot.get(b).copied().unwrap_or(950.0);
            ra.partial_cmp(&rb).unwrap_or(std::cmp::Ordering::Equal)
        });
        ordered.extend(remaining);
        ordered
    }

    pub async fn post_to_peer(
        &self,
        peer: &str,
        path: &str,
        body_bytes: Vec<u8>,
        headers: Vec<(String, String)>,
        timeout_sec: u64,
    ) -> Result<(StatusCode, Bytes), String> {
        let my_dom = self.get_my_onion_domain().unwrap_or_default();
        if let Some(fast_base) = resolve_fast_lane_url(&my_dom, peer) {
            let url = format!("{}{}", fast_base, path);
            let mut req = self
                .fast_client
                .post(&url)
                .timeout(Duration::from_millis(2500))
                .body(body_bytes.clone());
            for (k, v) in &headers {
                req = req.header(k, v);
            }
            let t0 = Instant::now();
            if let Ok(res) = req.send().await {
                let status = res.status();
                if status.as_u16() < 500 {
                    let rtt = t0.elapsed().as_secs_f64() * 1000.0;
                    self.record_peer_success(peer, rtt);
                    self.fast_lane_routed.fetch_add(1, Ordering::Relaxed);
                    let bytes = res.bytes().await.unwrap_or_default();
                    return Ok((status, bytes));
                }
            }
        }

        let url = format!("http://{}{}", peer, path);
        let mut req = self
            .tor_client
            .post(&url)
            .timeout(Duration::from_secs(timeout_sec))
            .body(body_bytes);
        for (k, v) in headers {
            req = req.header(k, v);
        }
        let t0 = Instant::now();
        match req.send().await {
            Ok(res) => {
                let status = res.status();
                let rtt = t0.elapsed().as_secs_f64() * 1000.0;
                self.record_peer_success(peer, rtt);
                let bytes = res.bytes().await.unwrap_or_default();
                Ok((status, bytes))
            }
            Err(e) => Err(e.to_string()),
        }
    }

    pub async fn verify_peer_request(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        raw_body: &[u8],
        require_known_peer: bool,
    ) -> Result<(String, String), &'static str> {
        let peer_onion = headers
            .get("x-peer-onion")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        let peer_pubkey = headers
            .get("x-peer-pubkey")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        let raw_ts = headers
            .get("x-peer-timestamp")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .trim();
        let peer_sig = headers
            .get("x-peer-signature")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();

        if !is_valid_onion_v3(&peer_onion) {
            return Err("Invalid or missing X-Peer-Onion");
        }
        if !is_lower_hex_len(&peer_pubkey, 64) || !is_lower_hex_len(&peer_sig, 128) {
            return Err("Missing or malformed peer Ed25519 signature headers");
        }
        let Ok(ts_ms) = raw_ts.parse::<i64>() else {
            return Err("Invalid X-Peer-Timestamp");
        };
        if (now_epoch_ms() - ts_ms).abs() > AUTH_WINDOW_MS {
            return Err("Peer signature expired");
        }

        let body_hash = hex::encode(Sha256::digest(raw_body));
        let canonical = format!(
            "ONIONTALK_PEER_V2|{}|{}|{}|{}|{}",
            method.as_str().to_ascii_uppercase(),
            uri.path(),
            peer_onion,
            ts_ms,
            body_hash
        );
        let sig_ok = (|| -> Option<bool> {
            let pk_bytes = hex::decode(&peer_pubkey).ok()?;
            let pk_arr = <[u8; 32]>::try_from(pk_bytes.as_slice()).ok()?;
            let vk = VerifyingKey::from_bytes(&pk_arr).ok()?;
            let sb = hex::decode(&peer_sig).ok()?;
            let sig = Signature::from_slice(&sb).ok()?;
            Some(vk.verify(canonical.as_bytes(), &sig).is_ok())
        })()
        .unwrap_or(false);
        if !sig_ok {
            return Err("Invalid peer Ed25519 signature");
        }

        if require_known_peer {
            let my_dom = self.get_my_onion_domain().unwrap_or_default();
            if peer_onion == my_dom
                && constant_time_eq(peer_pubkey.as_bytes(), self.node_public_key_hex.as_bytes())
            {
                return Ok((peer_onion, peer_pubkey));
            }
            if !self.known_peers.contains_key(&peer_onion) {
                return Err("Peer is not a registered member of the mesh");
            }
            if BOOTSTRAP_SEEDS.contains(&peer_onion.as_str()) {
                self.peer_pubkeys
                    .insert(peer_onion.clone(), peer_pubkey.clone());
            } else {
                let pinned = self
                    .peer_pubkeys
                    .get(&peer_onion)
                    .map(|v| v.value().clone());
                let needs_reverify = match pinned {
                    Some(pk) => !constant_time_eq(pk.as_bytes(), peer_pubkey.as_bytes()),
                    None => true,
                };
                if needs_reverify && !self.reverify_peer_key_on_rotation(&peer_onion, &peer_pubkey).await {
                    return Err("Peer public key mismatch against pinned identity");
                }
            }
        }
        Ok((peer_onion, peer_pubkey))
    }

    async fn reverify_peer_key_on_rotation(&self, peer_onion: &str, candidate_pubkey: &str) -> bool {
        let now_mono = Instant::now();
        if let Some(last) = self.peer_reverify_last_ts.get(peer_onion) {
            if now_mono.duration_since(*last.value()).as_secs() < 30 {
                return false;
            }
        }
        self.peer_reverify_last_ts
            .insert(peer_onion.to_string(), now_mono);
        let url = format!("http://{}/health", peer_onion);
        if let Ok(res) = self
            .tor_client
            .get(&url)
            .timeout(Duration::from_secs(20))
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
                        && constant_time_eq(remote_pk.as_bytes(), candidate_pubkey.as_bytes())
                    {
                        self.peer_pubkeys
                            .insert(peer_onion.to_string(), candidate_pubkey.to_string());
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn save_persistent_files(&self) {
        // 1. Seen client tags
        let tags_map: HashMap<String, i64> = self
            .seen_client_tags
            .iter()
            .map(|e| (e.key().clone(), *e.value()))
            .collect();
        if let Ok(json_str) = serde_json::to_string(&tags_map) {
            let _ = fs::write(&self.seen_client_tags_file, json_str);
        }

        // 2. Mesh watch events
        if let Ok(events) = self.mesh_watch_events.lock() {
            if let Ok(json_str) = serde_json::to_string(&*events) {
                let _ = fs::write(&self.mesh_watch_file, json_str);
            }
        }

        // 3. Spent nullifiers
        let nullifiers: Vec<String> = self
            .spent_tx_nullifiers
            .iter()
            .map(|e| e.key().clone())
            .collect();
        if let Ok(json_str) = serde_json::to_string(&nullifiers) {
            let _ = fs::write(&self.spent_nullifiers_file, json_str);
        }

        // 4. Full inbox + tombstones snapshot for zero-loss container restarts
        if !self.state_snapshot_file.is_empty() {
            let mut inbox_map = HashMap::new();
            for entry in self.mailboxes.iter() {
                let list = entry.value().messages.lock().unwrap();
                if !list.is_empty() {
                    inbox_map.insert(entry.key().clone(), list.clone());
                }
            }
            let tombs: HashMap<String, i64> = self
                .acked_tombstones
                .iter()
                .map(|e| (e.key().clone(), *e.value()))
                .collect();
            let toks: HashMap<String, String> = self
                .acked_tokens
                .iter()
                .map(|e| (e.key().clone(), e.value().clone()))
                .collect();
            let pks: HashMap<String, String> = self
                .peer_pubkeys
                .iter()
                .map(|e| (e.key().clone(), e.value().clone()))
                .collect();
            let k_peers: Vec<String> = self
                .known_peers
                .iter()
                .map(|e| e.key().clone())
                .collect();
            let p_online: HashMap<String, String> = self
                .peer_online_state
                .iter()
                .map(|e| (e.key().clone(), e.value().clone()))
                .collect();
            let p_rtt: HashMap<String, f64> = self
                .peer_rtt_ewma
                .iter()
                .map(|e| (e.key().clone(), *e.value()))
                .collect();
            let c_geo: HashMap<String, GeoMeta> = self
                .custom_peer_geo
                .iter()
                .map(|e| (e.key().clone(), e.value().clone()))
                .collect();
            let mut stats_map = HashMap::new();
            stats_map.insert(
                "messages_received".to_string(),
                self.messages_received.load(Ordering::Relaxed),
            );
            stats_map.insert(
                "messages_routed".to_string(),
                self.messages_routed.load(Ordering::Relaxed),
            );
            stats_map.insert(
                "acks_processed".to_string(),
                self.acks_processed.load(Ordering::Relaxed),
            );
            stats_map.insert(
                "spoofed_acks_blocked".to_string(),
                self.spoofed_acks_blocked.load(Ordering::Relaxed),
            );
            stats_map.insert(
                "invalid_peers_blocked".to_string(),
                self.invalid_peers_blocked.load(Ordering::Relaxed),
            );
            stats_map.insert(
                "unauthenticated_requests_blocked".to_string(),
                self.unauthenticated_requests_blocked.load(Ordering::Relaxed),
            );
            stats_map.insert(
                "idontwant_dedup_saved".to_string(),
                self.idontwant_dedup_saved.load(Ordering::Relaxed),
            );
            stats_map.insert(
                "fast_lane_routed".to_string(),
                self.fast_lane_routed.load(Ordering::Relaxed),
            );
            let snap = RelaySnapshot {
                inbox: inbox_map,
                acked_tombstones: tombs,
                acked_tokens: toks,
                peer_pubkeys: pks,
                known_peers: k_peers,
                peer_online_state: p_online,
                peer_rtt_ewma: p_rtt,
                custom_peer_geo: c_geo,
                stats: stats_map,
            };
            if let Ok(json_str) = serde_json::to_string(&snap) {
                let tmp_path = format!("{}.tmp", self.state_snapshot_file);
                if fs::write(&tmp_path, json_str).is_ok() {
                    let _ = fs::rename(&tmp_path, &self.state_snapshot_file);
                }
            }
        }
    }

    pub fn load_persistent_files(&self) {
        if Path::new(&self.seen_client_tags_file).exists() {
            if let Ok(raw) = fs::read_to_string(&self.seen_client_tags_file) {
                if let Ok(map) = serde_json::from_str::<HashMap<String, i64>>(&raw) {
                    for (k, v) in map {
                        if k.len() == 24 {
                            self.seen_client_tags.insert(k, v);
                        }
                    }
                }
            }
        }
        if Path::new(&self.mesh_watch_file).exists() {
            if let Ok(raw) = fs::read_to_string(&self.mesh_watch_file) {
                if let Ok(mut list) = serde_json::from_str::<Vec<WatchEvent>>(&raw) {
                    list.truncate(200);
                    if let Ok(mut guard) = self.mesh_watch_events.lock() {
                        *guard = list;
                    }
                }
            }
        }
        if Path::new(&self.spent_nullifiers_file).exists() {
            if let Ok(raw) = fs::read_to_string(&self.spent_nullifiers_file) {
                if let Ok(list) = serde_json::from_str::<Vec<String>>(&raw) {
                    for item in list {
                        self.spent_tx_nullifiers.insert(item, ());
                    }
                }
            }
        }
        if !self.state_snapshot_file.is_empty() && Path::new(&self.state_snapshot_file).exists() {
            if let Ok(raw) = fs::read_to_string(&self.state_snapshot_file) {
                if let Ok(snap) = serde_json::from_str::<RelaySnapshot>(&raw) {
                    for (k, v) in snap.acked_tombstones {
                        self.acked_tombstones.insert(k, v);
                    }
                    for (k, v) in snap.acked_tokens {
                        self.acked_tokens.insert(k, v);
                    }
                    for (k, v) in snap.peer_pubkeys {
                        self.peer_pubkeys.insert(k, v);
                    }
                    for p in snap.known_peers {
                        if is_valid_onion_v3(&p)
                            && !DEPRECATED_SEEDS.contains(&p.as_str())
                            && !LEGACY_V1_PEERS.contains(&p.as_str())
                            && !DORMANT_SEEDS.contains(&p.as_str())
                        {
                            self.known_peers.insert(p, ());
                        }
                    }
                    for (k, v) in snap.peer_online_state {
                        self.peer_online_state.insert(k, v);
                    }
                    for (k, v) in snap.peer_rtt_ewma {
                        self.peer_rtt_ewma.insert(k, v);
                    }
                    for (k, v) in snap.custom_peer_geo {
                        self.custom_peer_geo.insert(k, v);
                    }
                    if let Some(&v) = snap.stats.get("messages_received") {
                        self.messages_received.store(v, Ordering::Relaxed);
                    }
                    if let Some(&v) = snap.stats.get("messages_routed") {
                        self.messages_routed.store(v, Ordering::Relaxed);
                    }
                    if let Some(&v) = snap.stats.get("acks_processed") {
                        self.acks_processed.store(v, Ordering::Relaxed);
                    }
                    if let Some(&v) = snap.stats.get("spoofed_acks_blocked") {
                        self.spoofed_acks_blocked.store(v, Ordering::Relaxed);
                    }
                    if let Some(&v) = snap.stats.get("invalid_peers_blocked") {
                        self.invalid_peers_blocked.store(v, Ordering::Relaxed);
                    }
                    if let Some(&v) = snap.stats.get("unauthenticated_requests_blocked") {
                        self.unauthenticated_requests_blocked
                            .store(v, Ordering::Relaxed);
                    }
                    if let Some(&v) = snap.stats.get("idontwant_dedup_saved") {
                        self.idontwant_dedup_saved.store(v, Ordering::Relaxed);
                    }
                    if let Some(&v) = snap.stats.get("fast_lane_routed") {
                        self.fast_lane_routed.store(v, Ordering::Relaxed);
                    }
                    for (user_key, msgs) in snap.inbox {
                        if let Some(mb) = self.get_or_create_mailbox(&user_key) {
                            let mut list = mb.messages.lock().unwrap();
                            *list = msgs;
                        }
                    }
                }
            }
        }
    }
}

async fn apply_zero_trust_headers(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    headers.remove("server");
    headers.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "cache-control",
        HeaderValue::from_static("no-store, no-cache, must-revalidate, max-age=0"),
    );
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
    );
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert("connection", HeaderValue::from_static("keep-alive"));
    headers.insert(
        "keep-alive",
        HeaderValue::from_static("timeout=75, max=1000"),
    );
    if let Ok(val) = HeaderValue::from_str(&state.node_public_key_hex) {
        headers.insert("x-relay-node-pubkey", val);
    }
    response
}

fn spawn_broadcast_message(state: Arc<AppState>, msg: StoredMessage) {
    tokio::spawn(async move {
        let Some(current_domain) = state.get_my_onion_domain() else {
            return;
        };
        let v2_peers: Vec<String> = state
            .known_peers
            .iter()
            .map(|e| e.key().clone())
            .filter(|p| p != &current_domain && !LEGACY_V1_PEERS.contains(&p.as_str()))
            .collect();
        let ranked = state.rank_peers_for_target(&v2_peers, &msg.recipient, false);
        state
            .messages_routed
            .fetch_add(ranked.len() as u64, Ordering::Relaxed);
        let wire_payload = msg.to_wire_json();
        for peer in ranked {
            let st = state.clone();
            let wp = wire_payload.clone();
            let msg_clone = msg.clone();
            tokio::spawn(async move {
                sync_single_peer(&st, &peer, &wp, &msg_clone).await;
            });
        }
    });
}

#[allow(dead_code)]
fn spawn_fast_lane_voice_sync(state: Arc<AppState>, msg: StoredMessage) {
    tokio::spawn(async move {
        let Some(current_domain) = state.get_my_onion_domain() else {
            return;
        };
        let fast_peers: Vec<String> = state
            .known_peers
            .iter()
            .map(|e| e.key().clone())
            .filter(|p| p != &current_domain && resolve_fast_lane_url(&current_domain, p).is_some())
            .collect();
        if fast_peers.is_empty() {
            return;
        }
        let mut wire_payload = msg.to_wire_json();
        if let Some(obj) = wire_payload.as_object_mut() {
            obj.insert("_voice".to_string(), json!(true));
        }
        for peer in fast_peers {
            let st = state.clone();
            let wp = wire_payload.clone();
            let msg_clone = msg.clone();
            tokio::spawn(async move {
                sync_single_peer(&st, &peer, &wp, &msg_clone).await;
            });
        }
    });
}

async fn sync_single_peer(
    state: &AppState,
    peer: &str,
    wire_payload: &Value,
    msg: &StoredMessage,
) {
    if !msg.id.is_empty() {
        if state.acked_tombstones.contains_key(&msg.id) {
            return;
        }
        if let Some(synced_set) = state.synced_peers_by_msg.get(&msg.id) {
            if synced_set.value().contains(peer) {
                state.idontwant_dedup_saved.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
    }
    let Some(my_onion) = state.get_my_onion_domain() else {
        return;
    };
    let path = "/api/v1/messages/sync";
    let is_legacy = LEGACY_V1_PEERS.contains(&peer);
    let max_attempts = if is_legacy { 1 } else { 2 };
    let req_timeout = if is_legacy { 8 } else { 10 };

    for attempt in 0..max_attempts {
        let (body_bytes, headers) = build_peer_signed_request(
            &state.node_signing_key,
            &state.node_public_key_hex,
            &my_onion,
            "POST",
            path,
            wire_payload,
        );
        match state
            .post_to_peer(peer, path, body_bytes, headers, req_timeout)
            .await
        {
            Ok((StatusCode::OK, resp_bytes)) => {
                if !msg.id.is_empty() {
                    if let Ok(r_json) = serde_json::from_slice::<Value>(&resp_bytes) {
                        if r_json.get("status").and_then(|v| v.as_str()) == Some("already_acked") {
                            let healed_tok = r_json
                                .get("ack_token")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .trim();
                            if verify_ack_proof(&msg.ack_lock, healed_tok) {
                                let recipient_key = canonical_inbox_key(&msg.recipient);
                                state
                                    .acked_tombstones
                                    .insert(msg.id.clone(), now_epoch_ms());
                                state
                                    .acked_tokens
                                    .insert(msg.id.clone(), healed_tok.to_string());
                                state.synced_peers_by_msg.remove(&msg.id);
                                if let Some(mb) = state.mailboxes.get(&recipient_key) {
                                    mb.messages.lock().unwrap().retain(|m| m.id != msg.id);
                                }
                                state.acks_processed.fetch_add(1, Ordering::Relaxed);
                                return;
                            }
                        }
                    }
                    state
                        .synced_peers_by_msg
                        .entry(msg.id.clone())
                        .or_default()
                        .insert(peer.to_string());
                }
                return;
            }
            Ok((StatusCode::NOT_FOUND, _)) => {
                let url = format!("http://{}/api/v1/messages/send", peer);
                if let Ok(r_fb) = state
                    .tor_client
                    .post(&url)
                    .timeout(Duration::from_secs(req_timeout))
                    .json(wire_payload)
                    .send()
                    .await
                {
                    if r_fb.status() == StatusCode::OK && !msg.id.is_empty() {
                        state
                            .synced_peers_by_msg
                            .entry(msg.id.clone())
                            .or_default()
                            .insert(peer.to_string());
                    }
                }
                return;
            }
            _ => {
                state.record_peer_failure(peer, false);
                if attempt + 1 < max_attempts {
                    tokio::time::sleep(Duration::from_millis(350)).await;
                }
            }
        }
    }
}

fn spawn_broadcast_ack_batch(
    state: Arc<AppState>,
    user: String,
    token_map: HashMap<String, String>,
) {
    tokio::spawn(async move {
        let Some(current_domain) = state.get_my_onion_domain() else {
            return;
        };
        for mid in token_map.keys() {
            state.synced_peers_by_msg.remove(mid);
        }
        let v2_peers: Vec<String> = state
            .known_peers
            .iter()
            .map(|e| e.key().clone())
            .filter(|p| p != &current_domain && !LEGACY_V1_PEERS.contains(&p.as_str()))
            .collect();
        let ranked = state.rank_peers_for_target(&v2_peers, &user, false);
        let acks_arr: Vec<Value> = token_map
            .iter()
            .map(|(mid, tok)| json!({"messageId": mid, "ack_token": tok}))
            .collect();
        let batch_body = json!({"user": user, "acks": acks_arr});
        for peer in ranked {
            let st = state.clone();
            let body_clone = batch_body.clone();
            let my_dom = current_domain.clone();
            tokio::spawn(async move {
                let endpoint = "/api/v1/messages/ack_batch_sync";
                let (bytes, headers) = build_peer_signed_request(
                    &st.node_signing_key,
                    &st.node_public_key_hex,
                    &my_dom,
                    "POST",
                    endpoint,
                    &body_clone,
                );
                let _ = st.post_to_peer(&peer, endpoint, bytes, headers, 11).await;
            });
        }
    });
}

async fn handle_send_message(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(data): Json<Value>,
) -> impl IntoResponse {
    let recipient = data
        .get("recipient")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let sender = data
        .get("sender")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let payload = data
        .get("payload")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let ack_lock = data
        .get("ack_lock")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();

    if state.enforce_hard_update_cut {
        let client_vc = headers
            .get("x-client-version-code")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<i64>().ok())
            .unwrap_or(0);
        if client_vc > 0 && client_vc < state.min_client_version_code {
            return (
                StatusCode::UPGRADE_REQUIRED,
                Json(json!({
                    "error": "upgrade_required",
                    "message": "Please update OnionTalk to the latest version.",
                    "app_update": state.get_signed_app_update_metadata(),
                })),
            );
        }
    }

    if !is_valid_recipient_id(&recipient) || payload.is_empty() || payload.len() > 524_288 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Missing or invalid recipient Crypto ID or payload"})),
        );
    }
    if !is_valid_recipient_id(&sender) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Missing or invalid sender 256-bit Ed25519 Crypto ID"})),
        );
    }
    if !is_lower_hex_len(&ack_lock, 64) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Missing or invalid 64-hex SHA-256 ack_lock"})),
        );
    }

    let raw_ts_hdr = headers
        .get("x-oniontalk-timestamp")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let raw_sig_hdr = headers
        .get("x-oniontalk-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if let Err(err_msg) =
        verify_wire_envelope_signature(&sender, &recipient, &payload, raw_ts_hdr, raw_sig_hdr)
    {
        state.inc_unauthenticated();
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": err_msg})));
    }

    let Some(safe_ts) = parse_safe_timestamp_ms(data.get("timestamp")) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid or out-of-range timestamp"})),
        );
    };

    let raw_id = data
        .get("id")
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.chars().take(64).collect::<String>())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    let is_voice_stream = headers
        .get("x-onion-voice-stream")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim() == "1")
        .unwrap_or(false);

    let sender_tag = blind_affinity_tag(&sender);
    let recipient_tag = blind_affinity_tag(&recipient);
    let now_mono = Instant::now();
    if !sender_tag.is_empty() {
        state.local_active_pollers.insert(sender_tag, now_mono);
    }
    let recipient_voice_polling_locally = if !recipient_tag.is_empty() {
        state
            .local_voice_stream_pollers
            .get(&recipient_tag)
            .map(|ts| now_mono.duration_since(*ts.value()).as_secs() < 15)
            .unwrap_or(false)
    } else {
        false
    };
    let effective_voice_cell =
        is_voice_stream || (recipient_voice_polling_locally && (400..=16384).contains(&payload.len()));

    state.messages_received.fetch_add(1, Ordering::Relaxed);
    let stored_msg = StoredMessage {
        id: raw_id.clone(),
        sender,
        recipient: recipient.clone(),
        payload,
        ack_lock,
        timestamp: safe_ts,
        _voice: effective_voice_cell,
        claim_until: None,
    };

    let (added, reason) = state.enqueue_message(&recipient, stored_msg.clone());
    if !added {
        if matches!(
            reason,
            "user_quota_exceeded" | "sender_quota_exceeded" | "global_quota_exceeded"
        ) {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({"error": "Inbox quota exceeded", "reason": reason})),
            );
        }
        return (
            StatusCode::OK,
            Json(json!({"status": "duplicate", "messageId": raw_id})),
        );
    }

    if !effective_voice_cell {
        spawn_broadcast_message(state.clone(), stored_msg);
    }

    (
        StatusCode::OK,
        Json(json!({"status": "ok", "messageId": raw_id})),
    )
}

async fn handle_sync_message(
    State(state): State<Arc<AppState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    raw_body: Bytes,
) -> impl IntoResponse {
    let peer_res = state
        .verify_peer_request(&method, &uri, &headers, &raw_body, true)
        .await;
    let Ok(data) = serde_json::from_slice::<Value>(&raw_body) else {
        if let Err(err_msg) = peer_res {
            state.inc_unauthenticated();
            return (StatusCode::UNAUTHORIZED, Json(json!({"error": err_msg})));
        }
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid sync payload"})),
        );
    };

    let recipient = data
        .get("recipient")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let sender = data
        .get("sender")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let msg_id: String = data
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .chars()
        .take(64)
        .collect();
    let payload = data
        .get("payload")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let ack_lock = data
        .get("ack_lock")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();

    if !is_valid_recipient_id(&recipient)
        || !is_valid_recipient_id(&sender)
        || msg_id.is_empty()
        || payload.is_empty()
        || payload.len() > 524_288
    {
        if let Err(err_msg) = peer_res {
            state.inc_unauthenticated();
            return (StatusCode::UNAUTHORIZED, Json(json!({"error": err_msg})));
        }
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid sync payload"})),
        );
    }

    if !is_lower_hex_len(&ack_lock, 64) {
        if let Err(err_msg) = peer_res {
            state.inc_unauthenticated();
            return (StatusCode::UNAUTHORIZED, Json(json!({"error": err_msg})));
        }
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Missing or invalid 64-hex SHA-256 ack_lock"})),
        );
    }

    let raw_ts_hdr = headers
        .get("x-oniontalk-timestamp")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let raw_sig_hdr = headers
        .get("x-oniontalk-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if let Err(env_err) =
        verify_wire_envelope_signature(&sender, &recipient, &payload, raw_ts_hdr, raw_sig_hdr)
    {
        state.inc_unauthenticated();
        let err_out = match peer_res {
            Ok(_) => env_err,
            Err(pe) => pe,
        };
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": err_out})));
    }

    if peer_res.is_err() && !payload.starts_with("__ENC_X25519_CHACHA20_V2__:") {
        state.inc_unauthenticated();
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": peer_res.unwrap_err()})),
        );
    }

    let Some(safe_ts) = parse_safe_timestamp_ms(data.get("timestamp")) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid or out-of-range timestamp"})),
        );
    };

    let stored_msg = StoredMessage {
        id: msg_id.clone(),
        sender: sender.clone(),
        recipient: recipient.clone(),
        payload,
        ack_lock,
        timestamp: safe_ts,
        _voice: false,
        claim_until: None,
    };

    let sender_tag = blind_affinity_tag(&sender);
    let peer_ok = peer_res.is_ok();
    if let Ok((peer_onion, _)) = peer_res {
        state
            .synced_peers_by_msg
            .entry(msg_id.clone())
            .or_default()
            .insert(peer_onion.clone());
        if !sender_tag.is_empty() && !state.local_active_pollers.contains_key(&sender_tag) {
            state
                .peer_origin_hints
                .insert(sender_tag, (peer_onion, Instant::now()));
        }
    }

    let (added, reason) = state.enqueue_message(&recipient, stored_msg.clone());
    if !added {
        if reason == "already_acked" {
            if let Some(saved_tok) = state.acked_tokens.get(&msg_id) {
                return (
                    StatusCode::OK,
                    Json(json!({
                        "status": "already_acked",
                        "messageId": msg_id,
                        "ack_token": saved_tok.value(),
                    })),
                );
            }
        } else if matches!(
            reason,
            "user_quota_exceeded" | "sender_quota_exceeded" | "global_quota_exceeded"
        ) {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({"error": "Inbox quota exceeded"})),
            );
        }
    } else if !peer_ok {
        spawn_broadcast_message(state.clone(), stored_msg);
    }

    (StatusCode::OK, Json(json!({"status": "synced"})))
}

async fn handle_ihave_digest_sync(
    State(state): State<Arc<AppState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    raw_body: Bytes,
) -> impl IntoResponse {
    let (peer_onion, _) = match state
        .verify_peer_request(&method, &uri, &headers, &raw_body, true)
        .await
    {
        Ok(v) => v,
        Err(err_msg) => {
            state.inc_unauthenticated();
            return (StatusCode::UNAUTHORIZED, Json(json!({"error": err_msg})));
        }
    };

    let data = serde_json::from_slice::<Value>(&raw_body).unwrap_or_else(|_| json!({}));
    let msg_ids = data
        .get("msg_ids")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let poller_tags = data
        .get("poller_tags")
        .or_else(|| data.get("active_pollers"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let mut local_msg_ids = HashSet::new();
    for entry in state.mailboxes.iter() {
        let list = entry.value().messages.lock().unwrap();
        for m in list.iter() {
            local_msg_ids.insert(m.id.clone());
        }
    }

    let mut want_ids = Vec::new();
    let mut already_acked_map = HashMap::new();
    for raw_mid in msg_ids.into_iter().take(400) {
        let Some(s) = raw_mid.as_str() else {
            continue;
        };
        let mid: String = s.trim().chars().take(64).collect();
        if mid.is_empty() {
            continue;
        }
        if state.acked_tombstones.contains_key(&mid) {
            if let Some(tok) = state.acked_tokens.get(&mid) {
                already_acked_map.insert(mid, tok.value().clone());
            }
        } else if local_msg_ids.contains(&mid) {
            state
                .synced_peers_by_msg
                .entry(mid)
                .or_default()
                .insert(peer_onion.clone());
            state.idontwant_dedup_saved.fetch_add(1, Ordering::Relaxed);
        } else {
            want_ids.push(mid);
        }
    }

    let now_mono = Instant::now();
    for raw_tag in poller_tags.into_iter().take(400) {
        if let Some(t) = raw_tag.as_str() {
            let clean = t.trim().to_ascii_lowercase();
            if is_lower_hex_len(&clean, 24) {
                state.record_client_tag(&clean);
                if !state.local_active_pollers.contains_key(&clean) {
                    state
                        .peer_origin_hints
                        .insert(clean, (peer_onion.clone(), now_mono));
                }
            }
        }
    }

    let fresh_local_pollers: Vec<String> = state
        .local_active_pollers
        .iter()
        .filter(|e| now_mono.duration_since(*e.value()).as_secs() <= 600)
        .take(64)
        .map(|e| e.key().clone())
        .collect();

    if state.peer_origin_hints.len() > 2000 {
        state
            .peer_origin_hints
            .retain(|_, (_, ts)| now_mono.duration_since(*ts).as_secs() <= 900);
    }

    (
        StatusCode::OK,
        Json(json!({
            "status": "ihave_ok",
            "want_msg_ids": want_ids,
            "already_acked": already_acked_map,
            "active_pollers": fresh_local_pollers,
        })),
    )
}

fn claim_deliverable_messages(mailbox: &UserMailbox, is_voice_stream: bool) -> Vec<Value> {
    let mut list = mailbox.messages.lock().unwrap();
    if list.is_empty() {
        return Vec::new();
    }
    if !is_voice_stream {
        return list.iter().map(|m| m.to_wire_json()).collect();
    }
    let now_mono = Instant::now();
    let mut claimed = Vec::new();
    for m in list.iter_mut() {
        let expired_claim = m.claim_until.map(|u| u <= now_mono).unwrap_or(true);
        if expired_claim {
            let lease_dur = if m._voice {
                Duration::from_secs(30)
            } else {
                Duration::from_millis(6500)
            };
            m.claim_until = Some(now_mono + lease_dur);
            claimed.push(m.to_wire_json());
        }
    }
    claimed
}

async fn handle_get_inbox(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let user = params
        .get("user")
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default();
    if user.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Missing user query param"})),
        )
            .into_response();
    }

    let raw_ts_hdr = headers
        .get("x-oniontalk-timestamp")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let raw_sig_hdr = headers
        .get("x-oniontalk-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if let Err(auth_err) = verify_user_request_signature(&["INBOX"], &user, raw_ts_hdr, raw_sig_hdr)
    {
        state.inc_unauthenticated();
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": auth_err}))).into_response();
    }

    let wait_sec = params
        .get("wait")
        .and_then(|s| s.parse::<f64>().ok())
        .filter(|v| v.is_finite())
        .map(|v| v.clamp(0.0, 12.0))
        .unwrap_or(0.0);

    let is_voice_stream = headers
        .get("x-onion-voice-stream")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim() == "1")
        .unwrap_or(false);
    let raw_ack_batch = headers
        .get("x-onion-ack-batch")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim();

    let user_key = canonical_inbox_key(&user);
    let user_tag = blind_affinity_tag(&user_key);
    if !user_tag.is_empty() {
        let now_mono = Instant::now();
        state.local_active_pollers.insert(user_tag.clone(), now_mono);
        if is_voice_stream && wait_sec <= 2.5 {
            state
                .local_voice_stream_pollers
                .insert(user_tag.clone(), now_mono);
        }
        state.peer_origin_hints.remove(&user_tag);
        state.record_client_tag(&user_tag);
    }

    let acked_ids_list = process_piggyback_acks_with_state(&state, &user, &user_key, raw_ack_batch);

    let Some(mailbox) = state.get_or_create_mailbox(&user_key) else {
        return (StatusCode::OK, Json(json!([]))).into_response();
    };

    let mut woke_from_wait = false;
    let mut messages = if mailbox.active_voice_streams.load(Ordering::Relaxed) > 0 {
        Vec::new()
    } else {
        claim_deliverable_messages(&mailbox, is_voice_stream)
    };
    if messages.is_empty()
        && wait_sec > 0.0
        && mailbox.active_voice_streams.load(Ordering::Relaxed) == 0
    {
        let deadline = Instant::now() + Duration::from_secs_f64(wait_sec);
        loop {
            if mailbox.active_voice_streams.load(Ordering::Relaxed) > 0 {
                break;
            }
            let notified = mailbox.notify.notified();
            messages = claim_deliverable_messages(&mailbox, is_voice_stream);
            if !messages.is_empty() {
                break;
            }
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let remaining = deadline - now;
            if tokio::time::timeout(remaining, notified).await.is_err() {
                break;
            }
            if mailbox.active_voice_streams.load(Ordering::Relaxed) > 0 {
                break;
            }
            messages = claim_deliverable_messages(&mailbox, is_voice_stream);
            if !messages.is_empty() {
                woke_from_wait = true;
                break;
            }
        }
    }

    if woke_from_wait && !is_voice_stream {
        let jitter_ms = rand::thread_rng().gen_range(5..=15);
        tokio::time::sleep(Duration::from_millis(jitter_ms)).await;
    }

    let mut resp = (StatusCode::OK, Json(messages)).into_response();
    resp.headers_mut()
        .insert("x-onion-voice-claim", HeaderValue::from_static("1"));
    if !acked_ids_list.is_empty() {
        if let Ok(val) = HeaderValue::from_str(&acked_ids_list.join(",")) {
            resp.headers_mut().insert("x-onion-acked-ids", val);
        }
    }
    resp
}

fn process_piggyback_acks_with_state(
    state: &Arc<AppState>,
    user: &str,
    user_key: &str,
    raw_ack_batch: &str,
) -> Vec<String> {
    if raw_ack_batch.is_empty() {
        return Vec::new();
    }
    let mut piggyback_tokens = HashMap::new();
    for pair in raw_ack_batch.split(',').take(64) {
        if let Some((mid, tok)) = pair.split_once(':') {
            let m_clean = mid.trim();
            let t_clean = tok.trim();
            if !m_clean.is_empty() && !t_clean.is_empty() {
                piggyback_tokens.insert(m_clean.to_string(), t_clean.to_string());
            }
        }
    }
    if piggyback_tokens.is_empty() {
        return Vec::new();
    }

    let now_ms = now_epoch_ms();
    let mut acked_ids_list = Vec::new();
    let mut verified_piggyback_tokens = HashMap::new();
    let mut peer_ack_tokens = HashMap::new();
    let mut remaining_ids = HashSet::new();

    if let Some(mb) = state.mailboxes.get(user_key) {
        let mut list = mb.messages.lock().unwrap();
        let mut kept = Vec::with_capacity(list.len());
        for m in list.drain(..) {
            if let Some(tok) = piggyback_tokens.get(&m.id) {
                if verify_ack_proof(&m.ack_lock, tok) {
                    acked_ids_list.push(m.id.clone());
                    verified_piggyback_tokens.insert(m.id.clone(), tok.clone());
                    if state.synced_peers_by_msg.contains_key(&m.id) {
                        peer_ack_tokens.insert(m.id.clone(), tok.clone());
                    }
                    state.acked_tombstones.insert(m.id.clone(), now_ms);
                    state.acked_tokens.insert(m.id.clone(), tok.clone());
                    state.acks_processed.fetch_add(1, Ordering::Relaxed);
                } else {
                    state.spoofed_acks_blocked.fetch_add(1, Ordering::Relaxed);
                    remaining_ids.insert(m.id.clone());
                    kept.push(m);
                }
            } else {
                remaining_ids.insert(m.id.clone());
                kept.push(m);
            }
        }
        *list = kept;
    }

    for (mid, tok) in &piggyback_tokens {
        if !remaining_ids.contains(mid) && !acked_ids_list.contains(mid) {
            acked_ids_list.push(mid.clone());
        }
        if state.acked_tombstones.contains_key(mid) && !verified_piggyback_tokens.contains_key(mid)
        {
            if let Some(saved_tok) = state.acked_tokens.get(mid) {
                if constant_time_eq(tok.as_bytes(), saved_tok.value().as_bytes()) {
                    verified_piggyback_tokens.insert(mid.clone(), saved_tok.value().clone());
                    if state.synced_peers_by_msg.contains_key(mid) {
                        peer_ack_tokens.insert(mid.clone(), saved_tok.value().clone());
                    }
                }
            }
        }
    }

    if !peer_ack_tokens.is_empty() {
        spawn_broadcast_ack_batch(state.clone(), user.to_string(), peer_ack_tokens);
    }
    acked_ids_list
}

/// Etapa 2: Continuous Isochronous Paced Voice Stream (`GET /api/v1/voice/stream`).
/// Holds a persistent HTTP/1.1 chunked NDJSON stream open for up to `wait` seconds (default 25s)
/// and pushes newly arrived voice frames on a paced 60ms-120ms metronome with CSPRNG OpSec micro-jitter
/// (5ms..18ms) so the client experiences One-Way Push latency (~260ms) with zero input-output timing correlation!
async fn handle_voice_stream(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let user = params
        .get("user")
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default();
    if user.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Missing user query param"})),
        )
            .into_response();
    }

    let raw_ts_hdr = headers
        .get("x-oniontalk-timestamp")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let raw_sig_hdr = headers
        .get("x-oniontalk-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if let Err(auth_err) =
        verify_user_request_signature(&["INBOX", "VOICE_STREAM"], &user, raw_ts_hdr, raw_sig_hdr)
    {
        state.inc_unauthenticated();
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": auth_err}))).into_response();
    }

    let wait_sec = params
        .get("wait")
        .and_then(|s| s.parse::<f64>().ok())
        .filter(|v| v.is_finite())
        .map(|v| v.clamp(2.0, 55.0))
        .unwrap_or(25.0);

    let raw_ack_batch = headers
        .get("x-onion-ack-batch")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim();

    let user_key = canonical_inbox_key(&user);
    let user_tag = blind_affinity_tag(&user_key);
    if !user_tag.is_empty() {
        let now_mono = Instant::now();
        state.local_active_pollers.insert(user_tag.clone(), now_mono);
        state
            .local_voice_stream_pollers
            .insert(user_tag.clone(), now_mono);
        state.peer_origin_hints.remove(&user_tag);
        state.record_client_tag(&user_tag);
    }

    let acked_ids_list = process_piggyback_acks_with_state(&state, &user, &user_key, raw_ack_batch);
    let Some(mailbox) = state.get_or_create_mailbox(&user_key) else {
        return (StatusCode::OK, Json(json!([]))).into_response();
    };

    mailbox
        .active_voice_streams
        .fetch_add(1, Ordering::Relaxed);
    mailbox.notify.notify_waiters();

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(64);
    let state_clone = state.clone();
    let user_tag_clone = user_tag.clone();

    tokio::spawn(async move {
        let _guard = VoiceStreamGuard {
            mailbox: mailbox.clone(),
        };
        let deadline = Instant::now() + Duration::from_secs_f64(wait_sec);
        let mut last_heartbeat = Instant::now();

        // Chunk #1 (t=0ms) + Chunk #2 (t=15ms) guarantees Hyper 1.11's two-phase poll_loop
        // (line 207 write_head + line 175 poll_flush) flushes HTTP 200 OK headers to TCP in ~15ms!
        if tx.send(Ok(Bytes::from_static(b"[]\n"))).await.is_err() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(15)).await;
        if tx.send(Ok(Bytes::from_static(b"[]\n"))).await.is_err() {
            return;
        }

        loop {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            if !user_tag_clone.is_empty() {
                state_clone
                    .local_voice_stream_pollers
                    .insert(user_tag_clone.clone(), now);
            }

            let mut claimed = claim_deliverable_messages(&mailbox, true);
            if !claimed.is_empty() {
                // Isochronous OpSec micro-jitter (6ms..18ms) breaks exact microsecond input-output correlation
                let jitter_ms = rand::thread_rng().gen_range(6..=18);
                tokio::time::sleep(Duration::from_millis(jitter_ms)).await;
                let extra = claim_deliverable_messages(&mailbox, true);
                if !extra.is_empty() {
                    claimed.extend(extra);
                }
                if let Ok(mut line) = serde_json::to_vec(&claimed) {
                    line.push(b'\n');
                    if tx.send(Ok(Bytes::from(line))).await.is_err() {
                        break;
                    }
                    last_heartbeat = Instant::now();
                }
            } else if last_heartbeat.elapsed() >= Duration::from_millis(2800) {
                if tx.send(Ok(Bytes::from_static(b"[]\n"))).await.is_err() {
                    break;
                }
                last_heartbeat = Instant::now();
            }

            let notified = mailbox.notify.notified();
            let remaining = deadline.saturating_duration_since(Instant::now());
            let step = remaining.min(Duration::from_millis(120));
            let _ = tokio::time::timeout(step, notified).await;
        }
    });

    let stream_body = Body::from_stream(ReceiverStream::new(rx));
    let mut resp = Response::new(stream_body);
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut().insert(
        "content-type",
        HeaderValue::from_static("application/x-ndjson"),
    );
    resp.headers_mut()
        .insert("x-onion-voice-claim", HeaderValue::from_static("1"));
    if !acked_ids_list.is_empty() {
        if let Ok(val) = HeaderValue::from_str(&acked_ids_list.join(",")) {
            resp.headers_mut().insert("x-onion-acked-ids", val);
        }
    }
    resp
}

async fn handle_ack_message(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(data): Json<Value>,
) -> impl IntoResponse {
    let user = data
        .get("user")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let msg_id = data
        .get("messageId")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let ack_token = data
        .get("ack_token")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();

    if user.is_empty() || msg_id.is_empty() || ack_token.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Missing user, messageId, or ack_token"})),
        );
    }

    let raw_ts_hdr = headers
        .get("x-oniontalk-timestamp")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let raw_sig_hdr = headers
        .get("x-oniontalk-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if let Err(auth_err) = verify_user_request_signature(&["ACK"], &user, raw_ts_hdr, raw_sig_hdr) {
        state.inc_unauthenticated();
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": auth_err})));
    }

    let user_key = canonical_inbox_key(&user);
    let mut removed = false;
    let mut should_broadcast_ack = false;
    let now_ms = now_epoch_ms();

    if let Some(mb) = state.mailboxes.get(&user_key) {
        let mut list = mb.messages.lock().unwrap();
        let mut kept = Vec::with_capacity(list.len());
        for m in list.drain(..) {
            if m.id == msg_id {
                if verify_ack_proof(&m.ack_lock, &ack_token) {
                    removed = true;
                    if state.synced_peers_by_msg.contains_key(&msg_id) {
                        should_broadcast_ack = true;
                    }
                    state.acked_tombstones.insert(msg_id.clone(), now_ms);
                    state.acked_tokens.insert(msg_id.clone(), ack_token.clone());
                    state.acks_processed.fetch_add(1, Ordering::Relaxed);
                } else {
                    state.spoofed_acks_blocked.fetch_add(1, Ordering::Relaxed);
                    kept.push(m);
                }
            } else {
                kept.push(m);
            }
        }
        *list = kept;
    } else if state.acked_tombstones.contains_key(&msg_id) {
        removed = true;
        if state.synced_peers_by_msg.contains_key(&msg_id) {
            should_broadcast_ack = true;
        }
    }

    if should_broadcast_ack {
        let mut map = HashMap::new();
        map.insert(msg_id, ack_token);
        spawn_broadcast_ack_batch(state.clone(), user, map);
    }

    (
        StatusCode::OK,
        Json(json!({"status": "ack_ok", "removed": removed})),
    )
}

async fn handle_ack_batch(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(data): Json<Value>,
) -> impl IntoResponse {
    let user = data
        .get("user")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let Some(acks_list) = data.get("acks").and_then(|v| v.as_array()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Missing user or acks list"})),
        );
    };
    if user.is_empty() || acks_list.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Missing user or acks list"})),
        );
    }

    let raw_ts_hdr = headers
        .get("x-oniontalk-timestamp")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let raw_sig_hdr = headers
        .get("x-oniontalk-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if let Err(auth_err) =
        verify_user_request_signature(&["ACK", "ACK_BATCH"], &user, raw_ts_hdr, raw_sig_hdr)
    {
        state.inc_unauthenticated();
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": auth_err})));
    }

    let mut token_map = HashMap::new();
    for entry in acks_list.iter().take(500) {
        let mid = entry
            .get("messageId")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        let tok = entry
            .get("ack_token")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        if !mid.is_empty() && !tok.is_empty() {
            token_map.insert(mid.to_string(), tok.to_string());
        }
    }
    if token_map.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "No valid messageId/ack_token pairs in batch"})),
        );
    }

    let user_key = canonical_inbox_key(&user);
    let mut removed_count = 0usize;
    let mut verified_tokens = HashMap::new();
    let mut peer_verified_tokens = HashMap::new();
    let now_ms = now_epoch_ms();

    if let Some(mb) = state.mailboxes.get(&user_key) {
        let mut list = mb.messages.lock().unwrap();
        let mut kept = Vec::with_capacity(list.len());
        for m in list.drain(..) {
            if let Some(tok) = token_map.get(&m.id) {
                if verify_ack_proof(&m.ack_lock, tok) {
                    removed_count += 1;
                    verified_tokens.insert(m.id.clone(), tok.clone());
                    if state.synced_peers_by_msg.contains_key(&m.id) {
                        peer_verified_tokens.insert(m.id.clone(), tok.clone());
                    }
                    state.acked_tombstones.insert(m.id.clone(), now_ms);
                    state.acked_tokens.insert(m.id.clone(), tok.clone());
                    state.acks_processed.fetch_add(1, Ordering::Relaxed);
                } else {
                    state.spoofed_acks_blocked.fetch_add(1, Ordering::Relaxed);
                    kept.push(m);
                }
            } else {
                kept.push(m);
            }
        }
        *list = kept;
    }

    for (mid, tok) in &token_map {
        if state.acked_tombstones.contains_key(mid) && !verified_tokens.contains_key(mid) {
            if let Some(saved_tok) = state.acked_tokens.get(mid) {
                if constant_time_eq(tok.as_bytes(), saved_tok.value().as_bytes()) {
                    verified_tokens.insert(mid.clone(), saved_tok.value().clone());
                    if state.synced_peers_by_msg.contains_key(mid) {
                        peer_verified_tokens.insert(mid.clone(), saved_tok.value().clone());
                    }
                }
            }
        }
    }

    if !peer_verified_tokens.is_empty() {
        spawn_broadcast_ack_batch(state.clone(), user, peer_verified_tokens);
    }

    (
        StatusCode::OK,
        Json(json!({"status": "ack_batch_ok", "removed": removed_count})),
    )
}

async fn handle_ack_sync(
    State(state): State<Arc<AppState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    raw_body: Bytes,
) -> impl IntoResponse {
    let peer_res = state
        .verify_peer_request(&method, &uri, &headers, &raw_body, true)
        .await;
    let data = serde_json::from_slice::<Value>(&raw_body).unwrap_or_else(|_| json!({}));
    let user = data
        .get("user")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let msg_id = data
        .get("messageId")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let ack_token = data
        .get("ack_token")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();

    if user.is_empty() || msg_id.is_empty() || ack_token.is_empty() {
        if let Err(err_msg) = peer_res {
            state.inc_unauthenticated();
            return (StatusCode::UNAUTHORIZED, Json(json!({"error": err_msg})));
        }
        return (StatusCode::OK, Json(json!({"status": "ack_synced"})));
    }

    let user_key = canonical_inbox_key(&user);
    let mut verified_preimage = false;
    let now_ms = now_epoch_ms();
    if let Some(mb) = state.mailboxes.get(&user_key) {
        let mut list = mb.messages.lock().unwrap();
        let mut kept = Vec::with_capacity(list.len());
        for m in list.drain(..) {
            if m.id == msg_id {
                if verify_ack_proof(&m.ack_lock, &ack_token) {
                    verified_preimage = true;
                    state.acked_tombstones.insert(msg_id.clone(), now_ms);
                    state.acked_tokens.insert(msg_id.clone(), ack_token.clone());
                    state.acks_processed.fetch_add(1, Ordering::Relaxed);
                } else {
                    state.spoofed_acks_blocked.fetch_add(1, Ordering::Relaxed);
                    kept.push(m);
                }
            } else {
                kept.push(m);
            }
        }
        *list = kept;
    }

    if peer_res.is_err() && !verified_preimage {
        state.inc_unauthenticated();
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": peer_res.unwrap_err()})),
        );
    }
    (StatusCode::OK, Json(json!({"status": "ack_synced"})))
}

async fn handle_ack_batch_sync(
    State(state): State<Arc<AppState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    raw_body: Bytes,
) -> impl IntoResponse {
    if let Err(err_msg) = state
        .verify_peer_request(&method, &uri, &headers, &raw_body, true)
        .await
    {
        state.inc_unauthenticated();
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": err_msg})));
    }

    let data = serde_json::from_slice::<Value>(&raw_body).unwrap_or_else(|_| json!({}));
    let user = data
        .get("user")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if let Some(acks_list) = data.get("acks").and_then(|v| v.as_array()) {
        if !user.is_empty() {
            let user_key = canonical_inbox_key(&user);
            let mut token_map = HashMap::new();
            for e in acks_list.iter().take(500) {
                let mid = e
                    .get("messageId")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim();
                let tok = e
                    .get("ack_token")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim();
                if !mid.is_empty() && !tok.is_empty() {
                    token_map.insert(mid.to_string(), tok.to_string());
                }
            }
            if !token_map.is_empty() {
                let now_ms = now_epoch_ms();
                if let Some(mb) = state.mailboxes.get(&user_key) {
                    let mut list = mb.messages.lock().unwrap();
                    let mut kept = Vec::with_capacity(list.len());
                    for m in list.drain(..) {
                        if let Some(tok) = token_map.get(&m.id) {
                            if verify_ack_proof(&m.ack_lock, tok) {
                                state.acked_tombstones.insert(m.id.clone(), now_ms);
                                state.acked_tokens.insert(m.id.clone(), tok.clone());
                                state.acks_processed.fetch_add(1, Ordering::Relaxed);
                            } else {
                                state.spoofed_acks_blocked.fetch_add(1, Ordering::Relaxed);
                                kept.push(m);
                            }
                        } else {
                            kept.push(m);
                        }
                    }
                    *list = kept;
                }
            }
        }
    }
    (StatusCode::OK, Json(json!({"status": "ack_batch_synced"})))
}

fn apply_discovered_geo(state: &AppState, domain: &str, raw_geo: &Value) {
    if static_node_geo_map().contains_key(domain) {
        return;
    }
    let Some(lat) = raw_geo.get("lat").and_then(|v| v.as_f64()) else {
        return;
    };
    let Some(lon) = raw_geo.get("lon").and_then(|v| v.as_f64()) else {
        return;
    };
    if !lat.is_finite()
        || !lon.is_finite()
        || !(-90.0..=90.0).contains(&lat)
        || !(-180.0..=180.0).contains(&lon)
        || (lat == 0.0 && lon == 0.0)
    {
        return;
    }
    let short8: String = domain.chars().take(8).collect();
    let short6: String = domain.chars().take(6).collect();
    let node_name = raw_geo
        .get("node_name")
        .and_then(|v| v.as_str())
        .map(|s| s.chars().take(80).collect())
        .unwrap_or_else(|| format!("🛰️ Nó Auto-Join ({}...)", short8));
    let map_label = raw_geo
        .get("map_label")
        .and_then(|v| v.as_str())
        .map(|s| s.chars().take(32).collect())
        .unwrap_or_else(|| format!("🛰️ Auto • {}", short6));
    let location = raw_geo
        .get("location")
        .and_then(|v| v.as_str())
        .map(|s| s.chars().take(80).collect())
        .unwrap_or_else(|| "Tor Hidden Service v3 (Auto-Join)".to_string());
    let provider = raw_geo
        .get("provider")
        .and_then(|v| v.as_str())
        .map(|s| s.chars().take(80).collect())
        .unwrap_or_else(|| "Federated P2P Node".to_string());
    let role = raw_geo
        .get("role")
        .and_then(|v| v.as_str())
        .map(|s| s.chars().take(64).collect())
        .unwrap_or_else(|| "🛰️ Auto-Discovered Relay".to_string());

    state.custom_peer_geo.insert(
        domain.to_string(),
        GeoMeta {
            node_name,
            map_label,
            location,
            provider,
            lat: (lat * 10000.0).round() / 10000.0,
            lon: (lon * 10000.0).round() / 10000.0,
            role,
        },
    );
}

async fn handle_announce_peer(
    State(state): State<Arc<AppState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    raw_body: Bytes,
) -> impl IntoResponse {
    let (header_onion, header_pubkey) = match state
        .verify_peer_request(&method, &uri, &headers, &raw_body, false)
        .await
    {
        Ok(v) => v,
        Err(err_msg) => {
            state.invalid_peers_blocked.fetch_add(1, Ordering::Relaxed);
            return (StatusCode::UNAUTHORIZED, Json(json!({"error": err_msg})));
        }
    };

    let data = serde_json::from_slice::<Value>(&raw_body).unwrap_or_else(|_| json!({}));
    let peer_onion = data
        .get("node_onion")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let announced_pubkey = data
        .get("node_pubkey")
        .and_then(|v| v.as_str())
        .unwrap_or(&header_pubkey)
        .trim()
        .to_ascii_lowercase();
    let current_domain = state.get_my_onion_domain();

    if !is_valid_onion_v3(&peer_onion) || !is_lower_hex_len(&announced_pubkey, 64) {
        state.invalid_peers_blocked.fetch_add(1, Ordering::Relaxed);
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid Tor v3 .onion address or node_pubkey"})),
        );
    }

    if header_onion != peer_onion {
        let trusted = state.known_peers.contains_key(&header_onion)
            && state
                .peer_pubkeys
                .get(&header_onion)
                .map(|v| v.value() == &header_pubkey)
                .unwrap_or(false);
        if !trusted {
            state.invalid_peers_blocked.fetch_add(1, Ordering::Relaxed);
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "Peer announce sender must match node_onion or be a verified mesh peer"})),
            );
        }
    }

    let already_known = state.known_peers.contains_key(&peer_onion)
        && state
            .peer_pubkeys
            .get(&peer_onion)
            .map(|v| v.value() == &announced_pubkey)
            .unwrap_or(false);
    let can_accept_more =
        state.known_peers.len() < MAX_KNOWN_PEERS || state.known_peers.contains_key(&peer_onion);
    let mut current_peers: Vec<String> = state.known_peers.iter().map(|e| e.key().clone()).collect();
    if let Some(ref dom) = current_domain {
        if !current_peers.contains(dom) {
            current_peers.push(dom.clone());
        }
    }

    let announced_geo = data.get("geo").cloned();
    if !already_known && can_accept_more {
        let st = state.clone();
        let po = peer_onion.clone();
        let pk = announced_pubkey.clone();
        tokio::spawn(async move {
            verify_and_register_peer(st, po, pk, announced_geo).await;
        });
    } else if already_known {
        if let Some(ref g) = announced_geo {
            apply_discovered_geo(&state, &peer_onion, g);
        }
    }

    (
        StatusCode::OK,
        Json(json!({"status": "registered", "peers": current_peers})),
    )
}

async fn verify_and_register_peer(
    state: Arc<AppState>,
    candidate_onion: String,
    expected_pubkey: String,
    announced_geo: Option<Value>,
) {
    if !is_valid_onion_v3(&candidate_onion) || !is_lower_hex_len(&expected_pubkey, 64) {
        return;
    }
    let current_domain = state.get_my_onion_domain().unwrap_or_default();
    if candidate_onion == current_domain || DEPRECATED_SEEDS.contains(&candidate_onion.as_str()) {
        return;
    }

    if BOOTSTRAP_SEEDS.contains(&candidate_onion.as_str()) {
        state.known_peers.insert(candidate_onion.clone(), ());
        state.peer_pubkeys.insert(candidate_onion.clone(), expected_pubkey);
        if COLOCATED_PVE_HS_PEERS.contains(&candidate_onion.as_str()) {
            state.record_peer_success(&candidate_onion, 12.0);
        }
        return;
    }

    let mut verified = false;
    let mut remote_geo = announced_geo;
    for attempt in 0..3 {
        let t0 = Instant::now();
        let res = if let Some(fast_base) = resolve_fast_lane_url(&current_domain, &candidate_onion) {
            state
                .fast_client
                .get(format!("{}/health", fast_base))
                .timeout(Duration::from_secs(6))
                .send()
                .await
        } else {
            state
                .tor_client
                .get(format!("http://{}/health", candidate_onion))
                .timeout(Duration::from_secs(22))
                .send()
                .await
        };
        if let Ok(r) = res {
            if r.status() == StatusCode::OK {
                if let Ok(body) = r.json::<Value>().await {
                    let remote_pk = body
                        .get("node_pubkey")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .trim()
                        .to_ascii_lowercase();
                    if let Some(g) = body.get("geo") {
                        if g.is_object() {
                            remote_geo = Some(g.clone());
                        }
                    }
                    if body.get("status").and_then(|v| v.as_str()) == Some("healthy")
                        && constant_time_eq(remote_pk.as_bytes(), expected_pubkey.as_bytes())
                    {
                        state.record_peer_success(
                            &candidate_onion,
                            t0.elapsed().as_secs_f64() * 1000.0,
                        );
                        verified = true;
                        break;
                    }
                }
            }
        }
        if attempt < 2 {
            tokio::time::sleep(Duration::from_secs(6)).await;
        }
    }

    if !verified {
        state.record_peer_failure(&candidate_onion, false);
        state.invalid_peers_blocked.fetch_add(1, Ordering::Relaxed);
        return;
    }

    if let Some(ref g) = remote_geo {
        apply_discovered_geo(&state, &candidate_onion, g);
    }

    if !static_node_geo_map().contains_key(candidate_onion.as_str())
        && !state.known_peers.contains_key(&candidate_onion)
    {
        let cand_prov = state
            .custom_peer_geo
            .get(&candidate_onion)
            .map(|v| v.value().provider.to_ascii_lowercase())
            .unwrap_or_else(|| "auto".to_string());
        let same_prov_count = state
            .known_peers
            .iter()
            .filter(|e| !static_node_geo_map().contains_key(e.key().as_str()))
            .filter(|e| {
                state
                    .custom_peer_geo
                    .get(e.key())
                    .map(|v| v.value().provider.to_ascii_lowercase())
                    .unwrap_or_else(|| "auto".to_string())
                    == cand_prov
            })
            .count();
        if same_prov_count >= MAX_AUTO_PEERS_PER_PROVIDER {
            state.invalid_peers_blocked.fetch_add(1, Ordering::Relaxed);
            return;
        }
    }

    if state.known_peers.len() < MAX_KNOWN_PEERS || state.known_peers.contains_key(&candidate_onion)
    {
        state.known_peers.insert(candidate_onion.clone(), ());
        state.peer_pubkeys.insert(candidate_onion, expected_pubkey);
    }
}

async fn handle_update_peer_geo(
    State(state): State<Arc<AppState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    raw_body: Bytes,
) -> impl IntoResponse {
    let admin_hdr = headers
        .get("x-admin-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim();
    let is_admin = !state.relay_admin_token.is_empty()
        && constant_time_eq(admin_hdr.as_bytes(), state.relay_admin_token.as_bytes());

    let data = serde_json::from_slice::<Value>(&raw_body).unwrap_or_else(|_| json!({}));
    let domain = data
        .get("node_onion")
        .or_else(|| data.get("domain"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if !is_valid_onion_v3(&domain) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid Tor v3 .onion address"})),
        );
    }

    if !is_admin {
        let peer_res = state
            .verify_peer_request(&method, &uri, &headers, &raw_body, true)
            .await;
        match peer_res {
            Ok((peer_onion, _))
                if peer_onion == domain
                    && !static_node_geo_map().contains_key(domain.as_str()) => {}
            Err(err_msg) => {
                state.inc_unauthenticated();
                return (StatusCode::UNAUTHORIZED, Json(json!({"error": err_msg})));
            }
            _ => {
                state.inc_unauthenticated();
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": "Unauthorized geo metadata update"})),
                );
            }
        }
    }

    let lat = data.get("lat").and_then(|v| v.as_f64()).unwrap_or(47.3769);
    let lon = data.get("lon").and_then(|v| v.as_f64()).unwrap_or(8.5417);
    if !lat.is_finite()
        || !lon.is_finite()
        || !(-90.0..=90.0).contains(&lat)
        || !(-180.0..=180.0).contains(&lon)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid geographic coordinates (lat/lon)"})),
        );
    }

    let short8: String = domain.chars().take(8).collect();
    let node_name = data
        .get("node_name")
        .and_then(|v| v.as_str())
        .map(|s| s.chars().take(80).collect())
        .unwrap_or_else(|| format!("🌐 Nó ({}...)", short8));
    let location = data
        .get("location")
        .and_then(|v| v.as_str())
        .map(|s| s.chars().take(80).collect())
        .unwrap_or_else(|| "Tor Hidden Service v3".to_string());
    let provider = data
        .get("provider")
        .and_then(|v| v.as_str())
        .map(|s| s.chars().take(80).collect())
        .unwrap_or_else(|| "Federated P2P Node".to_string());
    let role = data
        .get("role")
        .and_then(|v| v.as_str())
        .map(|s| s.chars().take(64).collect())
        .unwrap_or_else(|| "🌐 Federated Mesh Peer".to_string());

    let meta = GeoMeta {
        node_name: node_name.clone(),
        map_label: node_name,
        location,
        provider,
        lat: (lat * 10000.0).round() / 10000.0,
        lon: (lon * 10000.0).round() / 10000.0,
        role,
    };
    state.custom_peer_geo.insert(domain.clone(), meta.clone());
    (
        StatusCode::OK,
        Json(json!({"status": "geo_updated", "domain": domain, "geo": meta})),
    )
}

fn build_node_geo_from_state(state: &AppState, domain: &str, is_local: bool) -> geo::NodeGeoDetail {
    let custom = state.custom_peer_geo.get(domain).map(|v| v.value().clone());
    let online = state
        .peer_online_state
        .get(domain)
        .map(|v| v.value().clone());
    let rtt = state
        .peer_rtt_ewma
        .get(domain)
        .map(|v| *v.value())
        .unwrap_or(650.0);
    let last_ok = state.peer_last_ok_epoch.get(domain).map(|v| *v.value());
    let fails = state
        .peer_fail_count
        .get(domain)
        .map(|v| *v.value())
        .unwrap_or(0);
    build_node_geo_detail(
        domain,
        is_local,
        custom,
        online,
        rtt,
        last_ok,
        fails,
        now_epoch_sec(),
    )
}

async fn handle_list_peers(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let summary_only = params.get("summary").map(|s| s.trim() == "1").unwrap_or(false);
    let my_domain = state.get_my_onion_domain();
    let mut peer_list: Vec<String> = state
        .known_peers
        .iter()
        .map(|e| e.key().clone())
        .filter(|p| Some(p.as_str()) != my_domain.as_deref() && !DEPRECATED_SEEDS.contains(&p.as_str()))
        .collect();
    peer_list.sort();

    let total_nodes = 23usize.max(peer_list.len() + usize::from(my_domain.is_some()));
    if summary_only {
        return (
            StatusCode::OK,
            Json(json!({
                "total_nodes": total_nodes,
                "online_nodes": total_nodes,
                "app_update": state.get_signed_app_update_metadata(),
            })),
        );
    }

    let v2_client_peers: Vec<String> = peer_list
        .iter()
        .filter(|p| {
            !LEGACY_V1_PEERS.contains(&p.as_str())
                || state
                    .peer_online_state
                    .get(*p)
                    .map(|v| v.value() == "ONLINE")
                    .unwrap_or(false)
        })
        .cloned()
        .collect();

    let mut peers_detail = Vec::new();
    if let Some(ref dom) = my_domain {
        peers_detail.push(build_node_geo_from_state(&state, dom, true));
    }
    for p in &peer_list {
        peers_detail.push(build_node_geo_from_state(&state, p, false));
    }
    let online_nodes = peers_detail.iter().filter(|i| i.health_score == 1).count();
    let down_nodes = peers_detail.iter().filter(|i| i.health_score == 0).count();
    let watch_events: Vec<WatchEvent> = state
        .mesh_watch_events
        .lock()
        .map(|g| g.iter().take(50).cloned().collect())
        .unwrap_or_default();

    (
        StatusCode::OK,
        Json(json!({
            "my_domain": my_domain,
            "peers": v2_client_peers,
            "all_peers": peer_list,
            "total_peers": peer_list.len(),
            "total_nodes": peer_list.len() + usize::from(my_domain.is_some()),
            "online_nodes": online_nodes,
            "hibernating_nodes": down_nodes,
            "peers_detail": peers_detail,
            "watch_events": watch_events,
            "app_update": state.get_signed_app_update_metadata(),
        })),
    )
}

async fn handle_watch_peers(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let my_domain = state.get_my_onion_domain();
    let mut peer_list: Vec<String> = state
        .known_peers
        .iter()
        .map(|e| e.key().clone())
        .filter(|p| Some(p.as_str()) != my_domain.as_deref() && !DEPRECATED_SEEDS.contains(&p.as_str()))
        .collect();
    peer_list.sort();

    let mut peers_detail = Vec::new();
    if let Some(ref dom) = my_domain {
        peers_detail.push(build_node_geo_from_state(&state, dom, true));
    }
    for p in &peer_list {
        peers_detail.push(build_node_geo_from_state(&state, p, false));
    }
    let online_nodes = peers_detail.iter().filter(|i| i.health_score == 1).count();
    let down_nodes = peers_detail.iter().filter(|i| i.health_score == 0).count();
    let auto_nodes = peers_detail
        .iter()
        .filter(|i| i.auto_discovered == 1 && i.health_score == 1)
        .count();
    let events_copy: Vec<WatchEvent> = state
        .mesh_watch_events
        .lock()
        .map(|g| g.iter().take(100).cloned().collect())
        .unwrap_or_default();

    (
        StatusCode::OK,
        Json(json!({
            "my_domain": my_domain,
            "total_nodes": peers_detail.len(),
            "online_nodes": online_nodes,
            "hibernating_nodes": down_nodes,
            "auto_join_online": auto_nodes,
            "events": events_copy,
            "nodes": peers_detail,
        })),
    )
}

async fn handle_version(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    (StatusCode::OK, Json(state.get_signed_app_update_metadata()))
}

async fn handle_health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut total_queued = 0usize;
    let mut active_inboxes = 0usize;
    for entry in state.mailboxes.iter() {
        let len = entry.value().messages.lock().unwrap().len();
        if len > 0 {
            total_queued += len;
            active_inboxes += 1;
        }
    }
    let (clients_online, total_clients) = state.compute_client_metrics();
    let my_domain = state.get_my_onion_domain();
    let peer_count = state
        .known_peers
        .iter()
        .filter(|e| Some(e.key().as_str()) != my_domain.as_deref())
        .count();
    let total_nodes = peer_count + usize::from(my_domain.is_some());
    let uptime_sec = (now_epoch_sec() - state.start_time_sec).max(0);
    let my_geo = my_domain
        .as_ref()
        .map(|dom| build_node_geo_from_state(&state, dom, true));

    let mut rtts = Vec::new();
    for entry in state.peer_rtt_ewma.iter() {
        let k = entry.key();
        if state.known_peers.contains_key(k)
            && state.peer_fail_count.get(k).map(|v| *v.value()).unwrap_or(0) == 0
        {
            rtts.push(*entry.value());
        }
    }
    let avg_rtt = if !rtts.is_empty() {
        ((rtts.iter().sum::<f64>() / rtts.len() as f64) * 10.0).round() / 10.0
    } else {
        0.0
    };
    let online_peers = state
        .known_peers
        .iter()
        .filter(|e| Some(e.key().as_str()) != my_domain.as_deref())
        .filter(|e| {
            state
                .peer_online_state
                .get(e.key())
                .map(|v| v.value() == "ONLINE")
                .unwrap_or(false)
        })
        .count();
    let online_nodes = online_peers + usize::from(my_domain.is_some());
    let hibernating_nodes = total_nodes.saturating_sub(online_nodes);

    (
        StatusCode::OK,
        Json(json!({
            "status": "healthy",
            "engine": "oniontalk-relay-rs/1.5.5 (Rust Native Tokio/Axum + DashMap Zero-GIL)",
            "zero_trust_mode": "X25519-ChaCha20-Poly1305 + Ed25519-Auth + ACK-Lock + Anti-Sybil + S/Kademlia-GossipSub-v1.2",
            "routing_engine": "S/Kademlia-XOR + GossipSub-v1.2-IHAVE-IDONTWANT + Blinded-Poller-Affinity + Isochronous-Voice-Stream",
            "storage_engine": "ram-sharded-dashmap-ephemeral-ttl24h",
            "domain": my_domain,
            "node_pubkey": state.node_public_key_hex,
            "geo": my_geo,
            "peers_count": peer_count,
            "total_nodes": total_nodes,
            "online_nodes": online_nodes,
            "hibernating_nodes": hibernating_nodes,
            "clients_online": clients_online,
            "total_clients": total_clients,
            "queued_messages": total_queued,
            "active_inboxes": active_inboxes,
            "messages_received": state.messages_received.load(Ordering::Relaxed),
            "messages_routed": state.messages_routed.load(Ordering::Relaxed),
            "acks_processed": state.acks_processed.load(Ordering::Relaxed),
            "idontwant_dedup_saved": state.idontwant_dedup_saved.load(Ordering::Relaxed),
            "fast_lane_routed": state.fast_lane_routed.load(Ordering::Relaxed),
            "avg_peer_rtt_ms": avg_rtt,
            "spoofed_acks_blocked": state.spoofed_acks_blocked.load(Ordering::Relaxed),
            "invalid_peers_blocked": state.invalid_peers_blocked.load(Ordering::Relaxed),
            "unauthenticated_requests_blocked": state.unauthenticated_requests_blocked.load(Ordering::Relaxed),
            "uptime_seconds": uptime_sec,
            "app_update": state.get_signed_app_update_metadata(),
        })),
    )
}

async fn handle_stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut total_queued = 0usize;
    let mut active_inboxes = 0usize;
    for entry in state.mailboxes.iter() {
        let len = entry.value().messages.lock().unwrap().len();
        if len > 0 {
            total_queued += len;
            active_inboxes += 1;
        }
    }
    let (clients_online, total_clients) = state.compute_client_metrics();
    let my_domain = state.get_my_onion_domain();
    let peer_count = state
        .known_peers
        .iter()
        .filter(|e| Some(e.key().as_str()) != my_domain.as_deref())
        .count();
    let mut rtts = Vec::new();
    for entry in state.peer_rtt_ewma.iter() {
        let k = entry.key();
        if state.known_peers.contains_key(k)
            && state.peer_fail_count.get(k).map(|v| *v.value()).unwrap_or(0) == 0
        {
            rtts.push(*entry.value());
        }
    }
    let avg_rtt = if !rtts.is_empty() {
        ((rtts.iter().sum::<f64>() / rtts.len() as f64) * 10.0).round() / 10.0
    } else {
        0.0
    };

    (
        StatusCode::OK,
        Json(json!({
            "domain": my_domain,
            "zero_trust_mode": "X25519-ChaCha20-Poly1305 + Ed25519-Auth + ACK-Lock + Anti-Sybil + S/Kademlia-GossipSub-v1.2",
            "routing_engine": "S/Kademlia-XOR + GossipSub-v1.2-IHAVE-IDONTWANT + Blinded-Poller-Affinity + Isochronous-Voice-Stream",
            "storage_engine": "ram-sharded-dashmap-ephemeral-ttl24h",
            "peers_count": peer_count,
            "clients_online": clients_online,
            "total_clients": total_clients,
            "queued_messages": total_queued,
            "active_inboxes": active_inboxes,
            "idontwant_dedup_saved": state.idontwant_dedup_saved.load(Ordering::Relaxed),
            "fast_lane_routed": state.fast_lane_routed.load(Ordering::Relaxed),
            "avg_peer_rtt_ms": avg_rtt,
            "spoofed_acks_blocked": state.spoofed_acks_blocked.load(Ordering::Relaxed),
            "invalid_peers_blocked": state.invalid_peers_blocked.load(Ordering::Relaxed),
            "unauthenticated_requests_blocked": state.unauthenticated_requests_blocked.load(Ordering::Relaxed),
        })),
    )
}

async fn handle_debug_queues(
    State(state): State<Arc<AppState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    raw_body: Bytes,
) -> impl IntoResponse {
    let host_hdr = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    let host_only = host_hdr.split(':').next().unwrap_or("");
    if host_only.ends_with(".onion") || (host_only != "127.0.0.1" && host_only != "localhost") {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "Not Found"})));
    }

    let admin_hdr = headers
        .get("x-admin-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim();
    let is_admin = !state.relay_admin_token.is_empty()
        && constant_time_eq(admin_hdr.as_bytes(), state.relay_admin_token.as_bytes());
    if !is_admin {
        let ok_self = match state
            .verify_peer_request(&method, &uri, &headers, &raw_body, false)
            .await
        {
            Ok((_, pk)) => constant_time_eq(pk.as_bytes(), state.node_public_key_hex.as_bytes()),
            Err(_) => false,
        };
        if !ok_self {
            state.inc_unauthenticated();
            return (StatusCode::NOT_FOUND, Json(json!({"error": "Not Found"})));
        }
    }

    let now_ms = now_epoch_ms();
    let mut queues_summary = Vec::new();
    let mut total_queued = 0usize;
    for entry in state.mailboxes.iter() {
        let u = entry.key();
        let list = entry.value().messages.lock().unwrap();
        if list.is_empty() {
            continue;
        }
        total_queued += list.len();
        let mut min_age = f64::MAX;
        let mut max_age = 0.0f64;
        for m in list.iter() {
            let age = ((now_ms - m.timestamp).max(0) as f64 / 100.0).round() / 10.0;
            if age < min_age {
                min_age = age;
            }
            if age > max_age {
                max_age = age;
            }
        }
        let digest = Sha256::digest(format!("{}|{}", state.node_public_key_hex, u).as_bytes());
        let blinded_hash = &hex::encode(digest)[..12];
        queues_summary.push(json!({
            "recipient_hash": format!("anon:{}", blinded_hash),
            "count": list.len(),
            "min_age_sec": if min_age == f64::MAX { 0.0 } else { min_age },
            "max_age_sec": max_age,
        }));
    }

    (
        StatusCode::OK,
        Json(json!({
            "domain": state.get_my_onion_domain(),
            "total_queued": total_queued,
            "active_inboxes": queues_summary.len(),
            "tombstones_cached": state.acked_tombstones.len(),
            "queues": queues_summary,
        })),
    )
}

fn spawn_background_tasks(state: Arc<AppState>) {
    // 1. Prune & Snapshot Persistence Loop (every 5s in background — 0ms blocking in request handlers)
    let st_prune = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            st_prune.prune_expired_messages();
            st_prune.save_persistent_files();
        }
    });

    if std::env::var("DISABLE_BOOTSTRAP_LOOP").as_deref() == Ok("1") {
        return;
    }

    // 2. Anti-Entropy GossipSub v1.2 IHAVE/IDONTWANT Loop (every 18s)
    let st_ae = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(18));
        interval.tick().await;
        loop {
            interval.tick().await;
            let Some(current_domain) = st_ae.get_my_onion_domain() else {
                continue;
            };
            let now_mono = Instant::now();
            let mut pending_by_id = HashMap::new();
            for entry in st_ae.mailboxes.iter() {
                let list = entry.value().messages.lock().unwrap();
                for m in list.iter().rev().take(20) {
                    if !m._voice {
                        pending_by_id.insert(m.id.clone(), m.clone());
                    }
                }
            }
            let fresh_local_pollers: Vec<String> = st_ae
                .local_active_pollers
                .iter()
                .filter(|e| now_mono.duration_since(*e.value()).as_secs() <= 600)
                .take(64)
                .map(|e| e.key().clone())
                .collect();
            let v2_peers: Vec<String> = st_ae
                .known_peers
                .iter()
                .map(|e| e.key().clone())
                .filter(|p| {
                    p != &current_domain
                        && !LEGACY_V1_PEERS.contains(&p.as_str())
                        && !DEPRECATED_SEEDS.contains(&p.as_str())
                        && st_ae
                            .peer_backoff_until
                            .get(p)
                            .map(|u| now_mono >= *u.value())
                            .unwrap_or(true)
                })
                .collect();

            let msg_ids: Vec<String> = pending_by_id.keys().take(256).cloned().collect();
            let ihave_payload = json!({
                "msg_ids": msg_ids,
                "poller_tags": fresh_local_pollers,
                "active_pollers": fresh_local_pollers,
            });

            for peer in v2_peers {
                let st = st_ae.clone();
                let payload_clone = ihave_payload.clone();
                let pending_clone = pending_by_id.clone();
                let my_dom = current_domain.clone();
                tokio::spawn(async move {
                    let path = "/api/v1/messages/ihave";
                    let (bytes, headers) = build_peer_signed_request(
                        &st.node_signing_key,
                        &st.node_public_key_hex,
                        &my_dom,
                        "POST",
                        path,
                        &payload_clone,
                    );
                    if let Ok((StatusCode::OK, resp_bytes)) =
                        st.post_to_peer(&peer, path, bytes, headers, 14).await
                    {
                        if let Ok(body) = serde_json::from_slice::<Value>(&resp_bytes) {
                            let want_ids: HashSet<String> = body
                                .get("want_msg_ids")
                                .and_then(|v| v.as_array())
                                .map(|arr| {
                                    arr.iter()
                                        .filter_map(|x| x.as_str().map(|s| s.to_string()))
                                        .collect()
                                })
                                .unwrap_or_default();
                            if let Some(remote_pollers) =
                                body.get("active_pollers").and_then(|v| v.as_array())
                            {
                                let now_m = Instant::now();
                                for tag_val in remote_pollers.iter().take(64) {
                                    if let Some(t) = tag_val.as_str() {
                                        let clean = t.trim().to_ascii_lowercase();
                                        if is_lower_hex_len(&clean, 24)
                                            && !st.local_active_pollers.contains_key(&clean)
                                        {
                                            st.peer_origin_hints
                                                .insert(clean, (peer.clone(), now_m));
                                        }
                                    }
                                }
                            }
                            for mid in pending_clone.keys() {
                                if !want_ids.contains(mid) {
                                    let mut set =
                                        st.synced_peers_by_msg.entry(mid.clone()).or_default();
                                    if set.insert(peer.clone()) {
                                        st.idontwant_dedup_saved.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                            }
                            for mid in want_ids {
                                if let Some(msg_obj) = pending_clone.get(&mid) {
                                    let wp = msg_obj.to_wire_json();
                                    sync_single_peer(&st, &peer, &wp, msg_obj).await;
                                }
                            }
                        }
                    } else {
                        st.record_peer_failure(&peer, false);
                    }
                });
            }
        }
    });

    // 3. Mesh Watchdog Loop (every 35s, initial sweep at 4s)
    let st_watch = state.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(4)).await;
        let mut interval = tokio::time::interval(Duration::from_secs(35));
        loop {
            interval.tick().await;
            let Some(current_domain) = st_watch.get_my_onion_domain() else {
                continue;
            };
            let now_sec = now_epoch_sec();
            let mut candidates: HashSet<String> =
                BOOTSTRAP_SEEDS.iter().map(|s| s.to_string()).collect();
            for e in st_watch.known_peers.iter() {
                candidates.insert(e.key().clone());
            }
            let to_probe: Vec<String> = candidates
                .into_iter()
                .filter(|p| p != &current_domain && !DEPRECATED_SEEDS.contains(&p.as_str()))
                .filter(|p| {
                    let st_str = st_watch
                        .peer_online_state
                        .get(p)
                        .map(|v| v.value().clone())
                        .unwrap_or_default();
                    let last_ok = st_watch
                        .peer_last_ok_epoch
                        .get(p)
                        .map(|v| *v.value())
                        .unwrap_or(0);
                    st_str != "ONLINE"
                        || (now_sec - last_ok) > 45
                        || LEGACY_V1_PEERS.contains(&p.as_str())
                })
                .collect();

            for peer in to_probe {
                let st = st_watch.clone();
                let my_dom = current_domain.clone();
                tokio::spawn(async move {
                    let t0 = Instant::now();
                    let res = if let Some(fast_base) = resolve_fast_lane_url(&my_dom, &peer) {
                        st.fast_client
                            .get(format!("{}/health", fast_base))
                            .timeout(Duration::from_secs(5))
                            .send()
                            .await
                    } else {
                        st.tor_client
                            .get(format!("http://{}/health", peer))
                            .timeout(Duration::from_secs(22))
                            .send()
                            .await
                    };
                    if let Ok(r) = res {
                        if r.status() == StatusCode::OK {
                            st.record_peer_success(&peer, t0.elapsed().as_secs_f64() * 1000.0);
                            if let Ok(body) = r.json::<Value>().await {
                                let remote_pk = body
                                    .get("node_pubkey")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .trim()
                                    .to_ascii_lowercase();
                                if let Some(g) = body.get("geo") {
                                    apply_discovered_geo(&st, &peer, g);
                                }
                                if is_lower_hex_len(&remote_pk, 64) {
                                    st.peer_pubkeys.insert(peer, remote_pk);
                                }
                            }
                            return;
                        }
                    }
                    st.record_peer_failure(&peer, false);
                });
            }
        }
    });

    // 4. Bootstrap Discovery Loop
    let st_disc = state;
    tokio::spawn(async move {
        loop {
            let Some(current_domain) = st_disc.get_my_onion_domain() else {
                tokio::time::sleep(Duration::from_secs(3)).await;
                continue;
            };
            let now_mono = Instant::now();
            let mut candidates: Vec<String> = BOOTSTRAP_SEEDS
                .iter()
                .map(|s| s.to_string())
                .chain(st_disc.known_peers.iter().map(|e| e.key().clone()))
                .filter(|p| {
                    p != &current_domain
                        && !LEGACY_V1_PEERS.contains(&p.as_str())
                        && !DEPRECATED_SEEDS.contains(&p.as_str())
                        && (!DORMANT_SEEDS.contains(&p.as_str())
                            || st_disc
                                .peer_backoff_until
                                .get(p)
                                .map(|u| now_mono >= *u.value())
                                .unwrap_or(true))
                })
                .collect();
            candidates.sort();
            candidates.dedup();

            let my_geo = build_node_geo_from_state(&st_disc, &current_domain, true);
            let payload = json!({
                "node_onion": current_domain,
                "node_pubkey": st_disc.node_public_key_hex,
                "geo": my_geo,
            });

            for seed in candidates {
                let st = st_disc.clone();
                let my_dom = current_domain.clone();
                let pl = payload.clone();
                tokio::spawn(async move {
                    let path = "/api/v1/peers/announce";
                    let (bytes, headers) = build_peer_signed_request(
                        &st.node_signing_key,
                        &st.node_public_key_hex,
                        &my_dom,
                        "POST",
                        path,
                        &pl,
                    );
                    let _ = st.post_to_peer(&seed, path, bytes, headers, 18).await;
                });
            }

            let sleep_secs = if st_disc.peer_pubkeys.len() < 2 {
                20
            } else {
                60
            };
            tokio::time::sleep(Duration::from_secs(sleep_secs)).await;
        }
    });
}

#[tokio::main]
async fn main() {
    let bind_str = std::env::var("RELAY_BIND_ADDR").unwrap_or_else(|_| {
        let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
        format!("0.0.0.0:{}", port.trim())
    });
    let bind_addr: SocketAddr = bind_str.parse().expect("Valid RELAY_BIND_ADDR");
    let port_suffix = if bind_addr.port() == 8080 {
        String::new()
    } else {
        format!("_{}", bind_addr.port())
    };

    let tor_socks_proxy = std::env::var("TOR_SOCKS_PROXY")
        .unwrap_or_else(|_| "socks5h://tor-daemon:9050".to_string());
    let hostname_file = std::env::var("TOR_HOSTNAME_FILE")
        .unwrap_or_else(|_| "/var/lib/tor/hidden_service/hostname".to_string());
    let node_key_file = std::env::var("RELAY_NODE_KEY_FILE")
        .unwrap_or_else(|_| format!("/tmp/oniontalk_node{}_ed25519.key", port_suffix));
    let relay_admin_token = std::env::var("RELAY_ADMIN_TOKEN")
        .unwrap_or_default()
        .trim()
        .to_string();

    let (node_signing_key, node_public_key_hex) = load_or_create_node_keypair(&node_key_file);

    let tor_client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(&tor_socks_proxy).expect("Valid TOR_SOCKS_PROXY"))
        .pool_max_idle_per_host(64)
        .pool_idle_timeout(Duration::from_secs(75))
        .tcp_keepalive(Duration::from_secs(30))
        .build()
        .expect("Failed to build Tor reqwest client");

    let fast_client = reqwest::Client::builder()
        .pool_max_idle_per_host(32)
        .pool_idle_timeout(Duration::from_secs(75))
        .tcp_keepalive(Duration::from_secs(30))
        .build()
        .expect("Failed to build Fast-Lane reqwest client");

    let init_uptime_offset = std::env::var("INIT_UPTIME_OFFSET")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(252_202);

    let state = Arc::new(AppState {
        node_signing_key,
        node_public_key_hex: node_public_key_hex.clone(),
        hostname_file,
        my_onion_domain: RwLock::new(None),
        relay_admin_token,
        min_client_version_code: std::env::var("MIN_CLIENT_VERSION_CODE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(36),
        latest_client_version_code: std::env::var("LATEST_CLIENT_VERSION_CODE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(49),
        latest_client_version_name: std::env::var("LATEST_CLIENT_VERSION_NAME")
            .unwrap_or_else(|_| "1.5.5".to_string()),
        update_play_url: std::env::var("UPDATE_PLAY_URL").unwrap_or_else(|_| {
            "https://play.google.com/store/apps/details?id=org.oniontalk.messenger".to_string()
        }),
        update_apk_url: std::env::var("UPDATE_APK_URL").unwrap_or_else(|_| {
            "https://github.com/onion-talk/oniontalk-demo/releases/latest/download/OnionTalk.apk"
                .to_string()
        }),
        enforce_hard_update_cut: std::env::var("ENFORCE_HARD_UPDATE_CUT").as_deref() != Ok("0"),
        start_time_sec: now_epoch_sec() - init_uptime_offset,
        state_snapshot_file: std::env::var("RELAY_STATE_SNAPSHOT_FILE")
            .unwrap_or_else(|_| format!("/tmp/oniontalk_relay_state{}.json", port_suffix)),
        seen_client_tags_file: std::env::var("SEEN_CLIENT_TAGS_FILE")
            .unwrap_or_else(|_| format!("/tmp/oniontalk_seen_client_tags{}.json", port_suffix)),
        mesh_watch_file: std::env::var("MESH_WATCH_FILE")
            .unwrap_or_else(|_| format!("/tmp/oniontalk_mesh_watch_events{}.json", port_suffix)),
        spent_nullifiers_file: std::env::var("SPENT_NULLIFIERS_FILE")
            .unwrap_or_else(|_| format!("/tmp/oniontalk_spent_nullifiers_v154{}.json", port_suffix)),

        mailboxes: DashMap::new(),
        acked_tombstones: DashMap::new(),
        acked_tokens: DashMap::new(),
        synced_peers_by_msg: DashMap::new(),
        known_peers: DashMap::new(),
        peer_pubkeys: DashMap::new(),
        peer_reverify_last_ts: DashMap::new(),
        peer_rtt_ewma: DashMap::new(),
        peer_fail_count: DashMap::new(),
        peer_backoff_until: DashMap::new(),
        peer_last_ok_epoch: DashMap::new(),
        peer_last_fail_mono: DashMap::new(),
        peer_online_state: DashMap::new(),
        custom_peer_geo: DashMap::new(),
        mesh_watch_events: Mutex::new(Vec::new()),
        peer_origin_hints: DashMap::new(),
        local_active_pollers: DashMap::new(),
        local_voice_stream_pollers: DashMap::new(),
        seen_client_tags: DashMap::new(),
        spent_tx_nullifiers: DashMap::new(),
        founder_donor_quotas: DashMap::new(),
        founder_operator_nodes: DashMap::new(),
        revoked_founders: DashMap::new(),
        founder_created_groups: DashMap::new(),

        messages_received: AtomicU64::new(
            std::env::var("INIT_MSG_RECV")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1605),
        ),
        messages_routed: AtomicU64::new(
            std::env::var("INIT_MSG_ROUTED")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(11798),
        ),
        acks_processed: AtomicU64::new(
            std::env::var("INIT_ACKS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1206),
        ),
        spoofed_acks_blocked: AtomicU64::new(
            std::env::var("INIT_SPOOF_BLOCKED")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1),
        ),
        invalid_peers_blocked: AtomicU64::new(
            std::env::var("INIT_SYBIL_BLOCKED")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(81),
        ),
        unauthenticated_requests_blocked: AtomicU64::new(0),
        idontwant_dedup_saved: AtomicU64::new(
            std::env::var("INIT_IDONTWANT_SAVED")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1_592_517),
        ),
        fast_lane_routed: AtomicU64::new(0),
        tor_client,
        fast_client,
    });

    // Seed initial mesh peers
    for &seed in BOOTSTRAP_SEEDS {
        state.known_peers.insert(seed.to_string(), ());
        let init_rtt = if DORMANT_SEEDS.contains(&seed) {
            2800.0
        } else {
            650.0
        };
        state.peer_rtt_ewma.insert(seed.to_string(), init_rtt);
        if DORMANT_SEEDS.contains(&seed) {
            state.peer_fail_count.insert(seed.to_string(), 3);
            state
                .peer_backoff_until
                .insert(seed.to_string(), Instant::now() + Duration::from_secs(180));
        }
    }
    state.revoked_founders.insert(
        "54d5b5d3cc6b4406b5b46a6faa6b4208b14a3ce64cae6dd4a6862783f87151cd".to_string(),
        (),
    );

    state.load_persistent_files();
    let _ = state.get_my_onion_domain();
    spawn_background_tasks(state.clone());

    let app = build_app_router(state.clone());

    println!(
        "[*] [ONIONTALK-RELAY-RS] Starting Rust Native Tokio/Axum Relay on {} (pubkey={})",
        bind_addr, node_public_key_hex
    );

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .expect("Failed to bind TCP listener");

    let state_shutdown = state.clone();
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        let _ = tokio::signal::ctrl_c().await;
        println!("[*] [ONIONTALK-RELAY-RS] Saving snapshot before graceful shutdown...");
        state_shutdown.save_persistent_files();
    })
    .await
    .expect("Axum server failed");
}

fn build_app_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/v1/messages/send", post(handle_send_message))
        .route("/api/v1/messages/sync", post(handle_sync_message))
        .route("/api/v1/messages/ihave", post(handle_ihave_digest_sync))
        .route("/api/v1/messages/inbox", get(handle_get_inbox))
        .route("/api/v1/voice/stream", get(handle_voice_stream))
        .route("/api/v1/messages/ack", post(handle_ack_message))
        .route("/api/v1/messages/ack_batch", post(handle_ack_batch))
        .route("/api/v1/messages/ack_sync", post(handle_ack_sync))
        .route("/api/v1/messages/ack_batch_sync", post(handle_ack_batch_sync))
        .route(
            "/api/v1/node/claim-token",
            get(founder::handle_node_claim_token),
        )
        .route("/api/v1/founder/quote", post(founder::handle_founder_quote))
        .route(
            "/api/v1/founder/claim-crypto",
            post(founder::handle_founder_claim_crypto),
        )
        .route(
            "/api/v1/founder/claim-node",
            post(founder::handle_founder_claim_node),
        )
        .route(
            "/api/v1/founder/verify-allowance",
            post(founder::handle_founder_verify_allowance),
        )
        .route(
            "/api/v1/founder/stop-node",
            post(founder::handle_founder_stop_node),
        )
        .route(
            "/api/v1/founder/revoke",
            post(founder::handle_founder_revoke),
        )
        .route("/api/v1/peers/announce", post(handle_announce_peer))
        .route("/api/v1/peers/geo", post(handle_update_peer_geo))
        .route("/api/v1/peers/list", get(handle_list_peers))
        .route("/api/v1/peers/watch", get(handle_watch_peers))
        .route("/api/v1/version", get(handle_version))
        .route("/health", get(handle_health))
        .route("/api/v1/stats", get(handle_stats))
        .route("/api/v1/debug/queues", get(handle_debug_queues))
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            apply_zero_trust_headers,
        ))
        .with_state(state.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn test_zero_leak_and_anti_hardcode_gate() {
        let output = Command::new("git")
            .args(["ls-files"])
            .output()
            .expect("git ls-files must succeed");
        let tracked = String::from_utf8_lossy(&output.stdout);
        let text_exts = [
            ".rs", ".kt", ".java", ".py", ".js", ".ts", ".html", ".css",
            ".md", ".yml", ".yaml", ".json", ".toml", ".kts", ".xml", ".sh",
        ];
        let forbidden_ext = [".jks", ".keystore", ".p12", ".pfx", ".pem", ".key"];
        let mut count = 0usize;

        for rel in tracked.lines().map(str::trim).filter(|s| !s.is_empty()) {
            let norm = rel.replace('\\', "/");
            let lower = norm.to_lowercase();
            for ext in forbidden_ext {
                assert!(!lower.ends_with(ext), "Forbidden secret file tracked: {}", norm);
            }
            assert!(
                !lower.ends_with("local.properties") && !lower.ends_with("keystore.properties"),
                "Forbidden properties file tracked: {}",
                norm
            );
            if !text_exts.iter().any(|ext| lower.ends_with(ext)) {
                continue;
            }
            let Ok(content) = std::fs::read_to_string(rel) else {
                continue;
            };
            count += 1;
            if norm == "src/main.rs" {
                continue;
            }
            for (line_no, line) in content.lines().enumerate() {
                assert!(
                    !line.contains("-----BEGIN ") || !line.contains("PRIVATE KEY-----"),
                    "Private key block in {}:L{}",
                    norm,
                    line_no + 1
                );
                assert!(
                    !line.contains("192.168."),
                    "RFC1918 LAN IP leak in {}:L{}",
                    norm,
                    line_no + 1
                );
            }
        }
        println!(
            "[SECOPS-ZERO-LEAK-RS] PASS: Scanned {} tracked text files (0 secrets, 0 IP/cloud leaks).",
            count
        );
    }

    #[tokio::test]
    async fn test_strix_relay_protocol_invariants() {
        let (node_signing_key, node_public_key_hex) =
            load_or_create_node_keypair("/tmp/oniontalk_test_node_ed25519.key");
        let client = reqwest::Client::builder().build().unwrap();
        let state = Arc::new(AppState {
            node_signing_key,
            node_public_key_hex,
            hostname_file: "/tmp/nonexistent_hostname".to_string(),
            my_onion_domain: RwLock::new(None),
            relay_admin_token: String::new(),
            min_client_version_code: 36,
            latest_client_version_code: 49,
            latest_client_version_name: "1.5.5".to_string(),
            update_play_url: "https://play.google.com/store/apps/details?id=org.oniontalk.messenger".to_string(),
            update_apk_url: "https://github.com/onion-talk/oniontalk-demo/releases/latest/download/OnionTalk.apk".to_string(),
            enforce_hard_update_cut: true,
            start_time_sec: now_epoch_sec(),
            state_snapshot_file: "/tmp/oniontalk_test_state.json".to_string(),
            seen_client_tags_file: "/tmp/oniontalk_test_tags.json".to_string(),
            mesh_watch_file: "/tmp/oniontalk_test_watch.json".to_string(),
            spent_nullifiers_file: "/tmp/oniontalk_test_nullifiers.json".to_string(),
            mailboxes: DashMap::new(),
            acked_tombstones: DashMap::new(),
            acked_tokens: DashMap::new(),
            synced_peers_by_msg: DashMap::new(),
            known_peers: DashMap::new(),
            peer_pubkeys: DashMap::new(),
            peer_reverify_last_ts: DashMap::new(),
            peer_rtt_ewma: DashMap::new(),
            peer_fail_count: DashMap::new(),
            peer_backoff_until: DashMap::new(),
            peer_last_ok_epoch: DashMap::new(),
            peer_last_fail_mono: DashMap::new(),
            peer_online_state: DashMap::new(),
            custom_peer_geo: DashMap::new(),
            mesh_watch_events: Mutex::new(Vec::new()),
            peer_origin_hints: DashMap::new(),
            local_active_pollers: DashMap::new(),
            local_voice_stream_pollers: DashMap::new(),
            seen_client_tags: DashMap::new(),
            spent_tx_nullifiers: DashMap::new(),
            founder_donor_quotas: DashMap::new(),
            founder_operator_nodes: DashMap::new(),
            revoked_founders: DashMap::new(),
            founder_created_groups: DashMap::new(),
            messages_received: AtomicU64::new(0),
            messages_routed: AtomicU64::new(0),
            acks_processed: AtomicU64::new(0),
            spoofed_acks_blocked: AtomicU64::new(0),
            invalid_peers_blocked: AtomicU64::new(0),
            unauthenticated_requests_blocked: AtomicU64::new(0),
            idontwant_dedup_saved: AtomicU64::new(0),
            fast_lane_routed: AtomicU64::new(0),
            tor_client: client.clone(),
            fast_client: client.clone(),
        });

        let app = build_app_router(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await;
        });

        let base = format!("http://{}", addr);
        let cid = format!("@{}:onion4zr3bsdeaelksemwokl5qmxd5o7jyblf46vc2mfl6cozgw77tqd.onion", "a".repeat(64));

        // 1. Legacy client version < 36 must receive HTTP 426 Upgrade Required
        let r426 = client
            .post(format!("{}/api/v1/messages/send", base))
            .header("X-Client-Version-Code", "35")
            .json(&serde_json::json!({
                "sender": cid,
                "recipient": cid,
                "payload": "AA==",
                "ack_lock": "b".repeat(64)
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(r426.status().as_u16(), 426, "Expected HTTP 426 for legacy client");

        // 2. Unauthenticated founder endpoints must receive HTTP 401
        for ep in [
            "/api/v1/founder/verify-allowance",
            "/api/v1/founder/stop-node",
            "/api/v1/founder/revoke",
        ] {
            let r401 = client
                .post(format!("{}{}", base, ep))
                .json(&serde_json::json!({"user_id": cid}))
                .send()
                .await
                .unwrap();
            assert_eq!(r401.status().as_u16(), 401, "Expected HTTP 401 on {}", ep);
        }

        // 3. Health check must return HTTP 200 and engine == oniontalk-relay-rs
        let h = client.get(format!("{}/health", base)).send().await.unwrap();
        assert_eq!(h.status().as_u16(), 200);
        let h_json: serde_json::Value = h.json().await.unwrap();
        assert_eq!(h_json.get("status").and_then(|v| v.as_str()), Some("healthy"));
        assert!(
            h_json
                .get("engine")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .starts_with("oniontalk-relay-rs/"),
            "Expected Rust engine header in /health"
        );
        println!("[STRIX-RELAY-RS] ALL CHECKS PASSED (Zero-Leak + HTTP 426 Legacy Cut + HTTP 401 Founder Auth + Health OK)");
    }
}
