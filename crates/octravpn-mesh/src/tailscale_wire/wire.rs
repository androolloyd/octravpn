//! Wire-protocol JSON shapes for the Tailscale coordination plane.
//!
//! These types mirror a deliberately-small subset of `tailcfg`:
//!
//! - `MachinePublic`-prefixed encoding (`mkey:<hex>`,
//!   `nodekey:<hex>`, `discokey:<hex>`) for keys.
//! - `RegisterRequest` / `RegisterResponse`: the JSON the client posts
//!   to `/machine/{node_key}/register`, and what we return on success.
//! - `MapRequest` / `MapResponse`: the long-poll request/response on
//!   `/machine/{node_key}/map`.
//!
//! ## Decision log
//!
//! - **We only model the fields stock `tailscale up` actually requires
//!   to reach "registered" and emit a single MapResponse.** Anything
//!   beyond that (ACLs, SSH attributes, DERPRegion, DNSConfig
//!   extensions, key-rotation fields) is **omitted on purpose** — the
//!   blocker doc rules them out for the interop test, and including
//!   them risks drift against the upstream `tailcfg` package.
//! - **Field names match `tailscale/tailcfg/tailcfg.go` verbatim.**
//!   We use `#[serde(rename = "…")]` only when Rust naming conventions
//!   would otherwise diverge (e.g. `NodeKey` instead of `node_key`).
//!   The upstream uses Go's default JSON encoder, which preserves
//!   field names as written — they're capitalised.
//! - **Key fields are typed `String` with the `mkey:`/`nodekey:`
//!   prefix included.** We don't decode to `[u8; 32]` at the serde
//!   layer because the prefix is part of the on-wire identity. A
//!   helper `strip_key_prefix` lives below for handlers that need the
//!   raw bytes.
//! - **`MapResponse.Peers` is the *only* peer-emission path we use.**
//!   Tailscale's incremental update mechanism
//!   (`PeersChanged{,Patch}`, `PeerSeenChange`) is intentionally not
//!   modelled — the interop test only needs the first full snapshot.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// One registered machine's state, kept in the in-memory
/// `MachineRegistry` after a successful `register`.
#[derive(Clone, Debug)]
pub struct MachineRecord {
    /// Hex-encoded (no prefix) Tailscale `NodeKey`. The map endpoint
    /// path `/machine/{node_key}/map` carries the raw hex.
    pub node_key_hex: String,
    /// Hex-encoded (no prefix) machine key (X25519). May be empty if
    /// the registrant only presented a NodeKey.
    pub machine_key_hex: String,
    /// User the preauth key was minted for.
    pub user: String,
    /// Hostname the client advertised in HostInfo (best-effort; may
    /// be empty).
    pub hostname: String,
    /// Allocated tailnet IPv4 in the CGNAT range.
    pub ipv4: std::net::Ipv4Addr,
}

/// Body of `POST /machine/{node_key}/register`.
///
/// Fields are a minimal subset of `tailcfg.RegisterRequest`. The real
/// upstream type carries ~25 fields including timestamps, OS info,
/// expiry preferences, and follow-up auth state. The minimum stock
/// `tailscale up` requires us to be able to *parse* on the happy path
/// is: a presented authkey + a node key.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct RegisterRequest {
    /// `nodekey:` prefixed hex string. The path parameter and this
    /// field both carry the same value in upstream Tailscale; we
    /// trust the body's copy.
    pub node_key: String,
    /// Preauth token the client presents (`Auth.AuthKey` in the
    /// upstream `tailcfg.RegisterRequest`). Tailscale models this as
    /// a nested `Auth { AuthKey, ... }`; we flatten it because the
    /// stock client always sends a flat key during interop.
    #[serde(default)]
    pub auth: Option<RegisterAuth>,
    /// Hostname / OS / etc. the client advertises. Not required for
    /// the interop test; kept here so future fields can extend
    /// without a breaking change.
    #[serde(default)]
    pub hostinfo: Option<HostInfo>,
    /// Optional follow-up flag if the client is presenting a fresh
    /// auth attempt rather than re-using a stored one. Modelled to
    /// silence "missing field" deserialise errors on edge cases.
    #[serde(default)]
    pub followup: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct RegisterAuth {
    /// Preauth bearer token (e.g. `octrapreauth-<hex>`). On the
    /// upstream wire this is `AuthKey`.
    #[serde(default)]
    pub auth_key: String,
}

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct HostInfo {
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub os: String,
    /// Upstream calls this `OSVersion`; PascalCase rename keeps the
    /// wire byte-identical.
    #[serde(default, rename = "OSVersion")]
    pub os_version: String,
}

/// Response to a successful `register`.
///
/// We always return `Login` (a synthetic user record) and an empty
/// `AuthURL` — the latter telling the client "no follow-up browser
/// flow is needed, the key was good." `MachineAuthorized = true` is
/// what flips the client into "registered" state.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RegisterResponse {
    /// User record bound into the machine. We synthesise this from
    /// the preauth's user label.
    pub user: SimpleUser,
    /// Display name of the user; lowercased login by default.
    pub login: SimpleLogin,
    /// Empty for preauth flows (no browser follow-up needed).
    #[serde(default)]
    pub node_key_expired: bool,
    /// Browser URL for OIDC/web auth. Empty on preauth-success path.
    #[serde(default)]
    pub auth_url: String,
    /// Per-machine flag the client polls for in subsequent `/map`
    /// calls. True ⇒ "you're admitted into the tailnet."
    pub machine_authorized: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SimpleUser {
    /// 64-bit stable user ID. We hash the preauth user label into a
    /// u64 — this is fine for the interop test (no cross-process
    /// reconciliation) but is a known weak link for production use.
    #[serde(rename = "ID")]
    pub id: u64,
    pub login_name: String,
    pub display_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SimpleLogin {
    #[serde(rename = "ID")]
    pub id: u64,
    pub provider: String,
    pub login_name: String,
    pub display_name: String,
}

/// Body of `POST /machine/{node_key}/map`.
///
/// The upstream `tailcfg.MapRequest` carries ~15 fields. We model only
/// the few that affect whether the client continues to poll. The
/// `Stream` flag in particular is critical: when true, the client
/// expects an HTTP chunked / NDJSON stream of map updates rather than
/// a single response body.
///
/// **Decision:** we always return a single-response body (Stream=false
/// behaviour) regardless of the request flag. This is wrong long-term
/// — the stock client *does* set Stream=true — but it lets us return
/// a usable MapResponse for the interop test without spinning a
/// streaming-writer task. Marked as a follow-up in the blocker doc.
#[derive(Debug, Deserialize, Serialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct MapRequest {
    /// Client's capability version. Pinned at >=39 for TS2021.
    #[serde(default)]
    pub version: u32,
    /// Whether the client wants the long-poll stream. We ignore this
    /// (see note above) but accept it on the wire.
    #[serde(default)]
    pub stream: bool,
    /// Whether the client wants the response in compressed form.
    /// Currently ignored.
    #[serde(default)]
    pub compress: String,
    /// HostInfo the client wants to update on this map call.
    #[serde(default)]
    pub hostinfo: Option<HostInfo>,
    /// `OmitPeers` true ⇒ client just wants a poke / heartbeat.
    #[serde(default)]
    pub omit_peers: bool,
}

/// Response to `/machine/{node_key}/map`.
///
/// We return only the fields needed for a fresh peer to learn its
/// own assigned addresses and the (one) other peer in the test
/// tailnet. `DERPMap`, `ACLs`, `DNSConfig`, key-rotation fields,
/// SSH attributes, `Domain`, etc. are all elided.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct MapResponse {
    /// `key_expiry_extension` in upstream; unused here, kept for shape.
    #[serde(default)]
    pub key_expiry_extension: u64,
    /// Own node record.
    pub node: MapNode,
    /// Other peers in the tailnet. Empty list is valid (e.g. a
    /// peer-A joining before peer-B does); the long-poll waits for a
    /// second registration to flesh this out.
    pub peers: Vec<MapNode>,
    /// Synthetic empty DNS config — present so the client doesn't
    /// reject the response for missing fields.
    pub dns_config: DnsConfig,
    /// Synthetic empty DERPMap — peers will fall back to direct
    /// connections on the docker bridge.
    pub derp_map: DerpMap,
    /// Domain string the client treats as the tailnet's MagicDNS root.
    /// We hard-code `octra.test` for the interop run.
    pub domain: String,
    /// Whether the client should keep polling. `true` matches stock
    /// expectations.
    pub keep_alive: bool,
}

/// A single node record inside a `MapResponse`.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct MapNode {
    /// Stable per-tailnet node ID. We use the FNV hash of the node
    /// key bytes — deterministic for a given key, fits in u64.
    #[serde(rename = "ID")]
    pub id: u64,
    /// `nodekey:` prefixed hex.
    pub key: String,
    /// `mkey:` prefixed hex.
    pub machine: String,
    /// Tailnet IPv4 + IPv6 addresses (we only emit the v4).
    pub addresses: Vec<String>,
    /// CIDR ranges the node accepts traffic for. Same as `Addresses`
    /// for a pure mesh peer.
    pub allowed_ips: Vec<String>,
    /// Hostname the node advertised.
    pub hostinfo: HostInfo,
    /// Stable string name for MagicDNS lookups. We use `<hostname>.<domain>`.
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct DnsConfig {
    /// MagicDNS resolvers. Empty = use system DNS.
    #[serde(default)]
    pub resolvers: Vec<String>,
    /// Domains tailnet members can reach by short name.
    #[serde(default)]
    pub domains: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct DerpMap {
    /// region_id → region info. Empty in the interop test.
    #[serde(default)]
    pub regions: HashMap<u16, DerpRegion>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DerpRegion {
    pub region_code: String,
    pub region_name: String,
    pub nodes: Vec<DerpRegionNode>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DerpRegionNode {
    pub name: String,
    #[serde(rename = "RegionID")]
    pub region_id: u16,
    pub host_name: String,
    pub i_pv4: String,
}

/// Strip a Tailscale key prefix (`mkey:`, `nodekey:`, `discokey:`)
/// and return the hex-encoded body. Returns `None` if no recognised
/// prefix is present, in which case the caller can treat the input as
/// raw hex.
pub fn strip_key_prefix(s: &str) -> Option<&str> {
    for p in ["mkey:", "nodekey:", "discokey:"] {
        if let Some(rest) = s.strip_prefix(p) {
            return Some(rest);
        }
    }
    None
}

/// Deterministic u64 from a 32-byte key. Used to derive `ID` fields in
/// `MapNode` / `SimpleUser`. Not cryptographic.
pub fn stable_id_from_key(hex_str: &str) -> u64 {
    // FNV-1a 64-bit. Inlined to avoid pulling in a fnv crate.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in hex_str.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_known_prefixes() {
        assert_eq!(strip_key_prefix("mkey:abcd"), Some("abcd"));
        assert_eq!(strip_key_prefix("nodekey:1234"), Some("1234"));
        assert_eq!(strip_key_prefix("discokey:beef"), Some("beef"));
        assert_eq!(strip_key_prefix("plainhex"), None);
    }

    #[test]
    fn register_request_round_trip() {
        let r = RegisterRequest {
            node_key: "nodekey:deadbeef".into(),
            auth: Some(RegisterAuth {
                auth_key: "octrapreauth-abc".into(),
            }),
            hostinfo: Some(HostInfo {
                hostname: "peer-a".into(),
                os: "linux".into(),
                os_version: "6.6".into(),
            }),
            followup: None,
        };
        let j = serde_json::to_string(&r).unwrap();
        // Field names PascalCased on the wire.
        assert!(j.contains("\"NodeKey\""));
        assert!(j.contains("\"Auth\""));
        assert!(j.contains("\"AuthKey\""));
        assert!(j.contains("\"OSVersion\""));
        let back: RegisterRequest = serde_json::from_str(&j).unwrap();
        assert_eq!(back.node_key, "nodekey:deadbeef");
    }

    #[test]
    fn stable_id_is_deterministic() {
        assert_eq!(stable_id_from_key("abcd"), stable_id_from_key("abcd"));
        assert_ne!(stable_id_from_key("abcd"), stable_id_from_key("dcba"));
    }
}
