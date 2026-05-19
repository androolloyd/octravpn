//! v2 substrate client-side discovery. Mirrors `discover.rs` but
//! against the circle-native v2 program (`program/main-v2.aml`).
//!
//! The discovery flow:
//!   1. List the tailnet's `authorized_circles[tid]` map via the raw
//!      RPC envelope (`contract_call_raw` exposes the storage block,
//!      from which we read keys of the shape
//!      `authorized_circles:<tid>:<circle_addr>`).
//!   2. For each circle, compute the resource_key of `/policy.json`
//!      and fetch the sealed asset via
//!      `circle_asset_ciphertext_by_resource_key`.
//!   3. Decrypt the sealed envelope with the per-tailnet passphrase.
//!      If decryption fails the circle is opaque to this member
//!      (non-member / wrong key id) — surface a friendly skip.
//!   4. Parse the JSON policy and return a `CirclePolicy` record.
//!
//! Caching is keyed on `policy_version`: if the cached copy carries
//! the same `policy_version` and the same `plaintext_hash`, we skip
//! the fetch + decrypt entirely. Cache files live under
//! `<cache_dir>/<circle_id>.json` (see `cache::PolicyCache`).
//!
//! The sealed passphrase comes from one of, in precedence order:
//!   * env var `OCTRAVPN_SEALED_PASSPHRASE`
//!   * config field `[v2].sealed_passphrase`
//!   * CLI `--secret <…>` (the caller pre-resolves and passes it in)

use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use octravpn_core::{
    address::Address,
    circle::{decrypt_sealed_bytes, resource_key},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{config::V2Cfg, runner::Client, v2_cache::PolicyCache};

/// Canonical sealed policy stored at `/policy.json` inside an operator
/// circle. Field order matters when re-encrypting from another tool,
/// but for decode any subset is accepted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CirclePolicy {
    /// WireGuard endpoint URL the client dials, plaintext after decrypt.
    pub endpoint: String,
    /// Operator WG pubkey (base64; matches webcli sealing convention).
    pub wg_pubkey_b64: String,
    /// Region tag for menu display + filtering.
    pub region: String,
    /// Per-MB tariff for CLASS_SHARED traffic.
    pub price_per_mb_shared: u64,
    /// Per-MB tariff for CLASS_INTERNAL traffic.
    pub price_per_mb_internal: u64,
    /// Monotonic version bumped each time the operator rotates policy.
    /// Cache key: if the on-chain version is unchanged from the cached
    /// copy we skip the fetch+decrypt.
    pub policy_version: u64,
    /// Unix-seconds when the operator last attested the policy was live.
    #[serde(default)]
    pub attestation_ts: u64,
}

/// Result of attempting to read one circle's sealed policy.
#[derive(Debug, Clone)]
pub(crate) enum CircleListing {
    /// Decrypt succeeded — display + connect-eligible.
    Open {
        circle_id: String,
        policy: CirclePolicy,
        /// `true` when we returned a cached copy without hitting RPC.
        from_cache: bool,
    },
    /// Sealed envelope fetched but decrypt failed — caller is not a
    /// member of this tailnet (or has the wrong key_id / passphrase).
    /// We still emit the entry so the operator menu shows "opaque" rows
    /// rather than silently dropping them.
    Opaque {
        circle_id: String,
        reason: String,
    },
    /// Listed on chain but no `/policy.json` asset exists yet.
    /// Operator hasn't published policy; treat as not connect-eligible.
    Unpublished { circle_id: String },
    /// Listed on chain but the asset RPC returned an error.
    Error { circle_id: String, error: String },
}

impl CircleListing {
    /// Circle id behind any variant. Used by integration tests + future
    /// debug surfaces.
    #[allow(dead_code)]
    pub(crate) fn circle_id(&self) -> &str {
        match self {
            Self::Open { circle_id, .. }
            | Self::Opaque { circle_id, .. }
            | Self::Unpublished { circle_id }
            | Self::Error { circle_id, .. } => circle_id,
        }
    }
}

/// Class of session a v2 client can open. Mirrors the AML constants
/// `CLASS_SHARED = 0` and `CLASS_INTERNAL = 1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionClass {
    Shared,
    Internal,
}

impl SessionClass {
    pub(crate) fn as_int(self) -> u64 {
        match self {
            Self::Shared => 0,
            Self::Internal => 1,
        }
    }

    /// Parse one of `shared`, `internal`, `s`, `i`, `0`, `1`.
    pub(crate) fn parse(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "shared" | "s" | "0" => Ok(Self::Shared),
            "internal" | "i" | "1" => Ok(Self::Internal),
            other => Err(anyhow!(
                "unknown session class '{other}' (expected shared|internal)"
            )),
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Shared => "shared",
            Self::Internal => "internal",
        }
    }
}

/// Resolve the sealed-policy passphrase from env > config > caller-arg.
/// Returns `None` when none of the three are present; the caller decides
/// whether to bail or prompt.
///
/// The return is wrapped in `zeroize::Zeroizing<String>` so the heap
/// buffer that holds the passphrase wipes on drop instead of sitting
/// in the allocator's free list. P1-10 from docs/v2-threat-model.md.
pub(crate) fn resolve_passphrase(
    cfg: &V2Cfg,
    cli_override: Option<&str>,
) -> Option<zeroize::Zeroizing<String>> {
    if let Ok(s) = std::env::var("OCTRAVPN_SEALED_PASSPHRASE") {
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            return Some(zeroize::Zeroizing::new(trimmed.to_string()));
        }
    }
    if let Some(s) = cli_override {
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            return Some(zeroize::Zeroizing::new(trimmed.to_string()));
        }
    }
    if let Some(s) = cfg.sealed_passphrase.as_ref() {
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            return Some(zeroize::Zeroizing::new(trimmed.to_string()));
        }
    }
    None
}

/// Returns all circle addresses currently `authorized_circles[tailnet_id] == 1`.
///
/// Implementation detail: v2's AML doesn't ship a `list_authorized_circles`
/// view today; we fetch the raw `{result, storage}` envelope for any view
/// that touches the tailnet (using `get_tailnet`) and scrape the storage
/// block for keys of the shape `authorized_circles:<tid>:<circle_addr>`
/// with value `"1"`. A later AML uplift should add a proper view.
pub(crate) async fn list_authorized_circles(client: &Client, tailnet_id: u64) -> Result<Vec<String>> {
    let raw = client
        .rpc()
        .contract_call_raw(
            client.program_addr(),
            "get_tailnet",
            &[json!(tailnet_id)],
            None,
        )
        .await
        .context("get_tailnet (raw)")?;

    if raw.is_null() {
        bail!("tailnet {tailnet_id} not found on chain");
    }

    let Some(storage) = raw.get("storage").and_then(|s| s.as_object()) else {
        // Mock / bare-value path — no storage block. We can't enumerate
        // without a proper view; surface as empty so callers don't crash.
        // The CLI prints a hint about the missing view in that case.
        tracing::debug!("no `storage` block in get_tailnet response; skipping circle scrape");
        return Ok(Vec::new());
    };

    let prefix = format!("authorized_circles:{tailnet_id}:");
    let mut circles = Vec::new();
    for (k, v) in storage {
        let Some(rest) = k.strip_prefix(&prefix) else {
            continue;
        };
        // Authorized iff value is the string "1" (storage block typically
        // stringifies ints) or numeric 1.
        let authed = match v {
            Value::String(s) => s == "1",
            Value::Number(n) => n.as_u64() == Some(1),
            _ => false,
        };
        if authed {
            circles.push(rest.to_string());
        }
    }
    circles.sort();
    circles.dedup();
    Ok(circles)
}

/// Discovery driver: list every authorized circle and try to decrypt
/// its `/policy.json`. Each entry is returned with its outcome (open /
/// opaque / unpublished / error) so the caller can render a menu.
pub(crate) async fn list(
    client: &Client,
    tailnet_id: u64,
    cfg: &V2Cfg,
    passphrase: Option<&str>,
    cache: &mut PolicyCache,
) -> Result<Vec<CircleListing>> {
    let circles = list_authorized_circles(client, tailnet_id).await?;
    if circles.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::with_capacity(circles.len());
    for circle_id in circles {
        out.push(fetch_one(client, &circle_id, cfg, passphrase, cache).await);
    }
    Ok(out)
}

/// Fetch + decrypt one circle's policy. Encapsulates cache + RPC + crypto.
pub(crate) async fn fetch_one(
    client: &Client,
    circle_id: &str,
    cfg: &V2Cfg,
    passphrase: Option<&str>,
    cache: &mut PolicyCache,
) -> CircleListing {
    // 1. Cache short-circuit (best-effort; cache miss is fine).
    let cache_entry = cache.get(circle_id);

    // 2. Fetch the sealed envelope.
    let rkey = resource_key(circle_id, "/policy.json");
    let resp = match client
        .rpc()
        .raw_call(
            "circle_asset_ciphertext_by_resource_key",
            json!([circle_id, &rkey]),
        )
        .await
    {
        Ok(v) => v,
        Err(e) => {
            // Distinguish "no such asset" (operator hasn't sealed policy
            // yet) from other RPC errors when possible. We treat "null"
            // result + RPC error strings containing "not found" as
            // Unpublished; anything else as Error.
            let msg = e.to_string();
            if msg.contains("not found") || msg.contains("no such") {
                return CircleListing::Unpublished {
                    circle_id: circle_id.to_string(),
                };
            }
            return CircleListing::Error {
                circle_id: circle_id.to_string(),
                error: msg,
            };
        }
    };
    if resp.is_null() {
        return CircleListing::Unpublished {
            circle_id: circle_id.to_string(),
        };
    }
    let Some(obj) = resp.as_object() else {
        return CircleListing::Error {
            circle_id: circle_id.to_string(),
            error: format!("unexpected response shape: {resp}"),
        };
    };
    let Some(ciphertext_b64) = obj.get("ciphertext_b64").and_then(Value::as_str) else {
        return CircleListing::Unpublished {
            circle_id: circle_id.to_string(),
        };
    };
    let Some(plaintext_hash) = obj.get("plaintext_hash").and_then(Value::as_str) else {
        return CircleListing::Error {
            circle_id: circle_id.to_string(),
            error: "response missing plaintext_hash".into(),
        };
    };
    let key_id_on_chain = obj
        .get("key_id")
        .and_then(Value::as_str)
        .unwrap_or(&cfg.key_id);

    // 3. Cache short-circuit if the plaintext_hash matches.
    if let Some(prev) = cache_entry.as_ref() {
        if prev.plaintext_hash.eq_ignore_ascii_case(plaintext_hash) {
            return CircleListing::Open {
                circle_id: circle_id.to_string(),
                policy: prev.policy.clone(),
                from_cache: true,
            };
        }
    }

    // 4. Decrypt.
    let Some(pp) = passphrase else {
        return CircleListing::Opaque {
            circle_id: circle_id.to_string(),
            reason: "no sealed-passphrase available (set OCTRAVPN_SEALED_PASSPHRASE or [v2].sealed_passphrase)".into(),
        };
    };
    let plaintext =
        match decrypt_sealed_bytes(circle_id, key_id_on_chain, pp, ciphertext_b64, plaintext_hash) {
            Ok(b) => b,
            Err(e) => {
                return CircleListing::Opaque {
                    circle_id: circle_id.to_string(),
                    reason: format!("policy sealed; you may not be a member of this tailnet ({e})"),
                };
            }
        };

    // 5. Parse JSON.
    let policy: CirclePolicy = match serde_json::from_slice(&plaintext) {
        Ok(p) => p,
        Err(e) => {
            return CircleListing::Error {
                circle_id: circle_id.to_string(),
                error: format!("decode policy JSON: {e}"),
            };
        }
    };

    // 6. Persist to cache (best-effort).
    if let Err(e) =
        cache.put(circle_id, plaintext_hash, &policy)
    {
        tracing::debug!(circle = circle_id, error = %e, "cache write failed");
    }

    CircleListing::Open {
        circle_id: circle_id.to_string(),
        policy,
        from_cache: false,
    }
}

/// Submit `open_session(tid, circle, class, max_pay)` against the v2
/// program. Returns the on-chain session id once it's observed in the
/// transaction events.
pub(crate) async fn open_session_v2(
    client: &Client,
    tailnet_id: u64,
    circle_id: &str,
    class: SessionClass,
    max_pay: u64,
) -> Result<u64> {
    let kp = client.wallet_kp();
    let from = Address::from_pubkey(&kp.public.0);
    let bal = client.rpc().balance(&from).await?;
    let nonce = bal.pending_nonce.max(bal.nonce);
    let fee = client
        .rpc()
        .recommended_fee(Some("contract_call"))
        .await?
        .recommended;

    let call = json!({
        "kind": "contract_call",
        "from": from.display(),
        "to": client.program_addr().display(),
        "method": "open_session",
        "params": [
            tailnet_id,
            circle_id,
            class.as_int(),
            max_pay,
        ],
        "value": 0u64,
        "fee": fee,
        "nonce": nonce,
    });
    let signed = octravpn_core::tx::sign_call(kp, call)?;
    let submit = client.rpc().submit(&signed).await?;
    poll_session_id_v2(client, &submit.hash).await
}

/// Poll the transaction receipt until the `SessionOpened` event surfaces
/// the session id. Caps out at ~30s wall clock.
async fn poll_session_id_v2(client: &Client, tx_hash: &str) -> Result<u64> {
    let mut delay_ms: u64 = 100;
    for _ in 0..20 {
        let v = client.rpc().transaction(tx_hash).await?;
        if let Some(events) = v.get("events").and_then(|x| x.as_array()) {
            for e in events {
                if e.get("name").and_then(Value::as_str) == Some("SessionOpened") {
                    if let Some(sid) = e.get("session_id").and_then(Value::as_u64) {
                        return Ok(sid);
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        delay_ms = (delay_ms * 2).min(2_000);
    }
    Err(anyhow!("session id not observed before timeout"))
}

/// Pretty-print one row of the operator menu, suitable for stdout.
pub(crate) fn render_row(listing: &CircleListing) -> String {
    match listing {
        CircleListing::Open {
            circle_id,
            policy,
            from_cache,
        } => format!(
            "{cid}  {region:>12}  {shared:>10}/{internal:<10} OU/MB  v={ver}{cache}",
            cid = circle_id,
            region = policy.region,
            shared = policy.price_per_mb_shared,
            internal = policy.price_per_mb_internal,
            ver = policy.policy_version,
            cache = if *from_cache { "  (cached)" } else { "" },
        ),
        CircleListing::Opaque { circle_id, reason } => {
            format!("{circle_id}  [opaque]   {reason}")
        }
        CircleListing::Unpublished { circle_id } => {
            format!("{circle_id}  [no policy yet]")
        }
        CircleListing::Error { circle_id, error } => {
            format!("{circle_id}  [error]    {error}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn session_class_parses_aliases() {
        assert_eq!(SessionClass::parse("shared").unwrap(), SessionClass::Shared);
        assert_eq!(SessionClass::parse("s").unwrap(), SessionClass::Shared);
        assert_eq!(SessionClass::parse("0").unwrap(), SessionClass::Shared);
        assert_eq!(
            SessionClass::parse("internal").unwrap(),
            SessionClass::Internal
        );
        assert_eq!(SessionClass::parse("I").unwrap(), SessionClass::Internal);
        assert_eq!(SessionClass::parse("1").unwrap(), SessionClass::Internal);
        assert!(SessionClass::parse("nonsense").is_err());
    }

    #[test]
    fn session_class_as_int_matches_aml() {
        // AML constants: CLASS_SHARED = 0, CLASS_INTERNAL = 1.
        assert_eq!(SessionClass::Shared.as_int(), 0);
        assert_eq!(SessionClass::Internal.as_int(), 1);
    }

    #[test]
    fn passphrase_precedence_env_beats_cli_beats_config() {
        let cfg = V2Cfg {
            sealed_passphrase: Some("cfg-pp".into()),
            key_id: "default".into(),
            cache_dir: String::new(),
        };
        // Env wins.
        std::env::set_var("OCTRAVPN_SEALED_PASSPHRASE", "env-pp");
        assert_eq!(
            resolve_passphrase(&cfg, Some("cli-pp")).as_deref().map(String::as_str),
            Some("env-pp")
        );
        // Without env, CLI wins.
        std::env::remove_var("OCTRAVPN_SEALED_PASSPHRASE");
        assert_eq!(
            resolve_passphrase(&cfg, Some("cli-pp")).as_deref().map(String::as_str),
            Some("cli-pp")
        );
        // Without env or CLI, config wins.
        assert_eq!(
            resolve_passphrase(&cfg, None).as_deref().map(String::as_str),
            Some("cfg-pp"),
        );
        // None of the three -> None.
        let empty = V2Cfg::default();
        assert!(resolve_passphrase(&empty, None).is_none());
    }

    #[test]
    fn render_row_handles_each_variant() {
        let policy = CirclePolicy {
            endpoint: "1.2.3.4:51820".into(),
            wg_pubkey_b64: "AAAAAAAA".into(),
            region: "us-east".into(),
            price_per_mb_shared: 10,
            price_per_mb_internal: 0,
            policy_version: 3,
            attestation_ts: 0,
        };
        let open = CircleListing::Open {
            circle_id: "octABC".into(),
            policy,
            from_cache: false,
        };
        assert!(render_row(&open).contains("us-east"));
        assert!(render_row(&open).contains("v=3"));
        let opaque = CircleListing::Opaque {
            circle_id: "octXYZ".into(),
            reason: "wrong key".into(),
        };
        assert!(render_row(&opaque).contains("[opaque]"));
        assert!(render_row(&CircleListing::Unpublished {
            circle_id: "octQ".into()
        })
        .contains("[no policy yet]"));
        assert!(render_row(&CircleListing::Error {
            circle_id: "octE".into(),
            error: "boom".into()
        })
        .contains("[error]"));
    }

    #[test]
    fn policy_round_trips_json() {
        let p = CirclePolicy {
            endpoint: "vpn.example:51820".into(),
            wg_pubkey_b64: "base64=".into(),
            region: "eu-west".into(),
            price_per_mb_shared: 25,
            price_per_mb_internal: 5,
            policy_version: 7,
            attestation_ts: 1_700_000_000,
        };
        let s = serde_json::to_string(&p).unwrap();
        let back: CirclePolicy = serde_json::from_str(&s).unwrap();
        assert_eq!(back.endpoint, p.endpoint);
        assert_eq!(back.policy_version, p.policy_version);
    }

    #[test]
    fn policy_decode_accepts_missing_attestation_ts() {
        let s = json!({
            "endpoint": "x:1",
            "wg_pubkey_b64": "a",
            "region": "r",
            "price_per_mb_shared": 1,
            "price_per_mb_internal": 0,
            "policy_version": 1
        })
        .to_string();
        let p: CirclePolicy = serde_json::from_str(&s).unwrap();
        assert_eq!(p.attestation_ts, 0);
    }
}
