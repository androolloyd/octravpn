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
//! a currently advertised hash and identical freshly authenticated policy,
//! we may reuse the matching cached object. Missing hashes always use the
//! fresh policy; a locally computed hash is bookkeeping only. Cache files live under
//! `<cache_dir>/<circle_id>.json` (see `cache::PolicyCache`).
//!
//! The sealed passphrase comes from one of, in precedence order:
//!   * env var `OCTRAVPN_SEALED_PASSPHRASE`
//!   * config field `[v2].sealed_passphrase`
//!   * CLI `--secret <…>` (the caller pre-resolves and passes it in)

use anyhow::{bail, Context, Result};
use octravpn_core::circle::{decrypt_sealed_asset_response, resource_key, SealedAssetLocator};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{config::V2Cfg, runner::Client, v2_cache::PolicyCache};

/// Canonical sealed policy stored at `/policy.json` inside an operator
/// circle. Field order matters when re-encrypting from another tool,
/// but for decode any subset is accepted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Included in the authenticated policy. Reuse still requires fresh
    /// envelope verification and equality of every parsed policy field.
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
        /// `true` only when a fresh authenticated response advertises the
        /// same hash and its parsed policy exactly equals the cached policy.
        from_cache: bool,
    },
    /// Sealed envelope fetched but decrypt failed — caller is not a
    /// member of this tailnet (or has the wrong key_id / passphrase).
    /// We still emit the entry so the operator menu shows "opaque" rows
    /// rather than silently dropping them.
    Opaque { circle_id: String, reason: String },
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
pub(crate) async fn list_authorized_circles(
    client: &Client,
    tailnet_id: u64,
) -> Result<Vec<String>> {
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
    decode_policy_response(circle_id, cfg, passphrase, cache, &resp)
}

/// The native public view may omit commitment metadata. OCRS1 authenticates
/// ciphertext but has empty AAD: missing path/freshness are not attested.
fn decode_policy_response(
    circle_id: &str,
    cfg: &V2Cfg,
    passphrase: Option<&str>,
    cache: &mut PolicyCache,
    resp: &Value,
) -> CircleListing {
    if resp.is_null() {
        return CircleListing::Unpublished {
            circle_id: circle_id.to_string(),
        };
    }
    if !resp.is_object() {
        return CircleListing::Error {
            circle_id: circle_id.to_string(),
            error: "unexpected policy response shape".into(),
        };
    }
    if resp.get("ciphertext_b64").is_none() {
        return CircleListing::Unpublished {
            circle_id: circle_id.to_string(),
        };
    }
    let Some(pp) = passphrase else {
        return CircleListing::Opaque {
            circle_id: circle_id.to_string(),
            reason: "no sealed-passphrase available (set OCTRAVPN_SEALED_PASSPHRASE or [v2].sealed_passphrase)".into(),
        };
    };
    let Ok(authenticated) = decrypt_sealed_asset_response(
        circle_id,
        SealedAssetLocator::Path("/policy.json"),
        &cfg.key_id,
        pp,
        resp,
    ) else {
        return CircleListing::Opaque { circle_id: circle_id.to_string(), reason: "policy authentication failed (metadata, passphrase, key id, envelope, or hash mismatch)".into() };
    };
    // The shared parser has authenticated bytes and all provided metadata.
    // Hashless public views always use the fresh policy; a cached hash is
    // bookkeeping and cannot manufacture an advertised chain commitment.
    let cache_entry = cache.get(circle_id);
    // 5. Parse JSON.
    let policy: CirclePolicy = match serde_json::from_slice(&authenticated.plaintext) {
        Ok(p) => p,
        Err(_) => {
            return CircleListing::Error {
                circle_id: circle_id.to_string(),
                error: "decode policy JSON".into(),
            };
        }
    };

    let cached = cache_entry.filter(|entry| {
        resp.get("plaintext_hash").is_some()
            && entry
                .plaintext_hash
                .eq_ignore_ascii_case(&authenticated.plaintext_hash)
            && entry.policy == policy
    });
    let from_cache = cached.is_some();
    let policy = cached.map_or(policy, |entry| entry.policy);

    // 6. Persist to cache (best-effort).
    if let Err(e) = cache.put(circle_id, &authenticated.plaintext_hash, &policy) {
        tracing::debug!(circle = circle_id, error = %e, "cache write failed");
    }

    CircleListing::Open {
        circle_id: circle_id.to_string(),
        policy,
        from_cache,
    }
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
    fn passphrase_precedence_env_beats_cli_beats_config() {
        let cfg = V2Cfg {
            sealed_passphrase: Some("cfg-pp".into()),
            key_id: "default".into(),
            cache_dir: String::new(),
        };
        // Env wins.
        std::env::set_var("OCTRAVPN_SEALED_PASSPHRASE", "env-pp");
        assert_eq!(
            resolve_passphrase(&cfg, Some("cli-pp"))
                .as_deref()
                .map(String::as_str),
            Some("env-pp")
        );
        // Without env, CLI wins.
        std::env::remove_var("OCTRAVPN_SEALED_PASSPHRASE");
        assert_eq!(
            resolve_passphrase(&cfg, Some("cli-pp"))
                .as_deref()
                .map(String::as_str),
            Some("cli-pp")
        );
        // Without env or CLI, config wins.
        assert_eq!(
            resolve_passphrase(&cfg, None)
                .as_deref()
                .map(String::as_str),
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
    fn sealed_policy_fixture(key_id: &str) -> (Value, String) {
        let policy = json!({
            "endpoint":"vpn.example:51820", "wg_pubkey_b64":"a", "region":"fresh",
            "price_per_mb_shared":1, "price_per_mb_internal":0, "policy_version":3
        });
        let bytes = serde_json::to_vec(&policy).unwrap();
        let (ciphertext, hash) = octravpn_core::circle::encrypt_sealed_bytes(
            "circMETA",
            key_id,
            "member-secret",
            &bytes,
            octravpn_core::circle::PaddingClass::None,
        )
        .unwrap();
        (json!({"ciphertext_b64":ciphertext}), hash)
    }

    #[test]
    fn public_policy_without_hash_ignores_cached_hash_and_authenticates_each_response() {
        let dir = tempfile::tempdir().unwrap();
        let mut cache = PolicyCache::open(dir.path()).unwrap();
        let cfg = V2Cfg {
            key_id: "configured".into(),
            ..V2Cfg::default()
        };
        let (response, hash) = sealed_policy_fixture("configured");
        let poison = CirclePolicy {
            endpoint: "untrusted:1".into(),
            wg_pubkey_b64: "bad".into(),
            region: "bad".into(),
            price_per_mb_shared: 0,
            price_per_mb_internal: 0,
            policy_version: 3,
            attestation_ts: 0,
        };
        cache.put("circMETA", &hash, &poison).unwrap();
        let result = decode_policy_response(
            "circMETA",
            &cfg,
            Some("member-secret"),
            &mut cache,
            &response,
        );
        assert!(
            matches!(result, CircleListing::Open { policy, from_cache:false, .. } if policy.endpoint == "vpn.example:51820")
        );
        let mut damaged = response;
        let mut bytes =
            octravpn_core::b64::decode(damaged["ciphertext_b64"].as_str().unwrap()).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        damaged["ciphertext_b64"] = json!(octravpn_core::b64::encode(&bytes));
        assert!(matches!(
            decode_policy_response(
                "circMETA",
                &cfg,
                Some("member-secret"),
                &mut cache,
                &damaged
            ),
            CircleListing::Opaque { .. }
        ));
        assert!(matches!(
            decode_policy_response(
                "circMETA",
                &cfg,
                Some("wrong"),
                &mut cache,
                &sealed_policy_fixture("configured").0
            ),
            CircleListing::Opaque { .. }
        ));
        assert_eq!(cache.get("circMETA").unwrap().plaintext_hash, hash);
    }

    #[test]
    fn public_policy_present_metadata_and_locator_never_downgrade_to_missing() {
        let dir = tempfile::tempdir().unwrap();
        let mut cache = PolicyCache::open(dir.path()).unwrap();
        let cfg = V2Cfg::default();
        let (response, hash) = sealed_policy_fixture(&cfg.key_id);
        for (field, value) in [
            ("plaintext_hash", Value::Null),
            ("plaintext_hash", json!(7)),
            ("plaintext_hash", json!("bad")),
            ("blob_hash", json!("00".repeat(32))),
            ("size_bytes", json!("0")),
            ("key_id", Value::Null),
            ("key_id", json!("")),
            ("circle_id", json!("different")),
            ("resource_key", json!("different")),
            ("path_key", json!("different")),
            ("canonical_path", json!("/other")),
            ("path", Value::Null),
        ] {
            let mut invalid = response.clone();
            invalid[field] = value;
            assert!(matches!(
                decode_policy_response(
                    "circMETA",
                    &cfg,
                    Some("member-secret"),
                    &mut cache,
                    &invalid
                ),
                CircleListing::Opaque { .. }
            ));
        }
        let mut wrong_hash = response.clone();
        wrong_hash["plaintext_hash"] = json!("00".repeat(32));
        assert!(matches!(
            decode_policy_response(
                "circMETA",
                &cfg,
                Some("member-secret"),
                &mut cache,
                &wrong_hash
            ),
            CircleListing::Opaque { .. }
        ));
        let mut strict = response;
        strict["plaintext_hash"] = json!(hash);
        strict["key_id"] = json!(cfg.key_id.clone());
        assert!(matches!(
            decode_policy_response("circMETA", &cfg, Some("member-secret"), &mut cache, &strict),
            CircleListing::Open {
                from_cache: false,
                ..
            }
        ));
    }

    #[test]
    fn public_policy_plaintext_masquerading_as_ciphertext_is_not_authenticated() {
        let dir = tempfile::tempdir().unwrap();
        let mut cache = PolicyCache::open(dir.path()).unwrap();
        let response =
            json!({"ciphertext_b64":octravpn_core::b64::encode(b"{\"endpoint\":\"bad\"}")});
        let result = decode_policy_response(
            "circMETA",
            &V2Cfg::default(),
            Some("member-secret"),
            &mut cache,
            &response,
        );
        assert!(matches!(result, CircleListing::Opaque { .. }));
        assert!(cache.get("circMETA").is_none());
    }
    #[test]
    fn advertised_policy_cache_requires_authenticated_content_equality() {
        let dir = tempfile::tempdir().unwrap();
        let mut cache = PolicyCache::open(dir.path()).unwrap();
        let cfg = V2Cfg::default();
        let (mut response, hash) = sealed_policy_fixture(&cfg.key_id);
        response["plaintext_hash"] = json!(hash.clone());
        let poison = CirclePolicy {
            endpoint: "untrusted:1".into(),
            wg_pubkey_b64: "bad".into(),
            region: "bad".into(),
            price_per_mb_shared: 999,
            price_per_mb_internal: 999,
            policy_version: 3,
            attestation_ts: 0,
        };
        cache.put("circMETA", &hash, &poison).unwrap();
        let fresh = decode_policy_response(
            "circMETA",
            &cfg,
            Some("member-secret"),
            &mut cache,
            &response,
        );
        assert!(
            matches!(fresh, CircleListing::Open { policy, from_cache:false, .. } if policy.endpoint == "vpn.example:51820" && policy.price_per_mb_shared == 1)
        );
        let matching = decode_policy_response(
            "circMETA",
            &cfg,
            Some("member-secret"),
            &mut cache,
            &response,
        );
        assert!(matches!(
            matching,
            CircleListing::Open {
                from_cache: true,
                ..
            }
        ));
        assert!(matches!(
            decode_policy_response("circMETA", &cfg, Some("wrong"), &mut cache, &response),
            CircleListing::Opaque { .. }
        ));
        let mut damaged =
            octravpn_core::b64::decode(response["ciphertext_b64"].as_str().unwrap()).unwrap();
        *damaged.last_mut().unwrap() ^= 1;
        response["ciphertext_b64"] = json!(octravpn_core::b64::encode(damaged));
        assert!(matches!(
            decode_policy_response(
                "circMETA",
                &cfg,
                Some("member-secret"),
                &mut cache,
                &response
            ),
            CircleListing::Opaque { .. }
        ));
    }
}
