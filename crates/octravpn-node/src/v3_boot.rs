//! v3 operator boot flow.
//!
//! Mirrors `Hub::register_endpoint_v2` shape but talks to the
//! chain-minimal `program/main-v3.aml` registry. The sequence is:
//!
//!   1. Build a canonical `octravpn_core::v3_state_root::StateRoot` from
//!      live operator state (policy hash, WG pubkey hash, region,
//!      member count, current epoch, wall-clock).
//!   2. Compute `anchor_hex()` — the 64-char hex sha256 the chain
//!      stores in `circle_state_root[circle]`.
//!   3. Decide which on-chain call to make:
//!        * Circle not yet registered → `register_circle(circle,
//!          anchor, receipt_pubkey)` with `value = initial stake`.
//!        * Circle registered but anchor differs → `update_circle_state(
//!          circle, new_anchor)`.
//!        * Anchor matches → log + continue (idempotent restart).
//!   4. Persist the (circle_id, anchor, tx_hash) triple into
//!      `state/circle-v3.toml` so subsequent restarts can short-circuit.
//!
//! ## Judgement calls flagged for review
//!
//!   * **`circle_id` source**: v3's `register_circle` requires a
//!     pre-existing circle address. The v2 path derives it via
//!     `deploy_circle` at boot, but v3 does not bundle deploy + register
//!     atomically (the smoke + adversarial scripts both use a hand-
//!     specified `OPCIRCLE` constant). We therefore REQUIRE
//!     `cfg.chain.circle_id` to be set when `protocol_version = "v3"`
//!     and fail-fast with a clear error if it's absent. Operators
//!     deploy the circle once out-of-band (via the wallet CLI or by
//!     reusing a v2 circle they own) and configure the id here.
//!   * **`policy_hash`**: derived from the canonical v3
//!     `OperatorPolicy` (PR #191 schema, see
//!     `octravpn_core::v3_policy::OperatorPolicy`). The boot fn builds
//!     the policy struct from operator config + WG state + best-effort
//!     epoch + wall-clock timestamp, then commits
//!     `OperatorPolicy::hash_hex()` into the state-root.
//!   * **`epoch`**: best-effort fetch via `octra_node_status`. Falls
//!     back to 0 if the chain RPC is unreachable. The state-root
//!     schema treats `epoch` as monotonic *per anchor*, so a 0 → real
//!     transition on the second boot is fine — verifiers don't reject
//!     a forward jump.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use octravpn_core::v3_policy::OperatorPolicy;
use octravpn_core::v3_state_root::StateRoot;
use sha2::{Digest, Sha256};
use tracing::{info, warn};
use x25519_dalek::{PublicKey as X25519Pub, StaticSecret};

use crate::{
    chain_v3::{
        ChainCtxV3, CircleV3State, RegisterCircleParams, MIN_CIRCLE_STAKE_DEFAULT,
    },
    config::NodeConfig,
};

/// Default cached-state path. Sits next to v2's `circle.toml` so an
/// operator running both versions side-by-side (different binaries,
/// shared filesystem) doesn't see them stomp on each other.
const DEFAULT_V3_STATE_PATH: &str = "./state/circle-v3.toml";

/// What `Hub::register_endpoint` needs to drive the boot flow. Bundled
/// so this module doesn't have to import `Hub` (the boot fn is also
/// useful in tests without spinning up a real Hub).
pub(crate) struct V3BootInputs<'a> {
    pub cfg: &'a NodeConfig,
    pub chain_v3: &'a ChainCtxV3,
    /// The X25519 noise static secret — its derived public key is what
    /// clients use to dial the operator. We hash the public bytes into
    /// `wg_pubkey_hash`.
    pub wg_static_secret: &'a StaticSecret,
    /// Ed25519 receipt keypair (the v1.1 / v2 ones use the same key).
    /// Its public half goes on chain in `receipt_pubkey_b64`; the
    /// chain uses it to verify `slash_double_sign` payloads.
    pub receipt_kp: &'a Arc<octravpn_core::sig::KeyPair>,
}

/// Drive the v3 boot flow. Idempotent: a second call with unchanged
/// state observes the on-chain anchor matches the locally-computed
/// one and short-circuits without sending a tx. Returns the
/// (anchor_hex, on_chain_action) pair for observability.
pub(crate) async fn run_v3_boot(inputs: &V3BootInputs<'_>) -> Result<V3BootOutcome> {
    let circle_id = required_circle_id(inputs.cfg)?;
    let state_path = v3_state_path(inputs.cfg);

    // --- Step 1: build the canonical state-root commitment ----------
    let wg_pub = X25519Pub::from(inputs.wg_static_secret).to_bytes();
    let wg_pubkey_hash = sha256_hex(&wg_pub);
    let wg_pubkey_b64 = B64.encode(wg_pub);

    // Epoch is best-effort. The state-root schema documents that it's
    // informational; a verifier doesn't reject a 0 → real jump.
    let epoch = inputs.chain_v3.current_epoch().await.unwrap_or(0);
    let timestamp_secs = octravpn_core::util::now_unix_secs();

    // Build the canonical `OperatorPolicy` (PR #191 schema). Its
    // `hash_hex()` is what flows into `state-root.policy_hash` — the
    // chain anchors `sha256_hex(canonical_bytes(state-root.json))`,
    // and state-root.json embeds this hash.
    let policy = build_operator_policy_for_v3(
        inputs.cfg,
        &wg_pubkey_b64,
        epoch,
        timestamp_secs,
    );
    policy
        .validate()
        .map_err(|e| anyhow!("v3 operator-policy validation: {e}"))?;
    let policy_hash = policy
        .hash_hex()
        .map_err(|e| anyhow!("v3 operator-policy hash: {e}"))?;

    let state_root = StateRoot::new_v1(
        circle_id,
        policy_hash,
        wg_pubkey_hash,
        None, // no attestation hash until remote-attestation lands
        inputs.cfg.pricing.region.clone(),
        0, // member_count starts at 0; tailnet-owner circle owns the
           // authoritative set, this is just observability.
        epoch,
        timestamp_secs,
    );
    // Validate before we hash it — catches an empty region / bad hash
    // length BEFORE we ship the broken anchor on chain.
    state_root
        .validate()
        .map_err(|e| anyhow!("v3 state-root validation: {e}"))?;
    let anchor_hex = state_root
        .anchor_hex()
        .map_err(|e| anyhow!("v3 state-root anchor: {e}"))?;
    info!(
        circle_id,
        anchor = %anchor_hex,
        epoch,
        "v3 state-root computed"
    );

    // --- Step 2: load cached state + slash guard --------------------
    let mut cached = CircleV3State::load(&state_path)?.unwrap_or_default();
    if cached.circle_id.is_empty() {
        cached.circle_id = circle_id.to_string();
    } else if cached.circle_id != circle_id {
        return Err(anyhow!(
            "v3 circle_id drift: cached {} vs config {}; \
             delete {} if the circle change is intentional",
            cached.circle_id,
            circle_id,
            state_path.display()
        ));
    }

    if inputs
        .chain_v3
        .is_circle_slashed(circle_id)
        .await
        .unwrap_or(false)
    {
        return Err(anyhow!(
            "v3 circle {} is permanently slashed; redeploy under a fresh \
             circle (update circle_id in node.toml and delete {})",
            circle_id,
            state_path.display()
        ));
    }

    // --- Step 3: decide register vs update vs no-op -----------------
    let on_chain_anchor = inputs
        .chain_v3
        .get_circle_state_root(circle_id)
        .await
        .unwrap_or(None);
    let is_registered = inputs
        .chain_v3
        .get_circle_active(circle_id)
        .await
        .unwrap_or(false);

    let receipt_pubkey_b64 = B64.encode(inputs.receipt_kp.public.0);

    let outcome = if !is_registered {
        // Brand-new circle: atomic register + bond.
        let stake = inputs
            .cfg
            .chain
            .v3_initial_stake
            .unwrap_or(MIN_CIRCLE_STAKE_DEFAULT);
        let nonce = inputs.chain_v3.nonce().await?;
        let fee = inputs.chain_v3.fee_or_fallback("contract_call").await;
        let params = RegisterCircleParams {
            circle_id,
            state_root_hex: &anchor_hex,
            receipt_pubkey_b64: &receipt_pubkey_b64,
            stake_amount: stake,
            fee,
            nonce,
        };
        let call = inputs.chain_v3.build_register_circle_call(&params);
        let signed = inputs.chain_v3.sign_call(call)?;
        let hash = inputs.chain_v3.submit_signed_tx(&signed).await?;
        info!(
            %hash,
            circle_id,
            stake,
            anchor = %anchor_hex,
            "v3 register_circle submitted (atomic register+bond)"
        );
        cached.register_tx_hash.clone_from(&hash);
        cached.last_anchor_hex.clone_from(&anchor_hex);
        cached.save(&state_path)?;
        V3BootOutcome::Registered {
            tx_hash: hash,
            anchor_hex,
        }
    } else if on_chain_anchor.as_deref() != Some(anchor_hex.as_str()) {
        // Registered but anchor drifted — submit `update_circle_state`.
        let nonce = inputs.chain_v3.nonce().await?;
        let fee = inputs.chain_v3.fee_or_fallback("contract_call").await;
        let call = inputs
            .chain_v3
            .build_update_circle_state_call(circle_id, &anchor_hex, fee, nonce);
        let signed = inputs.chain_v3.sign_call(call)?;
        let hash = inputs.chain_v3.submit_signed_tx(&signed).await?;
        info!(
            %hash,
            circle_id,
            old_anchor = on_chain_anchor.as_deref().unwrap_or("<none>"),
            new_anchor = %anchor_hex,
            "v3 update_circle_state submitted"
        );
        cached.last_update_tx_hash.clone_from(&hash);
        cached.last_anchor_hex.clone_from(&anchor_hex);
        cached.save(&state_path)?;
        V3BootOutcome::Updated {
            tx_hash: hash,
            anchor_hex,
        }
    } else {
        // Anchor already matches — boot is a no-op.
        info!(
            circle_id,
            anchor = %anchor_hex,
            "v3 anchor already matches on-chain state; skipping tx"
        );
        if cached.last_anchor_hex != anchor_hex {
            cached.last_anchor_hex.clone_from(&anchor_hex);
            // Best-effort persist — a missing state dir is not fatal for
            // a no-op boot. Log + continue.
            if let Err(e) = cached.save(&state_path) {
                warn!(error = %e, "v3 state file save failed (non-fatal no-op boot)");
            }
        }
        V3BootOutcome::AnchorMatches { anchor_hex }
    };
    Ok(outcome)
}

/// What `run_v3_boot` did. Exposed for tests + future control-plane
/// /health observability. `tx_hash` is captured even though no
/// production call site reads it yet — boot returning the hash is
/// useful for the planned `/health` JSON surface that reports the
/// last-known on-chain action.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) enum V3BootOutcome {
    Registered { tx_hash: String, anchor_hex: String },
    Updated { tx_hash: String, anchor_hex: String },
    AnchorMatches { anchor_hex: String },
}

impl V3BootOutcome {
    /// Convenience accessor — the anchor we ended up at (regardless of
    /// whether we submitted a tx).
    #[allow(dead_code)]
    pub(crate) fn anchor(&self) -> &str {
        match self {
            Self::Registered { anchor_hex, .. }
            | Self::Updated { anchor_hex, .. }
            | Self::AnchorMatches { anchor_hex } => anchor_hex,
        }
    }
}

/// `cfg.chain.circle_id` is REQUIRED for v3 (see module-level
/// judgement-call note). Surface a typed error so the CLI prints a
/// clear "set circle_id under [chain]" message rather than a generic
/// "missing field" deser failure.
fn required_circle_id(cfg: &NodeConfig) -> Result<&str> {
    cfg.chain
        .circle_id
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            anyhow!(
                "v3 requires `[chain].circle_id = \"oct…\"` in node.toml — \
                 the operator's pre-deployed circle id"
            )
        })
}

/// Resolve the path the v3 boot state is cached under. Uses the
/// configured override if set, else the default next to v2's circle
/// state file.
pub(crate) fn v3_state_path(cfg: &NodeConfig) -> std::path::PathBuf {
    match cfg.chain.circle_v3_state_path.as_deref() {
        Some(p) if !p.is_empty() => std::path::PathBuf::from(p),
        _ => std::path::PathBuf::from(DEFAULT_V3_STATE_PATH),
    }
}

/// Hash arbitrary bytes to lowercase hex sha256.
fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Construct the canonical v3 `OperatorPolicy` (PR #191 schema) from
/// operator config + WG state + chain epoch + wall-clock timestamp.
///
/// `wg_pubkey_b64` MUST be the 44-char base64 of the operator's 32-byte
/// X25519/WireGuard public key (i.e. `base64(X25519Pub::from(static))`).
/// The boot fn already derives this bytestring above.
///
/// This does NOT call `validate()` — callers do that before sealing the
/// policy / committing the hash, so an error surfaces with a clear
/// `anyhow!` context rather than at the canonical-bytes step.
fn build_operator_policy_for_v3(
    cfg: &NodeConfig,
    wg_pubkey_b64: &str,
    epoch: u64,
    timestamp_secs: u64,
) -> OperatorPolicy {
    OperatorPolicy::new_v1(
        cfg.tunnel.public_endpoint.clone(),
        wg_pubkey_b64.to_string(),
        cfg.pricing.region.clone(),
        cfg.pricing.shared_price(),
        cfg.pricing.internal_price(),
        epoch,
        timestamp_secs,
        cfg.chain
            .attestation_url
            .as_ref()
            .filter(|s| !s.is_empty())
            .cloned(),
    )
}

/// Canonical bytes of the v3 `OperatorPolicy` for this operator —
/// `sha256_hex` of this output is the value flowing into
/// `state-root.policy_hash`. Thin wrapper over
/// `build_operator_policy_for_v3` + `OperatorPolicy::canonical_bytes()`
/// so tests can pin both the bytes AND the round-tripped policy.
#[cfg(test)]
fn policy_bytes_for_v3(
    cfg: &NodeConfig,
    wg_pubkey_b64: &str,
    epoch: u64,
    timestamp_secs: u64,
) -> Result<Vec<u8>> {
    let policy = build_operator_policy_for_v3(cfg, wg_pubkey_b64, epoch, timestamp_secs);
    policy
        .canonical_bytes()
        .map_err(|e| anyhow!("v3 operator-policy canonical_bytes: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AnalyticsCfg, AttestationCfg, ChainCfg, ControlCfg, NodeConfig, PricingCfg,
        ProtocolVersion, TunCfg, TunnelCfg,
    };
    use std::path::Path;

    fn min_cfg(circle_id: Option<&str>) -> NodeConfig {
        NodeConfig {
            chain: ChainCfg {
                rpc_url: "http://127.0.0.1:0/unused".into(),
                program_addr: "oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3".into(),
                validator_addr: "oct8taXQ4CvohcgzCJFYyaKrrAbcZs5mxkBCJQQYWb2Pcun".into(),
                wallet_secret_path: "/tmp/unused".into(),
                protocol_version: ProtocolVersion::V3,
                chain_id: octravpn_core::receipt::CHAIN_ID_DEVNET,
                sealed_passphrase: None,
                circle_state_path: None,
                circle_id: circle_id.map(str::to_string),
                circle_v3_state_path: None,
                v3_initial_stake: None,
                pinned_root_paths: None,
                require_sealed_keys: false,
                attestation_url: None,
            },
            tunnel: TunnelCfg {
                public_endpoint: "1.2.3.4:51820".into(),
                listen: "0.0.0.0:51820".into(),
                wg_secret_path: "/tmp/unused".into(),
                amnezia: Default::default(),
            },
            pricing: PricingCfg {
                price_per_mb: 100,
                region: "eu-west".into(),
                price_per_mb_shared: Some(1000),
                price_per_mb_internal: Some(0),
            },
            control: ControlCfg::default(),
            attestation: AttestationCfg::default(),
            // #232: `analytics` was added to `NodeConfig` after this
            // fixture was written; the indexer defaults to disabled, so
            // the v3_boot tests are unaffected by the new field.
            analytics: AnalyticsCfg::default(),
            tun: TunCfg::default(),
        }
    }

    #[test]
    fn required_circle_id_present() {
        let cfg = min_cfg(Some("oct8taXQ4CvohcgzCJFYyaKrrAbcZs5mxkBCJQQYWb2Pcun"));
        assert_eq!(
            required_circle_id(&cfg).unwrap(),
            "oct8taXQ4CvohcgzCJFYyaKrrAbcZs5mxkBCJQQYWb2Pcun"
        );
    }

    #[test]
    fn required_circle_id_absent_errors() {
        let cfg = min_cfg(None);
        let err = required_circle_id(&cfg).unwrap_err();
        assert!(
            err.to_string().contains("circle_id"),
            "unhelpful error: {err}"
        );
    }

    #[test]
    fn required_circle_id_empty_errors() {
        let cfg = min_cfg(Some(""));
        assert!(required_circle_id(&cfg).is_err());
    }

    /// Deterministic 32-byte WG pubkey + its base64 form, for tests that
    /// pin the canonical policy bytes / hash. All-`0x11` bytes —
    /// matches the worked example in `docs/v3-policy-schema.md` so the
    /// hand-built expected string below is easy to cross-reference.
    fn sample_wg_pubkey_b64() -> String {
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        B64.encode([0x11_u8; 32])
    }

    #[test]
    fn policy_bytes_are_stable() {
        let a =
            policy_bytes_for_v3(&min_cfg(Some("oct…")), &sample_wg_pubkey_b64(), 0, 0).unwrap();
        let b =
            policy_bytes_for_v3(&min_cfg(Some("oct…")), &sample_wg_pubkey_b64(), 0, 0).unwrap();
        assert_eq!(a, b);
        // And contain the region we set.
        let s = std::str::from_utf8(&a).unwrap();
        assert!(s.contains("eu-west"));
        assert!(s.contains("\"price_per_mb_shared\":1000"));
    }

    #[test]
    fn policy_bytes_differ_when_pricing_changes() {
        let cfg_a = min_cfg(Some("oct…"));
        let mut cfg_b = min_cfg(Some("oct…"));
        cfg_b.pricing.price_per_mb_shared = Some(2000);
        let a = policy_bytes_for_v3(&cfg_a, &sample_wg_pubkey_b64(), 0, 0).unwrap();
        let b = policy_bytes_for_v3(&cfg_b, &sample_wg_pubkey_b64(), 0, 0).unwrap();
        assert_ne!(a, b);
    }

    /// Build a Cfg, derive an OperatorPolicy, canonical-encode, compare
    /// to a hand-built expected canonical string. Locks the wiring
    /// between operator config → `OperatorPolicy` fields → canonical
    /// bytes. If `OperatorPolicy::canonical_bytes()` changes shape (e.g.
    /// new sort, escape rules) the v3_policy test suite will catch it
    /// first; this test catches a regression in the operator-side
    /// adapter (wrong field plumbing in `build_operator_policy_for_v3`).
    #[test]
    fn policy_bytes_round_trip_through_operator_policy() {
        let cfg = min_cfg(Some("oct…"));
        let wg = sample_wg_pubkey_b64();
        let epoch = 12345_u64;
        let ts = 1_705_000_000_u64;

        // Canonical bytes via the boot path.
        let got = policy_bytes_for_v3(&cfg, &wg, epoch, ts).unwrap();
        let json = std::str::from_utf8(&got).unwrap();

        // Hand-built expected canonical form: sorted keys, no
        // whitespace. Mirrors the worked-example test in v3_policy.rs
        // but parameterised on the operator config fixture.
        let expected = format!(
            concat!(
                "{{",
                "\"effective_epoch\":12345,",
                "\"endpoint\":\"1.2.3.4:51820\",",
                "\"price_per_mb_internal\":0,",
                "\"price_per_mb_shared\":1000,",
                "\"region\":\"eu-west\",",
                "\"timestamp_secs\":1705000000,",
                "\"v\":1,",
                "\"wg_pubkey_b64\":\"{wg}\"",
                "}}",
            ),
            wg = wg
        );
        assert_eq!(json, expected);

        // And the OperatorPolicy round-trips bytes → struct → bytes.
        let back = OperatorPolicy::decode(&got).expect("decode");
        let again = back.canonical_bytes().expect("re-encode");
        assert_eq!(got, again);
    }

    /// Smoke: `OperatorPolicy::hash_hex()` is exactly 64 lowercase hex
    /// chars. This is the value `state-root.policy_hash` carries.
    #[test]
    fn policy_hash_is_64_char_lowercase_hex() {
        let cfg = min_cfg(Some("oct…"));
        let policy = build_operator_policy_for_v3(
            &cfg,
            &sample_wg_pubkey_b64(),
            12345,
            1_705_000_000,
        );
        let hash = policy.hash_hex().unwrap();
        assert_eq!(hash.len(), 64, "hash not 64 chars: {hash}");
        assert!(
            hash.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "hash not lowercase hex: {hash}"
        );
    }

    /// `attestation_url = Some(…)` flows through the canonical bytes
    /// and changes the hash, while `attestation_url = None` is omitted
    /// (not serialised as `null`).
    #[test]
    fn attestation_url_round_trips() {
        let cfg_none = min_cfg(Some("oct…"));
        let mut cfg_some = min_cfg(Some("oct…"));
        cfg_some.chain.attestation_url =
            Some("https://op.example/attestation".to_string());

        let bytes_none =
            policy_bytes_for_v3(&cfg_none, &sample_wg_pubkey_b64(), 1, 2).unwrap();
        let bytes_some =
            policy_bytes_for_v3(&cfg_some, &sample_wg_pubkey_b64(), 1, 2).unwrap();

        // `None` must not emit the key at all (no `null`).
        let s_none = std::str::from_utf8(&bytes_none).unwrap();
        assert!(!s_none.contains("attestation_url"));
        assert!(!s_none.contains("null"));

        // `Some` emits the URL verbatim.
        let s_some = std::str::from_utf8(&bytes_some).unwrap();
        assert!(s_some.contains("\"attestation_url\":\"https://op.example/attestation\""));

        // And the hashes differ.
        assert_ne!(bytes_none, bytes_some);

        // Empty-string attestation_url is treated as None (defensive: an
        // operator who clears the field in TOML shouldn't poison the
        // hash with an empty URL).
        let mut cfg_empty = min_cfg(Some("oct…"));
        cfg_empty.chain.attestation_url = Some(String::new());
        let bytes_empty =
            policy_bytes_for_v3(&cfg_empty, &sample_wg_pubkey_b64(), 1, 2).unwrap();
        assert_eq!(bytes_empty, bytes_none);
    }

    #[test]
    fn v3_state_path_default_and_override() {
        let cfg = min_cfg(Some("oct…"));
        assert_eq!(v3_state_path(&cfg), Path::new(DEFAULT_V3_STATE_PATH));
        let mut cfg2 = cfg;
        cfg2.chain.circle_v3_state_path = Some("/tmp/foo.toml".into());
        assert_eq!(v3_state_path(&cfg2), Path::new("/tmp/foo.toml"));
    }
}
