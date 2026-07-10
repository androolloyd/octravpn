//! On-chain operator presence: registration (v1.1 / v2 / v3),
//! bond/unbond/finalize, settle_claim, claim_earnings, the
//! validator-health refresh loop, HFHE-pubkey placeholders, and the
//! local earnings accumulator.
//!
//! Grow this file when adding another "tell-the-chain" op. When
//! adding a *new protocol version*, keep its register variant here and
//! the existing dispatcher handles it. If a single version grows
//! past ~400 LOC of pure registration logic, split it into
//! `attestation_v<n>.rs` and keep this file as the dispatcher.

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use octravpn_core::{
    earnings::{scalar_from_bytes, scalar_to_bytes},
    stealth,
};
use tokio::task::JoinHandle;
use tracing::{info, warn};
use x25519_dalek::PublicKey as X25519Pub;

use super::Hub;
use crate::{
    chain_v2::{
        asset_put_fee_fallback, deploy_circle_fee_fallback, CircleState, RegisterCircleParams,
        MIN_CIRCLE_STAKE_DEFAULT, POLICY_ASSET_PATH,
    },
    config::ProtocolVersion,
    v3_boot::{run_v3_boot, V3BootInputs},
};

impl Hub {
    /// Per-operator stake required for `register_endpoint` to
    /// succeed. Mirrors `Params.min_endpoint_stake` in the AML
    /// (1000 OCT = 1B OU by default). Kept local so the node can
    /// fail fast without first reading params.
    pub(crate) const MIN_ENDPOINT_STAKE_DEFAULT: u64 = 1_000_000_000;

    /// Entry point used by `Cmd::Register` and by the long-running
    /// `Cmd::Run` boot path. Dispatches to v1.1 or v2 based on
    /// `cfg.chain.protocol_version` so we don't disturb deployed
    /// v1.1 operators while still letting new operators opt into the
    /// Circle-native flow.
    pub(crate) async fn register_endpoint(self: &Arc<Self>) -> Result<()> {
        match self.cfg.chain.protocol_version {
            ProtocolVersion::V1_1 => self.register_endpoint_v1().await,
            ProtocolVersion::V2 => self.register_endpoint_v2().await,
            ProtocolVersion::V3 => self.register_endpoint_v3().await,
        }
    }

    /// v3 / chain-minimal register flow. Delegates to `v3_boot::run_v3_boot`,
    /// which computes the canonical `StateRoot` anchor, decides
    /// register / update / no-op, and persists the (anchor, tx_hash)
    /// pair into `state/circle-v3.toml`. Idempotent across restarts.
    async fn register_endpoint_v3(self: &Arc<Self>) -> Result<()> {
        let inputs = V3BootInputs {
            cfg: &self.cfg,
            chain_v3: &self.chain_v3,
            wg_static_secret: &self.wg_static_secret,
            receipt_kp: &self.wg_kp,
        };
        let outcome = run_v3_boot(&inputs).await?;
        info!(?outcome, "v3 boot complete");
        Ok(())
    }

    /// v1.1 / wallet-as-identity register flow. Bond first, then
    /// register_endpoint against `program/main.aml`. Untouched by
    /// the v2 work — kept here so existing deployed operators see
    /// no behaviour change.
    async fn register_endpoint_v1(self: &Arc<Self>) -> Result<()> {
        if self.chain.read_endpoint_record().await?.is_some() {
            info!("endpoint already registered on chain; skipping");
            return Ok(());
        }
        if self.chain.read_endpoint_slashed().await? {
            return Err(anyhow!(
                "{} is permanently slashed; cannot re-register at this address",
                self.chain.validator_addr.display()
            ));
        }
        let stake = self.chain.read_endpoint_stake().await?;
        if stake < Self::MIN_ENDPOINT_STAKE_DEFAULT {
            return Err(anyhow!(
                "{} has only {stake} OU bonded (need >= {}). \
                 Run `octravpn-node bond --amount <OU>` first.",
                self.chain.validator_addr.display(),
                Self::MIN_ENDPOINT_STAKE_DEFAULT
            ));
        }
        let nonce = self.chain.nonce().await?;
        let fee = self.chain.fee("contract_call").await?;
        let wg_pub_x25519 = X25519Pub::from(&self.wg_static_secret).to_bytes();
        let wg_pub_hex = hex::encode(wg_pub_x25519);
        // v1 placeholder HFHE values: real Octra clients generate via
        // libpvac. The node stores the placeholder on chain; clients
        // discovering this endpoint use the operator-side REST
        // surface to fetch the real HFHE pubkey for any FHE flows.
        // Once libpvac bindings are wired this will be replaced with
        // a deterministic per-operator HFHE keygen.
        let hfhe_placeholder = self.hfhe_pubkey_placeholder();
        let initial_enc_zero_placeholder = self.hfhe_initial_enc_zero_placeholder();
        // The receipt-signing key is HKDF'd from the master secret
        // under DOMAIN_RECEIPT_SIGN (see Hub::new). Its public half
        // is published on chain so `slash_double_sign` can verify
        // off-chain dual-signed receipts (v1.1 AML).
        let receipt_pub_hex = hex::encode(self.wg_kp.public.0);
        let params = crate::chain::RegisterEndpointParams {
            endpoint: &self.cfg.tunnel.public_endpoint,
            wg_pubkey_hex: &wg_pub_hex,
            hfhe_pubkey: &hfhe_placeholder,
            initial_enc_zero: &initial_enc_zero_placeholder,
            region: &self.cfg.pricing.region,
            price_per_mb: self.cfg.pricing.price_per_mb,
            receipt_pubkey_hex: &receipt_pub_hex,
            fee,
            nonce,
        };
        let call = self.chain.build_register_endpoint_call(&params);
        let signed = self.chain.sign_call(call)?;
        let hash = self.chain.submit_signed_tx(&signed).await?;
        info!(%hash, "register_endpoint submitted");
        Ok(())
    }

    /// v2 / Circle-native register flow. Four sub-steps:
    ///   1. Predict (or load from cache) the operator's circle_id.
    ///   2. If the chain doesn't know the circle yet, submit a
    ///      `deploy_circle` tx and persist the (predicted, nonce, hash)
    ///      triple to `state/circle.toml` so a crash partway through
    ///      can be recovered.
    ///   3. Encrypt + upload the operator's policy bundle as a sealed
    ///      asset at `/policy.json` via `circle_asset_put_encrypted`.
    ///   4. If the registry doesn't already list the circle as active,
    ///      submit `register_circle` with `value = MIN_CIRCLE_STAKE`.
    ///      The v2 program enforces `circle_stake[c] + value >=
    ///      min_circle_stake`, so we always pass at least that amount
    ///      on the first call (atomic register+bond).
    ///
    /// Subsequent restarts short-circuit any step whose tx is already
    /// recorded — running this fn from a steady-state config is
    /// idempotent.
    async fn register_endpoint_v2(self: &Arc<Self>) -> Result<()> {
        let circle_state_path = self.circle_state_path();
        let mut state = CircleState::load(&circle_state_path)?.unwrap_or(CircleState {
            circle_id: String::new(),
            deploy_nonce: 0,
            deploy_tx_hash: String::new(),
            policy_tx_hash: String::new(),
            register_tx_hash: String::new(),
            policy_plaintext_hash: String::new(),
        });

        // --- Step 1: predict / load circle id ----------------------------
        let payload = octravpn_core::circle::default_deploy_payload();
        // The deploy_circle nonce drives the predicted circle_id, so we
        // *must* lock it in before sending anything. Subsequent txs
        // (policy_put, register_circle) increment locally rather than
        // re-fetching, because the chain's `pending_nonce` may not yet
        // reflect our in-flight submissions within this same boot pass.
        let mut next_nonce = if state.circle_id.is_empty() {
            let nonce = self.chain_v2.nonce().await?;
            state.deploy_nonce = nonce;
            state.circle_id = self.chain_v2.predict_circle_id(nonce, &payload);
            info!(
                circle_id = %state.circle_id,
                deploy_nonce = nonce,
                "v2 circle predicted (no prior state on disk)"
            );
            state.save(&circle_state_path)?;
            nonce
        } else {
            info!(
                circle_id = %state.circle_id,
                deploy_nonce = state.deploy_nonce,
                "v2 circle loaded from {}",
                circle_state_path.display()
            );
            // Use the live chain nonce on a restart so we don't reuse
            // a slot that has since been consumed by some other tx
            // (e.g. operator ran `octravpn-node bond` between boots).
            self.chain_v2.nonce().await?
        };

        // Fail fast if a previous incarnation of this operator's circle
        // got slashed — v2 marks slashed circles permanently dead.
        if self
            .chain_v2
            .is_circle_slashed(&state.circle_id)
            .await
            .unwrap_or(false)
        {
            return Err(anyhow!(
                "circle {} is permanently slashed; redeploy under a fresh nonce \
                 (delete {} and restart)",
                state.circle_id,
                circle_state_path.display()
            ));
        }

        // --- Step 2: deploy_circle if not already on chain ---------------
        let already_deployed = self
            .chain_v2
            .is_circle_deployed(&state.circle_id)
            .await
            .unwrap_or(false);
        // If a deploy is already recorded (either on chain or in our
        // local state file), make sure subsequent txs skip past that
        // nonce slot.
        if !state.deploy_tx_hash.is_empty() {
            next_nonce = next_nonce.max(state.deploy_nonce + 1);
        }
        if !already_deployed && state.deploy_tx_hash.is_empty() {
            // Use the recommended fee if reasonable; otherwise fall back
            // to the well-known webcli default. Real Octra returns 0 on
            // an unknown op_type query — the fallback is the safer pick.
            let fee = self
                .chain_v2
                .fee("deploy_circle")
                .await
                .ok()
                .filter(|f| *f > 0)
                .unwrap_or_else(deploy_circle_fee_fallback);
            let env = self.chain_v2.build_deploy_circle_tx(
                &payload,
                &state.circle_id,
                state.deploy_nonce,
                fee,
            );
            let signed = self.chain_v2.sign_envelope(env)?;
            let hash = self.chain_v2.submit_signed_tx(&signed).await?;
            info!(%hash, circle_id = %state.circle_id, "v2 deploy_circle submitted");
            state.deploy_tx_hash = hash;
            state.save(&circle_state_path)?;
            // Reserve the next slot for the subsequent policy + register txs.
            next_nonce = state.deploy_nonce + 1;
        } else if already_deployed {
            info!(circle_id = %state.circle_id, "v2 circle already on chain; skipping deploy");
        } else {
            info!(
                circle_id = %state.circle_id,
                tx = %state.deploy_tx_hash,
                "v2 deploy_circle already submitted in a prior run"
            );
        }

        // --- Step 3: upload encrypted policy bundle ----------------------
        let passphrase = self.sealed_passphrase()?;
        let bundle = self.build_policy_bundle();
        let bundle_bytes = bundle.to_json_bytes()?;
        // We always upload if either the cached plaintext_hash differs
        // (operator changed config) or no policy tx was ever recorded.
        let needs_upload = state.policy_tx_hash.is_empty()
            || policy_hash_differs(&state.policy_plaintext_hash, &bundle_bytes);
        if needs_upload {
            // Use the locally-reserved next_nonce. If `deploy_circle`
            // ran in this same boot pass, it bumped next_nonce after
            // submit. If the deploy was already on-chain from a prior
            // boot, next_nonce reflects the live chain nonce.
            let fee = self
                .chain_v2
                .fee("circle_asset_put_encrypted")
                .await
                .ok()
                .filter(|f| *f > 0)
                .unwrap_or_else(asset_put_fee_fallback);
            let put = self.chain_v2.build_put_encrypted_tx(
                &state.circle_id,
                POLICY_ASSET_PATH,
                &bundle_bytes,
                &passphrase,
                next_nonce,
                fee,
            )?;
            let signed = self.chain_v2.sign_envelope(put.tx)?;
            let hash = self.chain_v2.submit_signed_tx(&signed).await?;
            info!(
                %hash,
                circle_id = %state.circle_id,
                resource_key = %self.chain_v2.policy_resource_key(&state.circle_id),
                "v2 policy bundle uploaded (sealed)"
            );
            state.policy_tx_hash = hash;
            state.policy_plaintext_hash = put.plaintext_hash;
            state.save(&circle_state_path)?;
            next_nonce += 1;
        } else {
            info!(
                circle_id = %state.circle_id,
                tx = %state.policy_tx_hash,
                "v2 policy bundle unchanged; skipping put-encrypted"
            );
        }

        // --- Step 4: register_circle (atomic register + bond) ----------
        let already_registered = self
            .chain_v2
            .is_circle_registered(&state.circle_id)
            .await
            .unwrap_or(false);
        if already_registered {
            info!(
                circle_id = %state.circle_id,
                "v2 circle already registered (circles[c].active==1); skipping register_circle"
            );
            return Ok(());
        }
        // Wire stake amount + tariffs.
        let min_stake = self.cfg_min_circle_stake();
        // Reuse the locally-incremented next_nonce: the deploy and
        // policy txs (if submitted this boot) each bumped it.
        let nonce = next_nonce;
        let fee = self
            .chain_v2
            .fee("contract_call")
            .await
            .ok()
            .filter(|f| *f > 0)
            .unwrap_or(1_000);
        // receipt_pubkey on chain is base64 (the form ed25519_ok decodes
        // natively in the v2 AML). Same Ed25519 key used in v1.1, just
        // a different encoding.
        let receipt_pubkey_b64 = octravpn_core::b64::encode(self.wg_kp.public.0);
        let hfhe_pk = self.hfhe_pubkey_placeholder();
        let hfhe_zero_ct = self.hfhe_initial_enc_zero_placeholder();
        let params = RegisterCircleParams {
            circle_id: &state.circle_id,
            region: &self.cfg.pricing.region,
            price_per_mb_shared: self.cfg.pricing.shared_price(),
            price_per_mb_internal: self.cfg.pricing.internal_price(),
            receipt_pubkey_b64: &receipt_pubkey_b64,
            op_pk_hfhe: &hfhe_pk,
            op_zero_ct_hfhe: &hfhe_zero_ct,
            stake_amount: min_stake,
            fee,
            nonce,
        };
        let call = self.chain_v2.build_register_circle_call(&params);
        let signed = self.chain_v2.sign_call(call)?;
        let hash = self.chain_v2.submit_signed_tx(&signed).await?;
        info!(
            %hash,
            circle_id = %state.circle_id,
            stake = min_stake,
            "v2 register_circle submitted (atomic register+bond)"
        );
        state.register_tx_hash = hash;
        state.save(&circle_state_path)?;
        Ok(())
    }

    /// Resolve the per-tailnet sealed-asset passphrase.
    /// Thin wrapper around [`super::boot::resolve_sealed_passphrase`]
    /// that pulls the env var + config field for the running hub.
    pub(super) fn sealed_passphrase(&self) -> Result<zeroize::Zeroizing<String>> {
        super::boot::resolve_sealed_passphrase(
            std::env::var("OCTRAVPN_SEALED_PASSPHRASE").ok().as_deref(),
            // Audit-2 CFG-2 / Audit-3 H-6: pull `Option<&str>` through the
            // redaction-safe accessor — the raw field is `Option<SecretString>`.
            self.cfg.chain.sealed_passphrase_expose(),
        )
    }

    /// Path where the v2 circle state (id + tx hashes) is cached. Picks
    /// `cfg.chain.circle_state_path` if set, else falls back to
    /// `./state/circle.toml`.
    pub(super) fn circle_state_path(&self) -> std::path::PathBuf {
        self.cfg.chain.circle_state_path.as_ref().map_or_else(
            || std::path::PathBuf::from("./state/circle.toml"),
            std::path::PathBuf::from,
        )
    }

    /// Minimum circle stake to send with the first `register_circle`.
    /// Sourced from a constant for now (the v2 AML's `min_circle_stake`
    /// param). Future work: read the live param from
    /// `contract_call(get_params)` so this picks up governance updates.
    #[allow(clippy::unused_self)] // future revisions will read live params
    fn cfg_min_circle_stake(&self) -> u64 {
        MIN_CIRCLE_STAKE_DEFAULT
    }

    /// `bond_endpoint(amount)` — deposit OU into the operator's stake.
    pub(crate) async fn bond_endpoint(self: &Arc<Self>, amount: u64) -> Result<()> {
        if amount == 0 {
            return Err(anyhow!("bond amount must be > 0"));
        }
        let nonce = self.chain.nonce().await?;
        let fee = self.chain.fee("contract_call").await?;
        let call = self.chain.build_bond_call(amount, fee, nonce);
        let signed = self.chain.sign_call(call)?;
        let hash = self.chain.submit_signed_tx(&signed).await?;
        info!(%hash, amount, "bond_endpoint submitted");
        Ok(())
    }

    /// `unbond_endpoint()` — start the grace period.
    pub(crate) async fn unbond_endpoint(self: &Arc<Self>) -> Result<()> {
        let nonce = self.chain.nonce().await?;
        let fee = self.chain.fee("contract_call").await?;
        let call = self.chain.build_unbond_call(fee, nonce);
        let signed = self.chain.sign_call(call)?;
        let hash = self.chain.submit_signed_tx(&signed).await?;
        info!(%hash, "unbond_endpoint submitted");
        Ok(())
    }

    /// `finalize_unbond()` — claim the unbonded stake.
    pub(crate) async fn finalize_unbond(self: &Arc<Self>) -> Result<()> {
        let nonce = self.chain.nonce().await?;
        let fee = self.chain.fee("contract_call").await?;
        let call = self.chain.build_finalize_unbond_call(fee, nonce);
        let signed = self.chain.sign_call(call)?;
        let hash = self.chain.submit_signed_tx(&signed).await?;
        info!(%hash, "finalize_unbond submitted");
        Ok(())
    }

    /// `settle_claim(session_id, bytes_used)` — operator-side half
    /// of the two-tx settle. Submit once per session at session
    /// close (or when the receipt rate crosses a threshold worth
    /// settling). Equivocation slashes us in-AML, so callers must
    /// commit to a single bytes_used per session.
    ///
    /// Dispatches to the v1.1 or v2 chain client based on
    /// `cfg.chain.protocol_version`. v2's `settle_claim` is identical
    /// in shape to v1.1's — only the program address (and the
    /// caller-vs-owner check) differs.
    pub(crate) async fn settle_claim(
        self: &Arc<Self>,
        session_id: u64,
        bytes_used: u64,
    ) -> Result<()> {
        match self.cfg.chain.protocol_version {
            ProtocolVersion::V1_1 => {
                let nonce = self.chain.nonce().await?;
                let fee = self.chain.fee("contract_call").await?;
                let call = self
                    .chain
                    .build_settle_claim_call(session_id, bytes_used, fee, nonce);
                let signed = self.chain.sign_call(call)?;
                let hash = self.chain.submit_signed_tx(&signed).await?;
                info!(%hash, session_id, bytes_used, "settle_claim (v1.1) submitted");
                Ok(())
            }
            ProtocolVersion::V2 => {
                let nonce = self.chain_v2.nonce().await?;
                let fee = self
                    .chain_v2
                    .fee("contract_call")
                    .await
                    .ok()
                    .filter(|f| *f > 0)
                    .unwrap_or(1_000);
                let call = self
                    .chain_v2
                    .build_settle_claim_call(session_id, bytes_used, fee, nonce);
                let signed = self.chain_v2.sign_call(call)?;
                let hash = self.chain_v2.submit_signed_tx(&signed).await?;
                info!(%hash, session_id, bytes_used, "settle_claim (v2) submitted");
                Ok(())
            }
            ProtocolVersion::V3 => {
                let fee = self.chain_v3.fee_or_fallback("contract_call").await;
                let call = self
                    .chain_v3
                    .build_settle_claim_call(session_id, bytes_used, fee, 0);
                let hash = self.chain_v3.submit_call(call).await?;
                info!(%hash, session_id, bytes_used, "settle_claim (v3) submitted");
                Ok(())
            }
        }
    }

    /// Per-operator placeholder HFHE pubkey. Replaced when the libpvac
    /// SDK lands.
    pub(super) fn hfhe_pubkey_placeholder(&self) -> String {
        // Deterministic per-operator string so the on-chain record is
        // stable across restarts; just a tag + the wallet's hex pubkey.
        format!(
            "hfhe_v1|placeholder|{}",
            hex::encode(self.chain.wallet.public.0)
        )
    }

    /// Per-operator placeholder enc(0). Same caveat as
    /// `hfhe_pubkey_placeholder`.
    pub(super) fn hfhe_initial_enc_zero_placeholder(&self) -> String {
        format!("hfhe_v1|enc0|{}", hex::encode(self.chain.wallet.public.0))
    }

    /// Claim accumulated earnings. v1 two-step: AML verifies FHE
    /// zero-proof + transfers plaintext OU; the operator's wallet is
    /// responsible for any follow-up native stealth payout.
    pub(crate) async fn claim_earnings(self: &Arc<Self>) -> Result<()> {
        // Read locally-tracked accumulator (we keep it for parity
        // with the old flow even though the on-chain side moved to
        // HFHE — operator still needs to know the amount).
        let acc = AccumulatorStore::load(&self.cfg.chain.wallet_secret_path)?;
        if acc.amount == 0 {
            return Err(anyhow!("local accumulator is zero — nothing to claim"));
        }

        // v1 placeholder proof: real Octra clients generate an HFHE
        // zero-proof via libpvac for the `enc_earnings - enc(amount)
        // = enc(0)` check. Until libpvac binding lands, the node
        // submits a placeholder; the mock chain treats this as a
        // direct equality check.
        let proof_placeholder = format!(
            "hfhe_v1|zero_proof|{}|{}",
            acc.amount,
            hex::encode(self.chain.wallet.public.0)
        );

        let nonce = self.chain.nonce().await?;
        let fee = self.chain.fee("contract_call").await?;
        let call = self
            .chain
            .build_claim_call(acc.amount, &proof_placeholder, fee, nonce);
        let signed = self.chain.sign_call(call)?;
        let hash = self.chain.submit_signed_tx(&signed).await?;
        info!(%hash, claimed = acc.amount, "claim_earnings submitted");

        // Reset the local accumulator.
        AccumulatorStore::save(&self.cfg.chain.wallet_secret_path, &Accumulator::zero())?;

        // Mirror the wallet's responsibility comment: real operators
        // submit a native op_type="stealth" tx here paying themselves
        // at a fresh address for unlinkable receipt. Out of scope for
        // the daemon — happens at the wallet layer.
        let _ = stealth::build_fresh_output(&self.view_pubkey);

        Ok(())
    }

    /// Background loop that periodically verifies our operator stake
    /// is above the AML's minimum. If we get slashed or unbonded, the
    /// program-side `endpoint_is_active` check will fail, so we log
    /// a clear warning here for operators.
    pub(crate) fn spawn_validator_health_loop(self: Arc<Self>) -> JoinHandle<Result<()>> {
        let poll = std::time::Duration::from_secs(self.cfg.attestation.poll_interval_secs.max(30));
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(poll).await;
                let slashed = self.chain.read_endpoint_slashed().await;
                self.metrics.record_rpc(slashed.is_ok());
                let stake = self.chain.read_endpoint_stake().await;
                self.metrics.record_rpc(stake.is_ok());
                match (slashed, stake) {
                    (Ok(true), _) => {
                        warn!("operator is permanently slashed — endpoint will be rejected");
                    }
                    (Ok(false), Ok(stake)) if stake >= Self::MIN_ENDPOINT_STAKE_DEFAULT => {
                        self.metrics.last_attestation_unix.store(
                            octravpn_core::util::now_unix_secs(),
                            std::sync::atomic::Ordering::Relaxed,
                        );
                    }
                    (Ok(false), Ok(stake)) => {
                        warn!(
                            stake,
                            min = Self::MIN_ENDPOINT_STAKE_DEFAULT,
                            "operator stake below MIN — endpoint will be rejected"
                        );
                    }
                    (Err(e), _) => warn!(error = %e, "endpoint_slashed check failed"),
                    (_, Err(e)) => warn!(error = %e, "endpoint_stake check failed"),
                }
            }
        })
    }

    /// Add a (delta_amount, delta_blind) contribution to the local
    /// accumulator. Reconciliation tooling calls this once per
    /// `SessionSettled` event so that a future `claim_earnings` knows
    /// the right opening to submit.
    pub(crate) fn accumulator_add(&self, delta_amount: u64, delta_blind_hex: &str) -> Result<()> {
        let bytes = hex::decode(delta_blind_hex).context("decode blind hex")?;
        if bytes.len() != 32 {
            return Err(anyhow!("blind must be 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        let blind = scalar_from_bytes(&arr)?;
        AccumulatorStore::add(&self.cfg.chain.wallet_secret_path, delta_amount, blind)
    }
}

/// Per-validator local accumulator: tracks the running sum (amount,
/// `blind_sum`) so we know how to open the on-chain Pedersen ledger.
#[derive(Clone, Debug)]
struct Accumulator {
    amount: u64,
    blind_sum: curve25519_dalek::scalar::Scalar,
}

impl Accumulator {
    fn zero() -> Self {
        Self {
            amount: 0,
            blind_sum: curve25519_dalek::scalar::Scalar::ZERO,
        }
    }
}

struct AccumulatorStore;

impl AccumulatorStore {
    /// File next to the wallet secret: `<wallet_secret_path>.acc`.
    fn path_for(secret_path: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(format!("{secret_path}.acc"))
    }

    fn load(secret_path: &str) -> Result<Accumulator> {
        let p = Self::path_for(secret_path);
        if !p.exists() {
            return Ok(Accumulator::zero());
        }
        let raw = std::fs::read(&p).context("read accumulator")?;
        if raw.len() != 8 + 32 {
            return Err(anyhow!("accumulator wrong size"));
        }
        let mut amt = [0u8; 8];
        amt.copy_from_slice(&raw[..8]);
        let amount = u64::from_be_bytes(amt);
        let mut b = [0u8; 32];
        b.copy_from_slice(&raw[8..]);
        let blind_sum = scalar_from_bytes(&b)?;
        Ok(Accumulator { amount, blind_sum })
    }

    fn save(secret_path: &str, acc: &Accumulator) -> Result<()> {
        let p = Self::path_for(secret_path);
        let mut buf = Vec::with_capacity(40);
        buf.extend_from_slice(&acc.amount.to_be_bytes());
        buf.extend_from_slice(&scalar_to_bytes(&acc.blind_sum));
        std::fs::write(&p, &buf).context("write accumulator")?;
        Ok(())
    }

    /// Add a (`delta_amount`, `delta_blind`) to the accumulator.
    fn add(
        secret_path: &str,
        delta_amount: u64,
        delta_blind: curve25519_dalek::scalar::Scalar,
    ) -> Result<()> {
        let mut acc = Self::load(secret_path)?;
        acc.amount = acc.amount.saturating_add(delta_amount);
        acc.blind_sum += delta_blind;
        Self::save(secret_path, &acc)
    }
}

/// True iff the cached `policy_plaintext_hash` doesn't match the
/// freshly-serialized bundle. Used to detect "operator changed config,
/// re-upload required" without making the operator manually nuke
/// `state/circle.toml`.
fn policy_hash_differs(cached_hex: &str, bundle_bytes: &[u8]) -> bool {
    use sha2::Digest;
    let actual = sha2::Sha256::digest(bundle_bytes);
    let actual_hex = hex::encode(actual);
    !cached_hex.eq_ignore_ascii_case(&actual_hex)
}
