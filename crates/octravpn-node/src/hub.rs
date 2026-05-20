//! Central node coordinator. Owns the chain client, control-plane HTTP
//! server, receipt store, onion router, and tunnel server, and exposes
//! the high-level operations the `main` binary calls into.

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use octravpn_core::{
    address::Address,
    earnings::{scalar_from_bytes, scalar_to_bytes},
    rpc::RpcClient,
    sig::KeyPair,
    stealth,
};
use tokio::task::JoinHandle;
use tracing::{info, warn};
use x25519_dalek::{PublicKey as X25519Pub, StaticSecret};

use crate::{
    chain::ChainCtx,
    chain_v2::{
        asset_put_fee_fallback, deploy_circle_fee_fallback, ChainCtxV2, CircleState, PolicyBundle,
        RegisterCircleParams, MIN_CIRCLE_STAKE_DEFAULT, POLICY_ASSET_PATH,
    },
    chain_v3::ChainCtxV3,
    config::{NodeConfig, ProtocolVersion},
    control::{serve as control_serve, ControlState},
    onion::OnionRouter,
    tunnel::Server,
    v3_boot::{run_v3_boot, V3BootInputs},
};

pub(crate) struct Hub {
    pub cfg: NodeConfig,
    pub chain: ChainCtx,
    /// v2 chain context. Always constructed (the wallet secret + RPC
    /// endpoint are the same as v1.1), but only USED when
    /// `cfg.chain.protocol_version == V2`. Holds the v2 program
    /// address + a duplicate of the wallet keypair derived from the
    /// same secret-on-disk so both flows can sign independently
    /// without sharing state.
    pub chain_v2: ChainCtxV2,
    /// v3 chain context. Same RPC + program address as v1.1 / v2 (the
    /// chain is the same Octra chain; only the AML on the configured
    /// `program_addr` differs across versions). Constructed
    /// unconditionally so identity / diagnostic subcommands have it
    /// available, but only consulted when
    /// `cfg.chain.protocol_version == V3`.
    pub chain_v3: ChainCtxV3,
    pub wg_kp: Arc<KeyPair>,
    pub wg_static_secret: StaticSecret,
    pub view_pubkey: [u8; 32],
    pub router: Arc<OnionRouter>,
    /// Pubkeys whitelisted via control-plane `announce`. The tunnel
    /// server consults this map before instantiating a `Tunn` for an
    /// arriving UDP source.
    pub allowlist: Arc<octravpn_core::bounded::BoundedMap<[u8; 32], crate::tunnel::AllowedClient>>,
    /// Shared metrics surface — both the attestation loop and the
    /// control plane write to this so /health reports real freshness.
    pub metrics: Arc<crate::control::NodeMetrics>,
    /// P1-8/9 persistent receipt journal. Opened once at boot so a
    /// bad path (permission denied, magic-mismatch on an existing
    /// file) fails-fast rather than at the first receipt request.
    /// Shared with the control plane via an Arc — every `get_state`
    /// call consults this before signing.
    pub receipt_journal: Arc<octravpn_core::receipt_journal::ReceiptJournal>,
    /// Managed `octra-pvac-sidecar` subprocess for the HFHE path.
    /// `Some` iff `cfg.pvac.enabled = true` AND
    /// `PvacClient::spawn` succeeded at boot. If the operator enabled
    /// `[pvac]` but the binary path doesn't resolve, this is `None`
    /// and the node continues without HFHE — boot does NOT fail. See
    /// `Hub::pvac` for the surfacing accessor used by the v3 settle
    /// path and the headscale bridge.
    #[allow(dead_code)] // consumed by v3_calls + headscale_bridge once HFHE rewires off placeholders
    pub pvac: Option<Arc<crate::pvac::PvacClient>>,
}

impl Hub {
    pub(crate) async fn new(cfg: NodeConfig) -> Result<Self> {
        let rpc = build_rpc(&cfg.chain)?;
        let validator_addr = Address::from_display(&cfg.chain.validator_addr);
        let program_addr = Address::from_display(&cfg.chain.program_addr);

        let wallet_secret = if cfg.chain.require_sealed_keys {
            *read_secret_32_strict(&cfg.chain.wallet_secret_path)
                .context("read wallet secret (strict, sealed-only)")?
        } else {
            read_secret_32(&cfg.chain.wallet_secret_path).context("read wallet secret")?
        };
        // KeyPair has no Clone (it zeroizes on drop); reconstruct the
        // same key from the on-disk secret twice — once for the v1.1
        // chain context and once for the v2 chain context. They sign
        // independently of each other.
        let wallet = KeyPair::from_secret_bytes(&wallet_secret);
        let wallet_v2 = KeyPair::from_secret_bytes(&wallet_secret);
        let wallet_v3 = KeyPair::from_secret_bytes(&wallet_secret);

        let chain = ChainCtx {
            rpc: rpc.clone(),
            program_addr: program_addr.clone(),
            validator_addr,
            wallet,
        };
        // v2 chain context shares the same RPC + program_addr (operators
        // run their v2 program on the same chain, just a different
        // deployed AML). The wallet addr is the deployer.
        let chain_v2 = ChainCtxV2::new(rpc.clone(), program_addr.clone(), wallet_v2);
        // v3 chain context — same wallet, same RPC, talks to the v3
        // deployment configured under `program_addr`.
        let chain_v3 = ChainCtxV3::new(rpc, program_addr, wallet_v3);

        // The on-disk file holds a single 32-byte master secret. Two
        // independent subkeys are derived via HKDF-Expand with distinct
        // domain tags so we never use the same scalar across protocols:
        //
        //   master ---HKDF--> ed25519 receipt-signing secret (Tunn unused;
        //                                                     used only
        //                                                     for HTTP
        //                                                     control-plane
        //                                                     signatures)
        //          ---HKDF--> X25519 noise static secret (WG handshake)
        //
        // The wallet key (transaction signing) is a separate file already.
        let master = if cfg.chain.require_sealed_keys {
            *read_secret_32_strict(&cfg.tunnel.wg_secret_path)
                .context("read wg master secret (strict, sealed-only)")?
        } else {
            read_secret_32(&cfg.tunnel.wg_secret_path).context("read wg master secret")?
        };
        let receipt_sk =
            octravpn_core::util::derive_subkey(&master, octravpn_core::util::DOMAIN_RECEIPT_SIGN);
        let noise_sk =
            octravpn_core::util::derive_subkey(&master, octravpn_core::util::DOMAIN_NOISE);
        let wg_kp = Arc::new(KeyPair::from_secret_bytes(&receipt_sk));
        let wg_static_secret = StaticSecret::from(noise_sk);

        let view_pubkey = wallet_view_pubkey(&wallet_secret);

        let allowlist = Arc::new(octravpn_core::bounded::BoundedMap::new(
            10_000,
            std::time::Duration::from_secs(3600),
        ));

        let metrics = Arc::new(crate::control::NodeMetrics::default());
        metrics.started_at_unix.store(
            octravpn_core::util::now_unix_secs(),
            std::sync::atomic::Ordering::Relaxed,
        );

        // P1-8/9: open the persistent receipt-seq journal at boot. The
        // journal is what stops a forced restart from letting the
        // daemon sign a fresh `seq=1` receipt for a session whose
        // last legitimate receipt was at seq=K. Default path is
        // `./state/receipts.bin`; operators on a system-managed
        // install should override to something under `/var/lib/octravpn/`.
        let journal_path: std::path::PathBuf = cfg
            .control
            .receipt_journal_path
            .clone()
            .map_or_else(|| "./state/receipts.bin".into(), std::path::PathBuf::from);
        let receipt_journal = Arc::new(
            octravpn_core::receipt_journal::ReceiptJournal::open(&journal_path).with_context(
                || format!("open receipt journal at {}", journal_path.display()),
            )?,
        );

        // PVAC sidecar wiring. Opt-in (operator must set `[pvac].enabled
        // = true`); failure to spawn is *non-fatal* — we log a warning
        // and run without HFHE. Behaviour rationale:
        //
        //   - The HFHE path is still optional in v1.1/v2/v3 (placeholder
        //     blobs work end-to-end without it; see
        //     `hfhe_pubkey_placeholder` above).
        //   - Operators commonly deploy the node before the C++ sidecar
        //     toolchain lands on their host. Failing boot would force a
        //     rollback for what is, until claim_earnings is wired through
        //     the real PVAC, a no-op service.
        //   - When the binary IS present but later disappears (operator
        //     `make clean` in the source tree), the supervisor retries on
        //     its own back-off curve, so transient absences self-heal.
        let pvac = if cfg.pvac.enabled {
            match crate::pvac::PvacClient::spawn(cfg.pvac.to_runtime()).await {
                Ok(client) => {
                    info!(
                        binary = %client.binary_path().display(),
                        "pvac sidecar spawned (HFHE path enabled)"
                    );
                    Some(Arc::new(client))
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        binary = %cfg.pvac.binary_path,
                        "pvac sidecar disabled: spawn failed — running without HFHE. \
                         Check `[pvac].binary_path` and that the binary is built \
                         (`cd pvac-sidecar && make`).",
                    );
                    None
                }
            }
        } else {
            None
        };

        Ok(Self {
            cfg,
            chain,
            chain_v2,
            chain_v3,
            wg_kp,
            wg_static_secret,
            view_pubkey,
            router: Arc::new(OnionRouter::new()),
            allowlist,
            metrics,
            receipt_journal,
            pvac,
        })
    }

    /// Accessor for the managed PVAC sidecar. Returns `None` when the
    /// operator has not enabled the `[pvac]` block, or when the
    /// subprocess failed to spawn at boot. Callers in the v3 settle
    /// path and `octravpn-mesh::headscale_bridge` consult this before
    /// touching the HFHE path.
    #[allow(dead_code)] // surface for v3 settle + headscale_bridge consumers (forthcoming)
    pub(crate) fn pvac(&self) -> Option<&Arc<crate::pvac::PvacClient>> {
        self.pvac.as_ref()
    }

    /// Open the audit log configured for this hub (or return `None`
    /// if no `audit_dir` is set). Used by the `verify-audit-log`
    /// subcommand to access the HMAC key for offline verification.
    pub(crate) fn open_audit_log(&self) -> Option<crate::audit::AuditLog> {
        let dir = self.cfg.control.audit_dir.as_ref()?;
        crate::audit::AuditLog::open(dir).ok()
    }

    pub(crate) fn print_identity(&self) {
        println!("validator addr   = {}", self.chain.validator_addr.display());
        println!("program addr     = {}", self.chain.program_addr.display());
        println!(
            "wallet pubkey    = {}",
            hex::encode(self.chain.wallet.public.0)
        );
        println!("wg pubkey        = {}", hex::encode(self.wg_kp.public.0));
        println!(
            "wg x25519 pub    = {}",
            hex::encode(X25519Pub::from(&self.wg_static_secret).to_bytes())
        );
        println!("view pubkey      = {}", hex::encode(self.view_pubkey));
        println!("public endpoint  = {}", self.cfg.tunnel.public_endpoint);
        println!(
            "protocol version = {}",
            match self.cfg.chain.protocol_version {
                ProtocolVersion::V1_1 => "v1.1",
                ProtocolVersion::V2 => "v2 (Circle-native)",
                ProtocolVersion::V3 => "v3 (chain-minimal, circle-resident)",
            }
        );
        if self.cfg.chain.protocol_version == ProtocolVersion::V3 {
            if let Some(cid) = self.cfg.chain.circle_id.as_deref() {
                println!("v3 circle id     = {cid}");
            } else {
                println!(
                    "v3 circle id     = <missing — set [chain].circle_id in node.toml>"
                );
            }
            let p = crate::v3_boot::v3_state_path(&self.cfg);
            match crate::chain_v3::CircleV3State::load(&p) {
                Ok(Some(state)) => {
                    if !state.last_anchor_hex.is_empty() {
                        println!("v3 last anchor   = {}", state.last_anchor_hex);
                    }
                    if !state.register_tx_hash.is_empty() {
                        println!("v3 register tx   = {}", state.register_tx_hash);
                    }
                    if !state.last_update_tx_hash.is_empty() {
                        println!("v3 last update tx= {}", state.last_update_tx_hash);
                    }
                }
                Ok(None) => {
                    println!(
                        "v3 boot state    = <not yet computed; run `octravpn-node register`>"
                    );
                }
                Err(e) => {
                    println!("v3 boot state    = <error reading {}: {e}>", p.display());
                }
            }
        }
        if self.cfg.chain.protocol_version == ProtocolVersion::V2 {
            // Predict what `register_endpoint` would produce, given the
            // current chain state. Best-effort: if the chain is
            // unreachable, just print the cache.
            let state_path = self.circle_state_path();
            match CircleState::load(&state_path) {
                Ok(Some(state)) => {
                    println!("v2 circle id     = {}", state.circle_id);
                    println!("v2 deploy nonce  = {}", state.deploy_nonce);
                    if !state.deploy_tx_hash.is_empty() {
                        println!("v2 deploy tx     = {}", state.deploy_tx_hash);
                    }
                    if !state.policy_tx_hash.is_empty() {
                        println!("v2 policy tx     = {}", state.policy_tx_hash);
                    }
                    if !state.register_tx_hash.is_empty() {
                        println!("v2 register tx   = {}", state.register_tx_hash);
                    }
                }
                Ok(None) => {
                    println!(
                        "v2 circle id     = <not yet derived; run `octravpn-node register`>"
                    );
                }
                Err(e) => {
                    println!("v2 circle state  = <error reading {}: {e}>", state_path.display());
                }
            }
        }
    }

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
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        let receipt_pubkey_b64 = B64.encode(self.wg_kp.public.0);
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
    /// Thin wrapper around [`resolve_sealed_passphrase`] that pulls the
    /// env var + config field for the running hub.
    fn sealed_passphrase(&self) -> Result<zeroize::Zeroizing<String>> {
        resolve_sealed_passphrase(
            std::env::var("OCTRAVPN_SEALED_PASSPHRASE").ok().as_deref(),
            self.cfg.chain.sealed_passphrase.as_deref(),
        )
    }

    /// Path where the v2 circle state (id + tx hashes) is cached. Picks
    /// `cfg.chain.circle_state_path` if set, else falls back to
    /// `./state/circle.toml`.
    fn circle_state_path(&self) -> std::path::PathBuf {
        self.cfg.chain.circle_state_path.as_ref().map_or_else(
            || std::path::PathBuf::from("./state/circle.toml"),
            std::path::PathBuf::from,
        )
    }

    /// Build the deployment-domain receipt context that gets bound into
    /// every signed receipt. v1.2 P1-5 hardening: a receipt is now
    /// non-replayable across programs, chains, and circles.
    ///
    /// v1.1 operators leave `circle_id = None`. v2 operators that have
    /// completed `register_endpoint_v2` will have a `state/circle.toml`
    /// on disk; we read it best-effort and populate `circle_id =
    /// Some(addr)` from it. If the circle file is missing (operator
    /// hasn't called `register` yet) we fall back to `None` — the
    /// startup path will rewrite the context as soon as the deploy
    /// completes (operators always run `register` before serving
    /// traffic).
    fn build_receipt_context(&self) -> octravpn_core::receipt::ReceiptContext {
        let chain_id = self.cfg.chain.chain_id;
        let program_addr = self.chain.program_addr.clone();
        match self.cfg.chain.protocol_version {
            ProtocolVersion::V1_1 => {
                octravpn_core::receipt::ReceiptContext::v1_1(program_addr, chain_id)
            }
            ProtocolVersion::V2 => {
                let circle_id = match CircleState::load(&self.circle_state_path()) {
                    Ok(Some(s)) if !s.circle_id.is_empty() => {
                        Some(Address::from_display(&s.circle_id))
                    }
                    _ => None,
                };
                octravpn_core::receipt::ReceiptContext {
                    program_addr,
                    chain_id,
                    circle_id,
                }
            }
            ProtocolVersion::V3 => {
                // v3 receipt context binds the operator's configured
                // circle (the same one anchored on-chain via
                // register_circle). Fall back to None if the operator
                // hasn't filled it in yet — register_endpoint will
                // fail-fast at the next boot.
                let circle_id = self
                    .cfg
                    .chain
                    .circle_id
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .map(Address::from_display);
                octravpn_core::receipt::ReceiptContext {
                    program_addr,
                    chain_id,
                    circle_id,
                }
            }
        }
    }

    /// Minimum circle stake to send with the first `register_circle`.
    /// Sourced from a constant for now (the v2 AML's `min_circle_stake`
    /// param). Future work: read the live param from
    /// `contract_call(get_params)` so this picks up governance updates.
    #[allow(clippy::unused_self)] // future revisions will read live params
    fn cfg_min_circle_stake(&self) -> u64 {
        MIN_CIRCLE_STAKE_DEFAULT
    }

    /// Assemble the v2 policy bundle from the live operator config.
    /// Clients fetch + decrypt this to learn endpoint + WG pubkey +
    /// tariffs without the data being readable on-chain.
    fn build_policy_bundle(&self) -> PolicyBundle {
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        let wg_pub_x25519 = X25519Pub::from(&self.wg_static_secret).to_bytes();
        PolicyBundle {
            endpoint: self.cfg.tunnel.public_endpoint.clone(),
            wg_pubkey_hex: hex::encode(wg_pub_x25519),
            region: self.cfg.pricing.region.clone(),
            price_per_mb_shared: self.cfg.pricing.shared_price(),
            price_per_mb_internal: self.cfg.pricing.internal_price(),
            attestation_ts: octravpn_core::util::now_unix_secs(),
            receipt_pubkey_b64: B64.encode(self.wg_kp.public.0),
            hfhe_pubkey: self.hfhe_pubkey_placeholder(),
            schema_version: 1,
        }
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
                let call =
                    self.chain
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
                let call =
                    self.chain_v2
                        .build_settle_claim_call(session_id, bytes_used, fee, nonce);
                let signed = self.chain_v2.sign_call(call)?;
                let hash = self.chain_v2.submit_signed_tx(&signed).await?;
                info!(%hash, session_id, bytes_used, "settle_claim (v2) submitted");
                Ok(())
            }
            ProtocolVersion::V3 => {
                let nonce = self.chain_v3.nonce().await?;
                let fee = self.chain_v3.fee_or_fallback("contract_call").await;
                let call =
                    self.chain_v3
                        .build_settle_claim_call(session_id, bytes_used, fee, nonce);
                let signed = self.chain_v3.sign_call(call)?;
                let hash = self.chain_v3.submit_signed_tx(&signed).await?;
                info!(%hash, session_id, bytes_used, "settle_claim (v3) submitted");
                Ok(())
            }
        }
    }

    /// Per-operator placeholder HFHE pubkey. Replaced when the libpvac
    /// SDK lands.
    fn hfhe_pubkey_placeholder(&self) -> String {
        // Deterministic per-operator string so the on-chain record is
        // stable across restarts; just a tag + the wallet's hex pubkey.
        format!(
            "hfhe_v1|placeholder|{}",
            hex::encode(self.chain.wallet.public.0)
        )
    }

    /// Per-operator placeholder enc(0). Same caveat as
    /// `hfhe_pubkey_placeholder`.
    fn hfhe_initial_enc_zero_placeholder(&self) -> String {
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

    pub(crate) fn spawn_tunnel(self: Arc<Self>) -> JoinHandle<Result<()>> {
        let allowlist = self.allowlist.clone();
        tokio::spawn(async move {
            let listen: std::net::SocketAddr = self
                .cfg
                .tunnel
                .listen
                .parse()
                .context("parse listen addr")?;
            let shield_cfg = self.cfg.tunnel.amnezia.to_wire();

            // P0-T (4-layer shielding pack, layer 2): if the operator
            // opted into the obfs4-modelled transport via
            // `[tun.transport].kind = "obfs4"`, validate the config
            // and log that the wrapper is engaged. The current data
            // plane still runs through `tokio::net::UdpSocket`
            // directly (see `tunnel.rs`); swap-in of `Obfs4Transport`
            // for the inbound + outbound datagram paths is gated
            // behind a follow-up task because the existing async
            // recv-loop in `tunnel::Server::run` does not yet plumb
            // through `octravpn_tun::Transport`. Validating the
            // config at boot means a typo in `bridge_node_id` /
            // `bridge_pubkey` surfaces immediately rather than at
            // first packet.
            validate_obfs4_config(&self.cfg)?;
            let server = Arc::new(
                Server::bind_with_shield(
                    listen,
                    self.wg_static_secret.clone(),
                    self.router.clone(),
                    allowlist,
                    shield_cfg,
                )
                .await?
                .with_metrics(self.metrics.clone()),
            );
            info!(?listen, "tunnel listening");
            server.run().await
        })
    }

    pub(crate) fn spawn_control_plane(self: Arc<Self>) -> JoinHandle<Result<()>> {
        let allowlist = self.allowlist.clone();
        let metrics = self.metrics.clone();
        let receipt_context = Arc::new(self.build_receipt_context());
        let receipt_journal = self.receipt_journal.clone();
        tokio::spawn(async move {
            let listen: std::net::SocketAddr = self
                .cfg
                .control
                .listen
                .parse()
                .context("parse control listen addr")?;
            // Admin token resolution order: explicit config field >
            // OCTRAVPN_ADMIN_TOKEN env var > absent (endpoint
            // hidden). The env-var path lets the
            // `docker/devnet/tailscale-interop` harness inject a
            // token via the compose secret without re-rendering
            // node.toml.
            let admin_token = self
                .cfg
                .control
                .admin_token
                .clone()
                .or_else(|| std::env::var("OCTRAVPN_ADMIN_TOKEN").ok());
            // Construct the Tailscale-wire surface state if a
            // `[control].tailscale_wire_state_dir` is configured. Absent
            // configuration ⇒ wire router is not mounted at all
            // (matching the `/events` "endpoint hidden" design). The
            // PreauthMinter is shared with `/admin/preauth` so a key
            // minted via that endpoint is redeemable through `register`.
            let wire_state = if let Some(dir) = self
                .cfg
                .control
                .tailscale_wire_state_dir
                .as_ref()
                .map(std::path::PathBuf::from)
            {
                use octravpn_mesh::{
                    ip_alloc::TailnetIpAllocator,
                    tailscale_wire::{
                        derp_config::{empty_derp_map, load_derp_map},
                        MachineRegistry,
                    },
                    PreauthMinter, ServerNoiseKey, WireState,
                };
                let server_noise_key = Arc::new(
                    ServerNoiseKey::load_or_generate(&dir)
                        .context("load tailscale_wire noise static key")?,
                );
                let tailnet_id = self
                    .cfg
                    .control
                    .tailscale_tailnet_id
                    .clone()
                    .unwrap_or_else(|| "octravpn-interop".to_string());
                // PreauthMinter is constructed *here* and then shared
                // into ControlState below. Reusing the same Arc<Mutex>
                // means an `/admin/preauth`-minted key is visible to
                // the wire `register` handler.
                //
                // The wire layer (now in headscale-api) sees the
                // minter only through the `PreauthRedeemer` trait —
                // implemented in `octravpn_mesh::headscale_bridge`.
                // Attach the node's metrics sink so the wire-side
                // `redeem` path bumps `preauth_redemptions_total`
                // without round-tripping through the control plane.
                // Mints from `/admin/preauth` are bumped at the
                // handler instead (control.rs::mint_preauth); the
                // sink path is for redemptions issued from the
                // headscale-api wire register handler.
                let metrics_sink: Arc<dyn octravpn_mesh::MetricsSink> = self.metrics.clone();
                let shared_minter = PreauthMinter::new().with_metrics_sink(metrics_sink);
                // Wall 6: optionally load a DERP-map fixture from the
                // path advertised in OCTRAVPN_DERP_MAP_PATH. Unset ⇒
                // empty map ⇒ matches pre-Wall-6 behaviour.
                let derp_map = match std::env::var("OCTRAVPN_DERP_MAP_PATH") {
                    Ok(path) if !path.is_empty() => load_derp_map(std::path::Path::new(&path))
                        .with_context(|| format!("load DERP map from {path}"))?,
                    _ => empty_derp_map(),
                };
                Some((
                    WireState {
                        server_noise_key,
                        preauth: Arc::new(shared_minter.clone()),
                        ip_allocator: Arc::new(TailnetIpAllocator::new(tailnet_id)),
                        machines: Arc::new(MachineRegistry::new()),
                        derp_map: Arc::new(derp_map),
                        // P1-policy: live ACL store, shared with the
                        // admin surface (when mounted). The default
                        // empty store keeps the wire layer's
                        // `allow_all_packet_filter` fallback in play
                        // until an operator pushes a doc.
                        policy: Arc::new(octravpn_mesh::policy::PolicyStore::new()),
                        // PSK-gated handshake: hub path is the
                        // chain-aware boot path and predates the
                        // knock layer. Always disabled here; the
                        // `mesh serve` entry point in `main.rs` is
                        // the one that honours the env var.
                        knock: octravpn_mesh::tailscale_wire::KnockConfig::disabled(),
                        dns: Arc::new(octravpn_mesh::headscale_api::dns::DnsStore::new()),
                    },
                    shared_minter,
                ))
            } else {
                None
            };
            let mut state = ControlState::with_metrics(
                self.wg_kp.clone(),
                self.router.clone(),
                allowlist,
                metrics,
                receipt_context,
                receipt_journal,
            )
            .with_events_token(self.cfg.control.events_token.clone())
            .with_metrics_token(self.cfg.control.metrics_token.clone())
            .with_admin_token(admin_token)
            .with_wire_state(wire_state.as_ref().map(|(ws, _)| ws.clone()));
            // If the wire surface is enabled, swap the auto-constructed
            // preauth minter for the one shared with the wire router so
            // both paths see the same store.
            if let Some((_, shared)) = wire_state {
                state.preauth_minter = shared;
            }
            // Open the audit log next to the wallet secret unless a
            // dedicated path is configured.
            let audit_dir = self
                .cfg
                .control
                .audit_dir
                .clone()
                .unwrap_or_else(|| "./audit".into());
            // Task #231: if the [analytics] block is enabled, spawn the
            // indexer + bind it to the audit-log live tap so new
            // events fan out into the in-memory time-buckets.
            let analytics_tap = if self.cfg.analytics.enabled {
                let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<
                    octravpn_analytics::AnalyticsEvent,
                >();
                let indexer = octravpn_analytics::Indexer::new();
                // Boot-time backfill: replay everything already on
                // disk so the dashboards have history immediately.
                // Errors are non-fatal — a missing audit dir on first
                // boot is normal.
                match octravpn_analytics::load_audit_key(std::path::Path::new(&audit_dir)) {
                    Ok(key) => match indexer
                        .ingest_audit_dir(&key, std::path::Path::new(&audit_dir))
                    {
                        Ok(scans) => info!(
                            files = scans.len(),
                            "analytics: replayed audit log at boot"
                        ),
                        Err(e) => warn!(error = %e, "analytics: audit replay failed"),
                    },
                    Err(e) => warn!(error = %e, "analytics: no audit key (cold start)"),
                }
                // Live stream: drain the unbounded channel into the
                // indexer state. The audit-log tap publishes here on
                // every successful write.
                let state_clone = indexer.state.clone();
                tokio::spawn(async move {
                    while let Some(ev) = rx.recv().await {
                        state_clone.ingest(&ev);
                    }
                });
                let http_state = octravpn_analytics::HttpState::new(
                    indexer.state.clone(),
                    self.cfg.analytics.bearer_token.clone(),
                );
                let listen_addr = self.cfg.analytics.listen_addr.clone();
                let listen_for_log = listen_addr.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        octravpn_analytics::serve(&listen_addr, http_state, None).await
                    {
                        warn!(error = %e, "analytics: http server stopped");
                    }
                });
                info!(
                    listen = %listen_for_log,
                    gated = self.cfg.analytics.bearer_token.is_some(),
                    "analytics indexer spawned"
                );
                Some(tx)
            } else {
                None
            };
            match crate::audit::AuditLog::open_batched(
                &audit_dir,
                crate::audit::DEFAULT_BATCH_SIZE,
                crate::audit::DEFAULT_BATCH_INTERVAL_MS,
            ) {
                Ok(mut audit) => {
                    if let Some(tap) = analytics_tap {
                        audit = audit.with_analytics_tap(tap);
                    }
                    state = state.with_audit(audit);
                    info!(
                        dir = %audit_dir,
                        batch_size = crate::audit::DEFAULT_BATCH_SIZE,
                        batch_interval_ms = crate::audit::DEFAULT_BATCH_INTERVAL_MS,
                        "audit log open (batched fsync)"
                    );
                }
                Err(e) => warn!(error = %e, dir = %audit_dir, "audit log disabled"),
            }
            let state = Arc::new(state);
            tokio::spawn(crate::control::run_sweeper(state.clone()));
            control_serve(state, listen).await
        })
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
    pub(crate) fn add(
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

impl Hub {
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

/// Validate the `[tun.transport]` config block. On `direct` (the
/// default) this is a no-op. On `obfs4` we verify that the required
/// hex-encoded fields decode, the lengths match, and (if the node is
/// bridge-side, i.e. `bridge_identity_secret` is set) the secret
/// agrees with the published pubkey.
///
/// Boot-time validation surfaces typos (wrong hex length, misformed
/// secret, IAT mode out of range) up front rather than at first
/// packet, where the diagnostic would be a silent handshake failure.
///
/// When obfs4 is enabled we additionally construct an
/// `Obfs4Transport` once to confirm the bind / role wiring compiles
/// end-to-end against the node's `[tunnel].listen` address. The
/// instance is then dropped — the WG data plane still uses
/// `tokio::net::UdpSocket` directly (the data-path swap is gated
/// behind a follow-up task that adapts `tunnel::Server::run` to the
/// `octravpn_tun::Transport` trait).
fn validate_obfs4_config(cfg: &crate::config::NodeConfig) -> Result<()> {
    use crate::config::{Obfs4Cfg, TransportKind};
    use octravpn_obfs4::{
        bridge::{BridgeCredentials, BridgeIdentity, NODE_ID_LEN},
        IatMode,
    };

    if cfg.tun.transport.kind != TransportKind::Obfs4 {
        return Ok(());
    }
    let o: &Obfs4Cfg = cfg
        .tun
        .transport
        .obfs4
        .as_ref()
        .ok_or_else(|| anyhow!("[tun.transport].kind = \"obfs4\" but [tun.transport.obfs4] missing"))?;

    let node_id_bytes =
        ::hex::decode(&o.bridge_node_id).context("[tun.transport.obfs4].bridge_node_id hex")?;
    if node_id_bytes.len() != NODE_ID_LEN {
        return Err(anyhow!(
            "[tun.transport.obfs4].bridge_node_id must decode to {NODE_ID_LEN} bytes, got {}",
            node_id_bytes.len()
        ));
    }
    let mut node_id = [0u8; NODE_ID_LEN];
    node_id.copy_from_slice(&node_id_bytes);

    let pubkey_bytes =
        ::hex::decode(&o.bridge_pubkey).context("[tun.transport.obfs4].bridge_pubkey hex")?;
    if pubkey_bytes.len() != 32 {
        return Err(anyhow!(
            "[tun.transport.obfs4].bridge_pubkey must decode to 32 bytes, got {}",
            pubkey_bytes.len()
        ));
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&pubkey_bytes);
    let bridge_pubkey = x25519_dalek::PublicKey::from(pk);

    let iat_mode = IatMode::from_u8(o.iat_mode).ok_or_else(|| {
        anyhow!(
            "[tun.transport.obfs4].iat_mode must be 0/1/2, got {}",
            o.iat_mode
        )
    })?;

    // Bridge-side: validate the secret matches the pubkey.
    if let Some(secret_hex) = o.bridge_identity_secret.as_ref() {
        let secret_bytes = ::hex::decode(secret_hex)
            .context("[tun.transport.obfs4].bridge_identity_secret hex")?;
        if secret_bytes.len() != 32 {
            return Err(anyhow!(
                "[tun.transport.obfs4].bridge_identity_secret must decode to 32 bytes"
            ));
        }
        let mut sec = [0u8; 32];
        sec.copy_from_slice(&secret_bytes);
        let identity = BridgeIdentity::from_bytes(node_id, sec);
        let derived = identity.credentials().identity_pubkey;
        if derived.as_bytes() != bridge_pubkey.as_bytes() {
            return Err(anyhow!(
                "[tun.transport.obfs4].bridge_identity_secret does not derive the configured bridge_pubkey"
            ));
        }
    }

    let _ = BridgeCredentials {
        node_id,
        identity_pubkey: bridge_pubkey,
    };
    info!(
        iat_mode = ?iat_mode,
        role = if o.bridge_identity_secret.is_some() { "bridge" } else { "client" },
        "obfs4 transport configured (data-plane swap-in pending; config validated at boot)"
    );
    Ok(())
}

fn read_secret_32(path: &str) -> Result<[u8; 32]> {
    octravpn_core::util::read_secret_32(path).with_context(|| format!("load secret {path}"))
}

/// Strict variant used when `[chain].require_sealed_keys = true`. Returns
/// a `Zeroizing<[u8; 32]>` so the caller's intermediate copy is wiped
/// on drop. Plaintext on disk surfaces as
/// `CoreError::PlaintextKeyOnDisk` — anyhow renders the suggested
/// `octravpn-node seal-keys` invocation into the error message so the
/// operator sees a copy-pasteable next step. Threat model: P1-6.
fn read_secret_32_strict(
    path: &str,
) -> Result<zeroize::Zeroizing<[u8; 32]>> {
    octravpn_core::util::read_secret_32_or_sealed(path, None)
        .with_context(|| format!("strict-load secret {path}"))
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

fn wallet_view_pubkey(wallet_secret: &[u8; 32]) -> [u8; 32] {
    // The view PUBLIC key is `view_secret · G_x25519`, where
    // `view_secret` is HKDF'd from the wallet SECRET. Deriving from the
    // public key would let anyone with the on-chain address recompute
    // stealth tags — see `octravpn_core::stealth` module docs.
    octravpn_core::stealth::view_pubkey_from_wallet(wallet_secret)
}

/// Build the RPC client honoring `[chain].pinned_root_paths` if any.
/// Empty / absent → system trust store (current behaviour). Set →
/// only the supplied PEM bundles are trusted, defeating
/// CA-compromise MITM on the chain endpoint. P0-2 from the v2 threat
/// model.
fn build_rpc(chain: &crate::config::ChainCfg) -> Result<RpcClient> {
    let paths = chain.pinned_root_paths.as_ref().map_or(&[][..], Vec::as_slice);
    if paths.is_empty() {
        return Ok(RpcClient::new(&chain.rpc_url));
    }
    let mut blobs = Vec::with_capacity(paths.len());
    for p in paths {
        let pem = std::fs::read(p)
            .with_context(|| format!("read pinned root {p}"))?;
        blobs.push(pem);
    }
    RpcClient::new_with_pinned_roots(&chain.rpc_url, &blobs)
        .map_err(|e| anyhow::anyhow!("pinned tls: {e}"))
}

/// Resolve the v2 sealed-asset passphrase given the env var + config
/// field. Env-first (matches `octravpn-client::discover_v2::resolve_passphrase`)
/// so an operator can override the TOML without editing the file.
/// Empty / whitespace-only values are treated as unset.
///
/// Free function (no `&self`) so the precedence is unit-testable without
/// constructing a Hub. The wrapper method on `Hub` simply pulls live env
/// + config and delegates here.
pub(crate) fn resolve_sealed_passphrase(
    env: Option<&str>,
    cfg_field: Option<&str>,
) -> Result<zeroize::Zeroizing<String>> {
    if let Some(s) = env {
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            return Ok(zeroize::Zeroizing::new(trimmed.to_string()));
        }
    }
    if let Some(s) = cfg_field {
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            return Ok(zeroize::Zeroizing::new(trimmed.to_string()));
        }
    }
    Err(anyhow!(
        "v2 sealed-asset passphrase required: export OCTRAVPN_SEALED_PASSPHRASE \
         or set `[chain].sealed_passphrase` in the operator's TOML"
    ))
}

#[cfg(test)]
mod sealed_passphrase_tests {
    use super::resolve_sealed_passphrase;

    #[test]
    fn env_wins_over_cfg_field() {
        let got = resolve_sealed_passphrase(Some("env-val"), Some("cfg-val")).unwrap();
        assert_eq!(&*got, "env-val");
    }

    #[test]
    fn cfg_field_used_when_env_absent() {
        let got = resolve_sealed_passphrase(None, Some("cfg-val")).unwrap();
        assert_eq!(&*got, "cfg-val");
    }

    #[test]
    fn cfg_field_used_when_env_empty() {
        let got = resolve_sealed_passphrase(Some(""), Some("cfg-val")).unwrap();
        assert_eq!(&*got, "cfg-val");
    }

    #[test]
    fn cfg_field_used_when_env_whitespace() {
        let got = resolve_sealed_passphrase(Some("   "), Some("cfg-val")).unwrap();
        assert_eq!(&*got, "cfg-val");
    }

    #[test]
    fn error_when_both_unset() {
        assert!(resolve_sealed_passphrase(None, None).is_err());
    }

    #[test]
    fn error_when_both_empty() {
        assert!(resolve_sealed_passphrase(Some(""), Some("   ")).is_err());
    }

    #[test]
    fn values_are_trimmed() {
        let got = resolve_sealed_passphrase(Some("  spaced  "), None).unwrap();
        assert_eq!(&*got, "spaced");
    }
}
