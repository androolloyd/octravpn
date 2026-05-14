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
    config::NodeConfig,
    control::{serve as control_serve, ControlState},
    onion::OnionRouter,
    tunnel::Server,
};

pub(crate) struct Hub {
    pub cfg: NodeConfig,
    pub chain: ChainCtx,
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
}

impl Hub {
    pub(crate) async fn new(cfg: NodeConfig) -> Result<Self> {
        let rpc = RpcClient::new(&cfg.chain.rpc_url);
        let validator_addr = Address::from_display(&cfg.chain.validator_addr);
        let program_addr = Address::from_display(&cfg.chain.program_addr);

        let wallet_secret =
            read_secret_32(&cfg.chain.wallet_secret_path).context("read wallet secret")?;
        let wallet = KeyPair::from_secret_bytes(&wallet_secret);

        let chain = ChainCtx {
            rpc,
            program_addr,
            validator_addr,
            wallet,
        };

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
        let master = read_secret_32(&cfg.tunnel.wg_secret_path).context("read wg master secret")?;
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

        Ok(Self {
            cfg,
            chain,
            wg_kp,
            wg_static_secret,
            view_pubkey,
            router: Arc::new(OnionRouter::new()),
            allowlist,
            metrics,
        })
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
    }

    /// Per-operator stake required for `register_endpoint` to
    /// succeed. Mirrors `Params.min_endpoint_stake` in the AML
    /// (1000 OCT = 1B OU by default). Kept local so the node can
    /// fail fast without first reading params.
    pub(crate) const MIN_ENDPOINT_STAKE_DEFAULT: u64 = 1_000_000_000;

    pub(crate) async fn register_endpoint(self: &Arc<Self>) -> Result<()> {
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
        let params = crate::chain::RegisterEndpointParams {
            endpoint: &self.cfg.tunnel.public_endpoint,
            wg_pubkey_hex: &wg_pub_hex,
            hfhe_pubkey: &hfhe_placeholder,
            initial_enc_zero: &initial_enc_zero_placeholder,
            region: &self.cfg.pricing.region,
            price_per_mb: self.cfg.pricing.price_per_mb,
            fee,
            nonce,
        };
        let call = self.chain.build_register_endpoint_call(&params);
        let signed = self.chain.sign_call(call)?;
        let hash = self.chain.submit_signed_tx(&signed).await?;
        info!(%hash, "register_endpoint submitted");
        Ok(())
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
    pub(crate) async fn settle_claim(
        self: &Arc<Self>,
        session_id: u64,
        bytes_used: u64,
    ) -> Result<()> {
        let nonce = self.chain.nonce().await?;
        let fee = self.chain.fee("contract_call").await?;
        let call = self.chain.build_settle_claim_call(session_id, bytes_used, fee, nonce);
        let signed = self.chain.sign_call(call)?;
        let hash = self.chain.submit_signed_tx(&signed).await?;
        info!(%hash, session_id, bytes_used, "settle_claim submitted");
        Ok(())
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
        format!(
            "hfhe_v1|enc0|{}",
            hex::encode(self.chain.wallet.public.0)
        )
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
        let call = self.chain.build_claim_call(
            acc.amount,
            &proof_placeholder,
            fee,
            nonce,
        );
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
        let poll = std::time::Duration::from_secs(
            self.cfg.attestation.poll_interval_secs.max(30),
        );
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(poll).await;
                let slashed = self.chain.read_endpoint_slashed().await;
                let stake = self.chain.read_endpoint_stake().await;
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
            let server = Arc::new(
                Server::bind(
                    listen,
                    self.wg_static_secret.clone(),
                    self.router.clone(),
                    allowlist,
                )
                .await?,
            );
            info!(?listen, "tunnel listening");
            server.run().await
        })
    }

    pub(crate) fn spawn_control_plane(self: Arc<Self>) -> JoinHandle<Result<()>> {
        let allowlist = self.allowlist.clone();
        let metrics = self.metrics.clone();
        tokio::spawn(async move {
            let listen: std::net::SocketAddr = self
                .cfg
                .control
                .listen
                .parse()
                .context("parse control listen addr")?;
            let mut state = ControlState::with_metrics(
                self.wg_kp.clone(),
                self.router.clone(),
                allowlist,
                metrics,
            );
            // Open the audit log next to the wallet secret unless a
            // dedicated path is configured.
            let audit_dir = self
                .cfg
                .control
                .audit_dir
                .clone()
                .unwrap_or_else(|| "./audit".into());
            match crate::audit::AuditLog::open(&audit_dir) {
                Ok(audit) => {
                    state = state.with_audit(audit);
                    info!(dir = %audit_dir, "audit log open");
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

fn read_secret_32(path: &str) -> Result<[u8; 32]> {
    octravpn_core::util::read_secret_32(path).with_context(|| format!("load secret {path}"))
}

fn wallet_view_pubkey(wallet_secret: &[u8; 32]) -> [u8; 32] {
    // The view PUBLIC key is `view_secret · G_x25519`, where
    // `view_secret` is HKDF'd from the wallet SECRET. Deriving from the
    // public key would let anyone with the on-chain address recompute
    // stealth tags — see `octravpn_core::stealth` module docs.
    octravpn_core::stealth::view_pubkey_from_wallet(wallet_secret)
}
