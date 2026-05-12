//! Central node coordinator. Owns the chain client, control-plane HTTP
//! server, receipt store, onion router, and tunnel server, and exposes
//! the high-level operations the `main` binary calls into.

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use octravpn_core::{
    address::Address,
    earnings::{self, scalar_from_bytes, scalar_to_bytes},
    rpc::RpcClient,
    sig::KeyPair,
    stealth,
};
use rand::rngs::OsRng;
use rand::RngCore;
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

        let validator_oracle =
            octravpn_core::validator_oracle::ValidatorOracle::new(rpc.clone());
        let chain = ChainCtx {
            rpc,
            program_addr,
            validator_addr,
            wallet,
            validator_oracle,
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

    pub(crate) async fn register_endpoint(self: &Arc<Self>) -> Result<()> {
        if self.chain.read_endpoint_record().await?.is_some() {
            info!("endpoint already registered on chain; skipping");
            return Ok(());
        }
        if !self.chain.is_octra_validator().await? {
            return Err(anyhow!(
                "{} is not an Octra protocol validator — register on Octra before \
                 advertising a dVPN endpoint",
                self.chain.validator_addr.display()
            ));
        }
        let nonce = self.chain.nonce().await?;
        let fee = self.chain.fee("contract_call").await?;
        let wg_pub_x25519 = X25519Pub::from(&self.wg_static_secret).to_bytes();
        let receipt_pub = self.wg_kp.public.0;
        let params = crate::chain::RegisterEndpointParams {
            endpoint: &self.cfg.tunnel.public_endpoint,
            wg_pubkey: &wg_pub_x25519,
            receipt_pubkey: &receipt_pub,
            view_pubkey: &self.view_pubkey,
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

    /// Claim accumulated Pedersen earnings via stealth payout.
    pub(crate) async fn claim_earnings(self: &Arc<Self>) -> Result<()> {
        let raw_point = self
            .chain
            .rpc
            .contract_call(
                &self.chain.program_addr,
                "get_encrypted_earnings",
                &[serde_json::json!(self.chain.validator_addr.display())],
                Some(&self.chain.validator_addr),
            )
            .await?;
        let point_hex = raw_point
            .as_str()
            .ok_or_else(|| anyhow!("ledger not string"))?;
        let point_bytes = hex::decode(point_hex).context("decode ledger point")?;
        if point_bytes.len() != earnings::POINT_LEN {
            return Err(anyhow!("ledger point wrong length"));
        }

        // Read locally-tracked accumulator.
        let acc = AccumulatorStore::load(&self.cfg.chain.wallet_secret_path)?;

        // Real ECDH stealth: pick an ephemeral secret, run X25519 DH
        // against our own view pubkey, get the tag. The ephemeral
        // secret is dropped immediately after `build_fresh_output`.
        let (stealth_out, _shared) =
            stealth::build_fresh_output(&self.view_pubkey)
                .map_err(|e| anyhow!("derive stealth output: {e}"))?;
        let stealth_target = stealth_out.tag;

        let nonce = self.chain.nonce().await?;
        let fee = self.chain.fee("contract_call").await?;
        let call = self.chain.build_claim_call(
            acc.amount,
            &scalar_to_bytes(&acc.blind_sum),
            &stealth_target,
            fee,
            nonce,
        );
        let signed = self.chain.sign_call(call)?;
        let hash = self.chain.submit_signed_tx(&signed).await?;
        info!(%hash, claimed = acc.amount, "claim_earnings submitted");

        // Reset the local accumulator.
        AccumulatorStore::save(&self.cfg.chain.wallet_secret_path, &Accumulator::zero())?;
        Ok(())
    }

    /// Background loop that periodically verifies our Octra-validator
    /// membership is still good. If we get jailed/unbonded on Octra,
    /// the program-side gate will refuse to serve our endpoint — so
    /// we log a clear warning here for operators.
    pub(crate) fn spawn_validator_health_loop(self: Arc<Self>) -> JoinHandle<Result<()>> {
        let poll = std::time::Duration::from_secs(
            self.cfg.attestation.poll_interval_secs.max(30),
        );
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(poll).await;
                match self.chain.is_octra_validator().await {
                    Ok(true) => {
                        self.metrics.last_attestation_unix.store(
                            octravpn_core::util::now_unix_secs(),
                            std::sync::atomic::Ordering::Relaxed,
                        );
                    }
                    Ok(false) => {
                        warn!("no longer an Octra protocol validator — dVPN endpoint will be rejected");
                    }
                    Err(e) => warn!(error = %e, "is_octra_validator check failed"),
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
