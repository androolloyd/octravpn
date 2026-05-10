//! Central node coordinator. Owns the chain client, control-plane HTTP
//! server, receipt store, onion router, and tunnel server, and exposes
//! the high-level operations the `main` binary calls into.

use std::{fs, sync::Arc};

use anyhow::{anyhow, Context, Result};
use octravpn_core::{
    address::Address,
    earnings::{self, fresh_blind, scalar_from_bytes, scalar_to_bytes, LedgerPoint},
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
    chain::{ChainCtx, TAG_ATTEST, TAG_BOND},
    config::NodeConfig,
    control::{serve as control_serve, ControlState},
    onion::OnionRouter,
    receipts::{ReceiptStore, SharedStore},
    tunnel::Server,
};

pub struct Hub {
    pub cfg: NodeConfig,
    pub chain: ChainCtx,
    pub wg_kp: Arc<KeyPair>,
    pub wg_static_secret: StaticSecret,
    pub view_pubkey: [u8; 32],
    pub receipts: SharedStore,
    pub router: Arc<OnionRouter>,
}

impl Hub {
    pub async fn new(cfg: NodeConfig) -> Result<Self> {
        let rpc = RpcClient::new(&cfg.chain.rpc_url);
        let validator_addr = Address::from_display(&cfg.chain.validator_addr);
        let program_addr = Address::from_display(&cfg.chain.program_addr);

        let wallet_secret = read_secret_32(&cfg.chain.wallet_secret_path)
            .context("read wallet secret")?;
        let wallet = KeyPair::from_secret_bytes(&wallet_secret);

        let chain = ChainCtx {
            rpc,
            program_addr,
            validator_addr,
            wallet,
        };

        let wg_secret_bytes = read_secret_32(&cfg.tunnel.wg_secret_path)
            .context("read wg secret")?;
        let wg_kp = Arc::new(KeyPair::from_secret_bytes(&wg_secret_bytes));
        let wg_static_secret = StaticSecret::from(wg_secret_bytes);

        let view_pubkey = wallet_view_pubkey(&chain.wallet);

        Ok(Self {
            cfg,
            chain,
            wg_kp,
            wg_static_secret,
            view_pubkey,
            receipts: Arc::new(ReceiptStore::new()),
            router: Arc::new(OnionRouter::new()),
        })
    }

    pub fn print_identity(&self) {
        println!("validator addr   = {}", self.chain.validator_addr.display);
        println!("program addr     = {}", self.chain.program_addr.display);
        println!("wallet pubkey    = {}", hex::encode(self.chain.wallet.public.0));
        println!("wg pubkey        = {}", hex::encode(self.wg_kp.public.0));
        println!(
            "wg x25519 pub    = {}",
            hex::encode(X25519Pub::from(&self.wg_static_secret).to_bytes())
        );
        println!("view pubkey      = {}", hex::encode(self.view_pubkey));
        println!("public endpoint  = {}", self.cfg.tunnel.public_endpoint);
    }

    pub async fn register_validator(self: &Arc<Self>) -> Result<()> {
        if self.chain.read_validator_record().await?.is_some() {
            info!("already registered on chain; skipping");
            return Ok(());
        }
        let epoch = self.chain.current_epoch().await?;
        let attest = self.chain.sign_attestation(TAG_BOND, epoch);
        let nonce = self.chain.nonce().await?;
        let fee = self.chain.fee("contract_call").await?;
        let bond = self.cfg.chain.initial_bond.unwrap_or(1_000_000_000);
        let wg_pub_x25519 = X25519Pub::from(&self.wg_static_secret).to_bytes();
        let call = self.chain.build_register_call(
            &self.cfg.tunnel.public_endpoint,
            &wg_pub_x25519,
            &self.view_pubkey,
            &self.cfg.pricing.region,
            self.cfg.pricing.price_per_mb,
            &attest,
            bond,
            fee,
            nonce,
        );
        let signed = self.chain.sign_call(call)?;
        let hash = self.chain.submit_signed_tx(&signed).await?;
        info!(%hash, "register_validator submitted");
        Ok(())
    }

    pub async fn refresh_attestation(self: &Arc<Self>) -> Result<()> {
        let epoch = self.chain.current_epoch().await?;
        let sig = self.chain.sign_attestation(TAG_ATTEST, epoch);
        let nonce = self.chain.nonce().await?;
        let fee = self.chain.fee("contract_call").await?;
        let call = self.chain.build_attest_call(&sig, fee, nonce);
        let signed = self.chain.sign_call(call)?;
        let hash = self.chain.submit_signed_tx(&signed).await?;
        info!(%hash, %epoch, "refresh_attestation submitted");
        Ok(())
    }

    /// Claim accumulated Pedersen earnings.
    ///
    /// Workflow:
    ///   1. Read the validator's earnings ledger point from chain.
    ///   2. Look up our locally-tracked `(amount, blind)` accumulator.
    ///   3. Submit `(claimed_amount, claimed_blind, stealth_output)`.
    ///   4. Reset our local accumulator.
    pub async fn claim_earnings(self: &Arc<Self>) -> Result<()> {
        let raw_point = self
            .chain
            .rpc
            .contract_call(
                &self.chain.program_addr,
                "get_encrypted_earnings",
                &[serde_json::json!(self.chain.validator_addr.display)],
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
        let mut p = [0u8; 32];
        p.copy_from_slice(&point_bytes);
        let _ledger = LedgerPoint(p);

        // Read locally-tracked accumulator.
        let acc = AccumulatorStore::load(&self.cfg.chain.wallet_secret_path)?;

        let mut nonce_buf = [0u8; 32];
        OsRng.fill_bytes(&mut nonce_buf);
        let stealth_target = stealth::derive_output(&self.view_pubkey, &nonce_buf);

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

    pub fn spawn_attestation_loop(self: Arc<Self>) -> JoinHandle<Result<()>> {
        tokio::spawn(async move {
            let every = self.cfg.attestation.refresh_every_epochs;
            let mut last_epoch_attested = 0u64;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                let epoch = match self.chain.current_epoch().await {
                    Ok(e) => e,
                    Err(e) => {
                        warn!(error = %e, "current_epoch failed");
                        continue;
                    }
                };
                if epoch >= last_epoch_attested + every {
                    if let Err(e) = self.refresh_attestation().await {
                        warn!(error = %e, "attestation refresh failed");
                    } else {
                        last_epoch_attested = epoch;
                    }
                }
            }
        })
    }

    pub fn spawn_tunnel(self: Arc<Self>) -> JoinHandle<Result<()>> {
        tokio::spawn(async move {
            let listen: std::net::SocketAddr =
                self.cfg.tunnel.listen.parse().context("parse listen addr")?;
            let server =
                Arc::new(Server::bind(listen, self.wg_static_secret.clone(), self.router.clone()).await?);
            info!(?listen, "tunnel listening");
            server.run().await
        })
    }

    pub fn spawn_control_plane(self: Arc<Self>) -> JoinHandle<Result<()>> {
        tokio::spawn(async move {
            let listen: std::net::SocketAddr = self
                .cfg
                .control
                .listen
                .parse()
                .context("parse control listen addr")?;
            let state = Arc::new(ControlState::new(self.wg_kp.clone(), self.router.clone()));
            control_serve(state, listen).await
        })
    }
}

/// Per-validator local accumulator: tracks the running sum (amount,
/// blind_sum) so we know how to open the on-chain Pedersen ledger.
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
        let raw = fs::read(&p).context("read accumulator")?;
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
        fs::write(&p, &buf).context("write accumulator")?;
        Ok(())
    }

    /// Add a (delta_amount, delta_blind) to the accumulator.
    pub fn add(secret_path: &str, delta_amount: u64, delta_blind: curve25519_dalek::scalar::Scalar) -> Result<()> {
        let mut acc = Self::load(secret_path)?;
        acc.amount = acc.amount.saturating_add(delta_amount);
        acc.blind_sum += delta_blind;
        Self::save(secret_path, &acc)
    }
}

/// Public helper used by the control-plane handler when settling: each
/// time a receipt is co-signed, we record (delta amount × split, blind).
/// The actual split percentages depend on the route, which only the
/// chain knows during settlement; on the node side we conservatively
/// record the *full* bytes_used credit for our local accounting and
/// reconcile on settlement events.
pub fn record_local_credit(
    secret_path: &str,
    pay: u64,
    blind: curve25519_dalek::scalar::Scalar,
) -> anyhow::Result<()> {
    AccumulatorStore::add(secret_path, pay, blind)
}

/// Helper: produce a fresh blind scalar for a settlement (called by the
/// client side when building a receipt; node tracks the same value
/// after co-signing).
pub fn fresh_settlement_blind() -> curve25519_dalek::scalar::Scalar {
    fresh_blind()
}

fn read_secret_32(path: &str) -> Result<[u8; 32]> {
    let raw = fs::read(path).with_context(|| format!("read {path}"))?;
    let bytes = if raw.len() == 32 {
        raw
    } else {
        let s = std::str::from_utf8(&raw)
            .map_err(|e| anyhow!("non-utf8 secret file: {e}"))?
            .trim()
            .to_string();
        hex::decode(&s).context("decode hex secret")?
    };
    if bytes.len() != 32 {
        return Err(anyhow!("secret must be 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn wallet_view_pubkey(kp: &KeyPair) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"octravpn-view-derive-v1");
    h.update(kp.public.0);
    h.finalize().into()
}
