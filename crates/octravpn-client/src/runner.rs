//! Wallet-bound client context and authenticated session lifecycle dispatch.

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use octravpn_core::{
    address::Address,
    chain_tx_queue::{self, ChainTxQueueHandle},
    receipt::ReceiptContext,
    rpc::RpcClient,
    session::{SessionId, ValidatorRecord},
    sig::KeyPair,
    v3_calls::Application,
};

use crate::{
    config::{ClientConfig, ProtocolVersion},
    settle_state, wallet,
};

pub(crate) struct Client {
    rpc: RpcClient,
    http: reqwest::Client,
    program_addr: Address,
    wallet_addr: Address,
    wallet_kp: Arc<KeyPair>,
    chain_tx_queue: ChainTxQueueHandle,
    /// Deployment domain bound into every receipt the client verifies /
    /// co-signs. v1.2 P1-5: receipt is non-replayable across programs,
    /// chains, or circles. v1.1 clients leave `circle_id = None`; v2
    /// clients overwrite it once they've fetched the operator's circle
    /// (see the v2 discovery path).
    receipt_context: ReceiptContext,
    relay: crate::config::V3RelayCfg,
    application: Application,
}

pub(crate) struct ActiveSession {
    pub session_id: SessionId,
    pub session_kp: KeyPair,
    pub open_tx_hash: String,
    pub exit: ValidatorRecord,
    pub deposit: u64,
    /// Canonically advertised control origin when it uses a nonstandard port.
    pub control_endpoint: Option<String>,
    /// Locally observed upper bound; absent only for explicit offline fixtures.
    pub metered_bytes: Option<u64>,
}

impl Client {
    pub(crate) async fn new(cfg: Arc<ClientConfig>) -> Result<Self> {
        let rpc = build_rpc(&cfg.chain)?;
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .context("build http client")?;
        let protocol = ProtocolVersion::parse(&cfg.chain.protocol_version)?;
        let effective_path = if protocol == ProtocolVersion::V3 {
            cfg.v3
                .wallet_key_path
                .as_deref()
                .unwrap_or(&cfg.wallet.secret_path)
        } else {
            &cfg.wallet.secret_path
        };
        let wallet_kp = Arc::new(wallet::load_keypair(effective_path)?);
        let (program_addr, wallet_addr) = if protocol == ProtocolVersion::V3 {
            let program = octravpn_core::parse_native_address(&cfg.chain.program_addr)
                .context("v3 settlement address")?;
            let address =
                Address::try_from_display(&cfg.wallet.addr).context("v3 wallet address")?;
            if address != Address::from_pubkey(&wallet_kp.public.0) {
                return Err(anyhow!("[wallet].addr must match the effective v3 wallet key so funding and recovery share one identity"));
            }
            if cfg.chain.chain_id == 0 {
                return Err(anyhow!("v3 receipt chain id must be nonzero"));
            }
            (program, address)
        } else {
            (
                Address::from_display(&cfg.chain.program_addr),
                Address::from_display(&cfg.wallet.addr),
            )
        };
        if protocol != ProtocolVersion::V3
            && (cfg.v3.relay.enabled || cfg.v3.application == Application::Circle)
        {
            return Err(anyhow!(
                "relay settlement and Circle application mode require protocol_version = \"v3\""
            ));
        }
        // Standalone settlement commands must retain the configured v3 circle
        // across restarts, before replaying the durable receipt journal.
        let receipt_context = configured_receipt_context(
            program_addr.clone(),
            cfg.chain.chain_id,
            protocol,
            &cfg.v3.circle_id,
        )?;
        let relay = cfg.v3.relay.clone();
        // TX-ENVELOPE chain_id is left EMPTY to match the node's ChainCtxV3
        // (all production ctors use String::new()). Devnet/mainnet do not verify
        // a v2 tx-envelope chain_id binding: splicing one makes the signature
        // cover a field the chain re-serializes without -> octra_submit 101
        // "invalid signature". The RECEIPT chain_id binding (settlement_hash via
        // receipt_context above) is a separate, needed thing and stays.
        let chain_tx_queue = chain_tx_queue::spawn(rpc.clone(), wallet_kp.clone(), String::new());
        let client = Self {
            rpc,
            http,
            program_addr,
            wallet_addr,
            wallet_kp,
            chain_tx_queue,
            receipt_context,
            relay,
            application: cfg.v3.application,
        };
        settle_state::replay_pending_for_client(&client)
            .await
            .context("replay pending relay settlement state")?;
        Ok(client)
    }

    pub(crate) fn receipt_context(&self) -> &ReceiptContext {
        &self.receipt_context
    }

    pub(crate) fn relay_config(&self) -> crate::config::V3RelayCfg {
        self.relay.clone()
    }

    /// Return a receipt context with `circle_id = Some(circle)` so v2
    /// settle paths can verify against the specific circle they're
    /// operating in. v1.1 paths use `receipt_context()` directly.
    /// `Client` itself stays immutable so it can be shared via
    /// `Arc<Client>` between the runner and the settler.
    #[allow(dead_code)]
    pub(crate) fn receipt_context_for_circle(&self, circle_id: Address) -> ReceiptContext {
        ReceiptContext {
            program_addr: self.receipt_context.program_addr.clone(),
            chain_id: self.receipt_context.chain_id,
            circle_id: Some(circle_id),
        }
    }

    pub(crate) fn rpc(&self) -> &RpcClient {
        &self.rpc
    }

    pub(crate) fn http(&self) -> &reqwest::Client {
        &self.http
    }

    pub(crate) fn program_addr(&self) -> &Address {
        &self.program_addr
    }

    pub(crate) fn wallet_addr(&self) -> &Address {
        &self.wallet_addr
    }

    pub(crate) fn wallet_kp(&self) -> &KeyPair {
        self.wallet_kp.as_ref()
    }

    pub(crate) fn chain_tx_queue(&self) -> ChainTxQueueHandle {
        self.chain_tx_queue.clone()
    }

    pub(crate) fn application(&self) -> Application {
        self.application
    }

    pub(crate) fn chain_context(&self) -> crate::chain_v3::ChainCtxV3<'_> {
        crate::chain_v3::ChainCtxV3::new_with_tx_queue(
            self.rpc(),
            self.program_addr(),
            self.wallet_kp(),
            Some(self.chain_tx_queue()),
        )
        .with_application(self.application)
    }

    pub(crate) async fn submit_application(&self, mut call: serde_json::Value) -> Result<String> {
        let fields = call
            .as_object_mut()
            .ok_or_else(|| anyhow!("application call must be an object"))?;
        if !fields.contains_key("timestamp") {
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .context("application transaction clock")?
                .as_secs_f64();
            fields.insert("timestamp".to_owned(), serde_json::json!(timestamp));
        }
        let call = self
            .application
            .route_call(call)
            .map_err(|error| anyhow!(error))?;
        self.chain_tx_queue.submit(call).await.map_err(Into::into)
    }

    pub(crate) fn arm_environment(&self) -> settle_state::ArmEnvironment {
        settle_state::ArmEnvironment {
            program_addr: self.program_addr.clone(),
            wallet_addr: self.wallet_addr.clone(),
            relay_expiry_epochs: self.relay.relay_expiry_epochs,
        }
    }

    pub(crate) fn open_settle_state(&self) -> Result<settle_state::SettleStateStore> {
        crate::migration::open_store(
            std::path::Path::new(&self.relay.state_dir),
            &self.wallet_addr,
            self.application,
            &self.receipt_context,
            self.wallet_kp(),
        )
    }

    pub(crate) fn print_identity(&self) {
        println!("wallet addr  = {}", self.wallet_addr.display());
        println!("program addr = {}", self.program_addr.display());
        println!("wallet pub   = {}", hex::encode(self.wallet_kp.public.0));
    }

    pub(crate) async fn connect(
        self: &Arc<Self>,
        cfg: &Arc<ClientConfig>,
        hops: u8,
        region: Option<&str>,
        deposit: u64,
        mode: crate::wireguard::Mode,
    ) -> Result<()> {
        if hops != 1 {
            return Err(anyhow!(
                "authenticated inter-hop forwarding is unavailable; use --hops 1"
            ));
        }
        if region.is_some() {
            return Err(anyhow!("select the operator with [v3].circle_id; region-based route discovery is unavailable for this flow"));
        }
        let mut effective = (**cfg).clone();
        effective.v3.max_pay = deposit;
        Box::pin(crate::v3_runner::connect_v3(
            self,
            &Arc::new(effective),
            None,
            false,
            Some(mode),
        ))
        .await
    }
}

/// Build the RPC client honoring `[chain].pinned_root_paths`. Empty
/// or unset → system trust store (current behaviour). Set → only the
/// supplied PEM bundles are trusted. P0-2 from the v2 threat model.
fn build_rpc(chain: &crate::config::ChainCfg) -> Result<RpcClient> {
    let paths = chain.pinned_root_paths.as_ref();
    let paths = paths.map_or(&[][..], Vec::as_slice);
    if paths.is_empty() {
        return Ok(RpcClient::new(&chain.rpc_url));
    }
    let mut blobs = Vec::with_capacity(paths.len());
    for p in paths {
        let pem = std::fs::read(p).with_context(|| format!("read pinned root {p}"))?;
        blobs.push(pem);
    }
    RpcClient::new_with_pinned_roots(&chain.rpc_url, &blobs)
        .map_err(|e| anyhow::anyhow!("pinned tls: {e}"))
}

fn configured_receipt_context(
    program_addr: Address,
    chain_id: u32,
    protocol: ProtocolVersion,
    circle: &str,
) -> Result<ReceiptContext> {
    let mut context = ReceiptContext::v1_1(program_addr, chain_id);
    if protocol == ProtocolVersion::V3 {
        if circle.trim().is_empty() {
            return Err(anyhow!(
                "[v3].circle_id is required for v3 receipt settlement"
            ));
        }
        context.circle_id = Some(octravpn_core::parse_native_address(circle)?);
    }
    Ok(context)
}

#[cfg(test)]
mod receipt_context_tests {
    use super::*;
    #[test]
    fn v3_settlement_context_retains_configured_circle() {
        let circle = Address::from_pubkey(&[9; 32]);
        let context = configured_receipt_context(
            Address::from_display("octPROGRAM"),
            9,
            ProtocolVersion::V3,
            circle.display(),
        )
        .unwrap();
        assert_eq!(context.circle_id.as_ref().unwrap(), &circle);
        assert_eq!(context.chain_id, 9);
        assert_eq!(context.program_addr.display(), "octPROGRAM");
    }
    #[test]
    fn v3_missing_circle_fails_before_journal_replay() {
        assert!(configured_receipt_context(
            Address::from_display("octPROGRAM"),
            9,
            ProtocolVersion::V3,
            " "
        )
        .is_err());
    }
    #[test]
    fn legacy_receipt_domain_remains_without_circle() {
        assert!(configured_receipt_context(
            Address::from_display("octPROGRAM"),
            9,
            ProtocolVersion::V1_1,
            "octCIRCLE"
        )
        .unwrap()
        .circle_id
        .is_none());
    }
}
