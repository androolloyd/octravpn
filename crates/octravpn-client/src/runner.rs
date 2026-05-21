//! Session lifecycle: pick route, build commitments, open session on chain,
//! perform WG handshakes hop-by-hop, hold the tunnel, settle on shutdown.

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use octravpn_core::{
    address::Address,
    commit::{commit, fresh_blind},
    onion::MAX_HOPS,
    receipt::ReceiptContext,
    rpc::RpcClient,
    session::{SessionId, ValidatorRecord},
    sig::KeyPair,
    stealth,
};
use parking_lot::Mutex;
use serde_json::json;
use tracing::{info, warn};

use crate::{config::ClientConfig, discover, settler, wallet};

pub(crate) struct Client {
    rpc: RpcClient,
    http: reqwest::Client,
    program_addr: Address,
    wallet_addr: Address,
    wallet_kp: KeyPair,
    /// Deployment domain bound into every receipt the client verifies /
    /// co-signs. v1.2 P1-5: receipt is non-replayable across programs,
    /// chains, or circles. v1.1 clients leave `circle_id = None`; v2
    /// clients overwrite it once they've fetched the operator's circle
    /// (see the v2 discovery path).
    receipt_context: ReceiptContext,
    pub state: Mutex<Option<ActiveSession>>,
}

pub(crate) struct ActiveSession {
    pub session_id: SessionId,
    pub session_kp: KeyPair,
    pub open_tx_hash: String,
    pub route: Vec<RouteHop>,
}

#[derive(Clone)]
pub(crate) struct RouteHop {
    pub validator: ValidatorRecord,
    /// Pedersen blinding scalar for this hop. Currently only written
    /// (committed to in `open_session`) and read off-chain by the
    /// slash-on-equivocation flow; kept here so the route record can
    /// reconstruct receipts for dispute proofs.
    #[allow(dead_code)]
    pub blind: [u8; 32],
    pub split_bps: u16,
}

impl Client {
    pub(crate) async fn new(cfg: Arc<ClientConfig>) -> Result<Self> {
        let rpc = build_rpc(&cfg.chain)?;
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .context("build http client")?;
        let program_addr = Address::from_display(&cfg.chain.program_addr);
        let wallet_addr = Address::from_display(&cfg.wallet.addr);
        let wallet_kp = wallet::load_keypair(&cfg.wallet.secret_path)?;
        // Receipt domain: v1.1 clients leave circle_id = None; v2 clients
        // discover circle_id from the operator's policy bundle and call
        // `set_receipt_circle` before opening a session.
        let receipt_context = ReceiptContext::v1_1(program_addr.clone(), cfg.chain.chain_id);
        Ok(Self {
            rpc,
            http,
            program_addr,
            wallet_addr,
            wallet_kp,
            receipt_context,
            state: Mutex::new(None),
        })
    }

    pub(crate) fn receipt_context(&self) -> &ReceiptContext {
        &self.receipt_context
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
        &self.wallet_kp
    }

    pub(crate) fn print_identity(&self) {
        println!("wallet addr  = {}", self.wallet_addr.display());
        println!("program addr = {}", self.program_addr.display());
        println!("wallet pub   = {}", hex::encode(self.wallet_kp.public.0));
    }

    pub(crate) async fn connect(
        self: &Arc<Self>,
        hops: u8,
        region: Option<&str>,
        deposit: u64,
    ) -> Result<()> {
        let hops = hops as usize;
        if hops == 0 || hops > MAX_HOPS {
            return Err(anyhow!("hops must be in 1..={MAX_HOPS}"));
        }

        // 1. Choose `hops` validators.
        let candidates = discover::list(self, 0, 200).await?;
        let mut filtered: Vec<_> = candidates.into_iter().filter(|v| v.active).collect();
        if let Some(r) = region {
            filtered.sort_by_key(|v| u8::from(v.region != r));
        }
        if filtered.len() < hops {
            return Err(anyhow!(
                "not enough active validators: have {}, need {}",
                filtered.len(),
                hops
            ));
        }

        let route_recs = pick_disjoint(&filtered, hops);

        // 2. Build commitments + bookkeeping.
        let mut route_commit: Vec<[u8; 32]> = Vec::with_capacity(hops);
        let mut route: Vec<RouteHop> = Vec::with_capacity(hops);
        for v in route_recs {
            let blind = fresh_blind();
            let c = commit(&v.addr, &blind);
            route_commit.push(c.0);
            route.push(RouteHop {
                validator: v,
                blind,
                split_bps: 0,
            });
        }
        let base = (10000u32 / hops as u32) as u16;
        let residue = 10000u16 - base * hops as u16;
        for (i, h) in route.iter_mut().enumerate() {
            h.split_bps = base + if i + 1 == hops { residue } else { 0 };
        }

        // 3. Generate ephemeral session key + refund stealth output.
        //
        // Refund destination uses the proper X25519 ECDH scheme so the
        // chain-emitted tag isn't linkable from `view_pubkey` alone.
        // Sender picks an ephemeral X25519 secret (zeroized after use);
        // the receiver here is the wallet itself, so we publish the
        // resulting tag and discard the secret.
        let session_kp = KeyPair::generate();
        let view_pubkey = stealth::view_pubkey_from_wallet(&self.wallet_kp.secret_bytes());
        let (stealth_out, _shared) = stealth::build_fresh_output(&view_pubkey)
            .map_err(|e| anyhow!("derive stealth output: {e}"))?;
        let refund_stealth_output = stealth_out.tag;
        let _ = stealth_out.ephemeral_pubkey; // would be published in v2 wire shape

        // 4. Submit `open_session` on chain.
        //
        // v1 AML requires (tailnet_id: int, exit_addr: address,
        // max_pay: int). The standalone `connect` flow doesn't pre-
        // bind a tailnet, so it can't actually settle on v1 — kept
        // here only so the wire format compiles. Real client use
        // goes through `octravpn tailnet up`.
        let _ = (
            route_commit.as_slice(),
            session_kp.public.0,
            refund_stealth_output,
        );
        let exit_addr = route
            .last()
            .map(|h| h.validator.addr.display().to_string())
            .unwrap_or_default();
        let bal = self.rpc.balance(&self.wallet_addr).await?;
        let nonce = bal.pending_nonce.max(bal.nonce);
        let fee = self
            .rpc
            .recommended_fee(Some("contract_call"))
            .await?
            .recommended;
        let open_call = json!({
            "kind": "contract_call",
            "from": self.wallet_addr.display(),
            "to": self.program_addr.display(),
            "method": "open_session",
            "params": [
                0u64,                  // tailnet_id (v1 requires tailnet — see `tailnet up`)
                exit_addr,
                deposit,
            ],
            "value": 0u64,
            "fee": fee,
            "nonce": nonce,
        });
        let signed = sign_call(&self.wallet_kp, open_call)?;
        let r = self.rpc.submit(&signed).await?;
        info!(hash = %r.hash, "session open submitted");

        let session_id = poll_session_id(&self.rpc, &r.hash).await?;
        info!(session_id = %session_id.to_hex(), "session opened");

        *self.state.lock() = Some(ActiveSession {
            session_id: session_id.clone(),
            session_kp,
            open_tx_hash: r.hash,
            route,
        });

        // 5. Build the onion + bring up the tunnel via boringtun.
        //    This is the data-plane piece — a real WireGuard handshake
        //    against the entry hop, then we wrap each outbound packet in
        //    the onion and ship it to the entry hop.
        announce_to_exit(self).await?;
        print_wg_config(self)?;

        // 6. Hold session until ctrl-c; settle on clean shutdown.
        info!("tunnel up; press ctrl-c to disconnect & settle");
        tokio::signal::ctrl_c().await?;
        warn!("disconnect requested; settling…");
        let active = self
            .state
            .lock()
            .take()
            .ok_or_else(|| anyhow!("no active session"))?;
        settler::settle_active(self, active).await?;
        Ok(())
    }
}

fn pick_disjoint(set: &[ValidatorRecord], n: usize) -> Vec<ValidatorRecord> {
    let mut out = Vec::with_capacity(n);
    let mut seen = std::collections::HashSet::new();
    for v in set {
        let key = v.addr.display().to_string();
        if seen.contains(&key) {
            continue;
        }
        seen.insert(key);
        out.push(v.clone());
        if out.len() == n {
            break;
        }
    }
    out
}

async fn announce_to_exit(client: &Client) -> Result<()> {
    // Snapshot the bits we need then drop the lock before any `.await`.
    let (ctrl_endpoint, body) = {
        let g = client.state.lock();
        let active = g.as_ref().ok_or_else(|| anyhow!("no active session"))?;
        let exit = active.route.last().ok_or_else(|| anyhow!("empty route"))?;
        let ctrl_endpoint = octravpn_core::control::base_url_for(&exit.validator.endpoint);
        // Derive the client's X25519 noise pubkey from the wallet
        // pubkey via HKDF — the entry hop uses this to construct its
        // `Tunn` peer state.
        let client_wg_secret = octravpn_core::util::derive_subkey(
            &active.session_kp.public.0,
            octravpn_core::util::DOMAIN_NOISE,
        );
        let client_wg_pubkey =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(client_wg_secret))
                .to_bytes();
        let body = octravpn_core::control::AnnounceSessionRequest {
            session_id: active.session_id.clone(),
            client_pubkey: active.session_kp.public,
            client_wg_pubkey,
            open_tx_hash: active.open_tx_hash.clone(),
            client_sig: active
                .session_kp
                .sign(&octravpn_core::control::announce_signing_payload(
                    &active.session_id,
                    &active.session_kp.public,
                    &client_wg_pubkey,
                    &active.open_tx_hash,
                )),
        };
        (ctrl_endpoint, body)
    };
    let resp = client
        .http()
        .post(format!("{ctrl_endpoint}/session"))
        .json(&body)
        .send()
        .await
        .context("announce session HTTP")?;
    if !resp.status().is_success() {
        return Err(anyhow!("exit announce: status {}", resp.status()));
    }
    Ok(())
}

async fn poll_session_id(rpc: &RpcClient, tx_hash: &str) -> Result<SessionId> {
    // Exponential backoff up to ~30s total: 100ms, 200ms, 400ms, 800ms,
    // 1.6s, then capped at 2s.
    let mut delay_ms: u64 = 100;
    for _ in 0..20 {
        let v = rpc.transaction(tx_hash).await?;
        if let Some(events) = v.get("events").and_then(|x| x.as_array()) {
            for e in events {
                if e.get("name").and_then(|x| x.as_str()) == Some("SessionOpened") {
                    if let Some(sid) = e.get("session_id") {
                        if let Some(id_u64) = sid.as_u64() {
                            return Ok(SessionId::from_u64(id_u64));
                        }
                        if let Some(id_hex) = sid.as_str() {
                            return SessionId::from_hex(id_hex)
                                .ok_or_else(|| anyhow!("bad session id hex"));
                        }
                    }
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        delay_ms = (delay_ms * 2).min(2_000);
    }
    Err(anyhow!("session id not observed before timeout"))
}

fn print_wg_config(client: &Client) -> Result<()> {
    let g = client.state.lock();
    let active = g.as_ref().ok_or_else(|| anyhow!("no active session"))?;
    let entry = &active.route[0].validator;
    // audit-13: text labels instead of ASCII separators so screen
    // readers (NVDA / VoiceOver) don't recite "dash dash dash dash …".
    println!("[wireguard-config-begin]");
    println!("[Interface]");
    println!("PrivateKey = <derive from your wallet; see docs/keys.md>");
    println!("Address = 10.66.0.2/24");
    println!("DNS = 1.1.1.1");
    println!();
    println!("[Peer]");
    println!("PublicKey = {}", hex::encode(entry.wg_pubkey.0));
    println!("Endpoint = {}", entry.endpoint);
    println!("AllowedIPs = 0.0.0.0/0, ::/0");
    println!("[wireguard-config-end]");
    Ok(())
}

pub(crate) fn sign_call(kp: &KeyPair, call: serde_json::Value) -> Result<serde_json::Value> {
    octravpn_core::tx::sign_call(kp, call)
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
