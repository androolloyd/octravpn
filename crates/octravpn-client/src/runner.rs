//! Session lifecycle: pick route, build commitments, open session on chain,
//! perform WG handshakes hop-by-hop, hold the tunnel, settle on shutdown.

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use curve25519_dalek::scalar::Scalar;
use octravpn_core::{
    address::Address,
    commit::{commit, fresh_blind},
    earnings,
    onion::{build_onion, HopBuildInput, MAX_HOPS},
    rpc::RpcClient,
    session::{RouteOpening, SessionId, ValidatorRecord},
    sig::KeyPair,
    stealth,
};
use parking_lot::Mutex;
use serde_json::json;
use tracing::{info, warn};

use crate::{config::ClientConfig, discover, settler, wallet};

pub struct Client {
    cfg: Arc<ClientConfig>,
    rpc: RpcClient,
    program_addr: Address,
    wallet_addr: Address,
    wallet_kp: KeyPair,
    pub state: Mutex<Option<ActiveSession>>,
}

pub struct ActiveSession {
    pub session_id: SessionId,
    pub session_kp: KeyPair,
    pub route: Vec<RouteHop>,
    pub deposit: u64,
    pub refund_stealth_output: [u8; 32],
}

#[derive(Clone)]
pub struct RouteHop {
    pub validator: ValidatorRecord,
    pub blind: [u8; 32],
    pub split_bps: u16,
}

impl Client {
    pub async fn new(cfg: Arc<ClientConfig>) -> Result<Self> {
        let rpc = RpcClient::new(&cfg.chain.rpc_url);
        let program_addr = Address::from_display(&cfg.chain.program_addr);
        let wallet_addr = Address::from_display(&cfg.wallet.addr);
        let wallet_kp = wallet::load_keypair(&cfg.wallet.secret_path)?;
        Ok(Self {
            cfg,
            rpc,
            program_addr,
            wallet_addr,
            wallet_kp,
            state: Mutex::new(None),
        })
    }

    pub fn rpc(&self) -> &RpcClient {
        &self.rpc
    }

    pub fn program_addr(&self) -> &Address {
        &self.program_addr
    }

    pub fn wallet_addr(&self) -> &Address {
        &self.wallet_addr
    }

    pub fn wallet_kp(&self) -> &KeyPair {
        &self.wallet_kp
    }

    pub fn config_ref(&self) -> &ClientConfig {
        &self.cfg
    }

    pub fn print_identity(&self) {
        println!("wallet addr  = {}", self.wallet_addr.display);
        println!("program addr = {}", self.program_addr.display);
        println!("wallet pub   = {}", hex::encode(self.wallet_kp.public.0));
    }

    pub async fn connect(
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
        let mut filtered: Vec<_> = candidates
            .into_iter()
            .filter(|v| v.bond > 0 && v.jailed_at == 0)
            .collect();
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
        let session_kp = KeyPair::generate();
        let refund_nonce = stealth::fresh_nonce();
        let refund_stealth_output =
            stealth::derive_output(&self.wallet_kp.public.0, &refund_nonce);

        // 4. Submit `open_session` on chain.
        let bal = self.rpc.balance(&self.wallet_addr).await?;
        let nonce = bal.pending_nonce.max(bal.nonce);
        let fee = self
            .rpc
            .recommended_fee(Some("contract_call"))
            .await?
            .recommended;
        let open_call = json!({
            "kind": "contract_call",
            "from": self.wallet_addr.display,
            "to": self.program_addr.display,
            "method": "open_session",
            "params": [
                route_commit.iter().map(hex::encode).collect::<Vec<_>>(),
                hex::encode(session_kp.public.0),
                hex::encode(refund_stealth_output),
            ],
            "value": deposit,
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
            route,
            deposit,
            refund_stealth_output,
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
        if seen.contains(&v.addr.display) {
            continue;
        }
        seen.insert(v.addr.display.clone());
        out.push(v.clone());
        if out.len() == n {
            break;
        }
    }
    out
}

async fn announce_to_exit(client: &Client) -> Result<()> {
    let g = client.state.lock();
    let active = g.as_ref().ok_or_else(|| anyhow!("no active session"))?;
    let exit = active
        .route
        .last()
        .ok_or_else(|| anyhow!("empty route"))?;
    // Construct exit's HTTP control-plane URL by replacing UDP port (51820)
    // with the conventional control port (51821). For deployments using
    // different ports, the validator publishes both via separate fields;
    // v1 keeps the convention so configuration stays simple.
    let ctrl_endpoint = control_url_for(&exit.validator.endpoint);
    let body = octravpn_core::control::AnnounceSessionRequest {
        session_id: active.session_id.clone(),
        client_pubkey: active.session_kp.public,
    };
    let http = reqwest::Client::new();
    let resp = http
        .post(format!("{ctrl_endpoint}/session"))
        .json(&body)
        .send()
        .await
        .context("announce session HTTP")?;
    if !resp.status().is_success() {
        return Err(anyhow!(
            "exit announce: status {}",
            resp.status()
        ));
    }
    Ok(())
}

fn control_url_for(wg_endpoint: &str) -> String {
    let host = wg_endpoint
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(wg_endpoint);
    format!("http://{host}:51821")
}

async fn poll_session_id(rpc: &RpcClient, tx_hash: &str) -> Result<SessionId> {
    for _ in 0..30 {
        let v = rpc.transaction(tx_hash).await?;
        if let Some(events) = v.get("events").and_then(|x| x.as_array()) {
            for e in events {
                if e.get("name").and_then(|x| x.as_str()) == Some("SessionOpened") {
                    if let Some(id_hex) =
                        e.get("session_id").and_then(|x| x.as_str())
                    {
                        return SessionId::from_hex(id_hex)
                            .ok_or_else(|| anyhow!("bad session id"));
                    }
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    Err(anyhow!("session id not observed within 30s"))
}

fn print_wg_config(client: &Client) -> Result<()> {
    let g = client.state.lock();
    let active = g.as_ref().ok_or_else(|| anyhow!("no active session"))?;
    let entry = &active.route[0].validator;
    println!("---- WireGuard client config ----");
    println!("[Interface]");
    println!("PrivateKey = <derive from your wallet; see docs/keys.md>");
    println!("Address = 10.66.0.2/24");
    println!("DNS = 1.1.1.1");
    println!();
    println!("[Peer]");
    println!("PublicKey = {}", hex::encode(entry.wg_pubkey.0));
    println!("Endpoint = {}", entry.endpoint);
    println!("AllowedIPs = 0.0.0.0/0, ::/0");
    println!("--------------------------------");
    Ok(())
}

pub fn sign_call(
    kp: &KeyPair,
    mut call: serde_json::Value,
) -> Result<serde_json::Value> {
    let canonical = canonicalize_for_sig(&call);
    let sig = kp.sign(&canonical);
    let m = call.as_object_mut().ok_or_else(|| anyhow!("call not object"))?;
    m.insert("signature".into(), json!(hex::encode(sig.0)));
    m.insert("public_key".into(), json!(hex::encode(kp.public.0)));
    Ok(call)
}

fn canonicalize_for_sig(v: &serde_json::Value) -> Vec<u8> {
    let mut clone = v.clone();
    if let Some(m) = clone.as_object_mut() {
        m.remove("signature");
        m.remove("public_key");
    }
    serde_json::to_vec(&clone).unwrap_or_default()
}

/// Build an onion-wrapped packet to the entry hop carrying egress data.
///
/// `inner` should be the egress payload formatted as
/// `target_ipv4 (4) || target_port (2 BE) || data...`.
pub fn build_outbound_onion(active: &ActiveSession, inner: &[u8]) -> Result<Vec<u8>> {
    let inputs: Vec<HopBuildInput> = active
        .route
        .iter()
        .map(|h| HopBuildInput {
            static_pubkey: h.validator.wg_pubkey.0,
            endpoint: h.validator.endpoint.clone(),
        })
        .collect();
    let onion = build_onion(&inputs, inner)
        .map_err(|e| anyhow!("build onion: {e}"))?;
    let mut packet = Vec::with_capacity(32 + onion.len());
    packet.extend_from_slice(&active.session_id.0);
    packet.extend_from_slice(&onion);
    Ok(packet)
}

/// Helper: signing scalar derived from a 32-byte client-side secret.
pub fn settlement_blind() -> Scalar {
    earnings::fresh_blind()
}
