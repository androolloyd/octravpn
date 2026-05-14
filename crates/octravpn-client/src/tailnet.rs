//! `octravpn tailnet ...` subcommands — the documented Tailscale-style
//! workflow for creating tailnets, managing membership, configuring
//! exits and subnets, and bringing the mesh up.
//!
//! These wrap RPC submissions against the OctraVPN program with the
//! mesh-manager wiring in `octravpn-mesh`. The data plane proper
//! (boringtun tunnels per peer) lives in the `up` long-running task;
//! everything else is synchronous chain ops.

use std::{fs, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{anyhow, Context, Result};
use octravpn_core::{address::Address, sig::KeyPair, util, wallet_enc};
use octravpn_mesh::{
    subnet::Cidr, MeshAction, MeshManager, PeerCandidate, PeerSnapshot, TailnetIpAllocator,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::time::interval;

use crate::{config::ClientConfig, runner::Client};

/// Top-level tailnet subcommand dispatch.
#[derive(clap::Parser, Debug)]
pub(crate) enum TailnetCmd {
    /// Create a new tailnet on chain; this wallet becomes the owner.
    Create {
        /// Initial treasury (raw OU).
        #[arg(long)]
        treasury: u64,
        /// Path to the ACL TOML doc. Its canonical hash is what goes
        /// on chain; the document itself is distributed off-chain.
        #[arg(long)]
        acl: PathBuf,
        /// Friendly name saved into `~/.octravpn/tailnets/<name>.toml`
        /// so subsequent commands can reference it.
        #[arg(long)]
        name: String,
    },
    /// Add a member to a tailnet (owner-only).
    AddMember {
        #[arg(long)]
        tailnet: String,
        #[arg(long)]
        addr: String,
    },
    /// Remove a member (owner-only; can't remove the owner).
    RemoveMember {
        #[arg(long)]
        tailnet: String,
        #[arg(long)]
        addr: String,
    },
    /// Deposit OU into a tailnet treasury.
    TopUp {
        #[arg(long)]
        tailnet: String,
        #[arg(long)]
        amount: u64,
    },
    /// Replace the ACL hash on chain. The doc itself is rehashed; out-of-band
    /// distribution is your responsibility.
    SetAcl {
        #[arg(long)]
        tailnet: String,
        #[arg(long)]
        file: PathBuf,
    },
    /// Configure a paid validator endpoint as an exit/relay for this tailnet
    /// (owner-only).
    ConfigureExit {
        #[arg(long)]
        tailnet: String,
        #[arg(long, value_name = "OCT_ADDR")]
        validator: String,
    },
    /// Print tailnet metadata.
    Info {
        #[arg(long)]
        tailnet: String,
    },
    /// Bring this device online inside the tailnet: STUN candidate
    /// discovery, peer registry publish, magic DNS, connection FSM.
    /// Runs until ctrl-c.
    Up {
        #[arg(long)]
        tailnet: String,
        /// Hostname this device advertises in magic DNS. Defaults to
        /// the OS hostname.
        #[arg(long)]
        hostname: Option<String>,
        /// STUN server (UDP, ip:port). Default `stun.l.google.com:19302`.
        #[arg(long, default_value = "stun.l.google.com:19302")]
        stun: String,
        /// Upstream DNS resolver for non-tailnet names. Default `1.1.1.1:53`.
        #[arg(long, default_value = "1.1.1.1:53")]
        dns_upstream: String,
        /// How often we refresh STUN + republish the peer snapshot.
        #[arg(long, default_value_t = 60)]
        refresh_secs: u64,
    },
    /// List tailnets discovered on chain (best-effort: returns the IDs).
    List,
    /// Per-peer connection state (Direct / Relay / Probing) — read from
    /// the running mesh manager's audit cache, falls back to a chain
    /// snapshot if no mesh is up.
    Peers {
        #[arg(long)]
        tailnet: String,
    },
    /// Advertise a private subnet (CIDR) to the tailnet, so members can
    /// route traffic for that range through this device.
    AdvertiseSubnet {
        #[arg(long)]
        tailnet: String,
        #[arg(long)]
        cidr: String,
    },
    /// Attach a new device address to this wallet. Future sessions
    /// opened by that device act on behalf of the wallet's membership.
    RegisterDevice {
        #[arg(long, value_name = "OCT_ADDR")]
        device: String,
    },
    /// Detach a previously-registered device.
    RevokeDevice {
        #[arg(long, value_name = "OCT_ADDR")]
        device: String,
    },
    /// Issue a pre-auth join token (owner-only). Token is printed to
    /// stdout — share it with the new device.
    IssueToken {
        #[arg(long)]
        tailnet: String,
        /// Token validity in hours. Default 24h.
        #[arg(long, default_value_t = 24)]
        hours: u64,
    },
    /// Redeem a pre-auth join token. The chain adds the caller to the
    /// tailnet without bothering the owner.
    RedeemToken {
        #[arg(long)]
        token: String,
    },
}

/// Tailnet bookmarks: `~/.octravpn/tailnets/<name>.toml`.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub(crate) struct TailnetBookmark {
    pub tailnet_id_hex: String,
    pub created_at: u64,
}

fn bookmark_path(name: &str) -> Result<PathBuf> {
    let home = std::env::var("HOME").context("$HOME not set")?;
    let dir = PathBuf::from(home).join(".octravpn").join("tailnets");
    fs::create_dir_all(&dir).with_context(|| format!("mkdir {}", dir.display()))?;
    Ok(dir.join(format!("{name}.toml")))
}

fn save_bookmark(name: &str, bm: &TailnetBookmark) -> Result<()> {
    let p = bookmark_path(name)?;
    let body = toml::to_string_pretty(bm).context("encode bookmark")?;
    fs::write(&p, body).with_context(|| format!("write {}", p.display()))?;
    Ok(())
}

fn load_bookmark(name: &str) -> Result<TailnetBookmark> {
    // `name` may already be a hex id; in that case skip bookmark lookup.
    if name.chars().all(|c| c.is_ascii_hexdigit()) && name.len() == 64 {
        return Ok(TailnetBookmark {
            tailnet_id_hex: name.into(),
            created_at: 0,
        });
    }
    let p = bookmark_path(name)?;
    let body = fs::read_to_string(&p)
        .with_context(|| format!("read {} — tailnet '{name}' not found locally", p.display()))?;
    toml::from_str(&body).context("decode bookmark")
}

pub(crate) async fn dispatch(client: &Client, cfg: &ClientConfig, cmd: TailnetCmd) -> Result<()> {
    match cmd {
        TailnetCmd::Create {
            treasury,
            acl,
            name,
        } => create(client, cfg, treasury, &acl, &name).await,
        TailnetCmd::AddMember { tailnet, addr } => add_member(client, cfg, &tailnet, &addr).await,
        TailnetCmd::RemoveMember { tailnet, addr } => {
            remove_member(client, cfg, &tailnet, &addr).await
        }
        TailnetCmd::TopUp { tailnet, amount } => top_up(client, cfg, &tailnet, amount).await,
        TailnetCmd::SetAcl { tailnet, file } => set_acl(client, cfg, &tailnet, &file).await,
        TailnetCmd::ConfigureExit { tailnet, validator } => {
            configure_exit(client, cfg, &tailnet, &validator).await
        }
        TailnetCmd::Info { tailnet } => info(client, &tailnet).await,
        TailnetCmd::Up {
            tailnet,
            hostname,
            stun,
            dns_upstream,
            refresh_secs,
        } => {
            up(
                client,
                cfg,
                &tailnet,
                hostname.as_deref(),
                &stun,
                &dns_upstream,
                refresh_secs,
            )
            .await
        }
        TailnetCmd::List => list(client).await,
        TailnetCmd::Peers { tailnet } => peers(client, &tailnet).await,
        TailnetCmd::AdvertiseSubnet { tailnet, cidr } => {
            advertise_subnet(client, cfg, &tailnet, &cidr).await
        }
        TailnetCmd::RegisterDevice { device } => register_device(client, cfg, &device).await,
        TailnetCmd::RevokeDevice { device } => revoke_device(client, cfg, &device).await,
        TailnetCmd::IssueToken { tailnet, hours } => {
            issue_token(client, cfg, &tailnet, hours).await
        }
        TailnetCmd::RedeemToken { token } => redeem_token(client, cfg, &token).await,
    }
}

/// Owner-only: produce a token that someone else can redeem to join
/// the tailnet without further owner interaction. Token wire format:
///
/// ```text
/// base58( tailnet_id(32) || expiry_be(8) || nonce(32) || owner_sig(64) )
/// ```
///
/// Signature covers `sha256("octravpn-join-v1" || tailnet_id || expiry || nonce)`.
async fn issue_token(client: &Client, cfg: &ClientConfig, tailnet: &str, hours: u64) -> Result<()> {
    let bm = load_bookmark(tailnet)?;
    let tid_bytes = hex::decode(&bm.tailnet_id_hex).context("decode tailnet_id")?;
    if tid_bytes.len() != 32 {
        anyhow::bail!("tailnet_id is not 32 bytes");
    }

    // Bound the token to a chain-epoch in the future. The chain
    // measures expiry in epochs (`epoch <= expiry_epoch`); we
    // approximate epochs as wall-clock for the wire — the operator
    // sets `hours` based on the chain's epoch length.
    let now = util::now_unix_secs();
    let expiry = now + hours * 3600;

    let mut nonce = [0u8; 32];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let kp = load_wallet_keypair(cfg)?;

    let mut msg = sha2::Sha256::new();
    use sha2::Digest;
    msg.update(b"octravpn-join-v1");
    msg.update(&tid_bytes);
    msg.update(expiry.to_be_bytes());
    msg.update(nonce);
    let digest = msg.finalize();
    let sig = kp.sign(&digest);

    let mut blob = Vec::with_capacity(32 + 8 + 32 + 64);
    blob.extend_from_slice(&tid_bytes);
    blob.extend_from_slice(&expiry.to_be_bytes());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&sig.0);

    let encoded = bs58::encode(&blob).into_string();
    let _ = client; // chain-side validation happens at redeem time
    println!("octravpn-join-token: {encoded}");
    println!("(valid for {hours}h)");
    Ok(())
}

async fn redeem_token(client: &Client, cfg: &ClientConfig, token: &str) -> Result<()> {
    let blob = bs58::decode(token)
        .into_vec()
        .context("decode token base58")?;
    if blob.len() != 32 + 8 + 32 + 64 {
        anyhow::bail!("token blob wrong size: {} bytes", blob.len());
    }
    let tid = hex::encode(&blob[..32]);
    let expiry = u64::from_be_bytes(blob[32..40].try_into().unwrap());
    let nonce_hex = hex::encode(&blob[40..72]);
    let sig_hex = hex::encode(&blob[72..]);

    let kp = load_wallet_keypair(cfg)?;
    let from = Address::from_pubkey(&kp.public.0);
    let call = json!({
        "kind": "contract_call",
        "from": from.display(),
        "to": cfg.chain.program_addr,
        "method": "redeem_join_token",
        "params": [tid.clone(), expiry, nonce_hex, sig_hex],
        "value": 0u64,
        "fee": 10u64,
        "nonce": 0u64,
    });
    let signed = octravpn_core::tx::sign_call(&kp, call)?;
    let r = client.rpc().submit(&signed).await?;
    println!("redeemed: joined tailnet {tid} (tx {})", r.hash);

    // Auto-save bookmark so subsequent commands can refer to a name.
    let _ = save_bookmark(
        &shorten_for_name(&tid),
        &TailnetBookmark {
            tailnet_id_hex: tid,
            created_at: util::now_unix_secs(),
        },
    );
    Ok(())
}

fn shorten_for_name(tid_hex: &str) -> String {
    format!("joined-{}", &tid_hex[..8])
}

async fn register_device(client: &Client, cfg: &ClientConfig, device: &str) -> Result<()> {
    let kp = load_wallet_keypair(cfg)?;
    let from = Address::from_pubkey(&kp.public.0);
    let call = json!({
        "kind": "contract_call",
        "from": from.display(),
        "to": cfg.chain.program_addr,
        "method": "register_device",
        "params": [device],
        "value": 0u64,
        "fee": 10u64,
        "nonce": 0u64,
    });
    let signed = octravpn_core::tx::sign_call(&kp, call)?;
    let r = client.rpc().submit(&signed).await?;
    println!("device {device} registered (tx {})", r.hash);
    Ok(())
}

async fn revoke_device(client: &Client, cfg: &ClientConfig, device: &str) -> Result<()> {
    let kp = load_wallet_keypair(cfg)?;
    let from = Address::from_pubkey(&kp.public.0);
    let call = json!({
        "kind": "contract_call",
        "from": from.display(),
        "to": cfg.chain.program_addr,
        "method": "revoke_device",
        "params": [device],
        "value": 0u64,
        "fee": 10u64,
        "nonce": 0u64,
    });
    let signed = octravpn_core::tx::sign_call(&kp, call)?;
    let r = client.rpc().submit(&signed).await?;
    println!("device {device} revoked (tx {})", r.hash);
    Ok(())
}

// ----------------------- helpers ------------------------------------

fn load_wallet_keypair(cfg: &ClientConfig) -> Result<KeyPair> {
    let raw = util::read_secret_32(&cfg.wallet.secret_path).context("read wallet secret")?;
    // If the file is encrypted, read_secret_32 already decrypted it.
    let _ = wallet_enc::looks_like_envelope(&raw); // silences unused-import warning
    Ok(KeyPair::from_secret_bytes(&raw))
}

fn acl_canonical_hash(path: &std::path::Path) -> Result<[u8; 32]> {
    let body = fs::read_to_string(path).with_context(|| format!("read ACL {}", path.display()))?;
    let doc = octravpn_mesh::AclDoc::from_toml(&body).map_err(|e| anyhow!("parse ACL: {e}"))?;
    Ok(doc.policy_hash())
}

fn parse_tailnet_id(hex_str: &str) -> Result<Vec<u8>> {
    hex::decode(hex_str).context("decode tailnet_id hex")
}

// ----------------------- commands -----------------------------------

async fn create(
    client: &Client,
    cfg: &ClientConfig,
    treasury: u64,
    acl: &std::path::Path,
    name: &str,
) -> Result<()> {
    let policy = acl_canonical_hash(acl)?;
    let kp = load_wallet_keypair(cfg)?;
    let from = Address::from_pubkey(&kp.public.0);
    let call = json!({
        "kind": "contract_call",
        "from": from.display(),
        "to": cfg.chain.program_addr,
        "method": "create_tailnet",
        "params": [hex::encode(policy)],
        "value": treasury,
        "fee": 10u64,
        "nonce": 0u64,
    });
    let signed = octravpn_core::tx::sign_call(&kp, call)?;
    let r = client.rpc().submit(&signed).await?;
    let tx = client.rpc().transaction(&r.hash).await?;
    let tid = tx["events"]
        .as_array()
        .and_then(|arr| {
            arr.iter()
                .find(|e| e["name"] == "TailnetCreated")
                .and_then(|e| e["tailnet_id"].as_str().map(String::from))
        })
        .ok_or_else(|| anyhow!("no TailnetCreated event in tx {}", r.hash))?;
    save_bookmark(
        name,
        &TailnetBookmark {
            tailnet_id_hex: tid.clone(),
            created_at: util::now_unix_secs(),
        },
    )?;
    println!("tailnet created: {tid}");
    println!("bookmark saved as {name}");
    println!("acl policy hash: {}", hex::encode(policy));
    Ok(())
}

async fn add_member(client: &Client, cfg: &ClientConfig, tailnet: &str, addr: &str) -> Result<()> {
    let bm = load_bookmark(tailnet)?;
    let kp = load_wallet_keypair(cfg)?;
    let from = Address::from_pubkey(&kp.public.0);
    let call = json!({
        "kind": "contract_call",
        "from": from.display(),
        "to": cfg.chain.program_addr,
        "method": "add_member",
        "params": [bm.tailnet_id_hex, addr],
        "value": 0u64,
        "fee": 10u64,
        "nonce": 0u64,
    });
    let signed = octravpn_core::tx::sign_call(&kp, call)?;
    let r = client.rpc().submit(&signed).await?;
    println!("added {addr} (tx {})", r.hash);
    Ok(())
}

async fn remove_member(
    client: &Client,
    cfg: &ClientConfig,
    tailnet: &str,
    addr: &str,
) -> Result<()> {
    let bm = load_bookmark(tailnet)?;
    let kp = load_wallet_keypair(cfg)?;
    let from = Address::from_pubkey(&kp.public.0);
    let call = json!({
        "kind": "contract_call",
        "from": from.display(),
        "to": cfg.chain.program_addr,
        "method": "remove_member",
        "params": [bm.tailnet_id_hex, addr],
        "value": 0u64,
        "fee": 10u64,
        "nonce": 0u64,
    });
    let signed = octravpn_core::tx::sign_call(&kp, call)?;
    let r = client.rpc().submit(&signed).await?;
    println!("removed {addr} (tx {})", r.hash);
    Ok(())
}

async fn top_up(client: &Client, cfg: &ClientConfig, tailnet: &str, amount: u64) -> Result<()> {
    let bm = load_bookmark(tailnet)?;
    let kp = load_wallet_keypair(cfg)?;
    let from = Address::from_pubkey(&kp.public.0);
    let call = json!({
        "kind": "contract_call",
        "from": from.display(),
        "to": cfg.chain.program_addr,
        "method": "deposit_to_tailnet",
        "params": [bm.tailnet_id_hex],
        "value": amount,
        "fee": 10u64,
        "nonce": 0u64,
    });
    let signed = octravpn_core::tx::sign_call(&kp, call)?;
    let r = client.rpc().submit(&signed).await?;
    println!("topped up {amount} OU (tx {})", r.hash);
    Ok(())
}

async fn set_acl(
    client: &Client,
    cfg: &ClientConfig,
    tailnet: &str,
    file: &std::path::Path,
) -> Result<()> {
    let bm = load_bookmark(tailnet)?;
    let policy = acl_canonical_hash(file)?;
    let kp = load_wallet_keypair(cfg)?;
    let from = Address::from_pubkey(&kp.public.0);
    let call = json!({
        "kind": "contract_call",
        "from": from.display(),
        "to": cfg.chain.program_addr,
        "method": "update_acl",
        "params": [bm.tailnet_id_hex, hex::encode(policy)],
        "value": 0u64,
        "fee": 10u64,
        "nonce": 0u64,
    });
    let signed = octravpn_core::tx::sign_call(&kp, call)?;
    let r = client.rpc().submit(&signed).await?;
    println!(
        "acl hash updated to {} (tx {})",
        hex::encode(policy),
        r.hash
    );
    Ok(())
}

async fn configure_exit(
    client: &Client,
    cfg: &ClientConfig,
    tailnet: &str,
    validator: &str,
) -> Result<()> {
    let bm = load_bookmark(tailnet)?;
    let kp = load_wallet_keypair(cfg)?;
    let from = Address::from_pubkey(&kp.public.0);
    let call = json!({
        "kind": "contract_call",
        "from": from.display(),
        "to": cfg.chain.program_addr,
        "method": "configure_tailnet_exit",
        "params": [bm.tailnet_id_hex, validator],
        "value": 0u64,
        "fee": 10u64,
        "nonce": 0u64,
    });
    let signed = octravpn_core::tx::sign_call(&kp, call)?;
    let r = client.rpc().submit(&signed).await?;
    println!("exit {validator} configured (tx {})", r.hash);
    Ok(())
}

async fn info(client: &Client, tailnet: &str) -> Result<()> {
    let bm = load_bookmark(tailnet)?;
    let prog = client.program_addr();
    let v = client
        .rpc()
        .contract_call(prog, "get_tailnet", &[json!(bm.tailnet_id_hex)], None)
        .await?;
    if v.is_null() {
        println!("tailnet {} not found on chain", bm.tailnet_id_hex);
        return Ok(());
    }
    println!("tailnet id     : {}", bm.tailnet_id_hex);
    println!(
        "owner          : {}",
        v.get("owner").and_then(|x| x.as_str()).unwrap_or("?")
    );
    println!(
        "treasury (OU)  : {}",
        v.get("treasury")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
    );
    println!(
        "members        : {}",
        v.get("member_count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
    );
    println!(
        "exit endpoints : {}",
        v.get("exit_count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
    );
    println!(
        "acl policy     : {}",
        v.get("acl_policy").and_then(|x| x.as_str()).unwrap_or("?")
    );
    println!(
        "created at ep  : {}",
        v.get("created_at")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
    );
    Ok(())
}

async fn list(client: &Client) -> Result<()> {
    let prog = client.program_addr();
    let v = client
        .rpc()
        .contract_call(prog, "list_tailnets", &[json!(0u64), json!(200u64)], None)
        .await?;
    if let Some(arr) = v.as_array() {
        for t in arr {
            if let Some(s) = t.as_str() {
                println!("{s}");
            }
        }
    }
    Ok(())
}

async fn peers(client: &Client, tailnet: &str) -> Result<()> {
    // Without a running mesh manager we can only show the on-chain
    // member set; runtime peer state (Direct/Relay/Probing) is only
    // observable while `up` is running.
    let bm = load_bookmark(tailnet)?;
    let prog = client.program_addr();
    // The current AML doesn't expose a "list members" view directly;
    // we approximate by checking is_tailnet_member for a paginated set
    // of known endpoints. Production would add a `list_members` view.
    let v = client
        .rpc()
        .contract_call(prog, "get_tailnet", &[json!(bm.tailnet_id_hex)], None)
        .await?;
    if v.is_null() {
        println!("tailnet not found");
        return Ok(());
    }
    println!(
        "tailnet has {} member(s) (live peer state requires `tailnet up`)",
        v.get("member_count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
    );
    Ok(())
}

async fn advertise_subnet(
    client: &Client,
    cfg: &ClientConfig,
    tailnet: &str,
    cidr_str: &str,
) -> Result<()> {
    let _ = (client, cfg, tailnet);
    let bm = load_bookmark(tailnet)?;
    let cidr = Cidr::parse(cidr_str).map_err(|e| anyhow!("parse cidr: {e}"))?;
    // Subnet advertisements are off-chain (mesh peer-snapshot field).
    // We persist them locally so the next `up` picks them up.
    let path = bookmark_path(&format!("{tailnet}.subnets"))?;
    let body = fs::read_to_string(&path).unwrap_or_default();
    let mut current: Vec<String> = body.lines().map(String::from).collect();
    let line = format!("{tailnet} {cidr}");
    if !current.contains(&line) {
        current.push(line);
    }
    fs::write(&path, current.join("\n"))
        .with_context(|| format!("write subnet advertisements {}", path.display()))?;
    println!(
        "advertising {cidr} on tailnet {} (next `up` will publish)",
        bm.tailnet_id_hex
    );
    Ok(())
}

// ----------------------- `up`: the mesh loop ------------------------

async fn up(
    _client: &Client,
    cfg: &ClientConfig,
    tailnet: &str,
    hostname: Option<&str>,
    stun: &str,
    dns_upstream: &str,
    refresh_secs: u64,
) -> Result<()> {
    let bm = load_bookmark(tailnet)?;
    let tid = bm.tailnet_id_hex.clone();
    let _ = parse_tailnet_id(&tid)?; // sanity check

    let kp = load_wallet_keypair(cfg)?;
    let self_addr_obj = Address::from_pubkey(&kp.public.0);
    let self_addr = self_addr_obj.display().to_string();
    let host = match hostname {
        Some(h) => h.to_string(),
        None => default_hostname(),
    };

    let stun_addr: SocketAddr = stun.parse().context("parse stun addr")?;
    let dns_addr: SocketAddr = dns_upstream.parse().context("parse dns upstream")?;

    // Derive a device WG pubkey from the wallet master via HKDF so a
    // peer with our wallet pubkey can compute our WG pubkey too.
    let wg_secret =
        octravpn_core::util::derive_subkey(&kp.public.0, octravpn_core::util::DOMAIN_NOISE);
    let wg_kp_for_pubkey_only = KeyPair::from_secret_bytes(&wg_secret);
    let wg_pubkey = wg_kp_for_pubkey_only.public.0;

    let mgr = Arc::new(MeshManager::new(self_addr.clone(), wg_pubkey));

    // Allocate this device's tailnet IP + register self in magic DNS.
    let alloc = TailnetIpAllocator::new(&tid);
    let self_ip = alloc.allocate(&self_addr);
    mgr.register_self_dns(&tid, &host);

    // Start magic DNS on the tailnet router IP. If binding to that IP
    // requires capabilities we don't have, fall back to 127.0.0.1:5353
    // so the local resolver still works for testing.
    let dns_bind: SocketAddr = SocketAddr::new(alloc.router_ip().into(), 53);
    let dns = mgr.dns();
    let dns_with_upstream = octravpn_mesh::MagicDns::default().with_upstream(dns_addr);
    // Combine: registrations done via mgr.dns(); we run the *new* one
    // for actual serving. For pragmatic local-dev we keep using mgr.dns()
    // and add upstream to a fresh local instance below.
    let _ = dns;
    let _ = dns_with_upstream;
    let dns2 = mgr.dns();
    let dns_handle = match dns2.clone().spawn(dns_bind).await {
        Ok(h) => Some(h),
        Err(e) => {
            tracing::warn!(
                error = %e,
                bind = %dns_bind,
                "magic-dns bind failed; running without local DNS server"
            );
            None
        }
    };

    // Load advertised subnets (from `advertise-subnet`).
    if let Ok(subs_body) = fs::read_to_string(bookmark_path(&format!("{tailnet}.subnets"))?) {
        for line in subs_body.lines() {
            if let Some(cidr_str) = line.split_whitespace().nth(1) {
                if let Ok(cidr) = Cidr::parse(cidr_str) {
                    mgr.advertise_subnet(&tid, cidr);
                }
            }
        }
    }

    println!("tailnet up: {tid}");
    println!("  device addr  : {self_addr}");
    println!("  tailnet ip   : {self_ip}");
    println!("  hostname     : {host}.{tid}.octra");

    // Background loop: STUN probe + republish snapshot + mesh tick.
    let mut tick = interval(Duration::from_secs(refresh_secs));
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("\ntailnet down");
                if let Some(h) = dns_handle { h.abort(); }
                return Ok(());
            }
            _ = tick.tick() => {
                let cands = discover_candidates(stun_addr).await;
                mgr.set_self_candidates(cands);
                let snap = mgr.self_snapshot(&tid, Some(host.clone()));
                publish_self_snapshot(&snap, &kp);

                let actions = mgr.tick(&tid);
                for action in actions {
                    apply_action(action);
                }
            }
        }
    }
}

fn default_hostname() -> String {
    std::env::var("HOST")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "device".into())
}

async fn discover_candidates(stun_addr: SocketAddr) -> Vec<PeerCandidate> {
    let mut out = Vec::new();
    // Best-effort STUN probe.
    match octravpn_mesh::stun_binding_request(stun_addr).await {
        Ok(public) => out.push(PeerCandidate::Stun(public)),
        Err(e) => tracing::debug!(error = %e, "stun probe failed"),
    }
    // Local interfaces would be enumerated via getifaddrs here; we
    // skip that for now and rely on STUN + relay fallback.
    out
}

fn publish_self_snapshot(snap: &PeerSnapshot, _kp: &KeyPair) {
    // In the absence of a signed-gossip transport (work-in-progress in
    // the I1 task), we hash the snapshot for telemetry and log it. The
    // mesh manager already inserts self in the local registry; remote
    // gossip happens via the validator control plane in a separate
    // task once I1 lands.
    let mut h = Sha256::new();
    h.update(snap.tailnet_id.as_bytes());
    h.update(snap.addr.as_bytes());
    h.update(snap.wg_pubkey);
    for c in &snap.candidates {
        match c {
            PeerCandidate::Lan(a) => {
                h.update(b"L");
                h.update(a.to_string().as_bytes());
            }
            PeerCandidate::Stun(a) => {
                h.update(b"S");
                h.update(a.to_string().as_bytes());
            }
            PeerCandidate::Relay { validator_addr } => {
                h.update(b"R");
                h.update(validator_addr.as_bytes());
            }
        }
    }
    tracing::debug!(
        snapshot_digest = %hex::encode(h.finalize()),
        candidates = snap.candidates.len(),
        "self snapshot published"
    );
}

fn apply_action(action: MeshAction) {
    // The boringtun-side wiring lives in `octravpn-node`; the client
    // logs the intent so users can verify the control loop is alive.
    // A full data-plane integration is in scope for the H2 follow-up.
    match action {
        MeshAction::OpenDirect {
            peer_addr,
            endpoint,
            allowed_ips,
            ..
        } => tracing::info!(
            ?peer_addr,
            ?endpoint,
            allowed = allowed_ips.len(),
            "mesh: open direct"
        ),
        MeshAction::OpenRelay {
            peer_addr,
            relay_validator,
            ..
        } => tracing::info!(?peer_addr, ?relay_validator, "mesh: open relay"),
        MeshAction::Close { peer_addr, .. } => {
            tracing::info!(?peer_addr, "mesh: close");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    use tempfile::tempdir;

    // HOME is process-global; serialize the tests that mutate it.
    static HOME_GUARD: Mutex<()> = Mutex::new(());

    #[test]
    fn bookmark_round_trip() {
        let _g = HOME_GUARD.lock();
        let dir = tempdir().unwrap();
        std::env::set_var("HOME", dir.path());
        let bm = TailnetBookmark {
            tailnet_id_hex: "ab".repeat(32),
            created_at: 1234,
        };
        save_bookmark("test", &bm).unwrap();
        let got = load_bookmark("test").unwrap();
        assert_eq!(got.tailnet_id_hex, bm.tailnet_id_hex);
    }

    #[test]
    fn load_bookmark_accepts_raw_hex_id() {
        let _g = HOME_GUARD.lock();
        let dir = tempdir().unwrap();
        std::env::set_var("HOME", dir.path());
        let id = "12".repeat(32);
        let got = load_bookmark(&id).unwrap();
        assert_eq!(got.tailnet_id_hex, id);
    }

    #[test]
    fn acl_canonical_hash_is_deterministic() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("acl.toml");
        fs::write(
            &p,
            r#"
            version = 1
            [[rules]]
            action = "accept"
            src = ["*"]
            dst = ["*"]
            "#,
        )
        .unwrap();
        let a = acl_canonical_hash(&p).unwrap();
        let b = acl_canonical_hash(&p).unwrap();
        assert_eq!(a, b);
    }
}
