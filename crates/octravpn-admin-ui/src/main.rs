//! `octravpn-admin` — Tailscale-style management UI **and** bulk CLI.
//!
//! Default mode: boots the embedded SPA + JSON API on a local HTTP
//! port. Subcommands provide headscale-style bulk operations:
//!
//!   octravpn-admin serve                              # the web UI (default)
//!   octravpn-admin list-tailnets
//!   octravpn-admin tailnet-info <ID>
//!   octravpn-admin add-member --tailnet T --addr A
//!   octravpn-admin remove-member --tailnet T --addr A
//!   octravpn-admin top-up --tailnet T --amount N
//!   octravpn-admin set-acl --tailnet T --file path.toml
//!   octravpn-admin broadcast-acl --file path.toml      # to every tailnet
//!   octravpn-admin list-endpoints

use std::{net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use octravpn_admin_ui::{router, state::AdminState};
use octravpn_core::{address::Address, rpc::RpcClient, sig::KeyPair};
use serde_json::{json, Value};
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "octravpn-admin", version)]
struct Cli {
    #[arg(long, default_value = "http://127.0.0.1:18080/rpc")]
    rpc_url: String,
    #[arg(long, default_value = "octPROG")]
    program: String,
    #[arg(long)]
    wallet: Option<PathBuf>,
    #[arg(long)]
    node_url: Option<String>,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Serve the web UI (default if no subcommand).
    Serve {
        #[arg(long, default_value = "127.0.0.1:8088")]
        bind: String,
    },
    /// List every tailnet on chain.
    ListTailnets,
    /// Print full metadata for one tailnet.
    TailnetInfo { id: String },
    /// Add `addr` to `tailnet`.
    AddMember {
        #[arg(long)]
        tailnet: String,
        #[arg(long)]
        addr: String,
    },
    /// Remove `addr` from `tailnet`.
    RemoveMember {
        #[arg(long)]
        tailnet: String,
        #[arg(long)]
        addr: String,
    },
    /// Deposit OU into `tailnet`'s treasury.
    TopUp {
        #[arg(long)]
        tailnet: String,
        #[arg(long)]
        amount: u64,
    },
    /// Update one tailnet's ACL hash from a TOML doc.
    SetAcl {
        #[arg(long)]
        tailnet: String,
        #[arg(long)]
        file: PathBuf,
    },
    /// Push the same ACL hash to *every* tailnet on chain.
    /// Useful for org-wide policy rollout.
    BroadcastAcl {
        #[arg(long)]
        file: PathBuf,
    },
    /// List every active endpoint on chain.
    ListEndpoints,
}

#[tokio::main]
async fn main() -> Result<()> {
    octravpn_core::util::init_tracing("info,octravpn_admin=debug");

    let cli = Cli::parse();
    let wallet = match &cli.wallet {
        Some(p) => Some(load_wallet(p)?),
        None => None,
    };
    let rpc = RpcClient::new(cli.rpc_url.clone());
    let program = Address::from_display(&cli.program);

    match cli.cmd.unwrap_or(Cmd::Serve {
        bind: "127.0.0.1:8088".into(),
    }) {
        Cmd::Serve { bind } => {
            let state = AdminState::new(cli.rpc_url, cli.program, wallet, cli.node_url);
            let addr: SocketAddr = bind.parse().context("parse bind addr")?;
            let listener = tokio::net::TcpListener::bind(addr).await?;
            info!(
                bind = %addr,
                writable = state.wallet.is_some(),
                "octravpn-admin listening"
            );
            println!("octravpn-admin: open http://{addr} in your browser");
            axum::serve(listener, router(state)).await?;
        }
        Cmd::ListTailnets => {
            let v = rpc
                .contract_call(
                    &program,
                    "list_tailnets",
                    &[json!(0u64), json!(500u64)],
                    None,
                )
                .await?;
            print_list(&v);
        }
        Cmd::TailnetInfo { id } => {
            let v = rpc
                .contract_call(&program, "get_tailnet", &[json!(id)], None)
                .await?;
            print_pretty(&v);
        }
        Cmd::AddMember { tailnet, addr } => {
            let kp = wallet.context("--wallet required for write ops")?;
            let r = submit(
                &rpc,
                &program,
                &kp,
                "add_member",
                vec![json!(tailnet), json!(addr)],
                0,
            )
            .await?;
            println!("tx {r}");
        }
        Cmd::RemoveMember { tailnet, addr } => {
            let kp = wallet.context("--wallet required")?;
            let r = submit(
                &rpc,
                &program,
                &kp,
                "remove_member",
                vec![json!(tailnet), json!(addr)],
                0,
            )
            .await?;
            println!("tx {r}");
        }
        Cmd::TopUp { tailnet, amount } => {
            let kp = wallet.context("--wallet required")?;
            let r = submit(
                &rpc,
                &program,
                &kp,
                "deposit_to_tailnet",
                vec![json!(tailnet)],
                amount,
            )
            .await?;
            println!("tx {r}");
        }
        Cmd::SetAcl { tailnet, file } => {
            let kp = wallet.context("--wallet required")?;
            let hash = compute_acl_hash(&file)?;
            let r = submit(
                &rpc,
                &program,
                &kp,
                "update_acl",
                vec![json!(tailnet), json!(hex::encode(hash))],
                0,
            )
            .await?;
            println!("tx {r}");
        }
        Cmd::BroadcastAcl { file } => {
            let kp = wallet.context("--wallet required")?;
            let hash = compute_acl_hash(&file)?;
            let hash_hex = hex::encode(hash);
            let list = rpc
                .contract_call(
                    &program,
                    "list_tailnets",
                    &[json!(0u64), json!(500u64)],
                    None,
                )
                .await?;
            let ids: Vec<String> = list
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            println!(
                "broadcasting ACL hash {} to {} tailnet(s)",
                hash_hex,
                ids.len()
            );
            let mut ok = 0u32;
            let mut fail = 0u32;
            for id in &ids {
                match submit(
                    &rpc,
                    &program,
                    &kp,
                    "update_acl",
                    vec![json!(id), json!(hash_hex)],
                    0,
                )
                .await
                {
                    Ok(tx) => {
                        ok += 1;
                        println!("  ok   {id}  tx {tx}");
                    }
                    Err(e) => {
                        fail += 1;
                        println!("  fail {id}  {e}");
                    }
                }
            }
            println!("done: {ok} ok / {fail} failed");
        }
        Cmd::ListEndpoints => {
            let v = rpc
                .contract_call(
                    &program,
                    "list_active_endpoints",
                    &[json!(0u64), json!(500u64)],
                    None,
                )
                .await?;
            print_list(&v);
        }
    }
    Ok(())
}

fn load_wallet(path: &std::path::Path) -> Result<KeyPair> {
    let secret =
        octravpn_core::util::read_secret_32(path.to_str().context("non-utf8 wallet path")?)?;
    Ok(KeyPair::from_secret_bytes(&secret))
}

async fn submit(
    rpc: &RpcClient,
    program: &Address,
    kp: &KeyPair,
    method: &str,
    params: Vec<Value>,
    value: u64,
) -> Result<String> {
    let from = Address::from_pubkey(&kp.public.0);
    let call = json!({
        "kind": "contract_call",
        "from": from.display(),
        "to": program.display(),
        "method": method,
        "params": params,
        "value": value,
        "fee": 10u64,
        "nonce": 0u64,
    });
    let signed = octravpn_core::tx::sign_call(kp, call)?;
    let r = rpc.submit(&signed).await?;
    Ok(r.hash)
}

fn compute_acl_hash(path: &std::path::Path) -> Result<[u8; 32]> {
    let body = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let doc = octravpn_mesh::AclDoc::from_toml(&body).map_err(|e| anyhow::anyhow!("parse: {e}"))?;
    Ok(doc.policy_hash())
}

fn print_list(v: &Value) {
    if let Some(arr) = v.as_array() {
        for x in arr {
            if let Some(s) = x.as_str() {
                println!("{s}");
            }
        }
    }
}

fn print_pretty(v: &Value) {
    println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
}
