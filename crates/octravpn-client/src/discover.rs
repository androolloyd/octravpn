//! Endpoint discovery. Pulls the active endpoint set from the on-chain
//! program and decodes each `EndpointRecord` into a Rust struct.

use anyhow::{anyhow, Context, Result};
use octravpn_core::{address::Address, session::EndpointRecord, sig::PublicKey, util};
use serde_json::{json, Value};

use crate::runner::Client;

fn decode_hex_32(field: Option<&Value>, what: &str) -> Result<[u8; 32]> {
    let s = field.and_then(|x| x.as_str()).unwrap_or("");
    util::hex_to_array::<32>(s, what).with_context(|| format!("decode {what}"))
}

pub(crate) async fn list(client: &Client, offset: u64, limit: u64) -> Result<Vec<EndpointRecord>> {
    let v = client
        .rpc()
        .contract_call(
            client.program_addr(),
            "list_active_endpoints",
            &[json!(offset), json!(limit)],
            None,
        )
        .await?;
    let arr = v
        .as_array()
        .ok_or_else(|| anyhow!("expected array of addrs"))?;
    let mut out = Vec::with_capacity(arr.len());
    for entry in arr {
        let addr_str = entry.as_str().ok_or_else(|| anyhow!("entry not string"))?;
        let addr = Address::from_display(addr_str);
        let rec = client
            .rpc()
            .contract_call(
                client.program_addr(),
                "get_endpoint",
                &[json!(addr_str)],
                None,
            )
            .await?;
        out.push(decode_record(addr, &rec)?);
    }
    Ok(out)
}

fn decode_record(addr: Address, v: &Value) -> Result<EndpointRecord> {
    let m = v.as_object().ok_or_else(|| anyhow!("record not object"))?;
    let active = m
        .get("active")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0)
        != 0;
    let endpoint = m
        .get("endpoint")
        .and_then(|x| x.as_str())
        .unwrap_or_default()
        .to_string();
    let wg = decode_hex_32(m.get("wg_pubkey"), "wg_pubkey")?;
    // v1 AML no longer stores receipt_pubkey / view_pubkey on chain.
    // Clients fetch those via the operator's REST control plane
    // (`/identity` endpoint). We default to zero here so the struct
    // shape stays stable; downstream code that needs the real key
    // hits the operator's REST surface.
    let receipt = decode_hex_32(m.get("receipt_pubkey"), "receipt_pubkey").unwrap_or([0u8; 32]);
    let view = decode_hex_32(m.get("view_pubkey"), "view_pubkey").unwrap_or([0u8; 32]);
    Ok(EndpointRecord {
        addr,
        active,
        endpoint,
        wg_pubkey: PublicKey(wg),
        receipt_pubkey: PublicKey(receipt),
        view_pubkey: view,
        region: m
            .get("region")
            .and_then(|x| x.as_str())
            .unwrap_or_default()
            .to_string(),
        price_per_mb: m
            .get("price_per_mb")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        registered_at: m
            .get("registered_at")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        reputation: m
            .get("reputation")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0),
    })
}
