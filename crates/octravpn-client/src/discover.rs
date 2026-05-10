//! Validator discovery. Pulls the active validator set from the on-chain
//! program and decodes each `ValidatorRecord` into a Rust struct.

use anyhow::{anyhow, Result};
use octravpn_core::{
    address::Address,
    session::ValidatorRecord,
    sig::PublicKey,
};
use serde_json::{json, Value};

use crate::runner::Client;

pub async fn list(client: &Client, offset: u64, limit: u64) -> Result<Vec<ValidatorRecord>> {
    let v = client
        .rpc()
        .contract_call(
            client.program_addr(),
            "list_active_validators",
            &[json!(offset), json!(limit)],
            None,
        )
        .await?;
    let arr = v
        .as_array()
        .ok_or_else(|| anyhow!("expected array of addrs"))?;
    let mut out = Vec::with_capacity(arr.len());
    for entry in arr {
        let addr_str = entry
            .as_str()
            .ok_or_else(|| anyhow!("entry not string"))?;
        let addr = Address::from_display(addr_str);
        let rec = client
            .rpc()
            .contract_call(
                client.program_addr(),
                "get_validator",
                &[json!(addr_str)],
                None,
            )
            .await?;
        out.push(decode_record(addr, rec)?);
    }
    Ok(out)
}

fn decode_record(addr: Address, v: Value) -> Result<ValidatorRecord> {
    let m = v.as_object().ok_or_else(|| anyhow!("record not object"))?;
    let bond = m.get("bond").and_then(|x| x.as_u64()).unwrap_or_default();
    let endpoint = m
        .get("endpoint")
        .and_then(|x| x.as_str())
        .unwrap_or_default()
        .to_string();
    let wg_pubkey_hex = m.get("wg_pubkey").and_then(|x| x.as_str()).unwrap_or("");
    let wg_bytes = hex::decode(wg_pubkey_hex).unwrap_or_default();
    let mut wg = [0u8; 32];
    if wg_bytes.len() == 32 {
        wg.copy_from_slice(&wg_bytes);
    }
    let view_pubkey_hex = m.get("view_pubkey").and_then(|x| x.as_str()).unwrap_or("");
    let view_bytes = hex::decode(view_pubkey_hex).unwrap_or_default();
    let mut view = [0u8; 32];
    if view_bytes.len() == 32 {
        view.copy_from_slice(&view_bytes);
    }
    Ok(ValidatorRecord {
        addr,
        bond,
        endpoint,
        wg_pubkey: PublicKey(wg),
        view_pubkey: view,
        region: m
            .get("region")
            .and_then(|x| x.as_str())
            .unwrap_or_default()
            .to_string(),
        price_per_mb: m.get("price_per_mb").and_then(|x| x.as_u64()).unwrap_or(0),
        registered_at: m.get("registered_at").and_then(|x| x.as_u64()).unwrap_or(0),
        last_attest_epoch: m
            .get("last_attest_epoch")
            .and_then(|x| x.as_u64())
            .unwrap_or(0),
        jailed_at: m.get("jailed_at").and_then(|x| x.as_u64()).unwrap_or(0),
        reputation: m.get("reputation").and_then(|x| x.as_i64()).unwrap_or(0),
    })
}
