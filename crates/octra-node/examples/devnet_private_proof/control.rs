//! Persist signed private requests before TLS; replies assert no finality.
use super::{call, raw, read, save, seed};
use anyhow::{ensure, Context, Result};
use octra_private_payments_experimental::pool::{self, Domain};
use rand::RngCore;
use serde_json::{json, Value};
use std::path::Path;

pub(super) async fn run(root: &Path, config: &Value, operation: &str) -> Result<()> {
    use octravpn_core::payments::{
        Deployment, PrivateAction, PrivateRequest, PrivateResult, PrivateTarget,
        SignedPrivateReply, SignedPrivateRequest,
    };
    let key = octravpn_core::KeyPair::from_secret_bytes(&*seed(root, "receipt.key")?);
    let origin = raw(config, "origin")?;
    let circle = config["pool"].as_str().context("pool")?;
    let target = PrivateTarget {
        chain_origin: origin,
        pool: Deployment {
            domain: hex::encode(Domain::new(&origin, &circle.as_bytes().try_into()?)?.digest()),
            program: octravpn_core::parse_native_address(circle)?,
        },
        directory: octravpn_core::parse_native_address(
            config["directory"].as_str().context("directory")?,
        )?,
        operator: octravpn_core::PublicKey(raw(config, "operator_public")?),
    };
    let request_input: Value = serde_json::from_slice(&read(
        &root.join(format!("{operation}-request.json")),
        65_536,
    )?)?;
    let now = request_input["canonical_ms"]
        .as_u64()
        .context("canonical clock missing")?;
    let channel = || -> Result<u64> {
        let saved: Value =
            serde_json::from_slice(&read(&root.join("open-control-result.json"), 262_144)?)?;
        saved["result"]["binding"]["plan"]
            .as_u64()
            .context("opened channel missing")
    };
    let action = match operation {
        "open" => PrivateAction::Open {
            offer: 0,
            ceiling_ou: 1000,
        },
        "quote" => PrivateAction::Quote {
            channel: channel()?,
            class: 0,
            bytes: 1_048_576,
            validity_ms: 120_000,
        },
        "receipt" => {
            let proof: Value =
                serde_json::from_slice(&read(&root.join("pay-proof.json"), 131_072)?)?;
            let confirmed: Value =
                serde_json::from_slice(&read(&root.join("pay-confirmation.json"), 131_072)?)?;
            ensure!(
                confirmed["success"] == true,
                "native successful execution observation missing"
            );
            let epoch = confirmed["epoch"]
                .as_u64()
                .context("native epoch missing")?;
            let siblings: Vec<[u8; 32]> =
                serde_json::from_value(proof["membership"]["siblings"].clone())?;
            let membership = pool::Membership {
                index: u32::try_from(
                    proof["membership"]["index"]
                        .as_u64()
                        .context("membership index")?,
                )?,
                siblings: siblings
                    .iter()
                    .map(pool::decode_field)
                    .collect::<Result<Vec<_>>>()?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("membership depth differs"))?,
            };
            let outputs: [[u8; 32]; 2] = serde_json::from_value(proof["outputs"].clone())?;
            let transcript = call(&proof["call"])?;
            let evidence = octra_node::vpn::payments::shielded::wallet::Receipt {
                epoch,
                commitment: outputs[0],
                membership: &membership,
                call: &transcript,
                relayer: config["relayer"]
                    .as_str()
                    .context("relayer")?
                    .as_bytes()
                    .try_into()?,
            }
            .evidence()?;
            PrivateAction::Receipt {
                channel: channel()?,
                quote: transcript.quote,
                evidence,
            }
        }
        _ => anyhow::bail!("unsupported private canary action"),
    };
    let request_path = root.join(format!("{operation}-control-request.json"));
    let signed: SignedPrivateRequest = if request_path.exists() {
        let saved: SignedPrivateRequest = serde_json::from_slice(&read(&request_path, 65_536)?)?;
        saved.verify()?;
        ensure!(
            saved.request.target == target
                && saved.receipt_key == key.public
                && serde_json::to_value(&saved.request.action)? == serde_json::to_value(&action)?,
            "saved request differs; preserve original canary"
        );
        saved
    } else {
        let mut id = [0; 32];
        rand::rngs::OsRng.fill_bytes(&mut id);
        let saved = SignedPrivateRequest::sign(
            PrivateRequest {
                target: target.clone(),
                id,
                valid_from_ms: now.saturating_sub(60_000),
                expires_ms: now.checked_add(3_600_000).context("clock overflow")?,
                action,
            },
            &key,
        )?;
        save(&request_path, &serde_json::to_vec(&saved)?)?;
        saved
    };
    ensure!(
        signed.request.valid_from_ms <= now && now < signed.request.expires_ms,
        "original request expired; no automatic replacement"
    );
    let destination = root.join(format!("{operation}-control-result.json"));
    let reply: SignedPrivateReply = if destination.exists() {
        let saved: Value = serde_json::from_slice(&read(&destination, 262_144)?)?;
        serde_json::from_value(saved["reply"].clone())?
    } else {
        let control = octravpn_client::PrivateControl::new(
            "https://control.octra.to",
            target,
            config["control_ca_pem"].as_str().context("CA missing")?,
            serde_json::from_value(config["control_spki"].clone())?,
        )?;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(120);
        loop {
            match control.exchange(&signed).await {
                Ok(reply) => break reply,
                Err(error)
                    if error.is::<octravpn_core::payments::Unavailable>()
                        && tokio::time::Instant::now() < deadline =>
                {
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
                Err(error) => return Err(error),
            }
        }
    };
    let result: PrivateResult = serde_json::from_slice(&reply.verify(&signed)?)?;
    if let PrivateResult::Open {
        binding,
        operator_generation,
        tariff,
        ceiling_ou,
    } = &result
    {
        ensure!(
            *operator_generation == 1
                && *ceiling_ou == 1000
                && binding.offer == 0
                && binding.payer == octravpn_core::Address::from_pubkey(&key.public.0)
                && tariff.hash_hex()? == config["tariff_hash"].as_str().context("tariff hash")?,
            "opened canary terms differ"
        );
    }
    if !destination.exists() {
        save(
            &destination,
            &serde_json::to_vec(&json!({"reply":reply,"result":result}))?,
        )?;
    }
    println!(
        "{}",
        json!({"authenticated_private_action":operation,"financial_finality_asserted":false})
    );
    Ok(())
}
