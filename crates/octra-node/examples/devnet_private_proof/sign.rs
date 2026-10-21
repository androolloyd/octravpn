//! Prepare one immutable, fee-bounded native envelope without broadcasting.
use super::{call, read, save};
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::path::Path;
use zeroize::Zeroizing;

pub(super) fn run(root: &Path, config: &Value, operation: &str) -> Result<()> {
    use ed25519_dalek::{Signer, SigningKey};
    use octra_node_protocol::transaction::{self, Nonce, OpType, Transaction};
    let kind = operation
        .strip_prefix("sign-")
        .context("signing operation")?;
    ensure!(
        ["deposit", "pay", "withdraw"].contains(&kind),
        "unsupported canary signature"
    );
    let proof: Value =
        serde_json::from_slice(&read(&root.join(format!("{kind}-proof.json")), 131_072)?)?;
    let input: Value = serde_json::from_slice(&read(
        &root.join(format!("{kind}-sign-request.json")),
        65_536,
    )?)?;
    let key_bytes = Zeroizing::new(read(
        Path::new(config["relayer_key"].as_str().context("relayer key path")?),
        128,
    )?);
    let key = Zeroizing::new(hex::decode(std::str::from_utf8(&key_bytes)?.trim())?);
    let key = SigningKey::from_bytes(key.as_slice().try_into()?);
    let public = STANDARD.encode(key.verifying_key().to_bytes()).into_bytes();
    let from = transaction::address_from_public_key(&public);
    ensure!(
        from == config["relayer"].as_str().context("relayer")?.as_bytes(),
        "canary signer differs"
    );
    let transcript = call(&proof["call"])?;
    ensure!(
        (kind == "deposit" && transcript.deposit_ou == 100_000 && transcript.withdraw_ou == 0)
            || (kind == "pay" && transcript.deposit_ou == 0 && transcript.withdraw_ou == 0)
            || (kind == "withdraw"
                && transcript.deposit_ou == 0
                && transcript.withdraw_ou == 99_000),
        "canary native amount differs"
    );
    let nonce = input["nonce"].as_i64().context("nonce missing")?;
    let timestamp = input["timestamp"].as_f64().context("timestamp missing")?;
    ensure!(
        nonce > 0 && timestamp.is_finite() && timestamp >= 0.,
        "canary native clock/nonce differs"
    );
    let mut tx = Transaction {
        from,
        to: config["pool"].as_str().context("pool")?.as_bytes().to_vec(),
        amount: transcript.deposit_ou.into(),
        nonce: Nonce::new(nonce)?,
        ou: 200_000.into(),
        timestamp,
        signature: Vec::new(),
        public_key: Some(public.clone()),
        message: Some(serde_json::to_vec(&proof["parameters"])?),
        encrypted_data: Some(b"exchange".to_vec()),
        op_type: OpType::CircleCall,
    };
    tx.signature = STANDARD
        .encode(key.sign(&tx.signing_bytes()?).to_bytes())
        .into_bytes();
    ensure!(
        tx.verify(&public) && transaction::normalize_envelope(&tx, Some(&public))? == tx,
        "native canary signature differs"
    );
    let wire: Value = serde_json::from_slice(&tx.to_json_bytes()?)?;
    save(
        &root.join(format!("{kind}-signed.json")),
        &serde_json::to_vec(
            &json!({"hash":hex::encode(tx.hash()?),"transaction":wire,"fee_ou":200_000,"possible_submission":false}),
        )?,
    )?;
    println!(
        "{}",
        json!({"signed":kind,"hash":hex::encode(tx.hash()?),"transactions_submitted":0})
    );
    Ok(())
}
