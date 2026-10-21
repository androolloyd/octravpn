//! Offline, finite public-devnet canary proofs. Never submits transactions or
//! treats candidate leaves, RPC replies or an operator signature as finality.
use anyhow::{ensure, Context, Result};
use ark_serialize::CanonicalDeserialize;
use base64::{engine::general_purpose::STANDARD, Engine};
use clap::Parser;
use octra_private_payments_experimental::{
    invoice::{Consent, Settlement, SignedInvoice},
    native_stealth,
    pool::{self, call::Call, envelope, transaction::Prover, Domain, PoolIndex, Spend, SpendKey},
};
use rand::RngCore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};
use zeroize::Zeroizing;

#[path = "devnet_private_proof/control.rs"]
mod control;
#[path = "devnet_private_proof/sign.rs"]
mod sign;

#[derive(Parser)]
struct Options {
    #[arg(long)]
    directory: PathBuf,
    /// init creates new protected seeds; deposit/pay/withdraw prepare only.
    #[arg(long)]
    operation: String,
}
#[expect(
    clippy::verbose_bit_mask,
    reason = "Explicit private POSIX permission mask"
)]
fn read(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let file: std::fs::File = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?
    .into();
    let meta = file.metadata()?;
    ensure!(
        meta.is_file()
            && meta.nlink() == 1
            && meta.permissions().mode() & 0o077 == 0
            && meta.len() <= maximum,
        "canary input must be a bounded private regular file with one link"
    );
    let mut bytes = Vec::new();
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    ensure!(
        u64::try_from(bytes.len())? <= maximum,
        "canary input grew past bound"
    );
    Ok(bytes)
}
fn save(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::File::open(path.parent().context("parent missing")?)?.sync_all()?;
    Ok(())
}
fn raw<const N: usize>(value: &Value, name: &str) -> Result<[u8; N]> {
    hex::decode(value[name].as_str().context("missing hex field")?)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("wrong {name} width"))
}
fn seed(root: &Path, name: &str) -> Result<Zeroizing<[u8; 32]>> {
    Ok(Zeroizing::new(
        read(&root.join(name), 32)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("wrong seed width"))?,
    ))
}
fn call(value: &Value) -> Result<Call> {
    Ok(Call {
        quote: raw(value, "quote")?,
        valid_from_ms: value["valid_from_ms"].as_u64().context("time")?,
        expires_ms: value["expires_ms"].as_u64().context("expiry")?,
        payout: value["payout"]
            .as_str()
            .context("payout")?
            .as_bytes()
            .try_into()?,
        deposit_ou: value["deposit_ou"].as_u64().context("deposit")?,
        withdraw_ou: value["withdraw_ou"].as_u64().context("withdraw")?,
        boxes: serde_json::from_value(value["boxes"].clone())?,
    })
}
#[tokio::main]
async fn main() -> Result<()> {
    let options = Options::parse();
    let root = options.directory;
    let config: Value = serde_json::from_slice(&read(&root.join("config.json"), 65_536)?)?;
    ensure!(
        config["chain_id"] == "octra-devnet-9871-cluster"
            && config["test_setup_acknowledged"] == true,
        "explicit public-devnet test setup required"
    );
    let origin = raw(&config, "origin")?;
    let circle: [u8; 47] = config["pool"]
        .as_str()
        .context("pool")?
        .as_bytes()
        .try_into()?;
    let relayer: [u8; 47] = config["relayer"]
        .as_str()
        .context("relayer")?
        .as_bytes()
        .try_into()?;
    let domain = Domain::new(&origin, &circle)?;
    if options.operation == "init" {
        for name in ["spend.key", "view.key", "receipt.key"] {
            let mut bytes = Zeroizing::new([0; 32]);
            rand::rngs::OsRng.fill_bytes(&mut *bytes);
            if name == "spend.key" {
                bytes[0] = 0;
                SpendKey::from_bytes(&bytes)?;
            }
            save(&root.join(name), &*bytes)?;
        }
        println!("{{\"initialized\":true,\"transactions_submitted\":0}}");
        return Ok(());
    }
    if options.operation.starts_with("sign-") {
        return sign::run(&root, &config, &options.operation);
    }
    if ["open", "quote", "receipt"].contains(&options.operation.as_str()) {
        control::run(&root, &config, &options.operation).await?;
        return Ok(());
    }
    ensure!(
        ["deposit", "pay", "withdraw"].contains(&options.operation.as_str()),
        "unknown canary operation"
    );
    let request_path = root.join(format!("{}-request.json", options.operation));
    let request_bytes = read(&request_path, 65_536)?;
    let request: Value = serde_json::from_slice(&request_bytes)?;
    let now = request["canonical_ms"]
        .as_u64()
        .context("canonical clock missing")?;
    let destination = root.join(format!("{}-proof.json", options.operation));
    ensure!(
        !destination.exists(),
        "preserve and reconcile the original proof; refusing replacement"
    );
    let owner = SpendKey::from_bytes(&*seed(&root, "spend.key")?)?;
    let view = seed(&root, "view.key")?;
    let mut index = PoolIndex::default();
    let input = if options.operation == "deposit" {
        None
    } else {
        let previous = if options.operation == "pay" {
            "deposit"
        } else {
            "pay"
        };
        let saved: Value = serde_json::from_slice(&read(
            &root.join(format!("{previous}-proof.json")),
            131_072,
        )?)?;
        let notes: Vec<[u8; 32]> = serde_json::from_value(saved["leaves"]["notes"].clone())?;
        let spent: Vec<[u8; 32]> = serde_json::from_value(saved["leaves"]["nullifiers"].clone())?;
        index = PoolIndex::rebuild(&notes, &spent)?;
        let prior = call(&saved["call"])?;
        let slot = saved["own_output"].as_u64().context("owned slot")? as usize;
        let position = u32::try_from(saved["first_output"].as_u64().context("output position")?)?
            + u32::try_from(slot)?;
        let note = envelope::open(
            domain,
            owner.owner(domain),
            &view,
            &prior.boxes[slot],
            &prior.context(&origin, &circle, &relayer)?,
            pool::decode_field(&notes[position as usize])?,
        )?;
        Some((note, position))
    };
    let mut outputs = Vec::new();
    let mut current = Call {
        quote: [0; 32],
        valid_from_ms: now.saturating_sub(60_000),
        expires_ms: now.checked_add(3_600_000).context("clock overflow")?,
        payout: relayer,
        deposit_ou: 0,
        withdraw_ou: 0,
        boxes: Default::default(),
    };
    let own_output;
    if options.operation == "deposit" {
        current.deposit_ou = 100_000;
        let draft = envelope::Draft::new(
            owner.owner(domain),
            current.deposit_ou,
            &native_stealth::view_public(&view),
        )?;
        current.boxes[0].clone_from(&draft.ciphertext);
        outputs.push(draft);
        own_output = 0;
    } else if options.operation == "pay" {
        let invoice = SignedInvoice::decode_private(
            &STANDARD.decode(request["invoice"].as_str().context("invoice missing")?)?,
        )?;
        let receipt = octravpn_core::KeyPair::from_secret_bytes(&*seed(&root, "receipt.key")?);
        ensure!(
            matches!(&invoice.invoice.settlement,Settlement::ShieldedPool{circle:actual,..} if *actual==circle),
            "invoice pool differs"
        );
        let consent = Consent {
            chain_origin: origin,
            directory_circle: config["directory"]
                .as_str()
                .context("directory")?
                .as_bytes()
                .try_into()?,
            operator_key: raw(&config, "operator_public")?,
            bond_generation: 1,
            offer: 0,
            tariff_hash: raw(&config, "tariff_hash")?,
            receipt_key: receipt.public.0,
            settlement: invoice.invoice.settlement.clone(),
            traffic_class: 0,
            rate_ou_per_mib: 1000,
            max_bytes: 1_048_576,
            max_cost_ou: 1000,
            canonical_ms: now,
            active_from_ms: 0,
            purchase_deadline_ms: None,
        };
        let purchase = pool::purchase::prepare(&invoice, &consent)?;
        ensure!(
            invoice.invoice.bytes == 1_048_576 && invoice.invoice.amount_ou()? == 1000,
            "canary purchase differs"
        );
        let remaining = input
            .as_ref()
            .context("deposit missing")?
            .0
            .value()
            .checked_sub(1000)
            .context("insufficient canary note")?;
        let change = envelope::Draft::new(
            owner.owner(domain),
            remaining,
            &native_stealth::view_public(&view),
        )?;
        current = purchase.call(Some(&change), relayer);
        outputs.extend([purchase.output, change]);
        own_output = 1;
    } else {
        current.withdraw_ou = input.as_ref().context("change missing")?.0.value();
        own_output = 0;
    }
    let context = current.context(&origin, &circle, &relayer)?;
    let notes = outputs.iter().map(|d| d.bind(&context)).collect::<Vec<_>>();
    let spends = input
        .as_ref()
        .map(|(note, index)| Spend {
            note,
            key: &owner,
            index: *index,
        })
        .into_iter()
        .collect::<Vec<_>>();
    let first_output = index.roots().2;
    let (circuit, candidate) = index.prepare(
        domain,
        &spends,
        &notes,
        current.deposit_ou,
        current.withdraw_ou,
        context,
    )?;
    let vk = STANDARD.decode(
        config["verification_key_b64"]
            .as_str()
            .context("VK missing")?,
    )?;
    ensure!(
        hex::encode(Sha256::digest(&vk))
            == "2ae86a97a89f6924d5f7f35285ed5f48c02e48975ba804ee06159228299087f9",
        "unaccepted canary VK"
    );
    let key_bytes = Zeroizing::new(read(
        Path::new(config["proving_key"].as_str().context("proving key path")?),
        100 * 1024 * 1024,
    )?);
    let key =
        ark_groth16::ProvingKey::<ark_bn254::Bn254>::deserialize_compressed(key_bytes.as_slice())?;
    let prover = Prover::new(Arc::new(key), &vk)?;
    let statement = circuit.statement.clone();
    let proof = prover.prove(circuit)?;
    ensure!(
        octra_node_runtime::groth16::verify(&vk, &proof, &pool::wire::inputs(&statement)),
        "native canary proof verification failed"
    );
    let leaves = candidate.public_leaves()?;
    let membership = if options.operation == "pay" {
        let m = candidate.membership(u32::try_from(first_output)?)?;
        json!({"index":m.index,"siblings":m.siblings.map(pool::encode_field)})
    } else {
        Value::Null
    };
    let document = json!({"request_sha256":hex::encode(Sha256::digest(&request_bytes)),"candidate_only":true,
        "parameters":pool::transaction::parameters(&statement,&current,&proof)?,"first_output":first_output,"own_output":own_output,
        "leaves":{"notes":leaves.notes,"nullifiers":leaves.nullifiers},"membership":membership,
        "outputs":statement.outputs.map(pool::encode_field),"context":hex::encode(context),
        "call":{"quote":hex::encode(current.quote),"valid_from_ms":current.valid_from_ms,"expires_ms":current.expires_ms,
        "payout":std::str::from_utf8(&current.payout)?,"deposit_ou":current.deposit_ou,"withdraw_ou":current.withdraw_ou,"boxes":current.boxes}});
    save(&destination, &serde_json::to_vec(&document)?)?;
    println!(
        "{}",
        json!({"prepared":options.operation,"candidate_only":true,"transactions_submitted":0})
    );
    Ok(())
}
