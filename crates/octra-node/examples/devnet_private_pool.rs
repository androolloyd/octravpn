//! Offline public-devnet alpha parameters. Never creates production ceremony material.
use anyhow::{ensure, Result};
use ark_bn254::Bn254;
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use base64::{engine::general_purpose::STANDARD, Engine};
use clap::Parser;
use octra_private_payments_experimental::pool::{
    self, transaction::Prover, wire, Domain, Note, PoolIndex, SpendKey,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Parser)]
struct Options {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    out: PathBuf,
    /// Shared shielded custody cap, in OU; at most 1 devnet OCT.
    #[arg(long, default_value_t = 1_000_000)]
    cap_ou: u64,
    /// Explicit acknowledgement that this is a single-party test setup.
    #[arg(long, required = true)]
    devnet_test_setup: bool,
}

fn validate(chain: &str, cap: u64, acknowledged: bool) -> Result<()> {
    ensure!(
        chain.as_bytes() == octra_node_protocol::consensus::policy::DEVNET,
        "parameter preparation is restricted to adopted public devnet"
    );
    ensure!(
        acknowledged && (1..=1_000_000).contains(&cap),
        "explicit devnet test setup and a cap of at most 1 OCT are required"
    );
    Ok(())
}

fn payload(code: &[u8]) -> serde_json::Value {
    serde_json::json!({"runtime":"octb","privacy_class":"public","browser_mode":"gateway_allowed",
        "resource_mode":"public_resources","code_b64":STANDARD.encode(code),
        "limits":{"max_stable_bytes":"33554432","max_assets_bytes":"33554432",
            "max_inline_value":"65536","max_wasm_bytes":"33554432"}})
}

fn save(
    root: &Path,
    name: &str,
    bytes: &[u8],
    hashes: &mut BTreeMap<String, String>,
) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join(name))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    hashes.insert(name.into(), hex::encode(Sha256::digest(bytes)));
    Ok(())
}

fn main() -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let options = Options::parse();
    let config = octra_node::network::read(&options.config)?;
    validate(
        &config.network.identity.chain_id,
        options.cap_ou,
        options.devnet_test_setup,
    )?;
    // An existing or partially written output is never replaced or silently reseeded.
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&options.out)?;
    let origin = octra_node::vpn::payments::application_domain(
        &config.network.identity,
        octra_node::vpn::payments::Application::Circle,
    );
    let origin_bytes: [u8; 32] = hex::decode(&origin)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid origin width"))?;
    let (pk, vk) = tracing::subscriber::with_default(
        tracing::subscriber::NoSubscriber::default(),
        || -> Result<_> {
            // Domain is a public circuit input: deployment can choose its final Circle address later.
            let domain = Domain::new(
                &origin_bytes,
                b"oct1JBUrYbeTQazQ39LQn4ZjnPLHfDpLGXouqon1jZhJfYP",
            )?;
            let owner = SpendKey::random();
            let note = Note::new(owner.owner(domain), 1, &[9; 32])?;
            let (sample, _) = PoolIndex::default().prepare(domain, &[], &[note], 1, 0, [9; 32])?;
            let pk = Arc::new(Groth16::<Bn254>::generate_random_parameters_with_reduction(
                sample.clone(),
                &mut rand::rngs::OsRng,
            )?);
            let vk = wire::key(&pk.vk)?;
            let proof = Prover::new(pk.clone(), &vk)?.prove(sample.clone())?;
            ensure!(
                octra_node_runtime::groth16::verify(&vk, &proof, &wire::inputs(&sample.statement)),
                "native verification of new parameters failed"
            );
            Ok((pk, vk))
        },
    )?;
    let source = pool::app::source(&origin_bytes, &vk, options.cap_ou)?;
    let mut hashes = BTreeMap::new();
    let mut code_hashes = BTreeMap::new();
    for (name, source) in [
        ("pool", source.as_bytes()),
        ("factory", pool::app::FACTORY.as_bytes()),
    ] {
        let compiled = octra_node_runtime::program::build::legacy(source, true, true)?;
        let code = STANDARD.decode(
            compiled["bytecode"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("compiler bytecode missing"))?,
        )?;
        code_hashes.insert(name, hex::encode(Sha256::digest(&code)));
        save(&options.out, &format!("{name}.aml"), source, &mut hashes)?;
        save(
            &options.out,
            &format!("{name}-payload.json"),
            &serde_json::to_vec(&payload(&code))?,
            &mut hashes,
        )?;
        save(
            &options.out,
            &format!("{name}-compile.json"),
            &serde_json::to_vec(&compiled)?,
            &mut hashes,
        )?;
    }
    let mut encoded = Vec::new();
    pk.serialize_compressed(&mut encoded)?;
    save(&options.out, "pool.pk", &encoded, &mut hashes)?;
    let report = serde_json::json!({"devnet_alpha_only":true,"production_setup_qualified":false,
        "chain":config.network.identity,"origin":origin,"custody_cap_ou":options.cap_ou,
        "verification_key_b64":STANDARD.encode(&vk),"verification_key_sha256":hex::encode(Sha256::digest(&vk)),
        "code_sha256":code_hashes,"files":hashes,"native_sample_verified":true,
        "scope":"Offline single-party devnet setup and local compilation; no deployment or public finality qualification"});
    let mut report_hash = BTreeMap::new();
    save(
        &options.out,
        "manifest.json",
        &serde_json::to_vec_pretty(&report)?,
        &mut report_hash,
    )?;
    std::fs::File::open(&options.out)?.sync_all()?;
    println!(
        "{}",
        serde_json::json!({"prepared":options.out,"devnet_alpha_only":true,"manifest_sha256":report_hash["manifest.json"]})
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_test_setup_requires_devnet_explicit_consent_and_a_finite_cap() {
        let devnet = std::str::from_utf8(octra_node_protocol::consensus::policy::DEVNET).unwrap();
        assert!(validate(devnet, 1_000_000, true).is_ok());
        for chain in [
            "octra-mainnet",
            "unknown",
            "octra-rust-local-0123456789abcdef",
        ] {
            assert!(validate(chain, 1_000_000, true).is_err());
        }
        assert!(validate(devnet, 1_000_000, false).is_err());
        assert!(validate(devnet, 0, true).is_err());
        assert!(validate(devnet, 1_000_001, true).is_err());
    }
}
