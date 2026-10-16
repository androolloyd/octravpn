//! Explicit opt-in read-only qualification of a downloaded public certificate.
//! Neither its embedded keys nor the certificate itself can supply trust.
use octra_node_protocol::{consensus::profile::Settings, state_sync::manifest};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::Read,
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
#[ignore = "requires an independently pinned network.env and a downloaded public certificate"]
fn public_snapshot_authenticates_against_the_adopted_network_configuration() {
    let config_path =
        std::env::var_os("OCTRA_PUBLIC_NETWORK_ENV_PATH").expect("pinned network.env path");
    let certificate_path =
        std::env::var_os("OCTRA_PUBLIC_MANIFEST_PATH").expect("downloaded public manifest path");
    let config = std::fs::read(config_path).unwrap();
    let inventory: serde_json::Value = serde_json::from_str(include_str!(
        "../../../docs/rust-node/network-authority.json"
    ))
    .unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&config)),
        inventory["sha256"].as_str().unwrap(),
        "network authority must come from the independently pinned adopted source"
    );
    let values = std::str::from_utf8(&config)
        .unwrap()
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
        .map(|line| {
            let (key, value) = line.split_once('=').expect("network assignment");
            (key.to_owned(), value.as_bytes().to_vec())
        })
        .collect::<BTreeMap<_, _>>();
    let settings = Settings::from_values(values).unwrap();
    let get = |name| {
        settings
            .get(name)
            .expect("required network authority setting")
    };
    let entries = |name| {
        get(name)
            .split(|byte| *byte == b',')
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>()
    };
    let validators = manifest::signer_set(&entries("OCTRA_VALIDATORS")).unwrap();
    let exporters = manifest::signer_set(&entries("OCTRA_STATE_SYNC_EXPORTERS")).unwrap();
    let trust = manifest::Trust {
        validators: &validators,
        exporters: &exporters,
        chain_id: get("OCTRA_CHAIN_ID"),
        config_hash: get("OCTRA_CONSENSUS_CONFIG_HASH"),
        minimum_epoch: std::str::from_utf8(get("OCTRA_CHECKPOINT_EPOCH"))
            .unwrap()
            .parse()
            .unwrap(),
    };
    let mut raw = Vec::new();
    std::fs::File::open(certificate_path)
        .unwrap()
        .take(manifest::MANIFEST_LIMIT as u64 + 1)
        .read_to_end(&mut raw)
        .unwrap();
    assert!(raw.len() <= manifest::MANIFEST_LIMIT);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let verified = trust.verify(&raw,now).expect("public certificate must have native finality, trusted exporters, network binding and freshness");
    assert!(
        verified.anchor().is_some(),
        "an exporter signature alone is insufficient"
    );
    assert!(verified.draft().checkpoint.epoch >= trust.minimum_epoch);
    println!(
        "verified public checkpoint={} root={} manifest_sha256={}",
        verified.draft().checkpoint.epoch,
        String::from_utf8_lossy(&verified.draft().checkpoint.state_root),
        hex::encode(Sha256::digest(&raw))
    );
}
