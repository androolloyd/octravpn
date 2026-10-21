//! Harness preparation for an isolated chain. This creates ephemeral public
//! proving material and native Circle payloads; it is not a production setup.
use super::*;
use ark_serialize::CanonicalSerialize;
use serde::Deserialize;
use std::{os::unix::fs::PermissionsExt, path::Path, process::Command};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    origin: String,
    custody_cap_ou: u64,
}

#[test]
#[ignore = "explicit isolated Linux multihop fixture preparation only"]
fn prepare_isolated_multihop_pool_material() {
    assert_eq!(std::env::consts::OS, "linux");
    assert!(Path::new("/.dockerenv").is_file());
    let scope: Value =
        serde_json::from_slice(&std::fs::read("/evidence/kernel-scope.json").unwrap()).unwrap();
    assert_eq!(scope["fixture_only"], true);
    assert_eq!(scope["network_none"], true);
    let links = Command::new("ip")
        .args(["-j", "link", "show"])
        .output()
        .unwrap();
    assert!(links.status.success());
    let links: Vec<Value> = serde_json::from_slice(&links.stdout).unwrap();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0]["ifname"], "lo");
    let input =
        crate::bootstrap::read_limited(Path::new("/evidence/private-material-input.json"), 4096)
            .unwrap();
    let input: Input = serde_json::from_slice(&input).expect("invalid public fixture input");
    let origin: [u8; 32] = hex::decode(&input.origin).unwrap().try_into().unwrap();
    assert_eq!(hex::encode(origin), input.origin);
    assert!(origin != [0; 32] && (1..=200_000_000).contains(&input.custody_cap_ou));

    let domain = Domain::new(&origin, &address(&payment_host::address(14))).unwrap();
    let owner = SpendKey::random();
    let note = pool::Note::new(owner.owner(domain), 1, &[9; 32]).unwrap();
    let (sample, _) = PoolIndex::default()
        .prepare(domain, &[], &[note], 1, 0, [9; 32])
        .unwrap();
    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(
        sample.clone(),
        &mut rand::rngs::OsRng,
    )
    .unwrap();
    let vk = wire::key(&pk.vk).unwrap();
    let _verified = proof(&sample, &pk);
    let source = pool::app::source(&origin, &vk, input.custody_cap_ou).unwrap();
    let code = compiled(&source);
    let factory = compiled(pool::app::FACTORY);
    let mut encoded = Vec::new();
    pk.serialize_compressed(&mut encoded).unwrap();

    let output = Path::new("/evidence/private-material");
    std::fs::create_dir(output).unwrap();
    std::fs::set_permissions(output, std::fs::Permissions::from_mode(0o700)).unwrap();
    let files = [
        ("pool.aml", source.into_bytes()),
        ("factory.aml", pool::app::FACTORY.as_bytes().to_vec()),
        (
            "pool-payload.json",
            serde_json::to_vec(&crate::vpn::payments::circle_tests::payload(&code)).unwrap(),
        ),
        (
            "factory-payload.json",
            serde_json::to_vec(&crate::vpn::payments::circle_tests::payload(&factory)).unwrap(),
        ),
        ("pool.pk", encoded),
    ];
    let mut hashes = std::collections::BTreeMap::new();
    for (name, bytes) in files {
        crate::storage::publish(&output.join(name), &bytes).unwrap();
        hashes.insert(name, hex::encode(Sha256::digest(&bytes)));
    }
    let metadata = json!({
        "fixture_only":true, "production_setup_qualified":false,
        "origin":input.origin, "custody_cap_ou":input.custody_cap_ou,
        "verification_key_b64":STANDARD.encode(&vk),
        "verification_key_sha256":hex::encode(Sha256::digest(&vk)),
        "pool_code_sha256":hex::encode(Sha256::digest(&code)),
        "factory_code_sha256":hex::encode(Sha256::digest(&factory)),
        "files":hashes,
    });
    crate::storage::publish(
        &output.join("manifest.json"),
        &serde_json::to_vec_pretty(&metadata).unwrap(),
    )
    .unwrap();
}
