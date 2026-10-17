//! Actual AML compilation and registered public-key loading. The canonical
//! binding is a local fixture; no public-network execution is inferred.
#[path = "common/crypto_worker.rs"]
mod crypto_worker;
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_hfhe::keys::{keygen_from_seed, Params};
use octra_node_protocol::{
    aml::source::{self, Syntax},
    native_json::Document,
};
use octra_node_runtime::{
    circle_query::Query, circle_view::Profile, pvac::Files, state_batch::StateBatch,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
#[path = "common/circle_host.rs"]
#[allow(dead_code)]
mod common;

#[test]
fn compiled_aml_loads_registered_key_and_refuses_missing_or_corrupt_material() {
    let compiled = source::compile(
        br"contract FheProbe {
        view fn probe(key_address: address): string {
            let key = fhe_load_pk(key_address)
            return sha256(fhe_ser_pk(key))
        }
    }",
        Syntax::Source,
        true,
    )
    .unwrap();
    let (key, _secret) = keygen_from_seed(Params::default(), &[91; 32]).unwrap();
    let public = key.to_bytes().unwrap();
    let expected = hex::encode(Sha256::digest(STANDARD.encode(&public)));
    let directory = tempfile::tempdir().unwrap();
    let files = Arc::new(Files(directory.path().join("pvac")));
    files.persist(&public).unwrap();
    let runtime = common::runtime().with_public_keys(files.clone());
    let address = format!("oct{}", "5".repeat(44));
    let wallet = format!("oct{}", "9".repeat(44));
    let mut state = StateBatch::default();
    state.begin().unwrap();
    state
        .set(
            &[b"contracts", address.as_bytes(), b"bytecode"],
            STANDARD.encode(&compiled.octb).into_bytes(),
        )
        .unwrap();
    let params = Document::parse(format!("[\"{wallet}\"]").as_bytes()).unwrap();
    let profile = Profile::prior(1);
    let before_registration = state.snapshot();
    let missing = Query::new(&before_registration, &profile)
        .unwrap()
        .with_runtime(&runtime)
        .program(
            address.as_bytes(),
            b"probe",
            &params,
            wallet.as_bytes(),
            10_000_000,
        )
        .unwrap();
    assert!(!missing.success);
    let hash = hex::encode(Sha256::digest(&public));
    state
        .set(
            &[b"pvac_hashes", wallet.as_bytes()],
            hash.as_bytes().to_vec(),
        )
        .unwrap();
    let snapshot = state.snapshot();
    let root = snapshot.root().unwrap();
    let loaded = {
        let _scope = crypto_worker::scope(true);
        Query::new(&snapshot, &profile)
            .unwrap()
            .with_runtime(&runtime)
            .program(
                address.as_bytes(),
                b"probe",
                &params,
                wallet.as_bytes(),
                10_000_000,
            )
            .unwrap()
    };
    assert!(loaded.success, "{:?}", loaded.error);
    assert_eq!(
        loaded.response.unwrap().result_json(),
        format!("\"{expected}\"").as_bytes()
    );
    assert_eq!(snapshot.root().unwrap(), root);
    let no_source = Query::new(&snapshot, &profile).unwrap().program(
        address.as_bytes(),
        b"probe",
        &params,
        wallet.as_bytes(),
        10_000_000,
    );
    assert!(matches!(
        no_source,
        Err(octra_node_protocol::circle_wasm::Error::Unavailable(_))
    ));
    let blob = files.0.join("blobs").join(format!("{hash}.pk"));
    std::fs::write(&blob, b"corrupted public material").unwrap();
    let corrupt = Query::new(&snapshot, &profile)
        .unwrap()
        .with_runtime(&runtime)
        .program(
            address.as_bytes(),
            b"probe",
            &params,
            wallet.as_bytes(),
            10_000_000,
        );
    assert!(matches!(
        corrupt,
        Err(octra_node_protocol::circle_wasm::Error::Unavailable(_))
    ));
    std::fs::remove_file(blob).unwrap();
    let absent = Query::new(&snapshot, &profile)
        .unwrap()
        .with_runtime(&runtime)
        .program(
            address.as_bytes(),
            b"probe",
            &params,
            wallet.as_bytes(),
            10_000_000,
        );
    assert!(matches!(
        absent,
        Err(octra_node_protocol::circle_wasm::Error::Unavailable(_))
    ));
    assert_eq!(snapshot.root().unwrap(), root);
}
