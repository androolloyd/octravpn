use octra_hfhe::{
    encrypt,
    field::Fp,
    keys::{keygen_from_seed, CircuitProfile, Params},
    recrypt::public,
    seeded_rng::CtrRng,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
mod common;
#[path = "common/entropy.rs"]
mod entropy;
#[test]
fn native_public_recryption_proofs_and_bundles_match_bytes_and_entropy() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/public_recrypt.json")).unwrap();
    let sources: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    common::assert_source_pin(&fixture, &sources);
    for (source, hash) in fixture["source_sha256"].as_object().unwrap() {
        assert_eq!(*hash, sources["files"][source]);
    }
    assert_eq!(
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/hfhe-public-recrypt-oracle.cpp"
        ))),
        fixture["oracle_sha256"]
    );
    for (index, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let params = Params {
            basis: 126,
            m_bits: 65,
            n_bits: 17,
            h_col_weight: 13,
            x_col_weight: 7,
            error_weight: 2,
            lpn_n: 65,
            lpn_t: 127,
            noise_entropy_bits: 0.0,
            ..Params::default()
        };
        let (mut pk, sk) =
            keygen_from_seed(params, &std::array::from_fn(|i| u8::try_from(i).unwrap())).unwrap();
        pk.set_circuit_profile(
            &sk,
            if case["profile"] == 1 {
                CircuitProfile::MimcX3V6
            } else {
                CircuitProfile::MimcX5V7
            },
        );
        let seed = std::array::from_fn(|i| 31 - u8::try_from(i).unwrap());
        let input = if case["variant"] == 0 {
            encrypt::synthesize(&pk, &sk, &[Fp::ZERO], 0, &mut CtrRng::seeded(&seed)).unwrap()
        } else {
            encrypt::value_seeded(&pk, &sk, 0, &seed).unwrap()
        };
        let mut output = input.clone();
        let mut key = public::Key::new(4, 128, 1).unwrap();
        key.require_smaller = false;
        if case["variant"] == 2 {
            output = output.add_constant(Fp::ONE, false).unwrap();
        }
        let mut entropy = entropy::Entropy::new(case["entropy_seed"].as_u64().unwrap());
        let proof = if case["variant"] == 3 {
            key.require_smaller = true;
            public::bundle_seeded(&pk, &sk, &key, &input, &seed, 1, 4, &mut entropy).map(|bundle| {
                output = bundle.output;
                bundle.proof
            })
        } else {
            public::prove(&pk, &sk, &input, &output, &mut entropy)
        };
        let actual = match proof {
            Err(error) => {
                json!({"error":error.to_string(),"calls":entropy.calls,"consumed":entropy.consumed})
            }
            Ok(proof) => {
                let mut changed = proof.clone();
                changed.equality.is_bound = true;
                let bound = public::verify(&pk, &key, &input, &output, &changed).unwrap();
                changed = proof.clone();
                changed.output_layers += 1;
                let layers = public::verify(&pk, &key, &input, &output, &changed).unwrap();
                changed = proof.clone();
                changed.output_edges += 1;
                let edges = public::verify(&pk, &key, &input, &output, &changed).unwrap();
                json!({"cipher":hex::encode(output.to_bytes().unwrap()),"proof":hex::encode(proof.equality.to_raw_bytes().unwrap()),"output_layers":proof.output_layers,"output_edges":proof.output_edges,"accepted":u8::from(public::verify(&pk,&key,&input,&output,&proof).unwrap()),"mutations":([bound,layers,edges].map(u8::from)),"calls":entropy.calls,"consumed":entropy.consumed})
            }
        };
        assert_eq!(actual, case["expected"], "public recryption case {index}");
    }
}
