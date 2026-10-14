mod common;

use octra_hfhe::{
    cipher::Cipher,
    decrypt::{self, DecPolicy},
    field::Fp,
    keys::{keygen_from_seed, CircuitProfile, Params},
};
use serde_json::{json, Value};

fn fixture() -> Value {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/decrypt.json")).unwrap();
    let sources: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    common::assert_source_pin(&fixture, &sources);
    for (path, hash) in fixture["source_sha256"].as_object().unwrap() {
        assert_eq!(*hash, sources["files"][path]);
    }
    fixture
}

fn field(value: Fp) -> String {
    hex::encode(value.to_bytes_le())
}

#[test]
fn decryption_policies_and_native_source_masks_match_native() {
    for case in fixture()["cases"].as_array().unwrap() {
        let seed: [u8; 32] = hex::decode(case["seed"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let (mut public, secret) = keygen_from_seed(
            Params {
                m_bits: 65,
                n_bits: 17,
                h_col_weight: 13,
                x_col_weight: 7,
                error_weight: 2,
                lpn_n: 65,
                lpn_t: 129,
                ..Params::default()
            },
            &seed,
        )
        .unwrap();
        let profile = if case["profile"] == 1 {
            CircuitProfile::MimcX3V6
        } else {
            CircuitProfile::MimcX5V7
        };
        public.set_circuit_profile(&secret, profile);
        let expected = &case["expected"];
        let nonce = std::array::from_fn(|i| case["nonce"][i].as_str().unwrap().parse().unwrap());
        let native_tag = decrypt::native_tag(&public, nonce);
        assert_eq!(native_tag.to_string(), expected["native_tag"]);
        assert_eq!(
            field(decrypt::native_affine(
                &secret,
                native_tag,
                nonce,
                usize::MAX
            )),
            expected["native_affine"]
        );
        let native_masks = decrypt::native_masks(
            &secret,
            native_tag,
            nonce,
            case["slots"].as_u64().unwrap() as usize,
        )
        .unwrap();
        assert_eq!(
            json!(native_masks.iter().copied().map(field).collect::<Vec<_>>()),
            expected["native_masks"]
        );
        let bytes = hex::decode(expected["bytes"].as_str().unwrap()).unwrap();
        let parsed = Cipher::from_bytes(&bytes);
        if let Some(error) = expected["import_error"].as_str() {
            assert_eq!(parsed.unwrap_err().to_string(), error);
            continue;
        }
        let cipher = parsed.unwrap();
        assert_eq!(
            decrypt::has_native_source(&public, &cipher),
            expected["native_source"]
        );
        for (index, policy) in [
            DecPolicy::Standard,
            DecPolicy::NativeLocal,
            DecPolicy::LegacyMask,
        ]
        .into_iter()
        .enumerate()
        {
            let mut actual = json!({});
            match decrypt::values(&public, &secret, &cipher, policy) {
                Ok(values) => {
                    actual["values"] = json!(values.iter().copied().map(field).collect::<Vec<_>>());
                }
                Err(error) => actual["values_error"] = json!(error.to_string()),
            }
            match decrypt::value(&public, &secret, &cipher, policy) {
                Ok(value) => actual["value"] = json!(field(value)),
                Err(error) => actual["value_error"] = json!(error.to_string()),
            }
            match decrypt::value_slot0(&public, &secret, &cipher, policy) {
                Ok(value) => actual["slot0"] = json!(field(value)),
                Err(error) => actual["slot0_error"] = json!(error.to_string()),
            }
            assert_eq!(
                actual, expected["policies"][index],
                "{} / {} / slots {}",
                case["kind"], case["profile"], case["slots"]
            );
        }
    }
}

#[test]
fn uncapped_legacy_slots_return_allocation_failure_without_panicking() {
    let (public, secret) = keygen_from_seed(
        Params {
            m_bits: 65,
            n_bits: 17,
            h_col_weight: 13,
            x_col_weight: 7,
            error_weight: 2,
            lpn_n: 65,
            lpn_t: 129,
            ..Params::default()
        },
        &[0; 32],
    )
    .unwrap();
    let mut wire = b"PVAC\x01\x00".to_vec();
    wire.extend_from_slice(&(usize::MAX as u64).to_le_bytes());
    wire.extend_from_slice(&[0; 24]);
    let cipher = Cipher::from_bytes_with_policy(&wire, false, false).unwrap();
    assert!(cipher.compatible_with(&public));
    // This is an operational failure, not a newly imposed consensus size cap.
    for policy in [
        DecPolicy::Standard,
        DecPolicy::NativeLocal,
        DecPolicy::LegacyMask,
    ] {
        assert_eq!(
            decrypt::values(&public, &secret, &cipher, policy)
                .unwrap_err()
                .to_string(),
            "HFHE allocation unavailable"
        );
        assert_eq!(
            decrypt::value_slot0(&public, &secret, &cipher, policy)
                .unwrap_err()
                .to_string(),
            "HFHE allocation unavailable"
        );
    }
    assert_eq!(
        decrypt::native_masks(&secret, 0, [0; 2], usize::MAX)
            .unwrap_err()
            .to_string(),
        "HFHE allocation unavailable"
    );
    assert_eq!(
        octra_hfhe::circuit_prf::slots(&public, &secret, 0, [0; 2], usize::MAX)
            .unwrap_err()
            .to_string(),
        "HFHE allocation unavailable"
    );
    assert_eq!(
        octra_hfhe::circuit_prf::delta_slots(&public, &secret, 0, [0; 2], 0, 0, usize::MAX)
            .unwrap_err()
            .to_string(),
        "HFHE allocation unavailable"
    );
}
