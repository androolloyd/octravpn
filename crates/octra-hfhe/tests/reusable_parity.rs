use octra_hfhe::{
    cipher::Cipher,
    keys::{keygen_from_seed, CircuitProfile, Params},
    recrypt::{
        chosen, digest, hidden, profile,
        reusable::{self, Admission, Key},
    },
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
mod common;
fn number(case: &Value, key: &str) -> usize {
    case[key].as_str().unwrap().parse().unwrap()
}
#[test]
fn native_reusable_key_ciphertexts_digests_and_admission() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/reusable.json")).unwrap();
    let sources: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    common::assert_source_pin(&fixture, &sources);
    for (source, hash) in fixture["source_sha256"].as_object().unwrap() {
        assert_eq!(*hash, sources["files"][source]);
    }
    assert_eq!(
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/hfhe-reusable-oracle.cpp"
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
            noise_entropy_bits: case["noise"].as_str().unwrap().parse().unwrap(),
            ..Params::default()
        };
        let (mut public, secret) =
            keygen_from_seed(params, &std::array::from_fn(|i| u8::try_from(i).unwrap())).unwrap();
        public.set_circuit_profile(
            &secret,
            if number(case, "profile") == 1 {
                CircuitProfile::MimcX3V6
            } else {
                CircuitProfile::MimcX5V7
            },
        );
        let result = Key::new(
            &public,
            &secret,
            number(case, "queries"),
            reusable::production_budget(),
        );
        if let Some(error) = case["expected"]["error"].as_str() {
            assert_eq!(result.err().unwrap().to_string(), error, "refusal {index}");
            continue;
        }
        let mut key = result.unwrap();
        let mut admission = Admission::default();
        match number(case, "admission") {
            1 => admission = Admission::linear(),
            2 => admission = Admission::wide(),
            3 => admission = Admission::vector(4),
            4 => admission = Admission::vector(8),
            5 => admission = Admission::production(),
            6 => admission.max_terms = 0,
            7 => admission.out_terms = 17,
            8 => admission.max_slots = 9,
            9 => admission.max_queries = 65,
            10 => admission.alpha_bits = 9,
            11 => admission.row_bits = 0,
            _ => {}
        }
        let mut actual = json!({"public":hex::encode(digest::public_key(&public).unwrap()),"secret":hex::encode(*digest::secret_key(&public,&secret).unwrap()),"domain":hex::encode(key.domain),"view":hex::encode(key.view),"ciphertexts":key.encrypted_secret.iter().map(|cipher|hex::encode(cipher.to_bytes().unwrap())).collect::<Vec<_>>()});
        match number(case, "mutation") {
            1 => key.key[0] ^= 1,
            2 => key.domain[0] ^= 1,
            3 => key.view[0] ^= 1,
            4 => key.safe = false,
            5 => key.prf = 3,
            6 => key.lpn = 1,
            7 => {
                key.encrypted_secret.pop();
            }
            8 => key.encrypted_secret[0] = Cipher::default(),
            9 => key.policy.reusable = false,
            10 => key.policy.hidden_output = false,
            11 => key.policy.statement_bound = false,
            12 => key.policy.transcript_bound = false,
            13 => key.policy.material_bound = false,
            14 => key.policy.no_basis_oracle = false,
            15 => key.policy.native_backend = false,
            16 => key.policy.max_queries = 0,
            17 => key.policy.certificate = hidden::Certificate::None,
            18 => key.budget.proof = profile::Kind::ShaCompat,
            19 => key.budget.target_bits = 127,
            20 => key.budget.max_trace_units = 1025,
            21 => key.budget.max_output_tags = 65,
            22 => key.budget.max_proof_bytes = (1 << 20) + 1,
            23 => key.budget.max_trace_units = 0,
            24 => key.budget.max_output_tags = 0,
            25 => key.budget.max_proof_bytes = 0,
            26 => key.policy.max_queries = 65,
            27 => key.budget = chosen::Budget::default(),
            _ => {}
        }
        let gate = key.production_gate(&public, admission).unwrap();
        actual["mutated_view"] = json!(hex::encode(key.digest(&public).unwrap()));
        actual["safe"] = json!(u8::from(key.is_safe(&public).unwrap()));
        actual["profile"] = json!(hex::encode(admission.digest()));
        actual["gate"] = json!([
            gate.admitted,
            gate.key,
            gate.profile,
            gate.budget,
            gate.rejects_key,
            gate.rejects_profile,
            gate.rejects_budget,
            gate.rejects_sha_compat,
            gate.rejects_underbudget,
            gate.rejects_trace_wide,
            gate.rejects_output_wide,
            gate.rejects_proof_wide
        ]
        .map(u8::from));
        assert_eq!(actual, case["expected"], "reusable key case {index}");
    }
}
