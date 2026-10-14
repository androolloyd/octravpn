use super::*;
use crate::{
    encrypt,
    keys::{keygen_from_seed, Params},
    seeded_rng::CtrRng,
};
use r1cs::VarType;
use serde_json::Value;
use sha2::{Digest, Sha256};

// Compact deterministic public fixture stream, never production entropy.
struct Entropy {
    state: u64,
    word: u64,
    available: usize,
    consumed: usize,
    calls: usize,
}
impl Entropy {
    fn new(state: u64) -> Self {
        Self {
            state,
            word: 0,
            available: 0,
            consumed: 0,
            calls: 0,
        }
    }
}
impl RngCore for Entropy {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        self.try_fill_bytes(bytes).unwrap();
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), rand::Error> {
        self.calls += 1;
        self.consumed += bytes.len();
        for byte in bytes {
            if self.available == 0 {
                self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
                let mut z = self.state;
                z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
                self.word = z ^ (z >> 31);
                self.available = 8;
            }
            *byte = self.word as u8;
            self.word >>= 8;
            self.available -= 1;
        }
        Ok(())
    }
}
impl CryptoRng for Entropy {}
// Official write_r1cs_proof_raw order. This test-only encoder compares every byte
// without claiming the production wire decoder/encoder is already implemented.
fn encode(proof: &r1cs::Proof) -> Vec<u8> {
    let mut result = Vec::new();
    for point in [&proof.a_i, &proof.a_o, &proof.s]
        .into_iter()
        .chain(proof.t.iter())
    {
        result.extend_from_slice(point);
    }
    for value in [proof.t_x, proof.t_x_blinding, proof.e_blinding] {
        result.extend_from_slice(&value.to_bytes());
    }
    result.extend_from_slice(&(proof.ipp.l.len() as u64).to_le_bytes());
    for point in proof.ipp.l.iter().chain(&proof.ipp.r) {
        result.extend_from_slice(point);
    }
    for value in [proof.ipp.a, proof.ipp.b] {
        result.extend_from_slice(&value.to_bytes());
    }
    result.extend_from_slice(&(proof.commitments.len() as u64).to_le_bytes());
    for point in &proof.commitments {
        result.extend_from_slice(point);
    }
    result
}

fn system_hash(prover: &Prover) -> String {
    let mut hash = Sha256::new();
    for n in [
        prover.num_gates(),
        prover.num_committed(),
        prover.num_constraints(),
    ] {
        hash.update((n as u64).to_le_bytes());
    }
    for constraint in prover.constraints() {
        hash.update((constraint.terms.len() as u64).to_le_bytes());
        for (var, value) in &constraint.terms {
            let kind = match var.kind {
                VarType::One => 0,
                VarType::Committed => 1,
                VarType::MultLeft => 2,
                VarType::MultRight => 3,
                VarType::MultOut => 4,
                VarType::Invalid(n) => n,
            };
            hash.update([kind]);
            hash.update((var.index as u64).to_le_bytes());
            hash.update(value.to_bytes());
        }
    }
    hex::encode(hash.finalize())
}
fn setup(case: &Value) -> (PublicKey, SecretKey, Cipher) {
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
    let (mut public, secret) = keygen_from_seed(params, &std::array::from_fn(|i| i as u8)).unwrap();
    public.set_circuit_profile(
        &secret,
        if case["profile"] == 1 {
            CircuitProfile::MimcX3V6
        } else {
            CircuitProfile::MimcX5V7
        },
    );
    let seed = std::array::from_fn(|i| 31 - i as u8);
    let value = case["value"].as_u64().unwrap();
    let mut cipher = encrypt::synthesize(
        &public,
        &secret,
        &[Fp::from_u64(value)],
        0,
        &mut CtrRng::seeded(&seed),
    )
    .unwrap();
    match case["variant"].as_u64().unwrap() {
        1 => cipher = encrypt::value_seeded(&public, &secret, value, &seed).unwrap(),
        2 => cipher = cipher.square_seeded(&public, &seed, 4, true).unwrap(),
        3 => cipher = cipher.subtract(&public, &cipher).unwrap(),
        _ => {}
    }
    (public, secret, cipher)
}
#[test]
fn native_zero_constraint_proof_transcript_and_entropy_parity() {
    let fixture: Value =
        serde_json::from_str(include_str!("../../tests/fixtures/zero.json")).unwrap();
    let sources: Value =
        serde_json::from_str(include_str!("../../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], sources["upstream_commit"]);
    for (source, hash) in fixture["source_sha256"].as_object().unwrap() {
        assert_eq!(*hash, sources["files"][source]);
    }
    assert_eq!(
        hex::encode(Sha256::digest(include_bytes!(
            "../../../../scripts/node-port/hfhe-zero-oracle.cpp"
        ))),
        fixture["oracle_sha256"]
    );
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 46);
    for (index, case) in cases.iter().enumerate() {
        eprintln!("native zero case {index}");
        let (public, secret, cipher) = setup(case);
        let rule = if case["rule"] == 0 {
            ScalarRule::Prior
        } else {
            ScalarRule::Wide
        };
        let operation = case["operation"].as_str().unwrap();
        let legacy = operation == "legacy";
        let bound = operation != "zero" && !legacy;
        let profile = match operation {
            "range" => BoundProfile::Range,
            "key_switch" => BoundProfile::KeySwitchRefresh,
            "migration" => BoundProfile::HistoricalMigration,
            _ => BoundProfile::Standard,
        };
        let masks = masks(&public, &secret, &cipher).unwrap();
        let inverse = inverse_masks(&masks).unwrap();
        let coefficients = layer_coefficients(&public, &cipher).unwrap();
        let bases = base_layer_indices(&cipher).unwrap();
        let values = CircuitValues {
            secret: &secret,
            masks: &masks,
            inverse: &inverse,
        };
        let amount = case["amount"].as_u64().unwrap();
        let binding = AmountBinding {
            amount,
            blinding: Zeroizing::new(Scalar::from_u64(19)),
            range_bits: if operation == "range" { 64 } else { 0 },
        };
        let mut prover = Prover::new(rule);
        let expected = &case["expected"];
        let built = if legacy {
            build_legacy_circuit(
                &mut prover,
                &cipher,
                &coefficients,
                &bases,
                Some(&values),
                None,
                true,
            )
        } else {
            build_key_bound_circuit(
                &mut prover,
                &public,
                &cipher,
                &coefficients,
                &bases,
                Some(&values),
                if bound { Some(&binding) } else { None },
                operation == "migration",
                true,
            )
        };
        if let Some(error) = expected["error"].as_str() {
            assert_eq!(
                built.err().unwrap().to_string(),
                error,
                "construction {index}"
            );
            continue;
        }
        built.unwrap();
        assert_eq!(
            prover.num_gates(),
            expected["gates"].as_u64().unwrap() as usize,
            "gates {index}"
        );
        assert_eq!(
            prover.num_committed(),
            expected["committed"].as_u64().unwrap() as usize,
            "commitments {index}"
        );
        assert_eq!(
            prover.num_constraints(),
            expected["constraints"].as_u64().unwrap() as usize,
            "constraints {index}"
        );
        assert_eq!(
            system_hash(&prover),
            expected["system_sha256"],
            "constraint bytes {index}"
        );
        assert_eq!(
            amount_terms_present(&cipher, &coefficients).unwrap(),
            expected["amount_terms"].as_bool().unwrap()
        );
        let mut verifier = Prover::verification(rule);
        let dummy = AmountBinding {
            amount: 0,
            blinding: Zeroizing::new(Scalar::ZERO),
            range_bits: binding.range_bits,
        };
        if legacy {
            build_legacy_circuit(
                &mut verifier,
                &cipher,
                &coefficients,
                &bases,
                None,
                None,
                true,
            )
        } else {
            build_key_bound_circuit(
                &mut verifier,
                &public,
                &cipher,
                &coefficients,
                &bases,
                None,
                if bound { Some(&dummy) } else { None },
                operation == "migration",
                true,
            )
        }
        .unwrap();
        assert_eq!(
            system_hash(&verifier),
            expected["verification_sha256"],
            "verification constraints {index}"
        );
        let commitment = generators::pedersen_commit(&Scalar::from_u64(amount), &binding.blinding);
        let state = || {
            let domain = if operation == "zero" {
                b"pvac.verify_zero.key_bound".as_slice()
            } else {
                profile.domain()
            };
            if legacy {
                let mut t = Transcript::new(domain, rule);
                t.append_u64(b"nL", cipher.layers.len() as u64);
                t.append_u64(b"S", cipher.slots as u64);
                t.append_u64(b"nB", bases.len() as u64);
                t
            } else {
                transcript(
                    domain,
                    &public,
                    &cipher,
                    &bases,
                    rule,
                    if operation == "zero" {
                        b"zero"
                    } else {
                        profile.kind()
                    },
                    if bound { Some(&commitment) } else { None },
                )
                .unwrap()
            }
        };
        assert_eq!(
            hex::encode(state().challenge_scalar(b"after").to_bytes()),
            expected["initial"],
            "initial transcript {index}"
        );
        if case["prove"] == true {
            let mut entropy = Entropy::new(case["entropy_seed"].as_u64().unwrap());
            let mut t = state();
            let proof = prover
                .prove(&mut t, &mut entropy, profile.limit_profile())
                .unwrap();
            assert_eq!(
                hex::encode(encode(&proof)),
                expected["proof"],
                "full proof bytes {index}"
            );
            assert_eq!(
                hex::encode(t.challenge_scalar(b"after").to_bytes()),
                expected["after"],
                "prover transcript {index}"
            );
            assert_eq!(
                entropy.consumed,
                expected["consumed"].as_u64().unwrap() as usize,
                "entropy bytes {index}"
            );
            assert_eq!(
                entropy.calls,
                expected["calls"].as_u64().unwrap() as usize,
                "entropy calls {index}"
            );
            let mut t = state();
            assert_eq!(
                r1cs::verify(
                    &mut t,
                    &verifier.into_system(),
                    &proof,
                    profile.limit_profile()
                )
                .unwrap(),
                expected["accepted"].as_bool().unwrap(),
                "verify {index}"
            );
            assert_eq!(
                hex::encode(t.challenge_scalar(b"after").to_bytes()),
                expected["verify_after"],
                "verify transcript {index}"
            );
            if !legacy {
                let zero = ZeroProof {
                    proof,
                    is_bound: bound,
                };
                let wrapped = if operation == "zero" {
                    verify_zero(&public, &cipher, &zero, rule)
                } else {
                    verify_bound(&public, &cipher, &zero, &commitment, profile, true, rule)
                }
                .unwrap();
                assert_eq!(
                    wrapped,
                    expected["wrapped_accepted"].as_bool().unwrap(),
                    "wrapped verify {index}"
                );
            }
        }
    }
}
