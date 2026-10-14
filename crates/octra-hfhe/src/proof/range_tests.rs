use super::*;
use crate::{
    keys::{keygen_from_seed, CircuitProfile, Params},
    scalar::Scalar,
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

#[test]
fn native_legacy_range_construction_and_disabled_verification() {
    let fixture: Value =
        serde_json::from_str(include_str!("../../tests/fixtures/range.json")).unwrap();
    let sources: Value =
        serde_json::from_str(include_str!("../../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], sources["upstream_commit"]);
    for (source, hash) in fixture["source_sha256"].as_object().unwrap() {
        assert_eq!(*hash, sources["files"][source]);
    }
    assert_eq!(
        hex::encode(Sha256::digest(include_bytes!(
            "../../../../scripts/node-port/hfhe-range-oracle.cpp"
        ))),
        fixture["oracle_sha256"]
    );
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 8);
    for (index, case) in cases.iter().enumerate() {
        eprintln!("native range case {index}");
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
        let (mut public, secret) =
            keygen_from_seed(params, &std::array::from_fn(|i| i as u8)).unwrap();
        public.set_circuit_profile(
            &secret,
            if case["profile"] == 1 {
                CircuitProfile::MimcX3V6
            } else {
                CircuitProfile::MimcX5V7
            },
        );
        let rule = if case["rule"] == 0 {
            ScalarRule::Prior
        } else {
            ScalarRule::Wide
        };
        let value = case["value"].as_u64().unwrap();
        let mut bits = Vec::new();
        for bit in 0..RANGE_BITS {
            let seed = std::array::from_fn(|k| ((bit * 17 + k * 11 + 7) & 255) as u8);
            bits.push(
                if case["variant"] == 0 {
                    encrypt::synthesize(
                        &public,
                        &secret,
                        &[Fp::from_u64((value >> bit) & 1)],
                        0,
                        &mut CtrRng::seeded(&seed),
                    )
                } else {
                    encrypt::value_seeded(&public, &secret, (value >> bit) & 1, &seed)
                }
                .unwrap(),
            );
        }
        let cipher = encrypt::synthesize(
            &public,
            &secret,
            &[Fp::from_u64(value)],
            0,
            &mut CtrRng::seeded(&std::array::from_fn(|i| 31 - i as u8)),
        )
        .unwrap();
        let expected = &case["expected"];
        for (bit, cipher) in bits.iter().enumerate() {
            let check = bit_check(&public, cipher, bit, false).unwrap();
            assert_eq!(
                hex::encode(Sha256::digest(check.to_bytes().unwrap())),
                expected["checks"][bit],
                "bit product {index}/{bit}"
            );
        }
        let diff = difference(&public, &bits, &cipher).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(diff.to_bytes().unwrap())),
            expected["difference"],
            "LC bytes {index}"
        );
        assert_eq!(
            diff.layers.len(),
            expected["lc_layers"].as_u64().unwrap() as usize
        );
        assert_eq!(
            zero::base_layer_indices(&diff).unwrap().len(),
            expected["lc_bases"].as_u64().unwrap() as usize
        );
        let mut rng = Entropy::new(0);
        assert_eq!(
            zero::make_zero(&public, &secret, &diff, rule, &mut rng)
                .err()
                .unwrap()
                .to_string(),
            expected["lc_error"]
        );
        assert_eq!(rng.consumed, 0);
        let (prover, mut state) = build_aggregated(&public, &secret, &cipher, &bits, rule).unwrap();
        assert_eq!(
            prover.num_gates(),
            expected["gates"].as_u64().unwrap() as usize
        );
        assert_eq!(
            prover.num_constraints(),
            expected["constraints"].as_u64().unwrap() as usize
        );
        assert_eq!(
            prover.num_committed(),
            expected["committed"].as_u64().unwrap() as usize
        );
        assert_eq!(
            system_hash(&prover),
            expected["system_sha256"],
            "constraints {index}"
        );
        assert_eq!(
            hex::encode(state.clone().challenge_scalar(b"after").to_bytes()),
            expected["initial"],
            "transcript {index}"
        );
        let empty = r1cs::Proof {
            a_i: [0; 32],
            a_o: [0; 32],
            s: [0; 32],
            t: [[0; 32]; 5],
            t_x: Scalar::ZERO,
            t_x_blinding: Scalar::ZERO,
            e_blinding: Scalar::ZERO,
            ipp: super::super::inner_product::InnerProductProof {
                l: vec![],
                r: vec![],
                a: Scalar::ZERO,
                b: Scalar::ZERO,
            },
            commitments: vec![],
        };
        let aggregate = AggregatedRangeProof {
            ct_bit: bits.clone(),
            proof: empty.clone(),
        };
        assert!(!verify_aggregated_range(&public, &cipher, &aggregate));
        assert_eq!(expected["aggregated_accepted"], false);
        let zero = ZeroProof {
            proof: empty,
            is_bound: false,
        };
        let ordinary = RangeProof {
            ct_bit: bits,
            bit_proofs: vec![zero.clone(); RANGE_BITS],
            lc_proof: zero,
        };
        assert_eq!(
            verify_range(&public, &cipher, &ordinary, rule).unwrap(),
            expected["empty_proofs_accepted"].as_bool().unwrap()
        );
        if case["prove"] == true {
            let mut rng = Entropy::new(case["entropy_seed"].as_u64().unwrap());
            let proof = prover
                .prove(&mut state, &mut rng, LimitProfile::Default)
                .unwrap();
            assert_eq!(
                hex::encode(encode(&proof)),
                expected["proof"],
                "full aggregate bytes {index}"
            );
            assert_eq!(
                hex::encode(state.challenge_scalar(b"after").to_bytes()),
                expected["after"]
            );
            assert_eq!(
                rng.consumed,
                expected["consumed"].as_u64().unwrap() as usize
            );
            assert_eq!(rng.calls, expected["calls"].as_u64().unwrap() as usize);
        }
    }
}
