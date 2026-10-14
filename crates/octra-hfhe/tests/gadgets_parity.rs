use octra_hfhe::{
    field::Fp,
    proof::{
        gadgets,
        r1cs::{self, Proof, Prover, VarType, Variable},
        transcript::Transcript,
    },
    scalar::{Scalar, ScalarRule},
};
use rand::{CryptoRng, RngCore};
use serde_json::Value;
use sha2::{Digest, Sha256};
mod common;
// Deterministic public test material only; never used by the production prover.
struct EntropyTape {
    bytes: Vec<u8>,
    consumed: usize,
    calls: usize,
}
impl RngCore for EntropyTape {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }
    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }
    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        self.try_fill_bytes(bytes).unwrap();
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), rand::Error> {
        self.calls += 1;
        let end = self.consumed + bytes.len();
        let Some(source) = self.bytes.get(self.consumed..end) else {
            return Err(rand::Error::new("fixture entropy exhausted"));
        };
        bytes.copy_from_slice(source);
        self.consumed = end;
        Ok(())
    }
}
impl CryptoRng for EntropyTape {}

// Official write_r1cs_proof_raw order. This test-only encoder compares every byte
// without claiming the production wire decoder/encoder is already implemented.
fn encode(proof: &Proof) -> Vec<u8> {
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
fn scalar(value: &Value) -> Scalar {
    Scalar::from_bytes_raw(
        &hex::decode(value.as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    )
}
fn variable(bytes: &mut Vec<u8>, value: Variable) {
    bytes.push(match value.kind {
        VarType::One => 0,
        VarType::Committed => 1,
        VarType::MultLeft => 2,
        VarType::MultRight => 3,
        VarType::MultOut => 4,
        VarType::Invalid(value) => value,
    });
    bytes.extend_from_slice(&(value.index as u64).to_le_bytes());
}
fn system_bytes(prover: &Prover, outputs: &[(Variable, Scalar)]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for count in [
        prover.num_gates(),
        prover.num_committed(),
        prover.num_constraints(),
    ] {
        bytes.extend_from_slice(&(count as u64).to_le_bytes());
    }
    for constraint in prover.constraints() {
        bytes.extend_from_slice(&(constraint.terms.len() as u64).to_le_bytes());
        for &(var, value) in &constraint.terms {
            variable(&mut bytes, var);
            bytes.extend_from_slice(&value.to_bytes());
        }
    }
    bytes.extend_from_slice(&(outputs.len() as u64).to_le_bytes());
    for &(var, value) in outputs {
        variable(&mut bytes, var);
        bytes.extend_from_slice(&value.to_bytes());
    }
    bytes
}
fn state(rule: ScalarRule, kind: &str) -> Transcript {
    let mut state = Transcript::new(b"pvac.bp.gadgets.fixture", rule);
    state.append_message(b"kind", kind.as_bytes());
    state
}
#[test]
fn native_gadget_constraints_full_proofs_and_acceptance() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/gadgets.json")).unwrap();
    let sources: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    common::assert_source_pin(&fixture, &sources);
    for (source, hash) in fixture["source_sha256"].as_object().unwrap() {
        assert_eq!(*hash, sources["files"][source]);
    }
    assert_eq!(
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/hfhe-gadgets-oracle.cpp"
        ))),
        fixture["oracle_sha256"]
    );
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 168);
    let mut proved = 0;
    for (index, case) in cases.iter().enumerate() {
        let rule = if case["rule"] == 0 {
            ScalarRule::Prior
        } else {
            ScalarRule::Wide
        };
        let canonical = case["canonical"].as_bool().unwrap();
        let kind = case["kind"].as_str().unwrap();
        let left = scalar(&case["left"]);
        let right = scalar(&case["right"]);
        let mut prover = Prover::new(rule);
        let left_var = prover.commit(left, Scalar::from_u64(11)).unwrap();
        let right_var = prover.commit(right, Scalar::from_u64(13)).unwrap();
        let words = right.to_words();
        let field = Fp::from_words(words[0], words[1]);
        let mut outputs = Vec::new();
        match kind {
            "range" => gadgets::range_check(
                &mut prover,
                left_var,
                left,
                case["bits"].as_u64().unwrap() as usize,
            )
            .unwrap(),
            "alias" => gadgets::reject_modulus_alias(&mut prover, left_var, left).unwrap(),
            "decompose" => {
                let result = gadgets::decompose(&mut prover, left_var, left, canonical).unwrap();
                outputs.extend(
                    result
                        .variables
                        .into_iter()
                        .zip(result.values.iter().copied()),
                );
            }
            "mul" | "cube" | "fifth" => {
                let result = match kind {
                    "mul" => gadgets::multiply(
                        &mut prover,
                        (left_var, left),
                        (right_var, right),
                        canonical,
                    ),
                    "cube" => gadgets::cube(&mut prover, (left_var, left), canonical),
                    _ => gadgets::fifth(&mut prover, (left_var, left), canonical),
                }
                .unwrap();
                outputs.push(result.pair());
            }
            "bind" => {
                let result =
                    gadgets::bind_commitment_value(&mut prover, left_var, field, canonical)
                        .unwrap();
                outputs.push(result.value.pair());
                outputs.extend(
                    result
                        .limbs
                        .variables
                        .into_iter()
                        .zip(result.limbs.values.iter().copied()),
                );
            }
            "fold" => {
                let limbs = gadgets::decompose(&mut prover, left_var, left, canonical).unwrap();
                let result = gadgets::multiply_constant_folded(field, &limbs, rule);
                prover.constrain(result.combination).unwrap();
                outputs.push((left_var, *result.value));
            }
            _ => panic!("unknown native gadget"),
        }
        let expected = &case["expected"];
        assert_eq!(
            prover.num_gates(),
            expected["gates"].as_u64().unwrap() as usize,
            "gates {index}"
        );
        assert_eq!(
            prover.num_constraints(),
            expected["constraints"].as_u64().unwrap() as usize,
            "constraints {index}"
        );
        assert_eq!(
            hex::encode(Sha256::digest(system_bytes(&prover, &outputs))),
            expected["system_sha256"],
            "constraint/output bytes {index}: {kind}"
        );
        if case["prove"] == true {
            proved += 1;
            let mut transcript = state(rule, kind);
            let mut tape = EntropyTape {
                bytes: hex::decode(case["tape"].as_str().unwrap()).unwrap(),
                consumed: 0,
                calls: 0,
            };
            let proof = prover
                .prove(&mut transcript, &mut tape, r1cs::LimitProfile::Default)
                .unwrap();
            assert_eq!(
                hex::encode(encode(&proof)),
                expected["proof"],
                "proof bytes {index}"
            );
            assert_eq!(
                hex::encode(transcript.challenge_scalar(b"after").to_bytes()),
                expected["after"],
                "prover transcript {index}"
            );
            assert_eq!(
                tape.consumed,
                expected["consumed"].as_u64().unwrap() as usize,
                "entropy bytes {index}"
            );
            assert_eq!(
                tape.calls,
                expected["calls"].as_u64().unwrap() as usize,
                "entropy calls {index}"
            );
            let mut checked = state(rule, kind);
            assert_eq!(
                r1cs::verify(
                    &mut checked,
                    &prover.system(),
                    &proof,
                    r1cs::LimitProfile::Default
                )
                .unwrap(),
                expected["accepted"].as_bool().unwrap(),
                "verifier {index}"
            );
            assert_eq!(
                hex::encode(checked.challenge_scalar(b"after").to_bytes()),
                expected["verify_after"],
                "verifier transcript {index}"
            );
        }
    }
    assert_eq!(proved, 40);
}
#[test]
fn range_gadget_rejects_native_assertion_inputs_before_mutation() {
    let mut prover = Prover::new(ScalarRule::Wide);
    let variable = prover.commit(Scalar::ZERO, Scalar::ZERO).unwrap();
    for bits in [0, 253, usize::MAX] {
        assert_eq!(
            gadgets::range_check(&mut prover, variable, Scalar::ZERO, bits)
                .err()
                .unwrap()
                .0,
            "HFHE range gadget bits rejected"
        );
        assert_eq!(prover.num_gates(), 0);
        assert_eq!(prover.num_constraints(), 0);
    }
}
