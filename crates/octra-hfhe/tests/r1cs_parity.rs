mod common;

use octra_hfhe::{
    proof::{
        generators,
        r1cs::{
            self, ConstraintSystem, LimitProfile, LinearCombination, Proof, Prover, VarType,
            Variable,
        },
        transcript::Transcript,
    },
    scalar::{Scalar, ScalarRule},
};
use rand::{CryptoRng, RngCore};
use serde_json::Value;
use sha2::{Digest, Sha256};

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

fn fixtures() -> Value {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/r1cs.json")).unwrap();
    let sources: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    common::assert_source_pin(&fixture, &sources);
    for (source, hash) in fixture["source_sha256"].as_object().unwrap() {
        assert_eq!(*hash, sources["files"][source], "native source {source}");
    }
    assert_eq!(
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/hfhe-r1cs-oracle.cpp"
        ))),
        fixture["oracle_sha256"]
    );
    fixture
}
fn scalar(value: &Value) -> Scalar {
    Scalar::from_bytes_raw(
        &hex::decode(value.as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    )
}
fn pairs(value: &Value) -> Vec<[Scalar; 2]> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|pair| [scalar(&pair[0]), scalar(&pair[1])])
        .collect()
}
fn transcript(rule: ScalarRule, variant: u64, different: bool) -> Transcript {
    let mut result = Transcript::new(
        if different {
            b"pvac.bp.r1cs.wrong"
        } else {
            b"pvac.bp.r1cs.fixture"
        },
        rule,
    );
    result.append_u64(b"variant", variant);
    result
}
fn build(case: &Value, rule: ScalarRule) -> Prover {
    let variant = case["variant"].as_u64().unwrap();
    let commits = pairs(&case["committed"]);
    let gates = pairs(&case["gates"]);
    let mut result = if case["error_case"] == 1 {
        Prover::verification(rule)
    } else {
        Prover::new(rule)
    };
    for &[value, blind] in &commits {
        let variable = result.commit(value, blind).unwrap();
        if variant != 3 {
            result
                .constrain(LinearCombination::new(variable).plus_constant(-value))
                .unwrap();
        }
    }
    for (index, &[mut left, right]) in gates.iter().enumerate() {
        let variables = if variant == 1 {
            let mut combination = LinearCombination::with_coefficient(Variable::one(), left);
            if !commits.is_empty() {
                combination += &LinearCombination::new(Variable::committed(index % commits.len()));
                left = left + commits[index % commits.len()][0];
            }
            result
                .multiply(
                    &combination,
                    &LinearCombination::with_coefficient(Variable::one(), right),
                )
                .unwrap()
        } else {
            result.allocate(left, right).unwrap()
        };
        if variant <= 2 {
            result
                .constrain(LinearCombination::new(variables.0).plus_constant(-left))
                .unwrap();
            result
                .constrain(LinearCombination::new(variables.1).plus_constant(-right))
                .unwrap();
            let expected = rule.mul(left, right)
                + if variant == 2 {
                    Scalar::ONE
                } else {
                    Scalar::ZERO
                };
            result
                .constrain(LinearCombination::new(variables.2).plus_constant(-expected))
                .unwrap();
        }
        if variant == 5 {
            result.constrain(LinearCombination::default()).unwrap();
            let mut duplicate = LinearCombination::new(variables.0);
            duplicate -= &LinearCombination::new(variables.0);
            result
                .constrain(duplicate.plus_constant(Scalar::ZERO))
                .unwrap();
        }
    }
    if variant == 4 {
        result
            .constrain(LinearCombination::new(Variable::mult_out(gates.len())))
            .unwrap();
        result
            .constrain(LinearCombination::new(Variable {
                kind: VarType::One,
                index: 1,
            }))
            .unwrap();
        result
            .constrain(LinearCombination::new(Variable {
                kind: VarType::Invalid(5),
                index: 0,
            }))
            .unwrap();
        result
            .constrain(LinearCombination::new(Variable::committed(commits.len())))
            .unwrap();
    }
    if case["error_case"] == 3 {
        for _ in 0..=r1cs::MAX_COMMITTED {
            result.commit(Scalar::ZERO, Scalar::ZERO).unwrap();
        }
    }
    result
}
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
fn mutate(system: &mut ConstraintSystem, proof: &mut Proof, mutation: usize) {
    let maximum = Scalar::from_words([u64::MAX; 4]);
    match mutation {
        1 => system.num_gates = r1cs::MAX_GATES + 1,
        2 => system.num_committed = r1cs::MAX_COMMITTED + 1,
        3 => proof.commitments.push(generators::identity()),
        4 => proof.a_i = [255; 32],
        5 => proof.t[4] = [255; 32],
        6 => {
            proof.ipp.l.push([255; 32]);
            proof.ipp.r.push([0; 32]);
        }
        7 => proof.t_x = proof.t_x + Scalar::ONE,
        8 => proof.t_x_blinding = maximum,
        9 => proof.e_blinding = proof.e_blinding + Scalar::ONE,
        10 => proof.ipp.a = proof.ipp.a + Scalar::ONE,
        11 => proof.ipp.r.push(generators::identity()),
        12 => system.constraints.clear(),
        13 => system
            .constraints
            .push(LinearCombination::new(Variable::one())),
        14 => system
            .constraints
            .push(LinearCombination::new(Variable::mult_left(
                system.num_gates,
            ))),
        15 => {
            if proof.commitments.is_empty() {
                proof.commitments.push(generators::pedersen_b());
            } else {
                proof.commitments[0] = generators::pedersen_b();
            }
        }
        18 => system.constraints.push(LinearCombination::with_coefficient(
            Variable::one(),
            maximum,
        )),
        19 => {
            proof.ipp.l.push(generators::identity());
            proof.ipp.r.push(generators::identity());
        }
        20 => system.num_gates += 1,
        21 => proof.ipp.b = maximum,
        _ => {}
    }
}
#[test]
fn native_r1cs_proof_bytes_entropy_and_verifier_transcripts() {
    let fixture = fixtures();
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 96);
    let mut proved = 0;
    let mut refused = 0;
    let mut prior_rejected = 0;
    let mut wide_accepted = 0;
    for (index, case) in cases.iter().enumerate() {
        let rule = if case["rule"] == 0 {
            ScalarRule::Prior
        } else {
            ScalarRule::Wide
        };
        let variant = case["variant"].as_u64().unwrap();
        let expected = &case["expected"];
        let prover = build(case, rule);
        let transcript_rule = if case["error_case"] == 2 {
            if rule == ScalarRule::Prior {
                ScalarRule::Wide
            } else {
                ScalarRule::Prior
            }
        } else {
            rule
        };
        let mut state = transcript(transcript_rule, variant, false);
        let mut tape = EntropyTape {
            bytes: hex::decode(case["tape"].as_str().unwrap()).unwrap(),
            consumed: 0,
            calls: 0,
        };
        let result = prover.prove(&mut state, &mut tape, LimitProfile::Default);
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
        assert_eq!(
            hex::encode(state.challenge_scalar(b"after").to_bytes()),
            expected["after"],
            "prover transcript {index}"
        );
        if let Some(error) = expected["error"].as_str() {
            let expected_error = if error == "fixture entropy exhausted" {
                "HFHE entropy unavailable"
            } else {
                error
            };
            assert_eq!(
                result.err().unwrap().0,
                expected_error,
                "proving refusal {index}"
            );
            refused += 1;
            continue;
        }
        let proof = result.unwrap();
        proved += 1;
        assert_eq!(
            hex::encode(encode(&proof)),
            expected["proof"],
            "proof bytes {index}"
        );
        for (mutation, expected) in expected["verify"].as_array().unwrap().iter().enumerate() {
            let mut system = prover.system();
            let mut changed = proof.clone();
            mutate(&mut system, &mut changed, mutation);
            let mut state = transcript(rule, variant, mutation == 16);
            let profile = if mutation == 17 {
                LimitProfile::KeySwitchRefresh
            } else {
                LimitProfile::Default
            };
            let accepted = r1cs::verify(&mut state, &system, &changed, profile).unwrap();
            assert_eq!(
                accepted,
                expected["accepted"].as_bool().unwrap(),
                "verify {index}/{mutation}"
            );
            assert_eq!(
                hex::encode(state.challenge_scalar(b"after").to_bytes()),
                expected["after"],
                "verifier transcript {index}/{mutation}"
            );
            if mutation == 0 {
                prior_rejected += usize::from(rule == ScalarRule::Prior && !accepted);
                wide_accepted += usize::from(rule == ScalarRule::Wide && accepted);
            }
        }
    }
    assert_eq!((proved, refused), (88, 8));
    assert!(prior_rejected > 0);
    assert!(wide_accepted > 0);
}

#[test]
fn verifier_prechecks_resource_and_variable_boundaries() {
    let rule = ScalarRule::Wide;
    let mut prover = Prover::new(rule);
    let (left, _, _) = prover.allocate(Scalar::ONE, Scalar::ONE).unwrap();
    let invalid = LinearCombination::new(Variable::committed(0));
    assert_eq!(
        prover
            .multiply(&invalid, &LinearCombination::new(left))
            .err()
            .unwrap()
            .0,
        "HFHE proof variable index rejected"
    );
    assert_eq!(prover.num_gates(), 1);
    let mut system = prover.system();
    assert!(system.valid(1, LimitProfile::Default));
    system.constraints.push(LinearCombination::new(Variable {
        kind: VarType::One,
        index: 1,
    }));
    assert!(!system.valid(1, LimitProfile::Default));
    system.constraints.clear();
    system.num_gates = usize::MAX;
    assert!(system.padded_gates().is_err());
    assert!(!system.valid(1, LimitProfile::Default));
    assert_eq!(LimitProfile::Default.constraint_limit(), 1_500_000);
    assert_eq!(LimitProfile::KeySwitchRefresh.constraint_limit(), 1_550_000);
}
