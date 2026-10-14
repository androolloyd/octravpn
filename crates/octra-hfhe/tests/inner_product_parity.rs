#![allow(clippy::many_single_char_names)] // Match the native proof equations.
mod common;
use octra_hfhe::{
    proof::{
        generators::Point,
        inner_product::{self, InnerProductProof},
        transcript::Transcript,
    },
    scalar::{Scalar, ScalarRule},
};
use serde_json::{json, Value};
use zeroize::Zeroizing;

fn bytes(value: &Value) -> [u8; 32] {
    hex::decode(value.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}
fn scalars(value: &Value) -> Vec<Scalar> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|value| Scalar::from_bytes_raw(&bytes(value)))
        .collect()
}
fn points(value: &Value) -> Vec<Point> {
    value.as_array().unwrap().iter().map(bytes).collect()
}
fn scalar_hex(values: &[Scalar]) -> Vec<String> {
    values
        .iter()
        .map(|value| hex::encode(value.to_bytes()))
        .collect()
}
fn transcript(rule: ScalarRule, n: usize) -> Transcript {
    let mut transcript = Transcript::new(b"pvac.bp.ipp.fixture", rule);
    transcript.append_u64(b"n", n as u64);
    transcript
}

fn check_verification(
    rule: ScalarRule,
    original_n: usize,
    n: usize,
    p: &Point,
    q: &Point,
    proof: &InnerProductProof,
    y: &[Scalar],
    weighted: bool,
) -> Value {
    let mut transcript = transcript(rule, original_n);
    let result = if weighted {
        inner_product::verify_with_y(&mut transcript, p, q, proof, n, y)
    } else {
        inner_product::verify(&mut transcript, p, q, proof, n)
    };
    let after = hex::encode(transcript.challenge_scalar(b"after").to_bytes());
    match result {
        Ok(accepted) => json!({"accepted": accepted, "after": after}),
        Err(error) => json!({"error": error.to_string(), "after": after}),
    }
}

#[test]
fn proof_bytes_scalar_helpers_and_verifier_transcripts_match_native() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/inner-product.json")).unwrap();
    assert_eq!(fixture["cases"].as_array().unwrap().len(), 192);
    let sources: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    common::assert_source_pin(&fixture, &sources);
    for (source, hash) in fixture["source_sha256"].as_object().unwrap() {
        assert_eq!(*hash, sources["files"][source], "native source {source}");
    }
    for (index, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let rule = if case["rule"] == 0 {
            ScalarRule::Prior
        } else {
            ScalarRule::Wide
        };
        let a = scalars(&case["a"]);
        let b = scalars(&case["b"]);
        let expected = &case["expected"];
        let actual = match case["mode"].as_str().unwrap() {
            "inner" => {
                json!({"scalar": hex::encode(inner_product::inner_product(&a, &b, rule).unwrap().to_bytes())})
            }
            "batch" => {
                json!({"scalars": scalar_hex(&inner_product::batch_inverse(&a, rule).unwrap())})
            }
            "verification_scalars" => {
                json!({"scalars": scalar_hex(&inner_product::verification_scalars(&a, rule).unwrap())})
            }
            "prove" => {
                let n = a.len();
                let g = points(&expected["g"]);
                let h = points(&expected["h"]);
                let q = bytes(&expected["q"]);
                let p = bytes(&expected["p"]);
                let y = scalars(&expected["y"]);
                let mut transcript = transcript(rule, n);
                let proof = inner_product::prove(
                    &mut transcript,
                    &q,
                    Zeroizing::new(a),
                    Zeroizing::new(b),
                    g,
                    h,
                )
                .unwrap();
                assert_eq!(
                    hex::encode(proof.a.to_bytes()),
                    expected["a"],
                    "a: case {index}"
                );
                assert_eq!(
                    hex::encode(proof.b.to_bytes()),
                    expected["b"],
                    "b: case {index}"
                );
                assert_eq!(
                    json!(proof.l.iter().map(hex::encode).collect::<Vec<_>>()),
                    expected["l"],
                    "L: case {index}"
                );
                assert_eq!(
                    json!(proof.r.iter().map(hex::encode).collect::<Vec<_>>()),
                    expected["r"],
                    "R: case {index}"
                );
                assert_eq!(
                    hex::encode(transcript.challenge_scalar(b"after").to_bytes()),
                    expected["after"],
                    "prover transcript: case {index}"
                );
                for check in expected["verify"].as_array().unwrap() {
                    let mutation = check["mutation"].as_u64().unwrap();
                    let mut changed = proof.clone();
                    let mut changed_p = p;
                    let mut changed_q = q;
                    let mut changed_y = y.clone();
                    let mut changed_n = n;
                    match mutation {
                        0 => {}
                        1 => changed_n = 0,
                        2 => changed_n = n + 1,
                        3 => changed.r.push([0; 32]),
                        4 => changed_p.fill(255),
                        5 => changed_q.fill(255),
                        6 => {
                            if changed.l.is_empty() {
                                changed.l.push([0; 32]);
                            }
                            changed.l[0].fill(255);
                        }
                        7 => {
                            if changed.r.is_empty() {
                                changed.r.push([0; 32]);
                            }
                            changed.r[0].fill(255);
                        }
                        8 => changed.a = changed.a + Scalar::ONE,
                        9 => changed.b = Scalar::from_bytes_raw(&[255; 32]),
                        10 => {
                            changed_y.pop();
                        }
                        11 => changed_y.fill(Scalar::ZERO),
                        _ => panic!("unknown mutation"),
                    }
                    for (name, weighted) in [("raw", false), ("weighted", true)] {
                        assert_eq!(
                            check_verification(
                                rule, n, changed_n, &changed_p, &changed_q, &changed, &changed_y,
                                weighted
                            ),
                            check[name],
                            "case {index}, mutation {mutation}, {name}"
                        );
                    }
                }
                continue;
            }
            _ => panic!("unknown operation"),
        };
        assert_eq!(actual, *expected, "case {index}");
    }
}

#[test]
fn malformed_dimensions_and_impossible_allocations_do_not_panic() {
    for rule in [ScalarRule::Prior, ScalarRule::Wide] {
        let mut transcript = transcript(rule, 0);
        assert!(inner_product::prove(
            &mut transcript,
            &[0; 32],
            Zeroizing::new(vec![]),
            Zeroizing::new(vec![]),
            vec![],
            vec![]
        )
        .is_err());
        assert!(inner_product::inner_product(&[Scalar::ONE], &[], rule).is_err());
        let proof = InnerProductProof {
            l: vec![[0; 32]; 64],
            r: vec![[0; 32]; 64],
            a: Scalar::ZERO,
            b: Scalar::ZERO,
        };
        assert!(!inner_product::verify(&mut transcript, &[0; 32], &[0; 32], &proof, 0).unwrap());
        assert!(
            !inner_product::verify_with_y(&mut transcript, &[0; 32], &[0; 32], &proof, 0, &[])
                .unwrap()
        );
        assert!(inner_product::verification_scalars(
            &vec![Scalar::ONE; usize::BITS as usize],
            rule
        )
        .is_err());
        let allocation =
            inner_product::verification_scalars(&vec![Scalar::ONE; usize::BITS as usize - 1], rule);
        assert!(
            matches!(allocation, Err(error) if error.to_string() == "HFHE allocation unavailable")
        );
    }
}
