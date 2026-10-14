mod common;

use octra_hfhe::{
    proof::{
        generators::{self, Point},
        transcript::Transcript,
    },
    scalar::{Scalar, ScalarRule},
};
use serde_json::{json, Value};

fn fixture() -> Value {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/proof-foundation.json")).unwrap();
    let sources: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    common::assert_source_pin(&fixture, &sources);
    for (path, hash) in fixture["source_sha256"].as_object().unwrap() {
        assert_eq!(*hash, sources["files"][path]);
    }
    fixture
}

fn bytes(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().unwrap()).unwrap()
}
fn point(value: &Value) -> Point {
    bytes(value).try_into().unwrap()
}
fn scalar(value: &Value) -> Scalar {
    Scalar::from_bytes_raw(&point(value))
}
fn number(value: &Value) -> u64 {
    value.as_str().unwrap().parse().unwrap()
}

#[test]
fn transcript_framing_and_both_reduction_profiles_match_native() {
    for (index, case) in fixture()["transcripts"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        let rule = if case["rule"] == 0 {
            ScalarRule::Prior
        } else {
            ScalarRule::Wide
        };
        let mut transcript = Transcript::new(&bytes(&case["domain"]), rule);
        let mut challenges = Vec::new();
        for step in case["ops"].as_array().unwrap() {
            let label = bytes(&step["label"]);
            match step["op"].as_str().unwrap() {
                "m" => transcript.append_message(&label, &bytes(&step["data"])),
                "p" => transcript.append_point(&label, &point(&step["data"])),
                "u" => transcript.append_u64(&label, number(&step["data"])),
                "s" => transcript.append_scalar(&label, &scalar(&step["data"])),
                "c" => challenges.push(hex::encode(transcript.challenge_scalar(&label).to_bytes())),
                _ => panic!("unknown transcript fixture operation"),
            }
        }
        assert_eq!(
            json!({"challenges":challenges}),
            case["expected"],
            "transcript {index}"
        );
        let mut fork = transcript.clone();
        assert_eq!(
            transcript.challenge_scalar(b"fork").to_bytes(),
            fork.challenge_scalar(b"fork").to_bytes()
        );
    }
}

#[test]
fn generator_domains_cache_growth_and_size_rejections_match_native() {
    let fixture = fixture();
    for case in fixture["hashes"].as_array().unwrap() {
        assert_eq!(
            hex::encode(generators::hash_to_point(
                &bytes(&case["domain"]),
                number(&case["index"])
            )),
            case["expected"]["point"]
        );
    }
    let table = generators::GeneratorTable::new();
    for case in fixture["tables"].as_array().unwrap() {
        let n = number(&case["n"]) as usize;
        let result = match case["op"].as_str().unwrap() {
            "g" => table.g(n).map(|point| json!({"point":hex::encode(point)})),
            "h" => table.h(n).map(|point| json!({"point":hex::encode(point)})),
            "g_vec" => table
                .g_vec(n)
                .map(|points| json!({"points":points.iter().map(hex::encode).collect::<Vec<_>>()})),
            "h_vec" => table
                .h_vec(n)
                .map(|points| json!({"points":points.iter().map(hex::encode).collect::<Vec<_>>()})),
            "precompute" => table.precompute(n).map(|()| json!({"ok":true})),
            _ => panic!("unknown generator fixture operation"),
        };
        let actual = result.unwrap_or_else(|error| json!({"error":error.to_string()}));
        assert_eq!(actual, case["expected"], "{}({n})", case["op"]);
    }
    for case in fixture["sizes"].as_array().unwrap() {
        let n = number(&case["n"]) as usize;
        let result = if case["op"] == "next" {
            generators::next_power_of_2(n)
        } else {
            generators::log2_size(n)
        };
        let actual = result.map_or_else(
            |error| json!({"error":error.to_string()}),
            |value| json!({"value":value}),
        );
        assert_eq!(actual, case["expected"]);
    }
}

#[test]
fn group_operations_raw_scalars_and_invalid_encodings_match_native() {
    let fixture = fixture();
    for (index, case) in fixture["groups"].as_array().unwrap().iter().enumerate() {
        let a = point(&case["a"]);
        let b = point(&case["b"]);
        let scalar = scalar(&case["scalar"]);
        let blind = Scalar::from_bytes_raw(&point(&case["blind"]));
        let mut actual = json!({"valid":generators::point_valid(&a),
            "base":hex::encode(generators::base_mul(&scalar)),
            "pedersen":hex::encode(generators::pedersen_commit(&scalar,&blind))});
        for (name, result) in [
            ("add", generators::point_add(&a, &b)),
            ("sub", generators::point_sub(&a, &b)),
            ("mul", generators::point_mul(&a, &scalar)),
        ] {
            match result {
                Ok(point) => actual[name] = json!(hex::encode(point)),
                Err(error) => actual[format!("{name}_error")] = json!(error.to_string()),
            }
        }
        assert_eq!(actual, case["expected"], "group case {index}");
    }
    for case in fixture["msms"].as_array().unwrap() {
        let entries = case["entries"].as_array().unwrap();
        let scalars = entries
            .iter()
            .map(|entry| scalar(&entry["scalar"]))
            .collect::<Vec<_>>();
        let points = entries
            .iter()
            .map(|entry| point(&entry["point"]))
            .collect::<Vec<_>>();
        let actual = generators::multi_scalar_mul(&scalars, &points).map_or_else(
            |error| json!({"error":error.to_string()}),
            |point| json!({"point":hex::encode(point)}),
        );
        assert_eq!(actual, case["expected"]);
    }
    assert_eq!(
        generators::multi_scalar_mul(&[Scalar::ONE], &[])
            .unwrap_err()
            .to_string(),
        "HFHE multiscalar shape rejected"
    );
    assert_eq!(generators::base_mul(&Scalar::ZERO), generators::identity());
    assert_eq!(generators::base_mul(&Scalar::ONE), generators::pedersen_b());
    assert_eq!(
        generators::pedersen_commit(&Scalar::ZERO, &Scalar::ONE),
        generators::pedersen_blinding()
    );
}
