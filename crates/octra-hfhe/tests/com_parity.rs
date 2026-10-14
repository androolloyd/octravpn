use octra_hfhe::{
    field::Fp,
    recrypt::commitment::{Cell, Decision, Kind, Opening, Operation},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
mod common;
fn number(case: &Value, key: &str) -> u64 {
    case[key].as_str().unwrap().parse().unwrap()
}
fn decision(value: Decision) -> Value {
    json!([
        value.admitted,
        value.digest,
        value.bound,
        value.hiding,
        value.native,
        value.basis_closed,
        value.prebound,
        value.composable,
        value.rejects_unbound,
        value.rejects_basis_open,
        value.rejects_posthoc,
        value.rejects_nonclosed
    ]
    .map(u8::from))
}
#[test]
fn native_composable_commitments_match_bytes_and_acceptance() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/com.json")).unwrap();
    let sources: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    common::assert_source_pin(&fixture, &sources);
    for (source, hash) in fixture["source_sha256"].as_object().unwrap() {
        assert_eq!(*hash, sources["files"][source]);
    }
    assert_eq!(
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/hfhe-com-oracle.cpp"
        ))),
        fixture["oracle_sha256"]
    );
    for (index, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let operation = match number(case, "operation") {
            0 => Operation::None,
            1 => Operation::Source,
            2 => Operation::Add,
            3 => Operation::Subtract,
            4 => Operation::Scale,
            5 => Operation::AddConstant,
            6 => Operation::Product,
            7 => Operation::Reset,
            tag => Operation::Unknown(u8::try_from(tag).unwrap()),
        };
        let a = std::array::from_fn(|i| u8::try_from(i * 7 + 1).unwrap());
        let b = std::array::from_fn(|i| u8::try_from(i * 3 + 9).unwrap());
        let tag = std::array::from_fn(|i| u8::try_from(i * 5 + 17).unwrap());
        let mut left_open = Opening::new(Fp::from_words(number(case, "lo"), number(case, "hi")), a);
        let mut right_open =
            Opening::new(Fp::from_words(number(case, "rlo"), number(case, "rhi")), b);
        let mut left = Cell::new(tag, &left_open, true);
        let mut right = Cell::new(b, &right_open, true);
        let mut scalar = Fp::from_words(number(case, "slo"), number(case, "shi"));
        let mut out_open = left_open
            .combine(operation, &right_open, scalar)
            .unwrap_or_else(|| Opening::new(Fp::ZERO, [0; 32]));
        let mut out = Cell::expression(operation, &left, &right, scalar, Some(&out_open));
        let bare = Cell::expression(operation, &left, &right, scalar, None);
        match number(case, "mutation") {
            1 => left.prebound = false,
            2 => right.prebound = false,
            3 => left.kind = Kind::Expression,
            4 => right.kind = Kind::Expression,
            5 => out.kind = Kind::None,
            6 => out.bound = false,
            7 => out.hiding = false,
            8 => out.native = false,
            9 => out.basis_closed = false,
            10 => out.prebound = false,
            11 => out.composable = false,
            12 => out.tag[0] ^= 1,
            13 => out.digest[0] ^= 1,
            14 => left_open.blind[0] ^= 1,
            15 => right_open.blind[0] ^= 1,
            16 => out_open.blind[0] ^= 1,
            17 => left_open.value = left_open.value + Fp::ONE,
            18 => right_open.value = right_open.value + Fp::ONE,
            19 => out_open.value = out_open.value + Fp::ONE,
            20 => scalar = scalar + Fp::ONE,
            _ => {}
        }
        let value = out_open.value.words();
        let actual = json!({"value":[value.0.to_string(),value.1.to_string()],"digests":[hex::encode(out_open.blind),hex::encode(out.tag),hex::encode(out.digest),hex::encode(bare.digest)],"opening":decision(left.verify_opening(&left_open)),"claim":decision(out.claim()),"expression":decision(out.verify_expression(operation,(&left,&left_open),(&right,&right_open),scalar,&out_open))});
        assert_eq!(actual, case["expected"], "native commitment case {index}");
    }
}
