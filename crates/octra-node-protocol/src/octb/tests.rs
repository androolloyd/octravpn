use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value as Json};
use sha2::{Digest, Sha256};
fn b64(raw: &[u8]) -> String {
    STANDARD.encode(raw)
}
pub(super) fn value(v: &Value) -> Json {
    match v {
        Value::Int(v) => json!({"int":v.to_string()}),
        Value::Bool(v) => json!({"bool":v}),
        Value::Str(v) => json!({"str":b64(v)}),
        Value::Bytes(v) => json!({"bytes":b64(v)}),
        Value::Addr(v) => json!({"addr":b64(v)}),
    }
}
fn image(raw: &[u8], active: bool) -> Json {
    let image = match Image::decode(raw, active) {
        Ok(v) => v,
        Err(e) => return json!({"error":e.to_string()}),
    };
    let m = &image.metadata;
    json!({
        "consts":image.consts.iter().map(|c|json!({"id":c.id,"at":c.at,"size":c.size,"tag":c.tag,"data":b64(&c.data)})).collect::<Vec<_>>(),
        "cells":image.cells.iter().map(|c|json!({"pc":c.pc,"at":c.at,"size":c.size})).collect::<Vec<_>>(),
        "code":image.code.iter().map(Instruction::signature).collect::<Vec<_>>(),"text_at":image.text_at,
        "state":m.state.as_ref().map(|rows|rows.iter().map(|(n,k)|json!([b64(n),*k as u8])).collect::<Vec<_>>()),
        "proof":m.proof.as_ref().map(|v|b64(v)),
        "emission":m.emission.map(|v|match v{Emission::Lowered=>"lowered",Emission::Specialized=>"specialized"}),
        "veil":m.veil.as_ref().map(|v|json!({"count":v.count.to_string(),"depth":v.depth.to_string()})),
        "encoded":b64(&encode(&image.code,m,active).unwrap()),
    })
}
#[test]
fn native_octb_images_and_reencoding_match_every_opcode_and_rule_mode() {
    let fixture: Json =
        serde_json::from_str(include_str!("../../tests/fixtures/octb.json")).unwrap();
    let inventory: Json =
        serde_json::from_str(include_str!("../../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], inventory["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], inventory["files"]);
    assert_eq!(fixture["instrumentation"], json!({}));
    for (key, raw) in [
        (
            "oracle_sha256",
            include_bytes!("../../../../scripts/node-port/octb-oracle.ml").as_slice(),
        ),
        (
            "runner_sha256",
            include_bytes!("../../../../scripts/node-port/native-oracle.py").as_slice(),
        ),
        (
            "generator_sha256",
            include_bytes!("../../../../scripts/node-port/octb-fixtures.py").as_slice(),
        ),
    ] {
        assert_eq!(fixture[key], hex::encode(Sha256::digest(raw)));
    }
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 6910);
    let mut failures = Vec::new();
    for (i, c) in cases.iter().enumerate() {
        let raw = STANDARD.decode(c["raw"].as_str().unwrap()).unwrap();
        let active = c["active"].as_bool().unwrap();
        let got = image(&raw, active);
        if got != c["expected"] {
            failures.push(format!(
                "case {i} {} active={active}:\n got {got}\nwant {}",
                c["name"], c["expected"]
            ));
            if failures.len() == 10 {
                break;
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
#[test]
fn repeated_large_constants_share_decoded_values() {
    let digits = [b"1".as_slice(), &vec![b'0'; 65_536]].concat();
    let mut raw = b"OCTB\x01\x00\x01\x00".to_vec();
    raw.extend(1024_u32.to_le_bytes());
    raw.push(0);
    raw.extend((digits.len() as u32).to_le_bytes());
    raw.extend(digits);
    for _ in 0..1024 {
        raw.extend([0x0b, 0, 0, 0]);
    }
    let image = Image::decode(&raw, true).unwrap();
    assert_eq!(image.consts.len(), 1);
    let Instruction::Ldi(_, first) = &image.code[0] else {
        panic!()
    };
    for instruction in &image.code {
        let Instruction::Ldi(_, value) = instruction else {
            panic!()
        };
        assert!(Arc::ptr_eq(first, value));
    }
}

#[test]
fn native_legacy_admission_matches_verification_policy_and_effect_order() {
    let fixture: Json =
        serde_json::from_str(include_str!("../../tests/fixtures/octb.json")).unwrap();
    for (i, c) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let raw = STANDARD.decode(c["raw"].as_str().unwrap()).unwrap();
        let active = c["active"].as_bool().unwrap();
        let got = match admission::decode(&raw, active) {
            Ok(v) => {
                json!({"effects":v.effects().iter().map(|effect|effect.name()).collect::<Vec<_>>()})
            }
            Err(e) => json!({"error":e.to_string()}),
        };
        assert_eq!(
            got, c["admission"],
            "admission case {i}: {} active={active}",
            c["name"]
        );
        if let Ok(image) = Image::decode(&raw, active) {
            let got = match admission::of_code(image.code, false) {
                Ok(v) => {
                    json!({"effects":v.effects().iter().map(|effect|effect.name()).collect::<Vec<_>>()})
                }
                Err(e) => json!({"error":e.to_string()}),
            };
            assert_eq!(
                got, c["readmit_prior"],
                "readmit case {i}: {} active={active}",
                c["name"]
            );
        } else {
            assert_eq!(c["readmit_prior"], Json::Null);
        }
    }
}
