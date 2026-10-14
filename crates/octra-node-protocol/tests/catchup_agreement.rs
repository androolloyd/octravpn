use ed25519_dalek::SigningKey;
use octra_node_protocol::consensus::{
    catchup_agreement::{self, Agreement},
    CatchupResponse, Validator, ValidatorSet,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[test]
fn native_range_agreement_matches() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/catchup-agreement.json")).unwrap();
    let source: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], source["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], source["files"]);
    assert_eq!(fixture["instrumentation"], json!({}));
    assert_eq!(
        fixture["oracle_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/catchup-agreement-oracle.ml"
        )))
    );
    assert_eq!(
        fixture["runner_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/native-oracle.py"
        )))
    );
    for (index, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let input = &case["input"];
        let number = |key: &str| input[key].as_str().unwrap().parse::<i64>().unwrap();
        let chain = input["chain"].as_str().unwrap().as_bytes();
        let epoch = number("from");
        let entries = input["weights"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
            .map(|(i, w)| {
                (
                    Validator {
                        address: format!("v{}", i + 1).into_bytes(),
                        pubkey: SigningKey::from_bytes(&[(i + 1) as u8; 32])
                            .verifying_key()
                            .to_bytes()
                            .to_vec(),
                    },
                    w.as_str().unwrap().parse().unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let set = if input["weighted"] == true {
            ValidatorSet::weighted(entries).unwrap()
        } else {
            ValidatorSet::unweighted(entries.into_iter().map(|(v, _)| v).collect())
        };
        let seed =
            CatchupResponse::decode(&hex::decode(input["wire"].as_str().unwrap()).unwrap(), true)
                .unwrap();
        let mut rejected = vec![];
        let responses = input["responses"]
            .as_array()
            .unwrap()
            .iter()
            .map(|spec| {
                let responder = spec["responder"].as_str().unwrap().as_bytes().to_vec();
                if spec["valid"] == false {
                    rejected.push(responder.clone());
                }
                let records = spec["records"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .enumerate()
                    .map(|(i, v)| {
                        let mut record = seed.records[0].clone();
                        record.epoch_id = epoch + i as i64;
                        record.state_root = vec![v.as_u64().unwrap() as u8; 32];
                        if spec["incomplete"] == true {
                            record.finality = None;
                        }
                        record
                    })
                    .collect();
                CatchupResponse {
                    records,
                    responder_addr: responder,
                    status: spec["status"].as_str().unwrap().as_bytes().to_vec(),
                    next_epoch: spec["next"].as_str().map(|v| v.parse().unwrap()),
                    ..seed.clone()
                }
            })
            .collect::<Vec<_>>();
        let mut agreement = Agreement::default();
        let mut calls = BTreeMap::<Vec<u8>, usize>::new();
        let mut chosen = None;
        // Native polls repeatedly after rejecting a source. Rechecking the same
        // response list must never re-run validation for an excluded responder.
        for _ in 0..3 {
            chosen = agreement
                .select(
                    chain,
                    epoch,
                    &responses,
                    |epoch| set.for_epoch(chain, epoch),
                    |r| {
                        *calls.entry(r.responder_addr.clone()).or_default() += 1;
                        Ok(!rejected.contains(&r.responder_addr))
                    },
                )
                .unwrap();
            if chosen.is_some() {
                break;
            }
        }
        let chosen=chosen.map(|r|json!({"responder":String::from_utf8(r.responder_addr).unwrap(),"status":String::from_utf8(r.status).unwrap(),"next":r.next_epoch.map(|v|v.to_string()),"roots":r.records.iter().map(|r|hex::encode(&r.state_root)).collect::<Vec<_>>()}));
        let actual = json!({"chosen":chosen,"limit":catchup_agreement::limit(epoch,input["max"].as_i64().unwrap(),input["activation"].as_str().map(|s|s.parse().unwrap())),
            "waves":catchup_agreement::waves(&set.for_epoch(chain,epoch).unwrap(),(0..input["peers"].as_u64().unwrap()).collect()),
            "delay":catchup_agreement::wave_delay(input["budget"].as_f64().unwrap(),input["wave_count"].as_u64().unwrap()as usize),
            "rejected_calls":rejected.iter().map(|r|json!([String::from_utf8(r.clone()).unwrap(),calls.get(r).copied().unwrap_or(0)])).collect::<Vec<_>>(),"clean":true});
        assert_eq!(actual, case["expected"], "native catchup agreement {index}");
    }
}
