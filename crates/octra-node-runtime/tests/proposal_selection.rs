use octra_node_protocol::{
    consensus::{
        engine::tx_list_hash_for_header, hash, CommitCertificate, EpochHeader, ParentCommit,
        ValidatorSet,
    },
    native_json::Document,
    transaction::Transaction,
};
use octra_node_runtime::proposal_select::{self, Limits, Slots};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn hashes(txs: &[Transaction]) -> Vec<String> {
    txs.iter()
        .map(|tx| hex::encode(tx.hash().unwrap()))
        .collect()
}
fn root(txs: &[Transaction]) -> Vec<u8> {
    tx_list_hash_for_header(
        &hashes(txs)
            .into_iter()
            .map(String::into_bytes)
            .collect::<Vec<_>>(),
    )
    .to_vec()
}
fn parent(mode: &str, txs: &[Transaction]) -> Option<ParentCommit> {
    if mode == "none" {
        return None;
    }
    let chain_id = if mode == "chain" {
        b"other".to_vec()
    } else {
        b"selection".to_vec()
    };
    let epoch_id = if mode == "epoch" { 10 } else { 11 };
    let header = EpochHeader {
        proto_version: octra_node_protocol::consensus::CURRENT_VERSION,
        chain_id: chain_id.clone(),
        epoch_id,
        prev_state_root: vec![b'p'; 32],
        tx_list_hash: root(if mode == "empty" { &[] } else { txs }),
        receipt_root: vec![b'r'; 32],
        proposed_state_root: vec![b's'; 32],
        parent_commit_hash: vec![b'c'; 32],
        creator_addr: b"creator".to_vec(),
        txid_hi: 0,
        ts: 10.,
    };
    let proposal_id = if mode == "hash" {
        vec![b'x'; 32]
    } else {
        hash::proposal_id(&header).unwrap().to_vec()
    };
    Some(ParentCommit {
        certificate: CommitCertificate {
            chain_id,
            epoch_id,
            commit_round: 0,
            header,
            proposal_id,
            precommits: vec![],
        },
        validator_set: ValidatorSet::unweighted(vec![]),
    })
}

#[test]
fn native_selection_caps_slots_turns_and_parent_bundles() {
    let report: Value =
        serde_json::from_str(include_str!("fixtures/proposal-selection.json")).unwrap();
    let source: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(report["upstream_commit"], source["upstream_commit"]);
    assert_eq!(report["source_sha256"], source["files"]);
    assert_eq!(report["instrumentation"], json!({}));
    for (name, bytes) in [
        (
            "oracle_sha256",
            include_bytes!("../../../scripts/node-port/proposal-selection-oracle.ml").as_slice(),
        ),
        (
            "generator_sha256",
            include_bytes!("../../../scripts/node-port/proposal-selection-fixtures.py").as_slice(),
        ),
        (
            "runner_sha256",
            include_bytes!("../../../scripts/node-port/native-oracle.py").as_slice(),
        ),
    ] {
        assert_eq!(report[name], hex::encode(Sha256::digest(bytes)), "{name}");
    }
    assert_eq!(report["cases"].as_array().unwrap().len(), 962);
    for (index, case) in report["cases"].as_array().unwrap().iter().enumerate() {
        let j = &case["input"];
        let txs = case["transactions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|j| {
                Transaction::from_document(
                    &Document::parse(j.as_str().unwrap().as_bytes()).unwrap(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let subset = |key: &str| {
            j[key]
                .as_array()
                .unwrap()
                .iter()
                .map(|i| txs[i.as_u64().unwrap() as usize].clone())
                .collect::<Vec<_>>()
        };
        let mode = j["parent"].as_str().unwrap();
        let epoch = j["epoch"].as_i64().unwrap();
        let parent = parent(mode, &txs);
        let lookup = match mode {
            "missing" => None,
            "mismatch" => Some([].as_slice()),
            _ => Some(txs.as_slice()),
        };
        let previous =
            proposal_select::previous(b"selection", epoch, parent.as_ref(), lookup).unwrap();
        let limits = Limits::new(
            j["count"].as_u64().unwrap() as usize,
            case["byte_limit"].as_u64().unwrap() as usize,
            j["ou"].as_i64().unwrap().into(),
        );
        let actual = json!({
            "cap": hashes(&limits.cap(&txs, &5000.into()).unwrap()),
            "within": limits.within(&txs, &5000.into()).unwrap(),
            "slots": hashes(&Slots::new(j["fhe"].as_u64().unwrap() as usize, j["stealth"].as_u64().unwrap() as usize).select(&txs, &subset("ready")).unwrap()),
            "without": hashes(&proposal_select::without(&txs)), "previous": previous,
            "turn": hashes(&proposal_select::turn(j["ordered"].as_bool().unwrap(), epoch, previous, &subset("ordinary"), &txs)),
        });
        assert_eq!(actual, case["expected"], "case {index}: {j}");
    }
}
