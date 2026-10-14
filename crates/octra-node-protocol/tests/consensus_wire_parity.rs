use octra_node_protocol::consensus::{
    codec::Wire, evidence, hash, policy::Protocol, qc, reward, BundleQuery, BundleResponse,
    CatchupQuery, CatchupResponse, CommitCertificate, EpochHeader, EpochRootQuery,
    EpochRootResponse, Error, Finalize, ParentCommit, Proposal, RoundFetch, RoundSync,
    ValidatorSet, Vote,
};
use octra_node_protocol::oce1::{Reader, Writer};
use serde_json::{json, Value};
fn raw(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}
fn caught(result: Result<Value, Error>) -> Value {
    result.unwrap_or_else(|error| json!({"error":error.to_string()}))
}
fn verdict(result: Result<(), Error>) -> Value {
    result.err().map_or(Value::Null, |e| json!(e.to_string()))
}
fn output(wire: Vec<u8>, fields: Value) -> Value {
    let Value::Object(mut output) = fields else {
        panic!("fixture output fields")
    };
    output.insert("wire".into(), json!(hex::encode(wire)));
    Value::Object(output)
}
fn execute(value: &Value) -> Result<Value, Error> {
    let wire = raw(&value["wire"]);
    let public = raw(&value["public"]);
    let chain = raw(&value["chain"]);
    let validators = ValidatorSet::decode(&raw(&value["validators"]))?;
    Ok(match value["kind"].as_str().unwrap() {
        "header" => {
            let x = EpochHeader::decode(&wire)?;
            output(
                x.encode()?,
                json!({"hash":hex::encode(hash::proposal_id(&x)?)}),
            )
        }
        "vote" => {
            let x = Vote::decode(&wire)?;
            output(
                x.encode()?,
                json!({"hash":hex::encode(hash::vote_sign_bytes(&x)?),"valid":hash::verify_vote(&public,&x)?,"slot":hex::encode(evidence::vote_slot_id(&x)?)}),
            )
        }
        "sync" => {
            let x = RoundSync::decode(&wire)?;
            output(
                x.encode()?,
                json!({"hash":hex::encode(hash::round_sync_sign_bytes(&x)?),"valid":hash::verify_round_sync(&public,&x)?}),
            )
        }
        "fetch" => {
            let x = RoundFetch::decode(&wire)?;
            output(x.encode()?, json!({}))
        }
        "proposal" => {
            let x = Proposal::decode(&wire)?;
            output(
                x.encode()?,
                json!({"hash":hex::encode(hash::propose_sign_bytes(&x)?),"valid":hash::verify_proposal(&public,&x)?,"shape":validators.proposal_well_formed(&chain,Protocol::default(),&x)?}),
            )
        }
        "certificate" => {
            let x = CommitCertificate::decode(&wire)?;
            output(
                x.encode()?,
                json!({"valid":verdict(qc::validate_certificate(&chain,&validators,&x,false)),"strict":verdict(qc::validate_certificate(&chain,&validators,&x,true))}),
            )
        }
        "parent" => {
            let x = ParentCommit::decode(&wire)?;
            let expected = qc::ExpectedParent {
                chain_id: chain,
                epoch_id: x.certificate.epoch_id,
                proposal_id: x.certificate.proposal_id.clone(),
                state_root: x.certificate.header.proposed_state_root.clone(),
                validator_set_hash: hash::validator_set_hash(&validators)?.to_vec(),
            };
            output(
                x.encode()?,
                json!({"hash":hex::encode(hash::parent_commit_hash(&x)?),"valid":verdict(qc::validate_parent(&expected,&x))}),
            )
        }
        "finalize" => {
            let x = Finalize::decode(&wire)?;
            output(
                x.encode()?,
                json!({"live":verdict(qc::validate_finalize(&chain,&validators,&x,qc::FinalityMode::Live(Protocol::default()))),"persisted":verdict(qc::validate_finalize(&chain,&validators,&x,qc::FinalityMode::Persisted)),"strict":verdict(qc::validate_finalize(&chain,&validators,&x,qc::FinalityMode::StrictPersisted))}),
            )
        }
        "root_query" => {
            let x = EpochRootQuery::decode(&wire)?;
            output(x.encode()?, json!({}))
        }
        "root_response" => {
            let x = EpochRootResponse::decode(&wire)?;
            output(
                x.encode()?,
                json!({"hash":hex::encode(hash::epoch_root_response_sign_bytes(&x)?)}),
            )
        }
        "bundle_query" => {
            let x = BundleQuery::decode(&wire)?;
            output(x.encode()?, json!({}))
        }
        "bundle_response" => {
            let x = BundleResponse::decode(&wire)?;
            output(
                x.encode()?,
                json!({"hash":hex::encode(hash::bundle_response_sign_bytes(&x)?),"tx_hash":hex::encode(hash::tx_list_hash(&x.tx_hashes)?),"receipt_hash":hex::encode(hash::receipt_root(&x.receipts_json)?)}),
            )
        }
        "catchup_query" => {
            let x = CatchupQuery::decode(&wire)?;
            output(
                x.encode()?,
                json!({"complete":hash::catchup_request_is_complete(&x.request_id),"marked":caught(hash::mark_complete_catchup_request(&x.request_id).map(|h|json!(hex::encode(h))))}),
            )
        }
        kind @ ("catchup_v1" | "catchup_v2") => {
            let v2 = kind == "catchup_v2";
            let x = CatchupResponse::decode(&wire, v2)?;
            let root = if v2 {
                hash::catchup_records_root(&x.records)?
            } else {
                hash::catchup_records_root_v1(&x.records)?
            };
            output(
                x.encode(v2)?,
                json!({"root":hex::encode(root),"hash":hex::encode(hash::catchup_response_sign_bytes(&x.chain_id,&x.request_id,&x.responder_addr,12,&root)?),"complete_hash":caught(hash::catchup_complete_sign_bytes(12,&x).map(|h|json!(hex::encode(h)))),"times":x.records.iter().map(|r|(r.epoch_ts.to_bits() as i64).to_string()).collect::<Vec<_>>()}),
            )
        }
        "evidence" => {
            let x = evidence::VoteConflict::decode(&wire)?;
            output(
                x.encode()?,
                json!({"hash":hex::encode(x.id()?),"root":hex::encode(evidence::root(&[x.clone(),x.clone()])?),"valid":x.verify(&public)?}),
            )
        }
        "reward" => {
            let mut r = Reader::new(&wire);
            let x = reward::get(&mut r)?;
            r.finish()?;
            let mut w = Writer::new();
            reward::put(&mut w, &x)?;
            output(w.into_bytes(), json!({}))
        }
        kind => panic!("unknown fixture kind: {kind}"),
    })
}
#[test]
fn native_consensus_messages_hashes_certificates_and_evidence() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/consensus-wire.json")).unwrap();
    let manifest: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], manifest["upstream_commit"]);
    for (path, hash) in fixture["source_sha256"].as_object().unwrap() {
        assert_eq!(*hash, manifest["files"][path]);
    }
    for (index, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        assert_eq!(
            caught(execute(&case["input"])),
            case["expected"],
            "case {index} {}",
            case["input"]["kind"]
        );
    }
}
