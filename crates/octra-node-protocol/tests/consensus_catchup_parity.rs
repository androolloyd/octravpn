use octra_node_protocol::consensus::{
    catchup as c, codec::Wire, driver_policy as d, engine, hash, pace::Pace, policy::Protocol,
    seen::Seen, CatchupResponse, Error, Proposal, RoundStep, RoundSync, ValidatorSet, Vote,
};
use serde_json::{json, Value};
fn raw(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}
fn i64_(j: &Value, k: &str) -> i64 {
    j[k].as_str().unwrap().parse().unwrap()
}
fn int(j: &Value, k: &str) -> i64 {
    j[k].as_i64().unwrap()
}
fn flag(j: &Value, k: &str) -> bool {
    j[k].as_bool().unwrap()
}
fn catch(r: Result<Value, Error>) -> Value {
    r.unwrap_or_else(|e| json!({"error":e.to_string()}))
}
fn verdict<T>(r: Result<T, Error>) -> Value {
    r.err().map_or(Value::Null, |e| json!(e.to_string()))
}
fn execute(j: &Value) -> Result<Value, Error> {
    Ok(match j["op"].as_str().unwrap() {
        "policy" => {
            let target = i64_(j, "target");
            let head = i64_(j, "head");
            let start = i64_(j, "start");
            let heads: Vec<_> = j["heads"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| c::PeerHead {
                    responder_addr: Vec::new(),
                    responder_head_epoch: v.as_str().unwrap().parse().unwrap(),
                })
                .collect();
            let lag = match c::classify_lag(target, head, int(j, "max_lag")) {
                c::LagDecision::InSync => json!(["sync"]),
                c::LagDecision::Catchup(n) => json!(["catchup", n]),
                c::LagDecision::SnapshotRequired(n) => json!(["snapshot", n]),
                c::LagDecision::AheadOfTarget(n) => json!(["ahead", n]),
            };
            let repair = match c::decide_fork_repair(
                head,
                target,
                flag(j, "current"),
                flag(j, "target_quorum"),
                flag(j, "matches"),
                flag(j, "empty"),
            ) {
                c::ForkRepair::None => Value::Null,
                c::ForkRepair::Rollback(e) => json!(e.to_string()),
                c::ForkRepair::SnapshotRequired(e) => json!(e),
            };
            json!({"target":catch(c::pick_target_epoch(&heads,int(j,"faults"),target).map(|n|json!(n.to_string()))),"lag":lag,"mode":if c::lag_mode(int(j,"max_lag"),int(j,"soft"))==c::LagMode::Soft{"soft"}else{"quarantine"},"recovery":match c::base_gate_recovery(target,start,head){c::Recovery::Quarantine=>"quarantine",c::Recovery::Retry=>"retry",c::Recovery::AlreadyApplied=>"already"},"record":match c::record_apply_decision(head,target){c::RecordApply::Apply=>"apply",c::RecordApply::SkipApplied=>"skip",c::RecordApply::RetryMovedHead=>"retry"},"repair":repair})
        }
        "pace" => {
            let p = Pace::new(
                i64_(j, "height"),
                int(j, "generation"),
                i64_(j, "now"),
                i64_(j, "started"),
                i64_(j, "interval"),
                i64_(j, "delay"),
            );
            json!({"until":p.map(|p|p.until.to_string()),"remaining":Pace::remaining(p.as_ref(),i64_(j,"read_height"),int(j,"read_generation"),i64_(j,"read_now")).to_string(),"grace":d::within_grace(i64_(j,"now"),i64_(j,"started"),int(j,"grace")),"timeout":(d::bounded_timeout(f64::from_bits(i64_(j,"seconds_bits")as u64)).to_bits()as i64).to_string()})
        }
        "seen" => {
            let mut s = Seen::new(int(j, "capacity"))?;
            json!(j["ids"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| {
                    let id = raw(v);
                    let prior = s.known(&id);
                    let added = s.remember(&id);
                    json!({"prior":prior,"added":added,"length":s.len()})
                })
                .collect::<Vec<_>>())
        }
        "record" => {
            let response = CatchupResponse::decode(&raw(&j["wire"]), true)?;
            let mut record = response.records[0].clone();
            let finality = record.finality.as_ref().unwrap().clone();
            let expected = hash::validator_set_hash(&finality.validator_set)?;
            let mutation = j["mutation"].as_str().unwrap();
            match mutation {
                "epoch" => record.epoch_id = record.epoch_id.wrapping_add(1),
                "previous" => record.prev_state_root = vec![42; 32],
                "root" => record.state_root = vec![42; 32],
                "txroot" => {
                    record.tx_list_hash =
                        engine::tx_list_hash_for_header(&record.tx_hashes).to_vec();
                }
                "receipts" => {
                    record.receipt_root = hash::receipt_root(&record.receipts_json)?.to_vec();
                }
                "timestamp" => record.epoch_ts += 1.,
                "creator" => record.creator_addr = b"other".to_vec(),
                "round" => record.commit_round += 1,
                "missing" => record.finality = None,
                "signature" => {
                    for vote in &mut record.finality.as_mut().unwrap().finalize.precommits {
                        vote.signature = vec![0; 64];
                    }
                }
                _ => {}
            }
            let mut parsed = record.tx_hashes.clone();
            if mutation == "count" {
                parsed.clear();
            } else if mutation == "tx" {
                parsed[0] = vec![42; 32];
            }
            let expected = if mutation == "set" {
                [42; 32]
            } else {
                expected
            };
            let expected_txid = if mutation == "txid" {
                1
            } else {
                finality.finalize.header.txid_hi.wrapping_add(1)
            };
            let chain = if mutation == "chain" {
                b"other"
            } else {
                response.chain_id.as_slice()
            };
            let mut next = record.clone();
            next.epoch_id = next.epoch_id.wrapping_add(1);
            next.prev_state_root.clone_from(&record.state_root);
            json!({"hashes":verdict(c::verify_record_hashes(&record,&parsed)),"receipts":verdict(c::verify_record_receipts(&record)),"finality":verdict(c::verify_record_finality(chain,&expected,expected_txid,&record)),"complete":d::catchup_record_complete(&record),"continuity":verdict(c::verify_chain_continuity(&[record.clone(),next],record.epoch_id,&record.prev_state_root))})
        }
        "apply" => {
            let head = c::ApplyPoint {
                epoch: i64_(j, "head"),
                root: raw(&j["root"]),
                eic: if j["eic"].is_null() {
                    None
                } else {
                    Some(raw(&j["eic"]))
                },
                txid: i64_(j, "txid"),
            };
            json!({"base":verdict(c::verify_apply_base(i64_(j,"from"),&head)),"final":verdict(c::verify_apply_final(i64_(j,"last"),&raw(&j["expected_root"]),&raw(&j["expected_eic"]),i64_(j,"expected_txid"),&head))})
        }
        "proposal" => {
            let p = Proposal::decode(&raw(&j["wire"]))?;
            let set = ValidatorSet::decode(&raw(&j["validators"]))?;
            let result =
                d::validate_proposal_frame(&raw(&j["chain"]), &set, Protocol::default(), &p)?;
            json!({"valid":result.map(|e|json!({"label":e.label(),"peer":e.peer_reason(),"source":match e.source(){d::FaultSource::Unresolved=>"unresolved",d::FaultSource::Sender=>"sender",d::FaultSource::Signer=>"signer"}})),"verify":d::proposal_verify_relevant(int(j,"round"),RoundStep::from_byte(int(j,"step")as u8)?,p.round)})
        }
        "vote" => {
            let v = Vote::decode(&raw(&j["wire"]))?;
            json!({"key":hex::encode(d::vote_key(&v)),"future_key":hex::encode(d::future_vote_key(&v)),"relay":d::vote_relay_relevant(i64_(j,"height"),int(j,"round"),&v),"future":d::future_vote_relay_relevant(i64_(j,"height"),&v)})
        }
        "sync" => {
            let s = RoundSync::decode(&raw(&j["wire"]))?;
            json!({"relay":d::round_sync_relay_relevant(i64_(j,"height"),int(j,"round"),&s),"allowed":d::round_sync_allowed(int(j,"round"),&s)})
        }
        "window" => json!(d::QueryWindow {
            from_epoch: i64_(j, "from"),
            max_epochs: int(j, "max")
        }
        .contains(i64_(j, "epoch"))),
        _ => panic!("unknown catchup fixture"),
    })
}
#[test]
fn native_catchup_finality_execution_gates_and_driver_policies() {
    let f: Value = serde_json::from_str(include_str!("fixtures/consensus-catchup.json")).unwrap();
    let manifest: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(f["upstream_commit"], manifest["upstream_commit"]);
    for (p, h) in f["source_sha256"].as_object().unwrap() {
        assert_eq!(*h, manifest["files"][p]);
    }
    for (index, c) in f["cases"].as_array().unwrap().iter().enumerate() {
        assert_eq!(
            catch(execute(&c["input"])),
            c["expected"],
            "case {index} {}",
            c["input"]["op"]
        );
    }
}
