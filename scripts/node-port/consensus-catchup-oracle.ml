open Yojson.Safe.Util
open Octra_consensus
module C=C_catchup
module D=C_driver
module W=C_codec
module T=C_types
module H=C_hash
let hex raw=String.concat ""(List.init(String.length raw)(fun i->Printf.sprintf "%02x"(Char.code raw.[i])))
let unhex s=String.init(String.length s/2)(fun i->Char.chr(int_of_string("0x"^String.sub s(i*2)2)))
let raw j k=j|>member k|>to_string|>unhex
let str j k=j|>member k|>to_string
let i64 j k=str j k|>Int64.of_string
let int j k=j|>member k|>to_int
let bool j k=j|>member k|>to_bool
let h s=`String(hex s)
let err=function Failure s|Invalid_argument s->s|e->Printexc.to_string e
let catch f=try f()with e->`Assoc["error",`String(err e)]
let verdict=function Ok _->`Null|Error e->`String e
let recovery=function C.Base_gate_quarantine->"quarantine"|C.Base_gate_retry->"retry"|C.Base_gate_already_applied->"already"
let execute j=catch(fun()->match str j "op"with
|"policy"->
 let target=i64 j "target"and head=i64 j "head"and start=i64 j "start"in
 let heads=member "heads"j|>to_list|>List.map(fun v->{C.responder_addr="";responder_head_epoch=Int64.of_string(to_string v)})in
 let lag=match C.classify_lag ~target ~our_head:head ~max_lag:(int j "max_lag")with C.In_sync->`List[`String"sync"]|C.Do_catchup n->`List[`String"catchup";`Int n]|C.Snapshot_required n->`List[`String"snapshot";`Int n]|C.Ahead_of_target n->`List[`String"ahead";`Int n]in
 let repair=match C.decide_fork_repair ~our_head:head ~target ~current_root_quorum:(bool j "current")~target_root_quorum:(bool j "target_quorum")~target_local_matches:(bool j "matches")~empty_fork:(bool j "empty")with C.No_fork_repair->`Null|C.Rollback_fork_head e->`String(Int64.to_string e)|C.Fork_snapshot_required e->`String e in
 `Assoc["target",catch(fun()->`String(Int64.to_string(C.pick_target_epoch ~responses:heads ~f:(int j "faults")~fallback:target)));"lag",lag;"mode",`String(match C.lag_mode ~lag:(int j "max_lag")~soft_lag:(int j "soft")with C.Soft->"soft"|C.Quarantine->"quarantine");"recovery",`String(recovery(C.base_gate_recovery ~target ~start_head:start ~current_head:head));"record",`String(match C.record_apply_decision ~head ~record_epoch:target with C.Apply_record->"apply"|C.Skip_applied_record->"skip"|C.Retry_moved_head->"retry");"repair",repair]
|"pace"->let height=i64 j "height"and generation=int j "generation"and now=i64 j "now"in let p=C_pace.make ~height ~generation ~now ~started:(i64 j "started")~interval:(i64 j "interval")~delay:(i64 j "delay")in
 `Assoc["until",(match p with None->`Null|Some p->`String(Int64.to_string p.until));"remaining",`String(Int64.to_string(C_pace.remaining p ~height:(i64 j "read_height")~generation:(int j "read_generation")~now:(i64 j "read_now")));"grace",`Bool(let elapsed=Int64.sub now(i64 j "started")in elapsed>=0L&&elapsed<Int64.mul(Int64.of_int(int j "grace"))1_000_000L);"timeout",`String(Int64.to_string(Int64.bits_of_float(D.bounded_timeout(Int64.float_of_bits(i64 j "seconds_bits")))))]
|"seen"->let s=C_seen.create ~capacity:(int j "capacity")in `List(member "ids"j|>to_list|>List.map(fun v->let id=unhex(to_string v)in let prior=C_seen.known s id in let added=C_seen.remember s id in `Assoc["prior",`Bool prior;"added",`Bool added;"length",`Int(C_seen.length s)]))
|"record"->let response=W.decode_catchup_range_response_v2(raw j "wire")in let record=List.hd response.records in let finality=Option.get record.finality in let expected=C_config.validator_set_hash finality.validator_set in
 let mutation=str j "mutation"in
 let record=match mutation with
 |"epoch"->{record with epoch_id=Int64.succ record.epoch_id}|"previous"->{record with prev_state_root=String.make 32 '\042'}|"root"->{record with state_root=String.make 32 '\042'}|"txroot"->{record with tx_list_hash=C_engine.tx_list_hash_for_header record.tx_hashes}|"receipts"->{record with receipt_root=H.receipt_root record.receipts_json}|"timestamp"->{record with epoch_ts=record.epoch_ts+.1.}|"creator"->{record with creator_addr="other"}|"round"->{record with commit_round=record.commit_round+1}|"missing"->{record with finality=None}|"signature"->{record with finality=Some{finality with finalize={finality.finalize with precommits=List.map(fun(v:T.vote)->{v with signature=String.make 64 '\000'})finality.finalize.precommits}}}|_->record in
 let parsed=if mutation="count"then[]else if mutation="tx"then String.make 32 '\042'::List.tl record.tx_hashes else record.tx_hashes in
 let expected=if mutation="set"then String.make 32 '\042'else expected in
 let expected_txid=if mutation="txid"then 1L else Int64.succ finality.finalize.header.txid_hi in
 let finality=C.verify_record_finality ~chain_id:(if mutation="chain"then"other"else response.chain_id)~expected_validator_set_hash:expected ~expected_txid ~record in
 `Assoc["hashes",verdict(C.verify_record_hashes ~record ~parsed_tx_hashes:parsed);"receipts",verdict(C.verify_record_receipts ~record);"finality",verdict finality;"complete",`Bool(D.catchup_record_complete record);"continuity",verdict(C.verify_chain_continuity ~records:[record;{record with epoch_id=Int64.succ record.epoch_id;prev_state_root=record.state_root}]~from_epoch:record.epoch_id ~prev_root:record.prev_state_root)]
|"apply"->let head:C.apply_point={epoch=i64 j "head";root=raw j "root";eic=(match member"eic"j with`Null->None|v->Some(unhex(to_string v)));txid=i64 j "txid"}in
 `Assoc["base",verdict(C.verify_apply_base ~from_epoch:(i64 j "from")~head);"final",verdict(C.verify_apply_final ~last_epoch:(i64 j "last")~expected_root:(raw j "expected_root")~expected_eic:(raw j "expected_eic")~expected_txid:(i64 j "expected_txid")~head)]
|"proposal"->let p=W.decode_propose(raw j "wire")and set=W.decode_validator_set(raw j "validators")in
 let result=D.validate_proposal_frame ~chain_id:(raw j "chain")~validator_set:set p in
 `Assoc["valid",(match result with Ok()->`Null|Error e->`Assoc["label",`String(D.proposal_frame_error_label e);"peer",`String(D.proposal_frame_peer_reason e);"source",`String(match D.proposal_fault_source e with D.Proposal_fault_unresolved->"unresolved"|D.Proposal_fault_sender->"sender"|D.Proposal_fault_signer->"signer")]);"verify",`Bool(D.proposal_verify_relevant ~current_round:(int j "round")~current_step:(T.round_step_of_u8(int j "step"))~proposal_round:p.round)]
|"vote"->let v=W.decode_vote(raw j "wire")in `Assoc["key",h(D.vote_key v);"future_key",h(D.future_vote_key v);"relay",`Bool(D.vote_relay_relevant ~current_height:(i64 j "height")~current_round:(int j "round")v);"future",`Bool(D.future_vote_relay_relevant ~current_height:(i64 j "height")v)]
|"sync"->let s=W.decode_round_sync(raw j "wire")in `Assoc["relay",`Bool(D.round_sync_relay_relevant ~current_height:(i64 j "height")~current_round:(int j "round")s);"allowed",`Bool(D.round_sync_allowed ~current_round:(int j "round")s)]
|"window"->let window:D.catchup_query_window={from_epoch=i64 j "from";max_epochs=int j "max"}in `Bool(D.catchup_epoch_in_window window(i64 j "epoch"))
|_->failwith"op")
let ()=Yojson.Safe.from_file Sys.argv.(1)|>to_list|>List.map(fun j->`Assoc["input",j;"expected",execute j])|>fun xs->Yojson.Safe.to_channel stdout(`List xs)
