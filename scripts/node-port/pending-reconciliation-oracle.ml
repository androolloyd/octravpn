open Yojson.Safe.Util
module R=Octra_node_runtime.Consensus_pending_commit_recovery
module W=Octra_core.Wal
let s j k=member k j|>to_string
let n j k=member k j|>to_int
let record j:W.pending_commit={epoch_id=n j"epoch";round=n j"round";proposal_id="";proposed_state_root=s j"root";txid_hi=0L;ts=0.;validator_addr="";proposal_b64=None;vote_b64=None;tx_hashes=[];txs_json=[];receipts_json=[]}
let run j=
 let head=ref(n j"head")and pending=ref(member"pending"j|>to_list|>List.map record)and reads=ref 0 and calls=ref[]in
 let call name values=calls:= !calls@[`List(`String name::values)]in
 let fault name=if s j"fault"=name then failwith("fixture "^name)in
 let deps:R.deps={
 head_epoch=(fun()->fault"head";!head);
 read_pending_commits=(fun()->incr reads;if !reads=n j"read_fault"then failwith"fixture read";!pending);
 restore_pending=(fun p->call"restore"[`Int p.epoch_id;`Int p.round];match s j"restore"with"lock"->R.Restored|"invalid"->R.Invalid"invalid record"|_->R.Legacy);
 query_epoch_root=(fun ~epoch_id->call"query"[`Int(Int64.to_int epoch_id)];fault"query";Lwt.return(member"responses"j|>to_list|>List.mapi(fun i v->Octra_consensus.C_driver.{responder_addr=string_of_int i;responder_head_epoch=epoch_id;state_root=(match v with`Null->None|`String s->R.raw32_of_hex s|_->assert false)})));
 run_catchup_to_target=(fun ~target_epoch ~reason->call"catchup"[`Int(Int64.to_int target_epoch);`String reason];fault"catchup";head:=n j"after";Lwt.return_unit);
 delete_pending_commit=(fun ~epoch_id ~round->call"delete"[`Int epoch_id;`Int round];fault"delete";pending:=List.filter(fun p->p.W.epoch_id<>epoch_id||p.round<>round)!pending)}in
 let result=try`Bool(Lwt_main.run(R.run_once deps ~validator_count:(n j"validators")~peer_quorum:(n j"quorum")))with e->`String(Printexc.to_string e)in
 `Assoc["result",result;"calls",`List !calls;"head",`Int !head;"reads",`Int !reads;"pending",`List(List.map(fun p->`List[`Int p.W.epoch_id;`Int p.round])!pending)]
let ()=let cases=Yojson.Safe.from_channel stdin|>to_list|>List.map(fun input->`Assoc["input",input;"expected",run input])in Yojson.Safe.to_channel stdout(`List cases);print_newline()
