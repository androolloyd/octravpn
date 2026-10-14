(* Enter the real proposal preview backend. A deliberately mismatched snapshot
   stops it after rule binding, before any operation or epoch effects execute. *)
open Yojson.Safe.Util
module C=Octra_core
module R=C.Rule_graph
module S=C.Store_irmin
module E=C.Epoch_exec
let bytes v=Base64.decode_exn(to_string v)
let mode=function R.Active->`Bool true|Prior->`Bool false
let run store ledger input=
 let chain=bytes(member"chain"input)and epoch=member"epoch"input|>to_int in
 let root_at height=
   let kind=match member(string_of_int height)(member"roots"input)with `String s->s|_->member"default"input|>to_string in
   match kind with
   |"missing"->R.Missing|"bad"->R.Root"wrong-root"|"unreadable"->R.Unreadable"disk unavailable"
   |"good"->(match member"plans"input|>to_list|>List.find_map(function `List[`Int e;root;_] when e=height->Some(bytes root)|_->None)with None->R.Missing|Some s->R.Root s)
   |_->assert false in
 let rules=match member"config"input with `Null->R.create ~chain_id:chain ~root_at|v->R.create_ready ~chain_id:chain ~root_at ~ready_config_hash:(bytes v) in
 let parent=match member"parent"input with `Null->None|v->Some(Octra_consensus.C_codec.decode_parent_commit(bytes v))in
 let backend=Octra_node_runtime.Consensus_proposal_preview_shell.node_backend
   ~program_trust:Octra_vm.Program_trust.empty ~rules
   ~legacy_replay:(fun ~epoch:_ ~address:_ ~cipher:_->assert false)
   ~private_result_policy:(fun _->assert false) ~max_fhe:0 ~max_stealth:0 store ledger in
 let env=E.{chain_id=chain;epoch_id=epoch;proposer_addr="unused";validator_addrs=[];validator_pubkeys=[];prev_state_root="unused";epoch_ts=1.;ready_state_root_at=None;ready_max_lag=2}in
 let reward=E.{proposer_addr="unused";proposer_public_key=None;validators=[]}in
 let result=Lwt_main.run(backend.run ~epoch_id:epoch ~proposal_id:"rule-oracle"
   ~expected_prev_root:(Some "not-a-canonical-root") ~preverify:(C.Preverify_commit.create [])
   ~parent_commit:parent ~reward ~env ~txs:[])in
 match result with
 | Error "preview_state_changed" ->
   let get f=f rules ~epoch|>Result.get_ok in
   let fold=Octra_node_runtime.Set_rule.bind rules ~chain_id:chain ~parent ~epoch|>Result.get_ok in
   let ctx=fold epoch|>Result.get_ok in
   `Assoc["manifest",`String(Octra_core.Circle_wasm_host.profile_name(if get R.wasm_compute=R.Active then Manifest else Compute));
     "update_policy",mode(get R.circle);"object_cost",mode(get R.object_cost);
     "owner_migration",mode(get R.owner_migration);"cipher_migration",mode(get R.cipher_migration);"private_payload",mode(get R.private_payload);
     "math",`Bool ctx.math;"proof_exec",mode ctx.proof_exec;"float",mode ctx.wasm_float;"inspect",mode ctx.vm_bytes;"storage_proof",mode ctx.standard_mode]
 | Error e->`Assoc["error",`String e]
 | Ok _->failwith "snapshot guard unexpectedly allowed execution"
let ()=
 let inputs=Yojson.Safe.from_channel stdin|>to_list in
 let store=Lwt_main.run(S.open_store ~fresh:true "/tmp/execution-rule-oracle")in
 store.S.batch_tree<-Some(S.Store.Tree.empty());
 Lwt_main.run(S.set_meta store "total_supply" "0");Lwt_main.run(S.commit_epoch_batch store "rule oracle");
 let ledger=C.Ledger.create store in
 let cases=List.map(fun input->`Assoc["input",input;"expected",run store ledger input])inputs in
 Lwt_main.run(S.close store);Yojson.Safe.to_channel stdout(`List cases);print_newline()
