(* Production Circle epochs, with independent child-call effort rule selection. *)
open Yojson.Safe.Util
module C=Octra_core
module S=C.Store_irmin
module L=C.Ledger
module T=C.Transaction
module E=C.Epoch_exec
module VM=Octra_node_runtime.Consensus_vm_transition
let bytes v=Base64.decode_exn(to_string v)
let b64 v=`String(Base64.encode_exn v)
let z j k=member k j|>to_string|>Z.of_string
let optional j k=match member k j with `Null->None|v->Some(bytes v)
let wasm=ref ""
let expand raw=Str.global_replace(Str.regexp_string "$COUNTER") !wasm raw
let payload j=optional j "params" |> Option.map expand
let derived j=match payload j with
 |None->"missing"
 |Some raw->try match C.Circles.deploy_payload_of_yojson(Yojson.Safe.from_string raw)with
   |Error _->"invalid"|Ok p->C.Circles.circle_id_of_deploy ~deployer:(bytes(member"from"j)) ~nonce:(member"nonce"j|>to_int) p
   with _->"invalid"
let previous=ref ""
let tx i j=T.{from=bytes(member"from"j);to_=(if bytes(member"to"j)="$derive" then derived j else if bytes(member"to"j)="$previous" then !previous else bytes(member"to"j));amount=z j"amount";nonce=member"nonce"j|>to_int;ou=z j"ou";timestamp=1.;signature=string_of_int i;public_key=None;message=payload j;encrypted_data=optional j"method";op_type=(match member"op"j|>to_string with "deploy"->CircleDeploy|"update"->CircleProgramUpdate|"call"->CircleCall|_->failwith"unknown operation")}
let sorted table f=Hashtbl.fold(fun k v xs->(k,v)::xs)table[]|>List.sort compare|>List.map f
let run index input=
 let store=Lwt_main.run(S.open_store ~fresh:true(Printf.sprintf"/tmp/epoch-circle-%d"index))in
 store.S.batch_tree<-Some(S.Store.Tree.empty());
 let tx_inputs=member"transactions"input|>to_list in
 let circle=match List.find_opt(fun j->member"op"j=`String"deploy")tx_inputs with Some j->derived j|None->"oct"^String.make 44 '3'in
 previous:=circle;
 List.iter(fun e->Lwt_main.run(S.write store(member"path"e|>to_list|>List.map(fun v->let v=bytes v in if v="$circle" then circle else v))(expand(bytes(member"value"e)))))(member"entries"input|>to_list);
 List.iter(fun a->Lwt_main.run(S.set_account store(bytes(member"address"a))L.{empty_account with balance=z a"balance";nonce=member"nonce"a|>to_int}))(member"accounts"input|>to_list);
 let supply=List.fold_left(fun total a->Z.add total(z a"balance"))Z.zero(member"accounts"input|>to_list)in
 Lwt_main.run(S.set_meta store"total_supply"(Z.to_string supply));
 Lwt_main.run(S.set_meta store"emission_remaining""0");
 Lwt_main.run(S.commit_epoch_batch store"initial Circle epoch fixture");
 Octra_circle_runtime.Circle_exec.clear_wasm_view_storage_cache();Hashtbl.clear Octra_circle_runtime.Circle_program.loaded_cache;
 let ledger=L.create store in
 let root=Lwt_main.run(S.state_hash store)in
 let mode name=if member name input=`Bool true then C.Rule_graph.Active else Prior in
 let fold epoch=E.prior_fold epoch|>Result.map(fun(f:E.fold_ctx)->{f with vm_bytes=mode"inspect";proof_exec=mode"proof";wasm_float=mode"float";fhe_work=mode"fhe_work"})in
 let backend=E.make_live_backend ~fold ~proof_mode:(mode"storage_proof") ~math:(member"math"input|>to_bool)
   ~validator_policy:C.Validator_policy.Inactive ~emission_policy:C.Emission_policy.Guard ~emission_schedule:C.Emission_schedule.Inactive store ledger in
 let reward_addr="oct"^String.make 44 '4'in
 let env=E.{chain_id="epoch-circle-fixture";epoch_id=member"epoch"input|>to_int;proposer_addr=reward_addr;validator_addrs=[reward_addr];validator_pubkeys=[];prev_state_root=root;epoch_ts=member"now"input|>to_float;ready_state_root_at=None;ready_max_lag=2}in
 let reward=E.{proposer_addr=reward_addr;proposer_public_key=None;validators=[{address=reward_addr;public_key=None;weight=Z.one}]}in
 let receipts=Hashtbl.create 10 in
 let process_tx ~backend ~env tx=VM.process_tx ~backend ~env ~circle_mode:(mode"circle_policy") ~wasm_compute_mode:(mode"wasm_compute")
   ~program_trust:Octra_vm.Program_trust.empty ~object_cost:false ~save_receipt_raw:(fun ~tx_hash ~json->Hashtbl.replace receipts tx_hash json) tx in
 let txs=member"transactions"input|>to_list|>List.mapi tx in
 let result=Lwt_main.run(E.run_core ~reward:(Some reward) ~preverify:None ~backend ~env ~txs ~process_tx)in
 let result=match result with Error e->`Assoc["error",`String e]|Ok r->`Assoc["fees",`String(Z.to_string r.artifacts.confirmed_fees);"confirmed",`List(List.map(fun(tx,p)->`List[`Int(int_of_string tx.T.signature);`Int p])r.artifacts.confirmed);"rejected",`List(List.map(fun(r:E.tx_reject)->`Assoc["index",`Int(int_of_string r.tx.signature);"type",b64 r.error_type;"reason",b64 r.reason;"charged",`Bool r.charged])r.artifacts.rejected)]in
 let deployments=List.filter_map(fun j->if member"op"j<>`String"deploy" then None else
  try match C.Circles.deploy_payload_of_yojson(Yojson.Safe.from_string(Option.get(payload j)))with
   |Error _->None|Ok p->Some(`List[`String(derived j);b64(Yojson.Safe.to_string(C.Circles.yojson_of_deploy_payload p))])
  with _->None)tx_inputs in
 let output=`Assoc["deployments",`List deployments;"before",`String root;"result",result;"root",`String(Lwt_main.run(S.state_hash store));"receipts",`List(sorted receipts(fun(k,v)->`List[`String k;b64 v]));"accounts",`List(sorted ledger.L.cache(fun(k,v)->`List[b64 k;b64(Yojson.Safe.to_string(L.account_to_yojson v))]));"supply",`String(Z.to_string ledger.total_supply);"spent",`Int(Hashtbl.length ledger.spent_nonces);"journal",`Bool(L.journal_active ledger)]in
 Lwt_main.run(S.close store);output
let ()=let input=Yojson.Safe.from_channel stdin in wasm:=member"wasm_b64"input|>to_string;let inputs=member"cases"input|>to_list in Yojson.Safe.to_channel stdout(`List(List.mapi(fun i input->`Assoc["input",input;"expected",run i input])inputs));print_newline()
