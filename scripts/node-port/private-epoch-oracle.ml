(* Native private epoch admission around real balance transitions. *)
let () = Octra_log._set_level Octra_log.FATAL
open Lwt.Syntax
open Yojson.Safe.Util
module C=Octra_core
module L=C.Ledger
module S=C.Store_irmin
module P=C.Private_ledger
module E=C.Private_transition
module R=C.Preverify_receipt
let raw j k=member k j |> to_string |> Base64.decode_exn
let b64 v=`String(Base64.encode_exn v)
let run index input =
 let* store=S.open_store ~fresh:true(Printf.sprintf "/tmp/private-epoch-%d" index) in
 Lwt.finalize(fun () ->
 let address="alice" in
 let* ()=S.set_account store address L.{empty_account with balance=Z.of_int 100;encrypted_balance=Some(raw input "current")} in
 let ledger=L.create store in
 let* ()=S.begin_epoch_batch store in
 let* ()=if member "bound" input=`Bool true then L.set_pvac_pubkey ledger address(raw input "public") else Lwt.return_unit in
 let tx:C.Transaction.t={from=address;to_=(if member "self" input=`Bool true then address else "elsewhere");
  amount=Z.of_int 7;nonce=(if member "warmup" input=`String "none" then 1 else 2);ou=Z.of_int 2;timestamp=1.;signature="fixture";public_key=None;message=None;
  encrypted_data=Some(raw input "payload");op_type=(match member "operation" input with `String "private"->PrivateOp|`String "recrypt"->RecryptOp|_->if member "withdraw" input=`Bool true then DecryptOp else EncryptOp)} in
 let active=member "active" input=`Bool true in
 let field_policy=if member "unique" input=`Bool true then P.Unique_fields else First_field in
 let prepare=if tx.op_type=DecryptOp then P.prepare_decrypt_plan else P.prepare_encrypt_plan in
 let pack plan=if tx.op_type=DecryptOp then P.Prepared_decrypt plan else P.Prepared_encrypt plan in
 let gate=member "gate" input |> to_string in
 let* expected=if gate="match" then
   let* p=prepare ~field_policy ~cap:active ledger tx in
   Lwt.return(Some(P.hash_prepared(pack(Result.get_ok p))))
  else Lwt.return(if gate="wrong" then Some(String.make 64 'a') else None) in
 let root=Irmin.Type.to_string S.Store.Hash.t(S.Store.Tree.hash(Option.get store.batch_tree)) in
 let* key=L.get_pvac_key_hash ledger address in
 let state:R.state={pre_state_hash=C.Preverify_worker.state_hash root;
   source_cipher_hash=Digestif.SHA256.(digest_string(raw input "current") |> to_hex);pvac_key_hash=Option.value key ~default:(String.make 64 '0');transition_hash=expected} in
 let state=if gate="unbound" then None else Some state in
 let input_hash,output_hash=match state with None->C.Preverify_worker.input_hash tx,C.Preverify_worker.output_hash tx "ok"
  |Some s->C.Preverify_worker.bound_input_hash tx s,C.Preverify_worker.bound_output_hash tx s "ok" in
 let receipt:R.t={tx_hash=C.Transaction.hash tx;lane=C.Resource_lanes.of_op tx.op_type;engine="";input_hash;output_hash;
   state;circle=None;ok=true;reason="";cost=C.Resource_lanes.cost tx} in
 let receipt={receipt with engine=R.expected_engine receipt} in
 let preverify=if gate="none" then None else Some(C.Preverify_commit.create(if gate="empty" then [] else [receipt])) in
 let ctx=E.create ~preverify ~legacy_replay:(fun ~epoch:_ ~address:_ ~cipher:_->failwith "unexpected replay")
  ~ledger ~epoch_id:1 ~owner_migration_mode:C.Rule_graph.Active ~cipher_mode:C.Rule_graph.Active
  ~proof_mode:(if active then Active else Prior) ~math:true ~field_policy ~result_policy:C.Private_result_policy.Recoverable
  ~limits:E.{max_fhe=member "max_fhe" input |> to_int;max_stealth=10} in
 let backend=C.Epoch_exec.make_live_backend store ledger in
 let env:C.Epoch_exec.env={chain_id="private-epoch";epoch_id=1;proposer_addr=address;validator_addrs=[];validator_pubkeys=[];
   prev_state_root=root;epoch_ts=1.;ready_state_root_at=None;ready_max_lag=8} in
 let execute tx=C.Tx_savepoint.run ~ledger ~store(fun ()->E.process ctx ~backend ~env tx) in
 let* ()=match member "warmup" input |> to_string with
  | "none" -> Lwt.return_unit
  | op -> let first={tx with nonce=1;to_=address;op_type=(if op="decrypt" then DecryptOp else EncryptOp)} in
    let* result=execute first in ignore(Result.get_ok result);Lwt.return_unit in
 let ()=match member "key_fault" input with
  | `String fault -> let hash=Option.get key in
    let path=Filename.concat(Filename.concat store.S.pvac_dir "blobs")(hash^".pk") in
    if fault="missing" then Sys.remove path else
      let channel=open_out_bin path in output_string channel "corrupt";close_out channel
  | _ -> () in
 let* outcome=Lwt.catch (fun () -> let* result=execute tx in
   Lwt.return(match result with Ok fee->`Assoc["fee",`String(Z.to_string fee)]|Error(tag,reason)->`Assoc["tag",`String tag;"reason",b64 reason]))
   (fun error->Lwt.return(`Assoc["exception",b64(Printexc.to_string error)])) in
 let* ()=L.flush_dirty_lwt ledger in
 Lwt.return(`Assoc["input",input;"expected",`Assoc["receipt",(if gate="none"||gate="empty" then `Null else b64(R.canonical receipt));
  "outcome",outcome;
  "account",b64(Yojson.Safe.to_string(L.account_to_yojson(Option.get(L.find_opt ledger address))));
  "root",`String(Irmin.Type.to_string S.Store.Hash.t(S.Store.Tree.hash(Option.get store.batch_tree)))]]))
 (fun ()->S.close store)
let () =
 if Sys.command "opam exec -- dune build bin/octra_pvac_worker.exe"<>0 then failwith "worker build failed";
 Unix.putenv "OCTRA_PVAC_VERIFY_WORKER"(Filename.concat(Sys.getcwd())"_build/default/bin/octra_pvac_worker.exe");
 let inputs=Yojson.Safe.from_channel stdin |> to_list in
 let rows=Lwt_main.run(Lwt_list.mapi_s run inputs) in
 Yojson.Safe.to_channel stdout(`List rows);print_newline()
