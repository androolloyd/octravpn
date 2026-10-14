(* Full native verification through the real isolated PVAC worker, followed by
   the native ledger application under its transaction savepoint. *)
let () = Octra_log._set_level Octra_log.FATAL
open Lwt.Syntax
open Yojson.Safe.Util
module C=Octra_core
module L=C.Ledger
module S=C.Store_irmin
module P=C.Private_ledger
let raw j k = member k j |> to_string |> Base64.decode_exn
let b64 v = `String(Base64.encode_exn v)
let nullable f = function None->`Null|Some x->f x
let failure (e:P.failure) = `Assoc["tag",`String e.tag;"reason",b64 e.reason;"user_reason",b64 e.user_reason]
let run index input =
 let* store=S.open_store ~fresh:true (Printf.sprintf "/tmp/private-balance-%d" index) in
 Lwt.finalize (fun () ->
 let address="alice" in
 let current=raw input "current" in
 let account=L.{empty_account with balance=Z.of_string(member "balance" input |> to_string);
    encrypted_balance=(if current="0" then None else Some current)} in
 let* ()=S.set_account store address account in
 let ledger=L.create store in
 let* ()=S.begin_epoch_batch store in
 let* ()=match member "public" input with `Null->Lwt.return_unit|_->L.set_pvac_pubkey ledger address (raw input "public") in
 let tx:C.Transaction.t={from=address;to_=address;amount=Z.of_string(member "amount" input |> to_string);
    nonce=member "nonce" input |> to_int;ou=Z.of_string(member "fee" input |> to_string);timestamp=1.;signature="fixture";
    public_key=None;message=None;encrypted_data=(match member "payload" input with `Null->None|_->Some(raw input "payload"));
    op_type=(if member "withdraw" input=`Bool true then DecryptOp else EncryptOp)} in
 let field_policy=if member "unique" input=`Bool true then P.Unique_fields else First_field in
 let strict=member "strict" input |> to_bool in
 let result_policy=if member "recoverable" input=`Bool true then C.Private_result_policy.Recoverable else Legacy in
 let state () = `Assoc["account",nullable(fun a->b64(Yojson.Safe.to_string(L.account_to_yojson a)))(L.find_opt ledger address);
    "supply",`String(Z.to_string ledger.total_supply);"spent",`Bool(Hashtbl.mem ledger.spent_nonces(address,tx.nonce))] in
 let before=state () in
 let verify=if tx.op_type=DecryptOp then P.decrypt_plan else P.encrypt_plan in
 let apply=if tx.op_type=DecryptOp then P.apply_decrypt_plan else P.apply_encrypt_plan in
 let prepared plan=if tx.op_type=DecryptOp then P.Prepared_decrypt plan else P.Prepared_encrypt plan in
 let* plan=verify ~math:true ~field_policy ~strict ~result_policy ledger tx in
 let* outcome=match plan with
 | Error error -> Lwt.return(`Assoc["error",failure error])
 | Ok plan ->
   let plan_json=`Assoc["current",b64 plan.current_cipher;"next",b64 plan.next_cipher;"hash",`String(P.hash_prepared(prepared plan))] in
   let ()=if member "stale" input=`Bool true then ignore(L.update_enc_balance ledger address "0") in
   let* result=C.Tx_savepoint.run ~ledger ~store (fun ()->apply ledger tx plan) in
   Lwt.return(`Assoc["plan",plan_json;"applied",(match result with Ok _->`Bool true|Error e->failure e)]) in
 let after=state () in
 let* ()=L.flush_dirty_lwt ledger in
 let root=Irmin.Type.to_string S.Store.Hash.t(S.Store.Tree.hash(Option.get store.batch_tree)) in
 let* account=S.read store["accounts";address;"data"] in
 Lwt.return(`Assoc["input",input;"expected",`Assoc["before",before;"outcome",outcome;"after",after;"root",`String root;"data",nullable b64 account]]))
 (fun ()->S.close store)
let () =
 if Sys.command "opam exec -- dune build bin/octra_pvac_worker.exe" <> 0 then failwith "worker build failed";
 Unix.putenv "OCTRA_PVAC_VERIFY_WORKER" (Filename.concat(Sys.getcwd())"_build/default/bin/octra_pvac_worker.exe");
 let rows=Yojson.Safe.from_channel stdin |> to_list in
 let results=Lwt_main.run(Lwt_list.mapi_s run rows) in
 Yojson.Safe.to_channel stdout (`List results);print_newline ()
