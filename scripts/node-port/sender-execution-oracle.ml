module Core=Octra_core
module Tx=Core.Transaction
module L=Core.Ledger
module Store=Core.Store_irmin
module Sender=Octra_node_runtime.Consensus_epoch_apply_sender
open Yojson.Safe.Util
let field v k=member k v
let text v k=field v k|>to_string
let bytes v k=text v k|>Base64.decode_exn
let b64 v=`String(Base64.encode_exn v)
let n v k=text v k|>int_of_string
let z v k=text v k|>Z.of_string
let tx_of i v=Tx.{from=bytes v"from";to_=bytes v"to";amount=z v"amount";nonce=n v"nonce";ou=z v"ou";timestamp=1.;signature=string_of_int i;public_key=None;message=None;encrypted_data=None;op_type=Tx.op_type_of_string(text v"op")|>Result.get_ok}
let sorted table convert=Hashtbl.fold(fun k v acc->(k,v)::acc)table[]|>List.sort compare|>List.map convert
let state ledger store=`Assoc[
 "accounts",`List(sorted ledger.L.cache(fun(address,account)->`List[b64 address;b64(Yojson.Safe.to_string(L.account_to_yojson account))]));
 "supply",`String(Z.to_string ledger.total_supply);"active",`Int ledger.active_accounts;
 "spent",`List(sorted ledger.spent_nonces(fun((address,nonce),())->`List[b64 address;`String(string_of_int nonce)]));
 "marker",(match Lwt_main.run(Store.read store["test";"marker"])with None->`Null|Some v->b64 v);
 "burn",(match Lwt_main.run(Store.get_meta store"op01_2026_burn_executed")with None->`Null|Some v->b64 v);
 "counter",`String(Int64.to_string !(store.Store.stealth_counter));"journal",`Bool(L.journal_active ledger)]
let run index input=
 let store=Lwt_main.run(Store.open_store ~fresh:true(Printf.sprintf"/tmp/sender-oracle-%d"index))in
 let accounts=field input"accounts"|>to_list in
 List.iter(fun v->Lwt_main.run(Store.set_account store(bytes v"address")L.{empty_account with balance=z v"balance";nonce=n v"nonce"}))accounts;
 let ledger=L.create store in Lwt_main.run(Store.begin_epoch_batch store);
 let raw=field input"transactions"|>to_list|>Array.of_list in let txs=Array.mapi tx_of raw|>Array.to_list in
 let events=ref[]in
 let push tx outcome=events:=`Assoc["index",`Int(int_of_string tx.Tx.signature);"outcome",outcome]::!events in
 let nullable=function None->`Null|Some v->`String v in
 let rejection ?notify_reason ?(consume_nonce=false) ?(persist_state=false) tag reason=`Assoc["rejected",`Assoc["tag",`String tag;"reason",`String reason;"notify",nullable notify_reason;"consume",`Bool consume_nonce;"persist",`Bool persist_state]]in
 let handle (ctx:Sender.tx_context)=
  let tx=ctx.tx in let action=text raw.(int_of_string tx.signature)"action"in
  Core.Tx_savepoint.run ~ledger ~store(fun()->
   let finish accepted persist callback=let open Lwt.Syntax in let*()=callback in Lwt.return(Sender.savepoint_result ~accepted ~persist_state:persist)in
   if action="public"then(match Core.Ledger_apply.apply_epoch_public ledger tx with
    |Accepted a->push tx(`Assoc["confirmed",(match a.created_account with None->`Null|Some v->b64 v)]);finish true true(ctx.confirm())
    |Rejected r->push tx(rejection ~notify_reason:r.notify_reason r.tag r.reason);finish false false(ctx.reject ~notify_reason:r.notify_reason r.tag r.reason))
   else let open Lwt.Syntax in
    let*()=Store.write store["test";"marker"]tx.signature in store.stealth_counter:=Int64.succ !(store.stealth_counter);
    ignore(L.credit ledger"host-account"(Z.of_int 5));
    match action with
    |"confirm"->push tx(`Assoc["confirmed",`Null]);finish true true(ctx.confirm())
    |"reject"|"consume"|"persist"->let consume_nonce=action="consume"and persist_state=action="persist"in
      push tx(rejection ~consume_nonce ~persist_state "host_rejected" "fixture refusal");finish false persist_state(ctx.reject ~consume_nonce ~persist_state "host_rejected" "fixture refusal")
    |"defer"->push tx(`Assoc["deferred",`Bool true]);finish false false(ctx.continue_after_reject ~consume_nonce:true)
    |"error"->Lwt.fail_with"fixture host failure"
    |_ ->failwith"unknown fixture action")|>Lwt.map(fun _->())in
 let execute()=Lwt_list.iter_s(fun(batch:Sender.batch)->Sender.run_nonce_loop ~account_nonce:(fun address->Option.map(fun a->a.L.nonce)(L.find_opt ledger address))
  ~nonce_mismatch:(fun tx ~expected ~got->push tx(`Assoc["mismatch",`List[`String(string_of_int expected);`String(string_of_int got)]]);Lwt.return_unit)
  ~confirm:(fun _->Lwt.return_unit)~reject:(fun _ ~notify_reason:_ ~error_type:_ ~reason:_->Lwt.return_unit)~handle batch.txs)(Sender.group txs)in
 let outcome=try ignore(Lwt_main.run(Core.Tx_savepoint.run ~ledger ~store(fun()->Lwt.map(fun()->Ok())(execute()))));`Assoc["events",`List(List.rev!events)]with Failure reason->`Assoc["error",`String reason]in
 let result=`Assoc["outcome",outcome;"state",state ledger store]in Lwt_main.run(Store.close store);result
let ()=let inputs=Yojson.Safe.from_file Sys.argv.(1)|>to_list in print_endline("ORACLE_RESULT="^Yojson.Safe.to_string(`List(List.mapi(fun index input->`Assoc["input",input;"output",run index input])inputs)))
