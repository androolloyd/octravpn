(* Real native sender, fee/value journals, Circle execution and receipt saving. *)
open Yojson.Safe.Util
module C=Octra_core
module S=C.Store_irmin
module T=S.Store
module L=C.Ledger
module Tx=C.Transaction
module Sender=Octra_node_runtime.Consensus_epoch_apply_sender
module Shell=Octra_node_runtime.Consensus_epoch_vm_shell
module VM=Octra_vm.Contract_vm
module E=Octra_circle_runtime.Circle_exec
let bytes v=Base64.decode_exn(to_string v)
let b64 s=`String(Base64.encode_exn s)
let z j key=j|>member key|>to_string|>Z.of_string
let optional j key=match j|>member key with `Null->None|v->Some(bytes v)
let tx i j=Tx.{from=bytes(j|>member "from");to_=bytes(j|>member "to");amount=z j "amount";nonce=j|>member "nonce"|>to_int;ou=z j "ou";timestamp=1.;signature=string_of_int i;public_key=None;message=optional j "params";encrypted_data=optional j "method";op_type=CircleCall}
let sorted t f=Hashtbl.fold(fun k v acc->(k,v)::acc)t[]|>List.sort compare|>List.map f
let root store=`String(Irmin.Type.to_string T.Hash.t(T.Tree.hash(Option.get store.S.batch_tree)))
let run index input=
 let store=Lwt_main.run(S.open_store ~fresh:true(Printf.sprintf "/tmp/circle-tx-%d" index))in
 let tree=Lwt_main.run(Lwt_list.fold_left_s(fun t j->T.Tree.add t (j|>member "path"|>to_list|>List.map bytes)(bytes(j|>member "value")))(T.Tree.empty())(input|>member "entries"|>to_list))in
 store.S.batch_tree<-Some tree;
 let code=let ch=open_in_bin "/oracle/counter.wasm"in let v=really_input_string ch(in_channel_length ch)in close_in ch;v in
 let circle=input|>member "circle"|>to_string in
 Lwt_main.run(S.write store["circles";circle;"program";"code_b64"](Base64.encode_exn code));
 Lwt_main.run(S.write store["circles";circle;"code_hash"](C.Circles.sha256_hex code));
 List.iter(fun a->Lwt_main.run(S.set_account store(bytes(a|>member "address"))L.{empty_account with balance=z a "balance";nonce=a|>member "nonce"|>to_int}))(input|>member "accounts"|>to_list);
 E.clear_wasm_view_storage_cache();Hashtbl.clear Octra_circle_runtime.Circle_program.loaded_cache;
 let ledger=L.create store in let before=root store in
 let mode k=if input|>member k|>to_bool then C.Rule_graph.Active else C.Rule_graph.Prior in
 let epoch=input|>member "epoch"|>to_int and now=input|>member "now"|>to_float in
 let receipts=Hashtbl.create 16 and events=ref[]and fees=ref Z.zero in
 let push tx outcome=events:=`Assoc["index",`Int(int_of_string tx.Tx.signature);"outcome",outcome]::!events in
 let handle (context:Sender.tx_context)=
  let tx=context.tx in
  C.Tx_savepoint.run ~ledger ~store(fun()->
   let saved=ref(Error()) in
   let effects=Shell.make_live_value_effects {ledger;store;add_fee=(fun fee->fees:=Z.add !fees fee)}in
   let reject ?(consume_nonce=false) ?notify_reason ?(persist_state=false) tag reason=
    saved:=Sender.savepoint_result ~accepted:false ~persist_state;
    push tx (`Assoc["rejected",`Assoc["tag",`String tag;"reason",b64 reason;"notify",(match notify_reason with None->`Null|Some s->b64 s);"consume",`Bool consume_nonce;"persist",`Bool persist_state]]);
    context.reject ~consume_nonce ?notify_reason ~persist_state tag reason in
   let confirm()=saved:=Ok();fees:=Z.add !fees tx.ou;push tx(`String"confirmed");context.confirm()in
   let deps:Shell.circle_call_deps={
    with_debited_fee=Shell.with_debited_fee ~debit:(L.debit ledger) ~reject:(fun tag reason->reject tag reason) tx;
    make_ctx=(fun tx_hash->{VM.default_ctx with byte_work=Some(Octra_vm.Byte_work.create Octra_vm.Byte_work.consensus_limits);proof_exec=mode"proof";wasm_float=mode"float";math=(input|>member"math"|>to_bool);current_epoch=epoch;tx_hash;node_id=tx.to_});
    balance=effects.balance;apply_value_effect=effects.apply;log_failed=(fun _ _ _ _->());
    reject_after_fee=Shell.reject_after_fee ~discard_fee:effects.discard_fee ~reject;
    reject=Shell.handle_direct_exec_reject ~discard:effects.discard ~reject;
    exec=(fun ~ctx call->E.execute_call ~journal:effects.program_journal ~ctx ~limit:call.Octra_vm.Call_plan.effort_limit ~inspect_mode:(mode"inspect") ~hfhe_strict:(mode"storage_proof"=C.Rule_graph.Active) store tx.to_ call.method_name call.params tx.from tx.amount);
    save=(fun ~tx_hash call result->Hashtbl.replace receipts tx_hash(Octra_vm.Receipt_view.direct_receipt_json ~epoch ~now ~target:tx.to_ ~method_name:call.Octra_vm.Call_plan.method_name result.E.receipt));
    commit=(fun result->E.commit_call_result ~float_mode:(mode"float") ~inspect_mode:(mode"inspect") ~proof_mode:(mode"storage_proof") store tx.to_ result);
    commit_effects=effects.commit;log_ok=(fun _ _ _->());confirm
   }in let open Lwt.Syntax in let*()=Shell.run_circle_call_tx deps tx in Lwt.return !saved)|>Lwt.map(fun _->())in
 let txs=input|>member "transactions"|>to_list|>List.mapi tx in
 let execute()=Lwt_list.iter_s(fun(batch:Sender.batch)->Sender.run_nonce_loop ~account_nonce:(fun address->Option.map(fun a->a.L.nonce)(L.find_opt ledger address))
  ~nonce_mismatch:(fun tx ~expected ~got->push tx(`Assoc["mismatch",`List[`Int expected;`Int got]]);Lwt.return_unit)
  ~confirm:(fun _->Lwt.return_unit)~reject:(fun _ ~notify_reason:_ ~error_type:_ ~reason:_->Lwt.return_unit)~handle batch.txs)(Sender.group txs)in
 Lwt_main.run(C.Tx_savepoint.run ~ledger ~store(fun()->Lwt.map(fun()->Ok())(execute())))|>ignore;
 let result=`Assoc["before",before;"root",root store;"events",`List(List.rev !events);"receipts",`List(sorted receipts(fun(k,v)->`List[`String k;b64 v]));"fees",`String(Z.to_string !fees);
  "accounts",`List(sorted ledger.L.cache(fun(k,v)->`List[b64 k;b64(Yojson.Safe.to_string(L.account_to_yojson v))]));"supply",`String(Z.to_string ledger.total_supply);"active",`Int ledger.active_accounts;
  "spent",`List(sorted ledger.spent_nonces(fun((addr,nonce),())->`List[b64 addr;`Int nonce]));"journal",`Bool(L.journal_active ledger)]in
 store.S.batch_tree<-None;Lwt_main.run(S.close store);result
let ()=let inputs=Yojson.Safe.from_channel stdin|>to_list in
 let results=List.mapi(fun index input->`Assoc["input",input;"expected",run index input])inputs in
 Yojson.Safe.to_channel stdout(`List results);print_newline()
