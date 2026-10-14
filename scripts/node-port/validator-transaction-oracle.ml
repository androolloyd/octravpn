(* Real Epoch_exec validator operations, sender loop and coupled savepoints. *)
open Yojson.Safe.Util
open Octra_consensus
module C=Octra_core
module S=C.Store_irmin
module T=S.Store
module L=C.Ledger
module Tx=C.Transaction
module E=C.Epoch_exec
module R=C.Validator_registry
module P=C.Validator_policy
module Sender=Octra_node_runtime.Consensus_epoch_apply_sender
let s j k=member k j|>to_string
let n j k=member k j|>to_int
let z j k=Z.of_string(s j k)
let b64 s=`String(Base64.encode_exn s)
let raw j k=Base64.decode_exn(s j k)
let key id=Mirage_crypto_ec.Ed25519.priv_of_octets(String.make 32(Char.chr id))|>Result.get_ok
let pub id=Mirage_crypto_ec.Ed25519.(pub_to_octets(pub_of_priv(key id)))
let sign id msg=Mirage_crypto_ec.Ed25519.sign ~key:(key id)msg
let address id=pub id|>Base64.encode_exn|>C.Crypto.Address.address_from_pubkey
let target j=match member"to"j with `String"escrow"->R.escrow_address|`Int id->address id|`String a->a|_->assert false
let tx chain index j=
 let from=address(n j"from")and to_=target j and amount=z j"amount"and nonce=n j"nonce"in
 let op_type=Tx.op_type_of_string(s j"op")|>Result.get_ok in
 let message=match member"raw_message"j with `String m->Some(Base64.decode_exn m)|_->
  match op_type with
  |ValidatorBond->let id=n j"from"in let signed=if member"proof_amount"j=`Null then amount else z j"proof_amount"in
    let msg=R.bond_message ~chain_id:chain ~address:from ~amount:signed ~nonce ~pubkey:(pub id)in
    Some(Yojson.Safe.to_string(`Assoc["consensus_pubkey",`String(Base64.encode_exn(pub id));"proof",`String(Base64.encode_exn(sign id msg))]))
  |ValidatorEvidence->let id=n j"offender"in
    let vote pid=let v=C_types.{chain_id=chain;epoch_id=Int64.of_int(n j"vote_epoch");round=1;vote_type=Precommit;proposal_id=String.make 32(Char.chr pid);validator=address id;signature=""}in
      {v with signature=sign id(C_hash.vote_sign_bytes v)}in
    let conflict=C_evidence.vote_conflict(vote 1)(vote 2)|>Option.get in Some(C.Validator_evidence.message conflict)
  |_->None in
 Tx.{from;to_;amount;nonce;ou=z j"ou";timestamp=1.;signature=string_of_int index;public_key=Some(Base64.encode_exn(pub(n j"from")));message;encrypted_data=None;op_type}
let sorted t f=Hashtbl.fold(fun k v acc->(k,v)::acc)t[]|>List.sort compare|>List.map f
let root store=`String(Irmin.Type.to_string T.Hash.t(T.Tree.hash(Option.get store.S.batch_tree)))
let run index input=
 let store=Lwt_main.run(S.open_store ~fresh:true(Printf.sprintf"/tmp/validator-tx-%d"index))in
 (* Starting with a captured tree avoids unrelated store boot metadata. *)
 store.S.batch_tree<-Some(T.Tree.empty());
 List.iter(fun a->Lwt_main.run(S.set_account store(address(n a"id"))L.{empty_account with balance=z a"balance";nonce=n a"nonce"}))(member"accounts"input|>to_list);
 let ledger=L.create store in let chain=raw input"chain"in
 let policy=if member"inactive"input=`Bool true then P.Inactive else P.Bonded {activation_epoch=64;parameters={P.parameters with unbonding_epochs=128L};snapshot_interval=64L;evidence_epochs=100L}in
 let result=`List(member"rounds"input|>to_list|>List.map(fun round->
  List.iter(fun v->Lwt_main.run(S.set_meta store(s v"key")(raw v"value")))(member"meta"round|>to_list);
  if member"drain_escrow"round=`Bool true then ignore(L.debit_amount_only ledger R.escrow_address(L.find_opt ledger R.escrow_address|>Option.get).balance);
  let active=member"active"round|>to_list|>List.map(fun v->address(to_int v))in
  let fold epoch=if member"fold_fail"round=`Bool true then Error"fixture anchor unavailable"else
    E.prior_fold epoch|>Result.map(fun (c:E.fold_ctx)->{c with exit_mode=(if member"exit_active"round=`Bool true then C.Rule_graph.Active else Prior);standard_mode=(if member"standard_active"round=`Bool true then C.Rule_graph.Active else Prior);members=active})in
  let backend=E.make_live_backend ~validator_policy:policy ~fold store ledger in
  let env=E.{chain_id=chain;epoch_id=n round"epoch";proposer_addr="";validator_addrs=(member"legacy_active"round|>to_list|>List.map(fun v->address(to_int v)));validator_pubkeys=[];prev_state_root="";epoch_ts=1.;ready_state_root_at=None;ready_max_lag=2}in
  let transactions=member"transactions"round|>to_list|>List.mapi(tx chain)in
  let events=ref[]and fees=ref Z.zero in
  let push tx out=events:=`Assoc["index",`Int(int_of_string tx.Tx.signature);"outcome",out]::!events in
  let handle (ctx:Sender.tx_context)=C.Tx_savepoint.run ~ledger ~store(fun()->
   let open Lwt.Syntax in let* result=E.process_standard_tx ~backend ~env ctx.tx in
   match result with
   |Ok fee->fees:=Z.add !fees fee;push ctx.tx(`String"confirmed");let*()=ctx.confirm()in Lwt.return(Ok())
   |Error(tag,reason)->push ctx.tx(`Assoc["rejected",`List[`String tag;`String reason]]);let*()=ctx.reject tag reason in Lwt.return(Error()))|>Lwt.map(fun _->())in
  let execute()=Lwt_list.iter_s(fun(batch:Sender.batch)->Sender.run_nonce_loop ~account_nonce:(fun a->Option.map(fun a->a.L.nonce)(L.find_opt ledger a))
    ~nonce_mismatch:(fun tx ~expected ~got->push tx(`Assoc["mismatch",`List[`Int expected;`Int got]]);Lwt.return_unit)
    ~confirm:(fun _->Lwt.return_unit)~reject:(fun _ ~notify_reason:_ ~error_type:_ ~reason:_->Lwt.return_unit)~handle batch.txs)(Sender.group transactions)in
  let outcome=try ignore(Lwt_main.run(C.Tx_savepoint.run ~ledger ~store(fun()->Lwt.map(fun()->Ok())(execute()))));`Assoc["events",`List(List.rev !events);"fees",`String(Z.to_string !fees)]with Failure e->`Assoc["error",`String e;"confirmed_before_error",`List(List.rev !events|>List.filter_map(fun v->if member"outcome"v=`String"confirmed"then Some(member"index"v)else None))]in
  Lwt_main.run(L.flush_dirty_lwt ledger);
  `Assoc["transactions",`List(List.map(fun tx->b64(Yojson.Safe.to_string(Tx.to_yojson tx)))transactions);"outcome",outcome;"root",root store;
   "accounts",`List(sorted ledger.L.cache(fun(k,a)->`List[b64 k;b64(Yojson.Safe.to_string(L.account_to_yojson a))]));"supply",`String(Z.to_string ledger.total_supply);
   "registry",(match Lwt_main.run(S.get_meta store R.meta_key)with None->`Null|Some v->b64 v);"retired",(match Lwt_main.run(S.get_meta store"supply_retired")with None->`Null|Some v->b64 v);
   "spent",`List(sorted ledger.spent_nonces(fun((a,n),())->`List[b64 a;`Int n]));"journal",`Bool(L.journal_active ledger)]))in
 store.S.batch_tree<-None;Lwt_main.run(S.close store);result
let ()=let inputs=Yojson.Safe.from_channel stdin|>to_list in Yojson.Safe.to_channel stdout(`List(List.mapi(fun index input->`Assoc["input",input;"expected",run index input])inputs));print_newline()
