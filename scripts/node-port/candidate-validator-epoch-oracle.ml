(* SPDX-License-Identifier: BSD-3-Clause *)
(* Copyright (c) 2023-2026 Octra Labs <dev@octra.org> *)
(* Epoch_exec validator-set advance under seatless voting at the candidate:
   penalties recorded before transactions, pending-set promotion against the
   finalizing set, eviction scheduling and the snapshot. Unchanged sources. *)
open Yojson.Safe.Util
open Octra_consensus
module C=Octra_core
module S=C.Store_irmin
module T=S.Store
module L=C.Ledger
module E=C.Epoch_exec
module R=C.Validator_registry
module P=C.Validator_policy
module U=C.Validator_set_update
let s j k=member k j|>to_string
let n j k=member k j|>to_int
let b64 s=`String(Base64.encode_exn s)
let raw j k=Base64.decode_exn(s j k)
let key id=Mirage_crypto_ec.Ed25519.priv_of_octets(String.make 32(Char.chr id))|>Result.get_ok
let pub id=Mirage_crypto_ec.Ed25519.(pub_to_octets(pub_of_priv(key id)))
let address id=pub id|>Base64.encode_exn|>C.Crypto.Address.address_from_pubkey
let list j k=match member k j with `List xs->xs|_->[]
let ids j k=list j k|>List.map to_int
let option f=function None->`Null|Some v->f v
let mode j name=if member name j=`Bool true then C.Rule_graph.Active else C.Rule_graph.Prior
let dump store key=option b64(Lwt_main.run(S.get_meta store key))
let weighted j k=list j k|>List.map(fun m->to_int(member"id"m),Z.of_string(s m"weight"))
let registry input=
 let candidates=list input"candidates"|>List.map(fun c->let id=n c"id"in `Assoc[
  "address",`String(address id);"consensus_pubkey",b64(pub id);"bond",`String(s c"bond");
  "bonded_epoch",`String"0";"ready_epoch",(match member"ready"c with `String e->`String e|_->`Null);
  "exit_epoch",(match member"exit"c with `String e->`String e|_->`Null)])in
 let slashes=list input"slashes"|>List.map(fun r->`Assoc[
  "id",`String(s r"id");"offender",`String(address(n r"offender"));
  "evidence_epoch",`String(s r"evidence");"applied_epoch",`String(s r"applied");"amount",`String(s r"amount")])in
 R.of_yojson(`Assoc["standard",`String"bonded_stake";"candidates",`List candidates;"slashes",`List slashes])
 |>Result.map R.to_string
let voting members=C_types.make_weighted_validator_set(List.map(fun(id,w)->C_types.{address=address id;pubkey=pub id},w)members)
let pending j=
 let members=weighted j"members"in
 U.make_weighted ~source_epoch:(Int64.of_string(s j"source"))~activate_epoch:(Int64.of_string(s j"activate"))
  (List.map(fun(id,weight)->C.Validator_entry.{address=address id;pubkey=pub id;weight})members)
 |>Result.map U.to_string
let eviction j=
 match voting(weighted j"source_set")with Error e->Error e|Ok current->
 let source=Int64.of_string(s j"source")in
 U.make_eviction ~source_epoch:source ~activate_epoch:(Int64.succ source)~offenders:(ids j"offenders"|>List.map address)current
 |>Result.map(fun(u,_)->U.to_string u)
let catch f=try Ok(f())with Failure e->Error e|Invalid_argument e->Error("invalid_argument: "^e)
let run index input=
 let store=Lwt_main.run(S.open_store ~fresh:true(Printf.sprintf"/tmp/candidate-validator-epoch-%d"index))in
 store.S.batch_tree<-Some(T.Tree.empty());
 let ledger=L.create store in
 let chain=raw input"chain"in
 let policy=P.Bonded{activation_epoch=64;parameters=P.parameters;snapshot_interval=64L;evidence_epochs=86400L}in
 let result=match registry input with
 | Error e->`Assoc["setup_error",`String e]
 | Ok registry->
  Lwt_main.run(S.set_meta store R.meta_key registry);
  let rounds=list input"rounds"|>List.map(fun round->
   List.iter(fun w->Lwt_main.run(S.set_meta store(s w"key")(raw w"value")))(list round"meta");
   let setup=match member"pending"round,member"eviction"round with
    | `Null,`Null->Ok None
    | j,`Null->pending j|>Result.map Option.some
    | _,j->eviction j|>Result.map Option.some in
   match setup with
   | Error e->`Assoc["setup_error",`String e]
   | Ok setup->
   Option.iter(fun v->Lwt_main.run(S.set_meta store U.pending_meta_key v))setup;
   let epoch=n round"epoch"in
   let voting_set=match member"voting"round with `Null->None|_->(match voting(weighted round"voting")with Ok set->Some(epoch,set)|Error _->None)in
   let legacy=ids round"legacy"in
   let fold e=E.prior_fold e|>Result.map(fun(c:E.fold_ctx)->{c with standard_mode=mode round"standard";plan_mode=mode round"plan"})in
   let backend=E.make_live_backend ?voting_set ~validator_policy:policy ~fold store ledger in
   let env=E.{chain_id=chain;epoch_id=epoch;proposer_addr="";validator_addrs=List.map address legacy;
     validator_pubkeys=List.map(fun id->address id,Base64.encode_exn(pub id))legacy;prev_state_root=String.make 32 '\004';
     epoch_ts=1.;ready_state_root_at=None;ready_max_lag=2}in
   let before=Irmin.Type.to_string T.Hash.t(T.Tree.hash(Option.get store.batch_tree))in
   let outcome=catch(fun()->Lwt_main.run(C.Tx_savepoint.run ~ledger ~store(fun()->
     Lwt.bind(E.prepare_validator_penalties ~backend ~env)(fun()->Lwt.map(fun()->Ok())(E.advance_validator_set ~backend ~env)))))in
   let addresses=list input"candidates"|>List.map(fun c->address(n c"id"))in
   `Assoc["setup_pending",option b64 setup;"before",`String before;
    "error",(match outcome with Ok(Ok())->`Null|Ok(Error _)->`String"savepoint"|Error e->`String e);
    "root",`String(Irmin.Type.to_string T.Hash.t(T.Tree.hash(Option.get store.batch_tree)));
    "pending",dump store U.pending_meta_key;"active",dump store U.active_meta_key;
    "wait",dump store E.eviction_wait_key;"penalty_epoch",dump store"validator_penalty_epoch";
    "penalties",`List(List.map(fun a->dump store(E.validator_penalty_key a))addresses)])in
  `Assoc["registry",b64 registry;"rounds",`List rounds]in
 store.batch_tree<-None;Lwt_main.run(S.close store);result
let ()=let inputs=Yojson.Safe.from_channel stdin|>to_list in
 Yojson.Safe.to_channel stdout(`List(List.mapi(fun i input->`Assoc["input",input;"expected",run i input])inputs));print_newline()
