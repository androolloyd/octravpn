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
let i j k=Int64.of_string(s j k)
let z j k=Z.of_string(s j k)
let b64 s=`String(Base64.encode_exn s)
let raw j k=Base64.decode_exn(s j k)
let key id=Mirage_crypto_ec.Ed25519.priv_of_octets(String.make 32(Char.chr id))|>Result.get_ok
let pub id=Mirage_crypto_ec.Ed25519.(pub_to_octets(pub_of_priv(key id)))
let sign id msg=Mirage_crypto_ec.Ed25519.sign ~key:(key id)msg
let address id=pub id|>Base64.encode_exn|>C.Crypto.Address.address_from_pubkey
let parent j=
 let chain_id=raw j"chain"and epoch_id=i j"epoch"and round=n j"round"in
 let validators=List.init(n j"members")(fun k->C_types.{address=address(k+1);pubkey=pub(k+1)})in
 let validator_set=C_types.make_validator_set validators in
 let header=C_types.{proto_version=C_protocol.version_for_epoch epoch_id;chain_id;epoch_id;prev_state_root=String.make 32 '\001';tx_list_hash=String.make 32 '\002';receipt_root=String.make 32 '\003';proposed_state_root=String.make 32 '\004';parent_commit_hash=String.make 32 '\000';creator_addr=address 1;txid_hi=7L;ts=1.}in
 let proposal_id=C_hash.proposal_id header in
 let precommits=member"signers"j|>to_list|>List.map(fun id->let id=to_int id in let v=C_types.{chain_id;epoch_id;round;vote_type=Precommit;proposal_id;validator=address id;signature=""}in {v with signature=(if member"corrupt"j=`Bool true then String.make 64 '\000'else sign id(C_hash.vote_sign_bytes v))})in
 let certificate=C_types.{chain_id;epoch_id;commit_round=round;header;proposal_id;precommits}in
 C_types.{certificate;validator_set}
let mode j name=if member name j=`Bool true then C.Rule_graph.Active else Prior
let opt_raw j name=match member name j with `String v->Some(Base64.decode_exn v)|_->None
let root_value j name default=match opt_raw j name with Some v->v|_->default
let option f=function None->`Null|Some v->f v
let pending ()=C.Validator_set_update.make_weighted ~source_epoch:0L ~activate_epoch:64L
 (List.init 4(fun k->C.Validator_admission.{address=address(k+1);pubkey=pub(k+1);weight=Z.of_int 1000000}))|>Result.get_ok
let ready_message chain round j=
 let id=n j"from"and head=n j"head"in
 let extra=match member"extra"j with `Assoc v->v|_->[]in
 let state_root=root_value j "root" (String.make 64 'a')in
 let fields=if member"legacy"j=`Bool true then
  ["fingerprint",`String(root_value j "fingerprint"(pending()).fingerprint);"head_epoch",`String(string_of_int head);"state_root",`String state_root]
 else ["consensus_pubkey",`String(root_value j "key"(Base64.encode_exn(pub id)));"head_epoch",`String(string_of_int head);"state_root",`String state_root]in
 let fields=match member"proposal"j with
  |`String"auto"->let p=parent(member"parent"round)in fields@["head_proposal_id",`String(String.concat ""(List.init 32(fun k->Printf.sprintf "%02x"(Char.code p.certificate.proposal_id.[k]))))]
  |`String v->fields@["head_proposal_id",`String(Base64.decode_exn v)]|_->fields in
 let fields=if member"proof"j=`Bool true then
  let p=parent(member"parent"round)in let owner=if member"proof_owner"j=`Null then id else n j"proof_owner"in
  let vote=List.find(fun(v:C_types.vote)->v.validator=address owner)p.certificate.precommits in
  fields@["duty_vote",`String(Base64.encode_exn(C_codec.encode_vote vote));"duty_commit",`String(Base64.encode_exn(C_codec.encode_parent_commit p))]
 else fields in
 let _=chain in Yojson.Safe.to_string(`Assoc(fields@extra))
let target j=match member"to"j with `String"escrow"->R.escrow_address|`Int id->address id|`String a->a|_->assert false
let tx chain round index j=
 let from=address(n j"from")and to_=target j and amount=z j"amount"and nonce=n j"nonce"in
 let op_type=Tx.op_type_of_string(s j"op")|>Result.get_ok in
 let message=match member"raw_message"j with `String m->Some(Base64.decode_exn m)|_->
  match op_type with
  |ValidatorReady->Some(ready_message chain round j)
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
  let p=match member"parent"round with `Null->None|j->Some(parent j)in
  let setup=ref[]in
  let setup_meta k v=setup:=(k,v)::!setup;Lwt_main.run(S.set_meta store k v)in
  if member"pending"round=`Bool true then setup_meta C.Validator_set_update.pending_meta_key(C.Validator_set_update.to_string(pending()));
  if member"record_final"round=`Bool true then begin
   let p=Option.get p in let f=C.Set_fold.{epoch=p.certificate.epoch_id;proposal_id=p.certificate.proposal_id;set_hash=C_config.validator_set_hash p.validator_set}in
   let st=C.Set_fold.note_final C.Set_fold.standard ~at:(Int64.succ f.epoch) ~active:[] ~final:f ~signers:[] C.Set_fold.empty|>Result.get_ok in
   setup_meta C.Set_fold.meta_key(C.Set_fold.to_string st)
  end;
  let active=member"active"round|>to_list|>List.map(fun v->address(to_int v))in
  let fold epoch=if member"fold_fail"round=`Bool true then Error"fixture anchor unavailable"else
    E.prior_fold epoch|>Result.map(fun (c:E.fold_ctx)->{c with mode=mode round"duty_active";ready_mode=mode round"ready_active";ready_ref_mode=mode round"ref_active";ready_exec_mode=mode round"exec_active";live_mode=mode round"live_active";ready_config_hash=opt_raw round"config";parent=p;exit_mode=(if member"exit_active"round=`Bool true then C.Rule_graph.Active else Prior);standard_mode=(if member"standard_active"round=`Bool true then C.Rule_graph.Active else Prior);members=active})in
  let backend=E.make_live_backend ~validator_policy:policy ~fold store ledger in
  let env=E.{chain_id=chain;epoch_id=n round"epoch";proposer_addr="";validator_addrs=(member"legacy_active"round|>to_list|>List.map(fun v->address(to_int v)));validator_pubkeys=[];prev_state_root=root_value round"prev_root"(String.make 64 'a');epoch_ts=1.;ready_state_root_at=(match member"roots"round with `Null->None|`Assoc items->Some(fun head->Lwt.return(List.assoc_opt(string_of_int head)items|>Option.map(fun v->Base64.decode_exn(to_string v))))|_->assert false);ready_max_lag=(if member"max_lag"round=`Null then 2 else n round"max_lag")}in
  let transactions=member"transactions"round|>to_list|>List.mapi(tx chain round)in
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
  `Assoc["setup",`List(List.rev !setup|>List.map(fun(k,v)->`Assoc["key",`String k;"value",b64 v]));"parent",option(fun p->b64(C_codec.encode_parent_commit p))p;"duty",option b64(Lwt_main.run(S.get_meta store C.Set_fold.meta_key));"transactions",`List(List.map(fun tx->b64(Yojson.Safe.to_string(Tx.to_yojson tx)))transactions);"outcome",outcome;"root",root store;
   "accounts",`List(sorted ledger.L.cache(fun(k,a)->`List[b64 k;b64(Yojson.Safe.to_string(L.account_to_yojson a))]));"supply",`String(Z.to_string ledger.total_supply);
   "registry",(match Lwt_main.run(S.get_meta store R.meta_key)with None->`Null|Some v->b64 v);"retired",(match Lwt_main.run(S.get_meta store"supply_retired")with None->`Null|Some v->b64 v);
   "spent",`List(sorted ledger.spent_nonces(fun((a,n),())->`List[b64 a;`Int n]));"journal",`Bool(L.journal_active ledger)]))in
 store.S.batch_tree<-None;Lwt_main.run(S.close store);result
let ()=let inputs=Yojson.Safe.from_channel stdin|>to_list in Yojson.Safe.to_channel stdout(`List(List.mapi(fun index input->`Assoc["input",input;"expected",run index input])inputs));print_newline()
