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
let option f=function None->`Null|Some v->f v
let list j k=match member k j with `List xs->xs|_->[]
let addresses j k=list j k|>List.map(fun v->address(to_int v))
let write store entries=List.iter(fun j->Lwt_main.run(S.write store (list j "path"|>List.map to_string)(raw j"value")))entries
let dump store path=option b64(Lwt_main.run(S.read store path))
let tree_hash store path=option(fun tree->`String(Irmin.Type.to_string T.Hash.t(T.Tree.hash tree)))(Lwt_main.run(S.read_tree store path))
let registry input=
 let candidates=List.init(n input"count")(fun k->let id=k+1 in `Assoc[
 "address",`String(address id);"consensus_pubkey",b64(pub id);"bond",`String(string_of_int(1000000+id));"bonded_epoch",`String"0";"ready_epoch",(if member"unready"input=`Bool true then `Null else `String"0");"exit_epoch",(if member"exited"input=`Bool true then `String"1"else `Null)])in
 R.of_yojson(`Assoc["standard",`String"bonded_stake";"candidates",`List candidates;"slashes",`List[]])|>Result.get_ok|>R.to_string
let pending j=
 C.Validator_set_update.make_weighted ~source_epoch:(i j"source") ~activate_epoch:(i j"activate")
 (addresses j "members"|>List.mapi(fun k address->C.Validator_admission.{address;pubkey=pub(to_int(List.nth(list j "members")k));weight=Z.of_int 1000000}))|>Result.get_ok|>C.Validator_set_update.to_string
let run index input=
 let store=Lwt_main.run(S.open_store ~fresh:true(Printf.sprintf"/tmp/validator-epoch-%d"index))in
 store.S.batch_tree<-Some(T.Tree.empty());
 let registry=registry input in Lwt_main.run(S.set_meta store R.meta_key registry);
 let ledger=L.create store in let chain=raw input"chain"in
 let policy=if member"inactive"input=`Bool true then P.Inactive else P.Bonded{activation_epoch=64;parameters=P.parameters;snapshot_interval=64L;evidence_epochs=86400L}in
 let results=list input "rounds"|>List.map(fun round->
  write store (list round "writes");
  let pending_raw=match member"pending"round with `Null->None|j->
    let value=pending j in let value=if member"noncanonical"j=`Bool true then "  "^value^"\n"else value in
    Lwt_main.run(S.set_meta store C.Validator_set_update.pending_meta_key value);Some value in
  (match member"head"round with `Null->()|j->
   let working=store.batch_tree in store.batch_tree<-Some(T.Tree.empty());write store(list j"entries");
   (match member"epoch"j with `String e->Lwt_main.run(S.set_meta store"last_epoch"e)|_->());
   Lwt_main.run(S.commit_epoch_batch store"fixture committed input");store.batch_tree<-working);
  let p=match member"parent"round with `Null->None|j->Some(parent j)in
  let fold epoch=if member"fold_fail"round=`Bool true then Error"fixture anchor unavailable"else
   E.prior_fold epoch|>Result.map(fun(c:E.fold_ctx)->{c with mode=mode round"duty";live_mode=mode round"live";seat_mode=mode round"seat";open_mode=mode round"open";standard_mode=mode round"standard";plan_mode=mode round"plan";vm_bytes=mode round"vm";parent=p;cap_mode=(if member"prune"round=`Bool true then C.Set_fold.Prune else Reject);members=addresses round"members";start=i round"start";profile_start=i round"start"})in
  let backend=E.make_live_backend ~validator_policy:policy ~fold store ledger in
  let env=E.{chain_id=chain;epoch_id=n round"epoch";proposer_addr="";validator_addrs=addresses round"legacy";validator_pubkeys=[];prev_state_root=raw round"previous";epoch_ts=1.;ready_state_root_at=None;ready_max_lag=2}in
  let before=Irmin.Type.to_string T.Hash.t(T.Tree.hash(Option.get store.batch_tree))in
  let outcome=try ignore(Lwt_main.run(C.Tx_savepoint.run ~ledger ~store(fun()->Lwt.map(fun()->Ok())(E.advance_validator_set ~backend ~env))));`Null
   with Failure e->`String e|Division_by_zero->`String"Division_by_zero"|Invalid_argument e->`Assoc["invalid_argument",`String e]in
  let roots=list round"queries"|>List.map(fun e->let epoch=Int64.of_string(to_string e)in let path=["compute";"roots";Int64.to_string(Int64.rem epoch 65L)]in `List[dump store(path@["meta"]);tree_hash store(path@["data"])])in
  `Assoc["setup_pending",option b64 pending_raw;"parent",option(fun p->b64(C_codec.encode_parent_commit p))p;"before",`String before;"error",outcome;"root",`String(Irmin.Type.to_string T.Hash.t(T.Tree.hash(Option.get store.batch_tree)));"duty",dump store["meta";C.Set_fold.meta_key];"pending",dump store["meta";C.Validator_set_update.pending_meta_key];"active",dump store["meta";C.Validator_set_update.active_meta_key];"roots",`List roots])in
 store.batch_tree<-None;Lwt_main.run(S.close store);`Assoc["setup_registry",b64 registry;"rounds",`List results]
let ()=let inputs=Yojson.Safe.from_channel stdin|>to_list in Yojson.Safe.to_channel stdout(`List(List.mapi(fun i input->`Assoc["input",input;"expected",run i input])inputs));print_newline()
