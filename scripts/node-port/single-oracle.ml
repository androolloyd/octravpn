(* Calls pristine native Single source/sender/footer/Tree and Irmin, without CLI
   chain-policy patches. Private prior-module fixtures are not public chains. *)
open Yojson.Safe.Util
module C=Octra_core
module R=Octra_node_runtime
module S=C.Store_irmin
module L=C.Ledger
module E=C.Epoch_exec
module T=C.Transaction
module Source=R.Consensus_epoch_apply_source
module Shared=R.Consensus_epoch_apply_shared
module Finish=R.Consensus_epoch_apply_finalize
module Proposer=R.Consensus_epoch_apply_proposer
let run=Lwt_main.run
let b64 raw=`String(Base64.encode_exn raw)
let int j k=member k j|>to_int
let text j k=member k j|>to_string
let bytes v=Base64.decode_exn(to_string v)
let optional j k=match member k j with `Null->None|v->Some(to_string v)
let pub id=Mirage_crypto_ec.Ed25519.(priv_of_octets(String.make 32(Char.chr id))|>Result.get_ok|>pub_of_priv|>pub_to_octets)|>Base64.encode_exn
let addr id=C.Crypto.Address.address_from_pubkey(pub id)
let tx input=
 let id=int input "from" in
 let value=T.{from=addr id;to_=(match member "to" input with `Int id->addr id|v->to_string v);amount=Z.of_string(text input "amount");nonce=int input "nonce";ou=Z.of_string(text input "ou");timestamp=10.;signature="";public_key=Some(pub id);message=optional input "message";encrypted_data=optional input "encrypted";op_type=T.op_type_of_string(text input "op")|>Result.get_ok}in
 T.sign_with_privkey value(Base64.encode_exn(String.make 32(Char.chr id)))
let root store=Option.get(run(S.get_batch_tree_hash store))
let head store=let c=run(S.Store.Head.get store.S.store)in `Assoc["hash",`String(Irmin.Type.to_string S.Store.Hash.t(S.Store.Commit.hash c));"date",`Intlit(Int64.to_string(S.Store.Info.date(S.Store.Commit.info c)));"message",`String(S.Store.Info.message(S.Store.Commit.info c))]
let output_accounts ledger=Hashtbl.fold(fun address account acc->(address,account)::acc)ledger.L.cache[]|>List.sort compare|>List.map(fun(address,account)->`List[b64 address;b64(Yojson.Safe.to_string(L.account_to_yojson account))])
let source rules epoch txs=Source.choose Source.{rules;check_override_receipts=(fun ~epoch_id:_ ~receipts:_ _->Error"unreachable override");find_finalized=(fun _->None);cached_bundle=(fun _->None);receipt_root_matches=(fun _ _->false);header_has_empty_bundle=(fun _->false);staging_txs=(fun()->txs)} Source.{epoch_id=epoch;override_ordered_txs=None;override_receipts_json=None;consensus_mode=false}
let case index input=
 let dir=Printf.sprintf "/tmp/single-native-%d" index in Unix.mkdir dir 0o700;
 let store=run(S.open_store ~fresh:true(Filename.concat dir "ledger"))in
 store.S.batch_tree<-Some(S.Store.Tree.empty());
 let metadata=["last_epoch",string_of_int(int input "epoch"-1);"current_epoch",string_of_int(int input "epoch");"emission_remaining",(match optional input "emission"with None->"0"|Some s->s);"total_supply","100000000000"]in
 List.iter(fun(k,v)->run(S.set_meta store k v))metadata;
 List.iter(fun id->run(S.set_account store(addr id)L.{empty_account with balance=Z.of_int(if id=4||id=5 then 0 else 1000000);public_key=Some(pub id);encrypted_balance=(if id=1 then match member "private" input with `Null->None|data->Some(bytes(member "current" data)) else None)}))[1;2;4;5];
 (match member "private" input with `Null->()|data->run(S.set_pvac_pubkey store(addr 1)(bytes(member "public" data))));
 run(S.commit_epoch_batch store "genesis");
 let before=run(S.state_hash store)and before_commit=head store in
 let chain="octra-single-local-native-oracle"and epoch=int input "epoch"in
 let rules=C.Rule_graph.create ~chain_id:chain ~root_at:(fun _->C.Rule_graph.Missing)in
 let chaindata=C.Store_chaindata.open_chaindata(Filename.concat dir "chain")in
 let ledger=L.create store in let txs=member "txs" input|>to_list|>List.map tx in
 let pairs=[addr 4,pub 4;addr 5,pub 5]in
 let selected=Proposer.choose Proposer.{epoch_id=epoch;consensus_mode=false;active_validators=List.map fst pairs;env_fee_recipient=optional input "fee";override_proposer=None;pending_proposer=None;finalized_header_proposer=None;disk_epoch=None}|>Result.get_ok in
 let proposer=selected.Proposer.proposer.C.Epochlog.creator_addr in
 let confirmed=ref[]and fees=ref Z.zero and processed=ref[]and total=ref 0 and pending=ref[]in
 let defers=Hashtbl.create 16 in
 List.iter(fun item->match to_list item with [id;count]->Hashtbl.replace defers(T.hash(List.nth txs(to_int id)))(to_int count)|_->assert false)(member "defer_counts" input|>to_list);
 R.Preverify_cache.retain(fun _->false);
 let ranges=match member "private" input with `Null->`Null|data->
  let module F=C.Crypto.FheBalance in
  let pk=F.load_pubkey_result(bytes(member "public" data))|>Result.get_ok in
  let current=bytes(member "current" data)in
  let transaction=List.hd txs in
  let payload=C.Crypto.PrivateTransferV4.of_json(Yojson.Safe.from_string(Option.get transaction.T.encrypted_data))|>Result.get_ok in
  let delta=F.decode_cipher ~cap:false payload.C.Crypto.PrivateTransferV4.delta_cipher|>Result.get_ok in
  let next=F.withdraw_with_pubkey ~cap:false ~result_policy:C.Private_result_policy.Recoverable pk ~current_cipher:(Some current) ~delta_cipher:delta|>Result.get_ok in
  let delta_ok=F.verify_range ~math:false ~strict:false pk payload.delta_cipher payload.range_proof_delta in
  let balance_ok=F.verify_range ~math:false ~strict:false pk next payload.range_proof_balance in
  R.Preverify_cache.insert_with_cap ~math:false (T.hash transaction)(Lwt.return(R.Preverify_cache.Checked {delta_ok;balance_ok;strict=false;math=false;sender_enc_snapshot=current}));
  `List[`Bool delta_ok;`Bool balance_ok]in
 let result=try match source rules epoch txs with
 |Error(Source.Outcome_invalid reason)->`Assoc["error",`String reason]
 |Error _->failwith"unexpected Single source refusal"
 |Ok selected->
  let ordered=C.Tx_outcome.executed ~confirmed:selected.Source.txs selected.rejections in
  run(S.begin_epoch_batch store);C.Store_chaindata.begin_batch chaindata;L.clear_spent_nonces ledger;
  let env=R.Consensus_epoch_apply_env.standard ~chain_id:chain ~epoch_id:epoch ~proposer_addr:proposer ~validator_pubkeys:pairs ~prev_state_root:before ~ready_state_root_at:(fun _->Lwt.return_none) ~ready_max_lag:10 in
  let result=run(Shared.run_node Shared.{ledger;store;chaindata;program_trust=Octra_vm.Program_trust.empty;rules;wallet_addr=addr 4;pre_state_hash=before;standard_env=(fun()->env);current_epoch=(fun()->epoch);consensus_mode=false;max_fhe_per_epoch=int input "fhe";max_stealth_per_epoch=int input "stealth";max_stealth_defer=int input "max_defer";stealth_inline_verify_allowed=false;fhe_in_epoch_counter=ref 0;stealth_in_epoch_counter=ref 0;stealth_defer_count=defers;pending_tx_saves=pending;total_tx_count=total;confirmed_fees=fees;processed_hashes=processed;short=Fun.id;log_shared=(fun ~tx_count:_->());fatal=failwith;exit=(fun()->failwith"unexpected exit");notify_new_account=ignore;notify_confirmed=(fun tx _->confirmed:=tx::!confirmed);notify_rejected=(fun _ _->());legacy_replay=(fun ~epoch:_ ~address ~cipher:_->C.Pvac_legacy_public_replay.replay_history ~addr:address []);private_result_policy=(fun _->C.Private_result_policy.Recoverable)}ordered)in
  let reward=R.Consensus_reward_attribution.full_set ~proposer_addr:proposer ~validator_pubkeys:pairs in
  let tree=ref(C.Tree.create ~epoch_id:epoch ~parent_commit:"GENESIS")in
  let get_meta name=run(S.get_meta store name)in
  let backend=E.make_live_backend ~emission_policy:C.Emission_policy.Allow ~emission_schedule:C.Emission_schedule.Inactive store ledger in
  let effects:Finish.effects={footer={get_meta;set_meta=S.set_meta store;policy=C.Emission_policy.Allow;schedule=C.Emission_schedule.Inactive;legacy_total=None;public_supply=(fun()->L.get_total_supply ledger);apply_footer=(fun env reward plan->E.apply_epoch_footer_with_reward ~reward ~backend ~env ~plan);log=ignore};tree={now=(fun()->10.);log=ignore;record_epoch_complete=(fun _ _->());notify_new_epoch=(fun _ _->());notify_epoch_finalized=(fun _ _->())};hash=(fun()->L.hash ledger)}in
  let finalized=run(Finish.run effects Finish.{tree_ref=tree;chain_id=chain;epoch_id=epoch;epoch_ts=0.;epoch_start=0.;proposer_addr=proposer;validator_addr=addr 4;validator_pubkeys=pairs;active_validators=List.map fst pairs;reward;ready_state_root_at=(fun _->Lwt.return_none);ready_max_lag=10;confirmed_fees= !fees;confirmed_txs=List.rev !confirmed;deferred_count=List.length !(result.Shared.deferred_stealth_txs);short=Fun.id})in
  let speculative=root store in run(L.flush_dirty_lwt ledger);let flushed=root store in run(S.commit_epoch_batch store(Printf.sprintf"epoch_%d"epoch));
  C.Store_chaindata.commit_batch chaindata;
  let rejected=List.filter_map(fun tx->match C.Store_chaindata.get_rejected_tx chaindata(T.hash tx)with None->None|Some(_,_,_,_,kind,reason,_,_)->Some(`Assoc["hash",`String(T.hash tx);"type",b64 kind;"reason",b64 reason]))txs in
  `Assoc["tree_state_hash",`String finalized.Finish.state_hash;"speculative",`String speculative;"ledger_root",`String flushed;"commit",head store;"legacy_digest",`String finalized.tree.new_commit;"fees",`String(Z.to_string !fees);"confirmed",`List(List.rev_map(fun tx->`String(T.hash tx))!confirmed);"processed",`List(List.map(fun s->`String s)!processed);"deferred",`List(List.map(fun t->`String(T.hash t))!(result.deferred_stealth_txs));"defer_counts",`List(Hashtbl.fold(fun h n xs->`List[`String h;`Int n]::xs)defers[]|>List.sort compare);"accounts",`List(output_accounts ledger);"rejected",`List rejected]
 with error->`Assoc["exception",`String(Printexc.to_string error)]in
 store.S.batch_tree<-None;C.Store_chaindata.close chaindata;run(S.close store);
 `Assoc["input",input;"before",`String before;"before_commit",before_commit;"metadata",`List(List.map(fun(k,v)->`List[`String k;`String v])metadata);"transactions",`List(List.map(fun t->b64(Yojson.Safe.to_string(T.to_yojson t)))txs);"proposer",b64 proposer;"cached_ranges",ranges;"result",result]
let ()=let values=Yojson.Safe.from_channel stdin|>to_list|>List.mapi case in Yojson.Safe.to_channel stdout(`List values);print_newline()
