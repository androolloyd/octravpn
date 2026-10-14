(* Native runtime footer, real ledger journals and native Irmin writes. *)
open Yojson.Safe.Util
module C=Octra_core
module E=C.Epoch_exec
module F=Octra_node_runtime.Consensus_epoch_apply_footer
module S=C.Store_irmin
module L=C.Ledger
let bytes v=Base64.decode_exn(to_string v)
let b64 v=`String(Base64.encode_exn v)
let z j k=j|>member k|>to_string|>Z.of_string
let optional j k=match j|>member k with `Null->None|v->Some(bytes v)
let sorted t f=Hashtbl.fold(fun k v acc->(k,v)::acc)t[]|>List.sort compare|>List.map f
let root store=`String(Irmin.Type.to_string S.Store.Hash.t(S.Store.Tree.hash(Option.get store.S.batch_tree)))
let run index j=
 let store=Lwt_main.run(S.open_store ~fresh:true(Printf.sprintf "/tmp/footer-%d" index))in store.S.batch_tree<-Some(S.Store.Tree.empty());
 let meta=Hashtbl.create 10 in
 List.iter(fun entry->let values=to_list entry in let key=bytes(List.nth values 0)and value=bytes(List.nth values 1)in Hashtbl.replace meta key value;Lwt_main.run(S.set_meta store key value))(j|>member"meta"|>to_list);
 List.iter(fun a->Lwt_main.run(S.set_account store(bytes(a|>member"address"))L.{empty_account with balance=z a"balance";nonce=a|>member"nonce"|>to_int;public_key=optional a"key"}))(j|>member"accounts"|>to_list);
 let ledger=L.create store in let before=root store in
 let reward:E.reward_attribution={proposer_addr=bytes(j|>member"proposer");proposer_public_key=optional j"proposer_key";validators=j|>member"validators"|>to_list|>List.map(fun v->E.{address=bytes(v|>member"address");public_key=optional v"key";weight=z v"weight"})}in
 let policy=if j|>member"guard"|>to_bool then C.Emission_policy.Guard else C.Emission_policy.Allow in
 let schedule=match j|>member"activation"with `Null->C.Emission_schedule.Inactive|v->C.Emission_schedule.Security_curve{activation_epoch=to_int v}in
 let backend=E.make_live_backend ~emission_policy:policy ~emission_schedule:schedule store ledger in
 let deps:F.node_deps={get_meta=Hashtbl.find_opt meta;set_meta=S.set_meta store;policy;schedule;legacy_total=optional j"legacy";public_supply=(fun()->L.get_total_supply ledger);apply_footer=(fun env reward plan->E.apply_epoch_footer_with_reward ~reward ~backend ~env ~plan);log=ignore}in
 let request:F.node_request={chain_id="footer-test";epoch_id=j|>member"epoch"|>to_int;epoch_ts=1.;proposer_addr=reward.proposer_addr;validator_pubkeys=j|>member"fallback"|>to_list|>List.map(fun v->match to_list v with [a;k]->bytes a,bytes k|_->failwith"key");reward;ready_state_root_at=(fun _->Lwt.return_none);ready_max_lag=0;confirmed_fees=z j"fees";short=Fun.id}in
 let outcome=try let r=Lwt_main.run(C.Tx_savepoint.run ~ledger ~store (fun()->Lwt.map(fun r->Ok r)(F.run_node deps request)))in
 match r with Error _->failwith"unexpected footer result"|Ok r->`Assoc["fees",`String(Z.to_string r.F.plan.total_reward);"base",`String(Z.to_string r.plan.base_reward);"burned",`String(Z.to_string r.plan.fees_burned);"recipients",`List(List.map(fun r->`Assoc["address",b64 r.C.Epochlog.reward_addr;"role",`String r.reward_role;"amount",`String r.reward_amount])r.reward_recipients)]
 with Failure reason->`Assoc["error",`String reason]in
 let speculative=root store in Lwt_main.run(L.flush_dirty_lwt ledger);
 let result=`Assoc["outcome",outcome;"before",before;"speculative",speculative;"flushed",root store;"supply",`String(Z.to_string ledger.L.total_supply);"active",`Int ledger.active_accounts;"journal",`Bool(L.journal_active ledger);"accounts",`List(sorted ledger.cache(fun(k,a)->`List[b64 k;b64(Yojson.Safe.to_string(L.account_to_yojson a))]))]in
 store.S.batch_tree<-None;Lwt_main.run(S.close store);result
let ()=let cases=Yojson.Safe.from_channel stdin|>to_list|>List.mapi(fun i input->`Assoc["input",input;"expected",run i input])in Yojson.Safe.to_channel stdout(`List cases);print_newline()
