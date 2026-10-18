(* Test-host callbacks around unchanged native execution. Initial workload is
   empty/Standard only. Unsupported operations return unavailable before voting;
   no private/Circle/proof success is manufactured by this host. *)
open Lwt.Syntax
open Lwt.Infix
open Fixture
module R = Octra_node_runtime.Consensus_reward_attribution
module VM = Octra_node_runtime.Consensus_vm_transition
module QC = N.C_qc
module Parent = N.C_parent_commit
module Types = N.C_types
module Hash = N.C_hash
module Codec = N.C_codec

type bundle = { hashes:string list; txs:T.t list; receipts:string list }
type t = {
  data:string; chain_id:string; validators:Types.validator_set;
  keys:(string*string) list; store:S.t; ledger:L.t; chain:SC.t;
  mutable head:HM.t; bundles:(string,bundle) Hashtbl.t;
  verified:(string,string) Hashtbl.t; lock:Lwt_mutex.t;
}
let limits=P.limits ~max_txs:100000 ~max_bytes:50000000 ~max_ou:(Z.of_string "10000000000")
let only_supported txs =
  if List.exists (fun tx -> tx.T.op_type<>T.Standard) txs then
    failwith "fixture_operation_unavailable: initial mixed workload is Standard only"
let cert_path state epoch = Filename.concat state.data (Printf.sprintf "cert-%020Ld.bin" epoch)
let load_final state epoch =
  let path=cert_path state epoch in
  if not(Sys.file_exists path) then None else
    let c=open_in_bin path in Fun.protect ~finally:(fun()->close_in c) (fun()->Some(Codec.decode_finalize(really_input_string c (in_channel_length c))))
let verify_qc state (final:Types.finalize) =
  let verify_vote (vote:Types.vote) = match Types.pubkey_of_addr state.validators vote.Types.validator with
    | None->false |Some key->Hash.verify_vote ~pubkey_raw:key vote in
  match QC.validate_persisted_finalize ~chain_id:state.chain_id ~validator_set:state.validators ~verify_vote final with
  | QC.Valid->() |QC.Invalid why->failwith("native_qc:"^why)
let parent state epoch =
  if N.C_protocol.version_for_epoch epoch=Types.proto_version_parent_legacy then None
  else if epoch=0L then None
  else match load_final state (Int64.pred epoch) with
    |None->failwith "native authenticated parent unavailable"
    |Some final->verify_qc state final;Some Types.{certificate=Types.certificate_of_finalize final;validator_set=state.validators}
let verify_parent state ~epoch_id value =
  try
    if epoch_id<>Int64.of_int(state.head.epoch_id+1) then Error "nonconsecutive parent"
    else if N.C_protocol.version_for_epoch epoch_id=Types.proto_version_parent_legacy then
      if Option.is_none value then Ok() else Error "legacy parent unexpected"
    else match value,parent state epoch_id with
      |Some candidate,Some expected ->
        let wanted=Parent.{chain_id=state.chain_id;epoch_id=Int64.pred epoch_id;
          proposal_id=expected.certificate.proposal_id;state_root=raw state.head.state_root;
          validator_set_hash=N.C_config.validator_set_hash state.validators} in
        (match Parent.validate wanted candidate with Parent.Valid->Ok()|Parent.Invalid why->Error why)
      |None,None->Ok()|_->Error "native parent missing"
  with Failure why->Error why
let public_key state tx = match tx.T.public_key with
  |Some value->Some value
  |None->Option.bind(L.find_opt state.ledger tx.from)(fun a->a.L.public_key)
let verify_bundle state (header:Types.epoch_header) bundle =
  only_supported bundle.txs;
  if List.map T.hash bundle.txs<>List.map raw_hex bundle.hashes then failwith "bundle transaction hash/order mismatch";
  if P.tx_list_hash(List.map T.hash bundle.txs)<>header.Types.tx_list_hash then failwith "bundle header hash mismatch";
  let deps=P.{public_key_for_tx=public_key state;
    verify_address_pubkey=(fun ~addr ~pubkey->Core.Crypto.Address.address_from_pubkey pubkey=addr);
    verify_tx_signature=(fun tx ~pubkey->T.verify tx pubkey)} in
  match P.verify_bundle deps ~limits ~header ~expected_tx_count:(List.length bundle.hashes) bundle.txs bundle.receipts with
  |Error _->failwith "native bundle verification rejected"
  |Ok checked->only_supported checked.inputs;checked
let run_on state store ledger (header:Types.epoch_header) parent (checked:P.verified_bundle) =
  let epoch=Int64.to_int header.Types.epoch_id in
  if epoch<1 || Int64.of_int epoch<>header.epoch_id then failwith "fixture epoch range";
  let root_at h = if h=0 then Core.Rule_graph.Root (genesis_root (Yojson.Safe.from_file(Filename.concat state.data "fixture-genesis.json"))) else Core.Rule_graph.Missing in
  let rules=Core.Rule_graph.create ~chain_id:state.chain_id ~root_at in
  let fold=ok(Octra_node_runtime.Set_rule.bind rules ~chain_id:state.chain_id ~parent ~epoch) in
  let backend=E.make_live_backend ~fold ~validator_policy:Core.Validator_policy.Inactive
    ~emission_policy:Core.Emission_policy.Guard ~emission_schedule:Core.Emission_schedule.Inactive store ledger in
  let backend={backend with E.sender_key_activation_epoch=Some 0} in
  let env=P.epoch_exec_env ~chain_id:state.chain_id ~epoch_id:header.epoch_id ~epoch_ts:header.ts
    ~proposer:header.creator_addr ~validator_pubkeys:state.keys ~prev_state_root:state.head.state_root
    ~ready_state_root_at:(fun _->Lwt.return_none) ~ready_max_lag:10 in
  let reward=ok(R.resolve_for_epoch ~chain_id:state.chain_id ~epoch_id:header.epoch_id
    ~proposer_addr:header.creator_addr ~validator_pubkeys:state.keys parent) in
  let process_tx ~backend ~env tx=VM.process_tx ~preverify:checked.P.preverify ~backend ~env
    ~circle_mode:Core.Rule_graph.Prior ~wasm_compute_mode:Core.Rule_graph.Active
    ~program_trust:Octra_vm.Program_trust.empty ~object_cost:false
    ~save_receipt_raw:(fun ~tx_hash:_ ~json:_->failwith "unexpected VM receipt in Standard-only fixture") tx in
  let* result=E.run_core ~reward:(Some reward) ~preverify:(Some checked.preverify)
    ~backend ~env ~txs:checked.inputs ~process_tx in
  let result=ok result in
  let confirmed=List.map fst result.E.artifacts.confirmed in
  let rejected=List.map(fun(r:E.tx_reject)->r.tx,r.error_type,r.reason)result.artifacts.rejected in
  let charged=List.filter_map(fun(r:E.tx_reject)->if r.charged then Some r.tx else None)result.artifacts.rejected in
  let outcomes=ok(Core.Tx_outcome.build ~charged ~inputs:checked.inputs rejected) in
  if List.map T.hash confirmed<>List.map T.hash checked.txs
     || not(Core.Tx_outcome.equal outcomes checked.rejections) then failwith "native execution outcome mismatch";
  let start=SC.next_txid state.chain in
  let epoch_hash,index=EI.next_root_from_hashes_i64 ~prev:(Option.get state.head.epoch_index_root)
    ~epoch_id:header.epoch_id ~start_txid:start (List.map T.hash confirmed) in
  let folded=EI.folded_state_root ~ledger_state_root:result.post_state_root ~epoch_index_root:index in
  Lwt.return(result,confirmed,epoch_hash,index,folded)
let preview state header parent bundle =
  let checked=verify_bundle state header bundle in
  Core.State_preview.with_state ~base_store:state.store ~base_ledger:state.ledger
    ~epoch_id:(Int64.to_int header.Types.epoch_id) ~proposal_id:(raw_hex(Hash.proposal_id header))
    ~expected_prev_root:(HM.ledger_state_root state.head)
    (fun store ledger->let* result=run_on state store ledger header parent checked in Lwt.return_ok result)
  >|= ok
let check_time state (proposal:Types.propose) =
  let previous=Some(ok(N.Epoch_time.of_seconds state.head.ts)) in
  let kind=if Option.is_none proposal.Types.valid_round then N.Epoch_time.Fresh else Reproposal in
  ignore(ok(N.Epoch_time.check_proposal
    ~rule:(N.C_epoch_time_policy.rule_for_epoch ~chain_id:state.chain_id ~epoch_id:proposal.epoch_id)
    ~kind ~now:(Unix.gettimeofday()) ~previous ~candidate:proposal.header.ts))
let check_header state (proposal:Types.propose) =
  if proposal.Types.header.prev_state_root<>raw state.head.state_root then failwith "native previous root differs";
  ignore(ok(verify_parent state ~epoch_id:proposal.epoch_id proposal.parent_commit));
  check_time state proposal
let validate state (proposal:Types.propose) bundle =
  check_header state proposal;
  let* _,_,_,_,folded=preview state proposal.Types.header proposal.parent_commit bundle in
  if raw folded<>proposal.header.proposed_state_root then failwith "native speculative root mismatch";
  let expected=Int64.add state.head.txid_hi(Int64.of_int(List.length bundle.txs)) in
  if proposal.header.txid_hi<>expected then failwith "native speculative txid mismatch";
  Hashtbl.replace state.bundles (Hash.proposal_id proposal.header) bundle;
  Hashtbl.replace state.verified (Hash.proposal_id proposal.header) state.head.state_root;
  Lwt.return_unit
let publish state (final:Types.finalize) bundle =
  verify_qc state final;
  let proposal=Types.{chain_id=final.chain_id;epoch_id=final.epoch_id;round=final.commit_round;valid_round=None;
    header=final.header;tx_hashes=bundle.hashes;parent_commit=final.parent_commit;proposer=final.header.creator_addr;signature=""} in
  let* ()=validate state proposal bundle in
  let checked=verify_bundle state final.header bundle in
  let _=J.stage state.data ~chain_id:state.chain_id ~validator_set:state.validators
    ~bundle:J.{tx_hashes=List.map T.hash bundle.txs;txs=bundle.txs;receipts_json=bundle.receipts} final in
  let commit_id=Core.Commit_journal.mk_commit_id(Int64.to_int final.epoch_id) in
  Core.Commit_journal.append state.data (Prepare{commit_id;prev_generation=state.head.generation;
    epoch_id=Int64.to_int final.epoch_id;planned_txid_hi=final.header.txid_hi;
    planned_state_root=raw_hex final.header.proposed_state_root;ts=final.header.ts});
  let* result,confirmed,epoch_hash,index,folded=run_on state state.store state.ledger final.header final.parent_commit checked in
  if raw folded<>final.header.proposed_state_root then failwith "native finalized root mismatch";
  SC.begin_batch state.chain;
  let start=SC.next_txid state.chain in
  List.iter(fun tx->SC.save_tx state.chain ~hash:(T.hash tx) ~epoch_id:(Int64.to_int final.epoch_id)
    ~from_addr:tx.T.from ~to_addr:tx.to_ ~tx_json:(json(T.to_yojson tx))
    ~op_type:(T.op_type_to_string tx.op_type) ~encrypted_data:(Option.value ~default:"" tx.encrypted_data)
    ~message:(Option.value ~default:"" tx.message))confirmed;
  SC.set_epoch state.chain {Core.Epochlog.empty_epoch_header with id=Int64.to_int final.epoch_id;
    state_root=folded;prev_state_root=state.head.state_root;parent_commit=Option.value ~default:"" state.head.irmin_commit;
    start_txid=start;tx_count=List.length confirmed;finalized_by=final.header.creator_addr;finalized_at=final.header.ts;
    proposer={creator_addr=final.header.creator_addr;commit_round=final.commit_round};fees_total=Z.to_string result.artifacts.confirmed_fees};
  SC.set_epoch_index_commitment state.chain ~epoch_id:(Int64.to_int final.epoch_id) ~epoch_hash ~root:index;
  SC.commit_batch state.chain;SC.fsync state.chain;
  let* ()=S.tag_epoch state.store(Int64.to_int final.epoch_id) in
  S.Store.flush state.store.repo;S.sync_branches state.store.store_path;
  let* irmin=S.get_commit_hash state.store in
  let head={state.head with HM.generation=state.head.generation+1;epoch_id=Int64.to_int final.epoch_id;
    state_root=folded;ledger_state_root=Some result.post_state_root;irmin_commit=irmin;txid_hi=final.header.txid_hi;
    epochlog_off=Some(SC.epochlog_offset state.chain);commit_id;ts=final.header.ts;
    epoch_index_hash=Some epoch_hash;epoch_index_root=Some index} in
  let certificate_path=cert_path state final.epoch_id in
  let encoded=Codec.encode_finalize final in
  (match load_final state final.epoch_id with
   |Some prior when Codec.encode_finalize prior=encoded->()
   |Some _->failwith "immutable native certificate conflict"
   |None->atomic certificate_path encoded);
  HM.atomic_write state.data head;
  Core.Commit_journal.append state.data (Commit{commit_id;generation=head.generation;ts=head.ts});
  let entry=N.Finality_log.make ~height:head.epoch_id ~round:final.commit_round
    ~proposal_id:(raw_hex final.proposal_id) ~tx_list_hash:(raw_hex final.header.tx_list_hash)
    ~state_root:folded ~creator_addr:final.header.creator_addr ~txid_hi:head.txid_hi ~ts:head.ts () in
  N.Finality_log.write state.data entry;
  J.promote_applied state.data ~epoch:final.epoch_id ~state_root:(raw folded);
  Core.Wal.delete_pending_commits_for_epoch state.data (Int64.to_int final.epoch_id);
  HM.set_cached head;state.head<-head;
  Lwt.return_unit
