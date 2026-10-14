(* Exercises unmodified native ordered proposal scheduling. Preview outcomes are
   scripted local test doubles; this oracle makes no execution/proof claim. *)
open Yojson.Safe.Util
module C = Octra_node_runtime.Consensus_proposal
module T = Octra_core.Transaction
module E = Octra_core.Epoch_exec
module W = Octra_core.Preverify_worker
let labels txs = `List (List.map (fun tx -> `Int (int_of_string (Option.get tx.T.message))) txs)
let tx j = T.{from = member "from" j |> to_string; to_ = "oct_receiver";
 amount = Z.zero; nonce = member "nonce" j |> to_int; ou = Z.of_int 1000;
 timestamp = 1.; signature = "sig"; public_key = Some "pub";
 message = Some (string_of_int (member "id" j |> to_int)); encrypted_data = None; op_type = Standard}
let raw ch = String.make 32 ch
let run j =
 Unix.putenv "OCTRA_BFT_RELEASE_PROFILE" "off";
 Unix.putenv "OCTRA_BFT_CRYPTO_PROFILE" "off";
 Unix.putenv Octra_consensus.C_protocol.activation_env "999999999";
 let staging = member "txs" j |> to_list |> List.map tx in
 let script = member "responses" j |> to_list in
 let requests = ref [] and evicted = ref [] and held = ref [] and output = ref None and live = ref true in
 let prepare (r : C.build_preview_request) =
  let step = List.length !requests in
  requests := !requests @ [labels r.txs];
  let response = Option.value (List.nth_opt script step) ~default:(`Assoc []) in
  let status tx = match member "status" response with `List values -> (List.nth values (int_of_string (Option.get tx.T.message))) |> to_string | _ -> "ok" in
  if member "revoke" response = `Bool true then live := false;
  if member "fail" response = `Bool true then Lwt.return_error "script failure"
  else if member "unknown_resource" response = `Bool true then Lwt.fail (Octra_core.Exec_resource.Exhausted (raw 'x', Host))
  else match List.find_opt (fun tx -> status tx = "exhausted") r.txs with
  | Some tx -> Lwt.fail (Octra_core.Exec_resource.Exhausted (T.hash tx, Host))
  | None ->
    let confirmed = List.filter (fun tx -> status tx = "ok") r.txs in
    let confirmed = if member "duplicate" response = `Bool true then confirmed @ confirmed else confirmed in
    let rejected = List.filter (fun tx -> status tx <> "ok") r.txs |> List.map (fun tx ->
      let error_type = match status tx with "unavailable" -> "vm_transition_incomplete" | "exception" -> "vm_transition_exception" | _ -> "bad" in
      E.{tx; error_type; reason="rejected"; charged=status tx = "paid"}) in
    Lwt.return_ok C.{execution={E.post_state_root=raw 'l'; artifacts={confirmed=List.map(fun tx->tx,0)confirmed; rejected; confirmed_fees=Z.zero; tx_count=List.length r.txs}};
      preverify=Octra_core.Preverify_commit.create []}
 in
 let deps : C.make_proposal_deps = {
  current=(fun()-> !live); start_height=(fun _->Lwt.return_unit); current_epoch=(fun()->12);
  state_attested=(fun()->true); quarantine_active=(fun()->false); quarantine_reason=(fun()->"");
  read_prev_ledger_root=(fun()->Lwt.return_some(raw 'p')); cached_head=(fun()->None); current_round=(fun()->0);
  parent_commit=(fun ~epoch_id:_->Ok None); parent_txs=(fun _->None); frozen_bundle=(fun _->None);
  store_bundle=(fun ~proposal_id:_ ~tx_hashes:_ ~txs ~receipts_json -> output:=Some(txs,receipts_json));
  staging_txs=(fun ?circles:_ ()->staging); evict_preview=(fun ?epoch:_ tx->evicted:= !evicted@[tx]); hold_preview=(fun ~epoch:_ tx->held:= !held@[tx]);
  admits_tx=(fun _->true); build_preverify_once=(fun ~state_root:_ ~tx_hashes:_ items->Lwt.return W.{ready=List.map(fun tx-> W.{tx;receipt=None})items;skipped=[]});
  staging_total=(fun()->List.length staging); proposer=(fun()->"oct_creator"); validator_pubkeys=(fun _->[]);
  preview=(fun _->failwith "ordered preparation required"); prev_eic_root=(fun()->Octra_core.Epoch_index_commitment.genesis_root);
  next_txid=(fun()->7L);set_proposal=(fun _ _->());head_txid_hi=(fun()->Some 6L);freeze=(fun _ _->());
  now=(fun()->99.);previous_epoch_ts=(fun _->Some 89.);
 } in
 let result = Lwt_main.run (C.make_proposal ~prepare deps ~chain_id:"octra-test" ~root_to_raw32:Fun.id
   ~limits:(C.limits ~max_txs:(member "cap" j |> to_int) ~max_bytes:1000000 ~max_ou:(Z.of_int 1000000)) ~epoch_id:12L) in
 let confirmed, receipts = match !output with None->`Null,`Null | Some(txs,rs)->labels txs,`List(List.map(fun r->`String r)rs) in
 `Assoc["built",`Bool(Option.is_some result);"requests",`List !requests;"refused",labels !evicted;"held",labels !held;"confirmed",confirmed;"receipts",receipts]
let () = let cases = Yojson.Safe.from_channel stdin |> to_list |> List.map(fun input->`Assoc["input",input;"expected",run input]) in Yojson.Safe.to_channel stdout (`List cases); print_newline()
