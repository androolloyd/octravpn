module Core = Octra_core
module SC = Core.Store_chaindata
module SI = Core.Store_irmin
module HM = Core.Head_manifest
module EL = Core.Epochlog
module Eic = Core.Epoch_index_commitment
let run = Lwt_main.run
let some = Option.get

let publish dir = Recovery_case.with_stores dir (fun chain store ->
  let _, plan, _, _ = run (Core.Startup_recovery.inspect ~data_dir:dir ~chaindata:chain ~store) in
  match plan with
  | Core.Recovery_phase.Publish head ->
    run (SI.tag_epoch store head.epoch_id);
    HM.atomic_write dir head;
    head
  | _ -> failwith "expected forward publication")

let advance dir (head : HM.t) epoch count =
  Recovery_case.with_stores dir (fun chain store ->
    run (SI.begin_epoch_batch store);
    run (SI.set_meta store "last_epoch" (string_of_int epoch));
    run (SI.set_meta store "current_epoch" (string_of_int (epoch + 1)));
    run (SI.commit_epoch_batch store "native history fixture");
    let ledger_root = some (run (SI.get_head_hash store)) in
    SC.begin_batch chain;
    let start_txid = SC.next_txid chain in
    let items = List.init count (fun index ->
      let txid = Int64.add start_txid (Int64.of_int index) in
      let tx = Core.Transaction.{from = "octFROM"; to_ = "octTO"; amount = Z.one;
        nonce = Int64.to_int txid; ou = Z.zero; timestamp = float_of_int epoch;
        signature = "fixture"; public_key = None;
        message = (if epoch = 3 && index = 1 then Some "raw\000\255" else None);
        op_type = Standard; encrypted_data = None} in
      let hash = Core.Transaction.hash tx in
      SC.save_tx chain ~hash ~epoch_id:epoch ~from_addr:"octFROM" ~to_addr:"octTO"
        ~tx_json:(Yojson.Safe.to_string (Core.Transaction.to_yojson tx))
        ~op_type:"standard" ~encrypted_data:"" ~message:"";
      SC.save_receipt_raw chain ~tx_hash:hash
        ~json:(Printf.sprintf {|{"success":true,"events":[],"epoch":%d}|} epoch);
      Eic.item ~txid ~hash) in
    let epoch_hash, root = Eic.next_root ~prev:(some head.epoch_index_root) ~epoch_id:epoch items in
    let state_root = Eic.folded_state_root ~ledger_state_root:ledger_root ~epoch_index_root:root in
    SC.set_epoch chain {EL.empty_epoch_header with id = epoch; state_root;
      prev_state_root = head.state_root; parent_commit = some head.irmin_commit;
      finalized_by = "fixture"; start_txid; tx_count = count};
    SC.set_epoch_index_commitment chain ~epoch_id:epoch ~epoch_hash ~root;
    SC.commit_batch chain;
    SC.fsync chain;
    Core.Commit_journal.append dir (Core.Commit_journal.Prepare {
      commit_id = Printf.sprintf "fixture-%d" epoch; prev_generation = head.generation;
      epoch_id = epoch; planned_txid_hi = Int64.pred (Int64.add start_txid (Int64.of_int count));
      planned_state_root = state_root; ts = 0.});
    Core.Wal.write dir Core.Wal.{epoch_id = epoch; pre_state_root = HM.ledger_state_root head;
      post_state_root = ledger_root; parent_commit = some head.irmin_commit; start_txid;
      tx_count = count; finalized_by = "fixture"; finalized_at = 0.;
      irmin_last_epoch_before = head.epoch_id; irmin_parent = head.irmin_commit};
    Core.Epoch_commit_marker.write_marker dir epoch "irmin_committed")

let recover dir = Recovery_case.with_stores dir (fun chain store ->
  ignore (run (Core.Startup_recovery.recover ~data_dir:dir ~chaindata:chain ~store)))

let export dir after limit =
  run (Native_history_export.read dir after limit) |> Yojson.Safe.from_string

let refusal action = match action () with
  | _ -> failwith "unexpected export success"
  | exception error -> `String (Printexc.to_string error)

let () =
  let dir = Sys.argv.(1) in
  Unix.mkdir dir 0o700;
  let head, _ = Recovery_case.prepare dir in
  Recovery_case.with_stores dir (fun _ store -> run (SI.tag_epoch store 0));
  let empty = export dir 0 64 in
  let writer_active = Recovery_case.with_stores dir (fun _ _ ->
    refusal (fun () -> export dir 0 64)) in
  advance dir head 1 1;
  let before_head = refusal (fun () -> export dir 0 64) in
  let head1 = publish dir in
  let after_head = export dir 0 64 in
  recover dir;
  let after_recovery = export dir 0 64 in
  if after_head <> after_recovery then failwith "recovery changed committed history";
  advance dir head1 2 0;
  let head2 = publish dir in
  recover dir;
  advance dir head2 3 2;
  let head3 = publish dir in
  recover dir;
  let full = export dir 0 64 in
  let first_page = export dir 0 1 in
  let remaining = export dir 1 64 in
  let caught_up = export dir 3 64 in
  let future = refusal (fun () -> export dir 4 64) in
  let oversize = refusal (fun () -> export dir 0 65) in
  let open Yojson.Safe.Util in
  let receipt_hash = full |> member "epochs" |> to_list |> List.hd
    |> member "transactions" |> to_list |> List.hd |> member "hash" |> to_string in
  Recovery_case.with_stores dir (fun chain _ ->
    let aux = Core.Chaindata_index.auxiliary chain.SC.index in
    Core.Aux_index.with_write aux ~previous:(Some (SC.head_anchor head3))
      ~target:Core.Aux_delta.{epoch = 4; root = "fixture"; commit_id = "pending"}
      ~writes:[Core.Aux_delta.Receipt receipt_hash,
        Core.Aux_delta.Value (Some {|{"epoch":4,"success":true,"events":[]}|})]
      (fun _ -> ()));
  let auxiliary_pending = refusal (fun () -> export dir 0 64) in
  Recovery_case.with_stores dir (fun chain _ ->
    let aux = Core.Chaindata_index.auxiliary chain.SC.index in
    ignore (Lmdb.Txn.go Lmdb.Rw aux.Core.Aux_index.env (fun txn ->
      Core.Aux_index.apply_restore aux txn ~head:(Some (SC.head_anchor head3)))));
  if export dir 0 64 <> full then failwith "auxiliary recovery changed retained events";
  Recovery_case.with_stores dir (fun _ store ->
    run (SI.Store.Branch.remove store.SI.repo "epoch_0"));
  let pruned = refusal (fun () -> export dir 0 64) in
  (* Independently chosen fixture policy, never inferred from a header. Invoke
     the real native attribution callback on the actual exported bytes. *)
  Unix.putenv Octra_consensus.C_protocol.activation_env "0";
  let keys = ["fixture", Base64.encode_exn (String.make 32 'a');
    "validatorB", Base64.encode_exn (String.make 32 'b')] in
  let reward_sources = full |> member "epochs" |> to_list |> List.map (fun row ->
    let raw = row |> member "epoch_header" |> to_string |> Base64.decode_exn in
    let header = some (EL.epoch_of_json raw) in
    let source = match Octra_node_runtime.Consensus_reward_attribution.epoch_source
      ~validator_activation_epoch:None ~validator_pubkeys:keys header with
      | Ok source -> source | Error error -> failwith error in
    `Assoc ["epoch", `Int header.id; "header_sha256", `String (Digestif.SHA256.(to_hex (digest_string raw)));
      "source", `String (Base64.encode_exn (Octra_net.Oce1.encode
        (fun buffer -> Octra_consensus.C_reward_source.encode_into buffer source)))]) in
  let output = `Assoc ["empty", empty; "after_head", after_head;
    "after_recovery", after_recovery; "full", full;
    "first_page", first_page; "remaining", remaining; "caught_up", caught_up;
    "reward_sources", `List reward_sources;
    "refusals", `Assoc ["before_head", before_head; "future", future;
      "oversize", oversize; "pruned", pruned; "writer_active", writer_active;
      "auxiliary_pending", auxiliary_pending]] in
  print_endline (Yojson.Safe.to_string output)
