(* Offline legacy storage compatibility helper. No consensus body is modified.
   The actual chaindata directory owner is held until the protocol ends. *)
module Core = Octra_core
module SC = Core.Store_chaindata
module SI = Core.Store_irmin
module Fork = Core.Fork_head_repair
module Plan = Core.Fork_repair_log
module HM = Core.Head_manifest
module FL = Octra_consensus.Finality_log
module Journal = Octra_node_runtime.Consensus_finality_journal
let unwrap = function Ok value -> value | Error reason -> failwith reason
let require reason value = if not value then failwith reason
let some reason = function Some value -> value | None -> failwith reason
let head dir = match HM.load_result dir with
 | HM.Present head -> head
 | HM.Missing -> failwith "HEAD is missing"
 | HM.Corrupt reason -> failwith reason
let plan dir = some "fork repair plan is missing" (unwrap (Fork.read_plan dir))
let finality dir epoch = FL.find (FL.index dir) epoch
let entry dir json =
 let open Yojson.Safe.Util in
 let selected = FL.entry_of_json (Yojson.Safe.from_string (Base64.decode_exn (json |> member "entry" |> to_string))) in
 let actual = some "finality entry is missing" (finality dir selected.FL.height) in
 require "finality entry changed" (actual = selected);
 actual
let preflight dir chain store chain_id =
 let selected = plan dir in
 let target = selected.Plan.head.HM.epoch_id in
 unwrap (Fork.source_ready dir selected);
 let binding = unwrap (Lwt_main.run (SI.epoch_binding store target)) in
 unwrap (Fork.validate_binding selected binding);
 let current = head dir in
 let record = some "target finality entry is missing" (finality dir target) in
 require "target finality root mismatch" (record.FL.state_root = selected.target_root);
 require "target finality txid mismatch" (record.txid_hi = selected.head.txid_hi && current.txid_hi = record.txid_hi);
 if Journal.committed dir then unwrap (Journal.committed_for ~chain_id ~entry:record dir);
 let boundary = unwrap (SC.epoch_boundary chain target) in
 require "target transaction boundary mismatch"
   (boundary.txid_hi = selected.head.txid_hi && Some boundary.txlog_seg = selected.head.txlog_seg
    && Some boundary.txlog_off = selected.head.txlog_off);
 let chain_head = some "chaindata head is missing" (unwrap (SC.last_epoch_id chain)) in
 require "chaindata is behind target" (chain_head >= target);
 require "chaindata suffix is not empty" (Fork.empty_after chain ~target ~head:chain_head);
 require "chaindata target root mismatch" (Fork.target_matches chain ~target ~root:(Fork.hex_raw selected.target_root));
 require "epochlog offset mismatch" (SC.epochlog_offset_after chain target = selected.head.epochlog_off);
 require "epoch commitment mismatch"
   (SC.get_epoch_index_commitment chain target = (selected.head.epoch_index_hash, selected.head.epoch_index_root));
 require "transaction high-water mismatch" (SC.next_txid chain = selected.next_txid)
let resume = function Fork.Idle -> `Null | Fork.Resumed target -> `Int target
let run dir chain_id channel =
 let reject name = require ("legacy repair refuses " ^ name) (not (Sys.file_exists (Filename.concat dir name))) in
 List.iter reject ["canonical.sqlite"; "canonical.sqlite-wal"; "exex.db"];
 List.iter (fun name -> require ("legacy directory missing: " ^ name)
   ((Unix.lstat (Filename.concat dir name)).Unix.st_kind = Unix.S_DIR)) ["chaindata"; "irmin_store"];
 let chain = SC.open_chaindata (Filename.concat dir "chaindata") in
 Fun.protect ~finally:(fun () -> SC.close chain) (fun () ->
 let store = Lwt_main.run (SI.open_store (Filename.concat dir "irmin_store")) in
 Fun.protect ~finally:(fun () -> Lwt_main.run (SI.close store)) (fun () ->
 let selection = ref None in
 let reply value =
  let bytes = Yojson.Safe.to_string value in
  require "backend response exceeds bound" (String.length bytes < 1048576);
  output_string channel bytes; output_char channel '\n'; flush channel in
 reply (`Assoc ["ok", `Assoc ["protocol", `String "octra-legacy-repair-v1";
   "upstream", `String Legacy_repair_version.upstream; "chain_id", `String chain_id]]);
 let rec loop () = match input_line stdin with
 | line ->
   require "backend request exceeds bound" (String.length line <= 1048576);
   let open Yojson.Safe.Util in
   let result = try
    let json = Yojson.Safe.from_string line in
    let operation = json |> member "op" |> to_string in
    let value = match operation with
    | "selection" ->
      require "selection already captured" (!selection = None);
      let settings = Legacy_repair_selection.settings (json |> member "settings") in
      let captured = Legacy_repair_selection.capture dir chain store chain_id settings (json |> member "origin") in
      selection := Some (settings,captured); captured
    | "stage" ->
      let settings,captured = some "selection was not captured" !selection in
      Legacy_repair_selection.stage dir chain store chain_id settings captured json
    | "read_plan" -> let p = plan dir in `String (Base64.encode_exn (Yojson.Safe.to_string (Plan.to_json p)))
    | "head" -> `String (Base64.encode_exn (HM.to_json (head dir)))
    | "preflight" -> preflight dir chain store chain_id; `Null
    | "store" -> preflight dir chain store chain_id;
      resume (unwrap (Lwt_main.run (Fork.resume_store ~data_dir:dir ~store)))
    | "chain" -> resume (unwrap (Fork.resume_chain ~data_dir:dir ~chaindata:chain))
    | "verify" -> Legacy_repair_storage.verify dir store chain; `Null
    | "finality" -> let epoch = json |> member "epoch" |> to_int in
      (match finality dir epoch with None -> `Null | Some record -> `Assoc ["wire", `String (Base64.encode_exn (FL.line record));
        "root", `String (Base64.encode_exn record.FL.state_root);
        "txid_hi", `String (Int64.to_string record.txid_hi)])
    | "journal_committed" -> `Bool (Journal.committed dir)
    | "committed_for" -> let record = entry dir json in
      unwrap (Journal.committed_for ~chain_id ~entry:record dir); `Null
    | "rewind_journal" -> let record = entry dir json in
      unwrap (Journal.rewind_committed ~chain_id ~entry:record dir); `Null
    | "drop_after" -> let target = (plan dir).head.epoch_id in
      require "finality target differs" (json |> member "target" |> to_int = target);
      `Int (FL.drop_after dir target)
    | "clear" -> Fork.clear dir; `Null
    | _ -> failwith "unknown legacy repair operation" in
    `Assoc ["ok", value]
   with error -> `Assoc ["error", `String (Printexc.to_string error)] in
   reply result;
   (match result with `Assoc [("error", _)] -> () | _ -> loop ())
 | exception End_of_file -> () in
 loop ()))
let () =
 (* Keep native diagnostics off the bounded machine protocol. *)
 let descriptor = Unix.dup Unix.stdout in
 Unix.dup2 Unix.stderr Unix.stdout;
 let channel = Unix.out_channel_of_descr descriptor in
 try
  require "usage: legacy-repair-backend DIRECTORY CHAIN_ID" (Array.length Sys.argv = 3);
  run Sys.argv.(1) Sys.argv.(2) channel;
  close_out channel
 with error ->
  Printf.eprintf "legacy repair backend refused: %s\n%!" (Printexc.to_string error);
  exit 2
