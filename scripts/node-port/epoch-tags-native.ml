(* Unchanged native store and lifecycle policy; no consensus or pack GC edits. *)
module SI = Octra_core.Store_irmin
module Lifecycle = Octra_node_runtime.Consensus_epoch_lifecycle
module Startup = Octra_node_runtime.Startup_store_shell
let run = Lwt_main.run
let option f = function None -> `Null | Some value -> f value
let number value = `Int value
let text value = `String value
let snapshot store applied =
  let count, oldest, newest = run (SI.epoch_tag_stats store) in
  `Assoc ["applied", number applied; "count", number count;
    "min_epoch", number oldest; "max_epoch", number newest;
    "tags", `List (List.map number (run (SI.list_epoch_tags store)))]
let keep_case raw =
  let expected = match SI.gc_keep_epochs_of (fun name ->
    if name = "OCTRA_GC_KEEP_EPOCHS" then raw else None) with
    | Ok value -> number value | Error _ -> `Null in
  `Assoc ["raw", option text raw; "expected", expected]
let schedule applied =
  let current = applied + 1 in
  let selected = Lifecycle.should_cleanup_old_tags current in
  let floor = current - SI.gc_keep_epochs in
  `Assoc ["applied", text (string_of_int applied);
    "current", text (string_of_int current);
    "floor", (if selected && floor > 0 then number floor else `Null)]
let initial_case empty raw =
  let label, error = try
    match Startup.epoch_tag_plan ~existing_tags:(if empty then [] else [1]) ~last_epoch:raw with
    | Startup.Create_initial_tag label -> number label, false
    | Startup.Skip_initial_tag | Startup.Tags_present _ -> `Null, false
    with _ -> `Null, true in
  `Assoc ["empty", `Bool empty; "raw", option text raw; "label", label; "error", `Bool error]
let main path =
  let store = run (SI.open_store ~fresh:true path) in
  let tag epoch =
    run (SI.write store ["value"] (string_of_int epoch));
    run (SI.tag_epoch store epoch) in
  let retagged, lifecycle = Fun.protect ~finally:(fun () -> run (SI.close store)) (fun () ->
    List.iter tag [0; 1; 7; 8; 99; 100];
    if run (SI.read_at_epoch store 0 ["value"]) <> Some "0" then
      failwith "native tag did not retain its earlier immutable value";
    run (SI.tag_epoch store 7);
    let retagged = run (SI.read_at_epoch store 7 ["value"]) in
    if retagged <> Some "100" then
      failwith "native tag replacement did not retain the current value";
    (* Actual tag cleanup policy, with the separately asynchronous pack
       collector omitted. This fixture measures tags, not physical collection. *)
    let deps = Lifecycle.{trace=(fun _ -> ()); log_head=(fun _ -> ());
      log_gc=(fun _ -> ()); save_state_root=(fun () -> Lwt.return_unit);
      get_head_hash=(fun () -> SI.get_head_hash store);
      cleanup_old_tags=SI.cleanup_old_tags store;
      collect_pack=(fun _ -> Lwt.return_unit)} in
    retagged, List.map (fun applied -> tag applied;
      run (Lifecycle.run deps Lifecycle.{current_epoch=applied + 1});
      snapshot store applied) [8198; 8199; 8299]) in
  let readonly = run (SI.open_store ~readonly:true path) in
  let gc, restarted = Fun.protect ~finally:(fun () -> run (SI.close readonly)) (fun () ->
    let split, enabled, running, need = run (SI.pack_gc_status readonly) in
    (* pack_gc_status exposes Store.Gc.is_allowed for this real Irmin-pack
       repository, independently of readonly. Observe it unchanged; readonly
       is not evidence that this backend capability is disabled. No collector
       is invoked by this tag lifecycle fixture. *)
    let gc = `Assoc ["split_epoch", option number split;
      "pack_gc_enabled", `Bool enabled; "pack_gc_running", `Bool running;
      "pack_gc_need_bytes", option (fun n -> text (Int64.to_string n)) need] in
    gc, snapshot readonly 8299) in
  `Assoc ["storage_backend", text "irmin-pack";
    "pack_collection_invoked", `Bool false;
    "retagged_value", option text retagged;
    "keep_cases", `List (List.map keep_case [None; Some "4096";
    Some "65536"; Some " 0x2000 \n"; Some "4_096"; Some "+8192";
    Some "4095"; Some "65537"; Some "many"; Some "\0118192\011"]);
    "schedule_cases", `List (List.map schedule [0; 98; 99; 100; 4098;
      4099; 8198; 8199; 8200; max_int]);
    "initial_cases", `List (List.map (fun (empty, raw) -> initial_case empty raw)
      [true,None; true,Some "0"; true,Some "7"; true,Some "-1";
       true,Some "0x20"; true,Some "many"; false,Some "many"]);
    "lifecycle", `List lifecycle; "restarted", restarted;
    "readonly_pack_status", gc]
let () =
  let descriptor = Unix.dup Unix.stdout in
  Unix.dup2 Unix.stderr Unix.stdout;
  let output = Unix.out_channel_of_descr descriptor in
  let result = main Sys.argv.(1) in
  Yojson.Safe.to_channel output result; output_char output '\n'; flush output
