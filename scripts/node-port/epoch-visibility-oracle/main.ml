(* Differential fixture driver. Link the unchanged adopted Epoch_visibility.ml;
   do not substitute a reimplementation. This file has not been executed. *)
open Lwt.Syntax
module V = Epoch_visibility
let log = ref []
let record label calls result =
  log := !log @ [`Assoc ["case", `String label; "calls", `Int calls;
                        "result", result]]
let main () =
  let visibility = V.create () in
  let calls = ref 0 in
  let release, releasing = Lwt.wait () in
  let applying = V.try_apply visibility (fun () -> release) in
  let reading = V.read visibility (fun () -> incr calls; Lwt.return (`String "value")) in
  assert (!calls = 0 && Lwt.is_sleeping reading);
  Lwt.wakeup_later releasing ();
  let* _ = applying in
  let* result = reading in
  assert (!calls = 1 && result = Some (`String "value"));
  record "wait_apply" !calls (Option.get result);
  let calls = ref 0 in
  let* result = V.read visibility (fun () ->
    incr calls;
    let* _ = V.try_apply visibility (fun () -> Lwt.return_unit) in
    Lwt.return (`Int 17)) in
  assert (!calls = 3 && result = None);
  record "three_changed_attempts" !calls `Null;
  let calls = ref 0 in
  let* result = V.read visibility (fun () ->
    incr calls;
    if !calls = 1 then
      let+ _ = V.try_apply visibility (fun () -> Lwt.return_unit) in
      Error "old failure"
    else Lwt.return (Ok "new value")) in
  assert (!calls = 2 && result = Some (Ok "new value"));
  record "error_result_retried" !calls (`String "new value");
  let calls = ref 0 in
  let* result = V.read visibility (fun () ->
    incr calls; Lwt.return (Error "stable failure")) in
  assert (!calls = 1 && result = Some (Error "stable failure"));
  record "stable_error_no_retry" !calls (`String "error:stable failure");
  let () = Result.get_ok (V.begin_apply visibility) in
  let calls = ref 0 in
  let first = V.read visibility (fun () -> incr calls; Lwt.return "first") in
  let second = V.read visibility (fun () -> incr calls; Lwt.return "second") in
  assert (!calls = 0 && Lwt.is_sleeping first && Lwt.is_sleeping second);
  let () = Result.get_ok (V.finish_apply visibility) in
  let* first, second = Lwt.both first second in
  assert (!calls = 2 && first = Some "first" && second = Some "second");
  record "queued_two_reads" !calls (`String "first,second");
  let () = Result.get_ok (V.begin_apply visibility) in
  let calls = ref 0 in
  let reader = V.read visibility (fun () -> incr calls; Lwt.return_unit) in
  Lwt.cancel reader;
  assert (V.is_applying visibility && !calls = 0);
  record "cancelled_reader_not_owner" !calls (`String "applying");
  let () = Result.get_ok (V.finish_apply visibility) in
  (* Native effect_dispatch is concatenated outside guard_reads. This is a
     dispatch-class control, not an executed financial transaction. *)
  let () = Result.get_ok (V.begin_apply visibility) in
  let writes = ref 0 in
  incr writes;
  let () = Result.get_ok (V.finish_apply visibility) in
  let* _ = V.read visibility (fun () -> Lwt.return_unit) in
  assert (!writes = 1);
  record "effects_not_replayed" !writes (`String "write1");
  Lwt.return_unit
let () =
  assert (Array.length Sys.argv = 3);
  Lwt_main.run (main ());
  print_endline (Yojson.Safe.to_string (`Assoc [
    "schema", `String "octra_epoch_visibility_native_fixture_v1";
    "native_pin", `String "7f9be4489870645cfcc95439638cde40f5da9f50";
    "native_source_sha256", `String Sys.argv.(1);
    "oracle_source_sha256", `String Sys.argv.(2);
    "cases", `List !log;
  ]))
