(* Only fixture construction/callbacks live here. All plan, HEAD, compatibility
   and finish bodies are unchanged adopted production modules. No store opens. *)
open Yojson.Safe.Util
module H = Octra_core.Head_manifest
module P = Octra_core.Fork_repair_log
module R = Octra_core.Fork_head_repair
module B = Octra_node_runtime.Fork_repair_boot
module F = Octra_consensus.Finality_log

let raw value = Base64.decode_exn (to_string value)
let encoded value = `String (Base64.encode_string value)
let integer value = `String (string_of_int value)
let plan input =
  match P.of_json (raw (member "plan" input) |> Yojson.Safe.from_string) with
  | Ok value -> value | Error reason -> failwith reason
let read_head value = H.of_json (raw value)
let error reason = `Assoc ["error", `String reason]
let outcome = function
  | B.Idle -> `Assoc ["kind", `String "idle"]
  | B.Resumed { target; head; dropped } -> `Assoc [
      "kind", `String "resumed"; "target", integer target;
      "head", integer head; "dropped", integer dropped]
let entry input : F.entry = {
  height = member "height" input |> to_string |> int_of_string;
  round = 0; proposal_id = "unused"; tx_list_hash = "unused";
  state_root = raw (member "root" input); creator_addr = "unused";
  txid_hi = member "txid" input |> to_string |> Int64.of_string;
  qc_hash = None; ts = 0.;
}
let run input = match member "op" input |> to_string with
  | "parse" ->
    begin try match P.of_json (raw (member "raw" input) |> Yojson.Safe.from_string) with
    | Error _ -> `Assoc ["accepted", `Bool false]
    | Ok value -> `Assoc ["accepted", `Bool true;
        "encoded", encoded (P.to_json value |> Yojson.Safe.to_string);
        "source", encoded (H.to_json value.source);
        "head", encoded (H.to_json value.head)]
    with _ -> `Assoc ["accepted", `Bool false]
    end
  | "source" ->
    let value = plan input in
    let current = read_head (member "current" input) in
    `Assoc ["same_source", `Bool (R.same_source current value.source);
      "accepts", `Bool (R.same_source current value.source || current = value.head)]
  | "finish" ->
    let calls = ref [] in
    let touch name =
      calls := name :: !calls;
      if member "fail" input = `String name then failwith ("injected:" ^ name) in
    let entries = member "entries" input |> to_list |> List.map entry in
    let deps = B.{
      read_plan = (fun () -> touch "read_plan";
        match member "plan" input with `Null -> Ok None | _ -> Ok (Some (plan input)));
      head = (fun () -> touch "head";
        match member "current" input with `Null -> None | value -> Some (read_head value));
      finality_at = (fun epoch -> touch ("finality:" ^ string_of_int epoch);
        List.find_opt (fun (value:F.entry) -> value.height = epoch) entries);
      journal_committed = (fun () -> touch "journal_committed";
        member "committed" input |> to_bool);
      committed_for = (fun entry -> touch ("committed_for:" ^ string_of_int entry.F.height); Ok ());
      rewind_journal = (fun entry -> touch ("rewind:" ^ string_of_int entry.F.height); Ok ());
      drop_after = (fun epoch -> touch ("drop_after:" ^ string_of_int epoch);
        member "dropped" input |> to_string |> int_of_string);
      clear = (fun () -> touch "clear");
    } in
    let result = try match B.run deps with
      | Ok value -> `Assoc ["ok", outcome value] | Error reason -> error reason
      with Failure reason -> error reason in
    `Assoc ["result", result; "trace", `List (List.rev_map (fun call -> `String call) !calls)]
  | op -> failwith ("unknown fork repair operation: " ^ op)

let () =
  let cases = Yojson.Safe.from_channel stdin |> to_list |> List.map (fun input ->
    `Assoc ["input", input; "expected", run input]) in
  Yojson.Safe.to_channel stdout (`List cases);
  print_newline ()
