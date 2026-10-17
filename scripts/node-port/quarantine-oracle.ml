(* Oracle driver only. Consensus_runtime_state is copied and compiled unchanged. *)
open Yojson.Safe.Util
module Q = Consensus_runtime_state

let raw value = Base64.decode_exn (to_string value)
let bytes name input = member name input |> raw
let encoded value = `String (Base64.encode_string value)
let integer value = `String (string_of_int value)
let state value = `Assoc [
  "active", `Bool (Q.quarantine_active value);
  "reason", encoded (Q.quarantine_reason value);
  "since", integer (Q.quarantine_since_epoch value);
  "attested", `Bool (Q.state_attested value);
  "attested_head", `Bool (Q.attested_head value 9);
  "streaks", `List (List.map integer [Q.prev_root_streak value;
    Q.state_root_streak value; Q.ahead_streak value]);
]
let cleared = function
  | Q.Cleared -> `Assoc ["kind", `String "cleared"]
  | Q.Inactive -> `Assoc ["kind", `String "inactive"]
  | Q.Refused reason -> `Assoc ["kind", `String "refused"; "reason", encoded reason]

let run input =
  match member "op" input |> to_string with
  | "classify" ->
    let reason = bytes "reason" input in
    `Assoc [
      "root", `Bool (Q.root_attestation_recovers reason);
      "consensus", `Bool (Q.consensus_root_attestation_recovers reason);
      "catchup", `Bool (Q.catchup_recovers reason);
      "recoverable", `Bool (Q.recoverable_reason reason);
    ]
  | "evidence" -> `Bool (Q.root_evidence (bytes "evidence" input))
  | "recovery" ->
    begin match Q.root_recovery_evidence ~reason:(bytes "reason" input)
      ~evidence:(bytes "evidence" input)
      ~consensus_proved:(member "consensus" input |> to_bool) with
    | None -> `Null | Some evidence -> encoded evidence
    end
  | "clear" -> `Bool (Q.clear_allowed ~reason:(bytes "reason" input)
      ~evidence:(bytes "evidence" input))
  | "inactive" -> cleared (Q.clear_quarantine (Q.create ())
      ~evidence:(bytes "evidence" input))
  | "transition" ->
    let value = Q.create () in
    Q.set_prev_root_streak value 3;
    Q.set_state_root_streak value 4;
    Q.incr_ahead_streak value;
    Q.set_state_attested value ~head:7 ~root:"before";
    let first = Q.enter_quarantine value
      ~epoch:(member "epoch" input |> to_string |> int_of_string)
      ~reason:(bytes "reason" input) in
    let initial = state value in
    Q.set_state_attested value ~head:9 ~root:"after";
    let second = Q.enter_quarantine value
      ~epoch:(member "next_epoch" input |> to_string |> int_of_string)
      ~reason:(bytes "incoming" input) in
    let entered = state value in
    let result = Q.clear_quarantine value ~evidence:(bytes "evidence" input) in
    `Assoc ["first", `Bool first; "initial", initial; "second", `Bool second;
      "entered", entered; "clear", cleared result; "final", state value]
  | op -> failwith ("unknown quarantine oracle operation: " ^ op)

let () =
  let rows = Yojson.Safe.from_channel stdin |> to_list |> List.map (fun input ->
    `Assoc ["input", input; "expected", run input]) in
  Yojson.Safe.to_channel stdout (`List rows);
  print_newline ()
