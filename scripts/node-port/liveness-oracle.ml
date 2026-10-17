(* Oracle driver only. The adopted Consensus_liveness implementation is copied
   unchanged and linked against the real adopted Octra_consensus library. *)
open Yojson.Safe.Util
module Q = Consensus_liveness
module C = Octra_consensus

let string name input = member name input |> to_string
let integer name input = string name input |> int_of_string
let int64 name input = string name input |> Int64.of_string
let raw name input = string name input |> Base64.decode_exn
let float value = Int64.float_of_bits (Int64.of_string ("0x" ^ to_string value))
let floating name input = member name input |> float
let optional decode = function `Null -> None | value -> Some (decode value)
let encoded value = `String (Base64.encode_string value)
let number value = `String (string_of_int value)
let wide value = `String (Int64.to_string value)
let bits value = `String (Printf.sprintf "%016Lx" (Int64.bits_of_float value))
let option encode = function None -> `Null | Some value -> encode value

let state (value : Q.state) = `Assoc [
  "key", encoded value.key; "key_started_at", bits value.key_started_at;
  "height_key", encoded value.height_key;
  "height_started_at", bits value.height_started_at; "resets", number value.resets;
]
let read_state input : Q.state = {
  key = raw "key" input; key_started_at = floating "key_started_at" input;
  height_key = raw "height_key" input;
  height_started_at = floating "height_started_at" input;
  resets = integer "resets" input;
}
let sample input : Q.sample = {
  height = int64 "height" input; round = integer "round" input;
  step = raw "step" input; expected = int64 "expected" input;
  now = floating "now" input; source = raw "source" input;
  stall_sec = floating "stall_sec" input;
  step_timeout_sec = member "step_timeout_sec" input |> optional float;
  observer = member "observer" input |> to_bool;
  voting = member "voting" input |> to_bool;
  catchup_active = member "catchup_active" input |> to_bool;
  quarantine_active = member "quarantine_active" input |> to_bool;
  state_attested = member "state_attested" input |> to_bool;
  pending_finalized = member "pending_finalized" input |> to_bool;
  proposal_active = member "proposal_active" input |> to_bool;
}
let reset (value : Q.reset) = `Assoc [
  "height", wide value.height; "round", number value.round;
  "step", encoded value.step; "expected", wide value.expected;
  "source", encoded value.source; "stall_sec", bits value.stall_sec;
  "step_timeout_sec", option bits value.step_timeout_sec;
  "state_age", bits value.state_age; "height_age", bits value.height_age;
  "resets", number value.resets;
]
let result (value : Q.result) = `Assoc [
  "state", state value.state; "reset", option reset value.reset;
]
let snapshot (value : Q.driver_snapshot) = `Assoc [
  "height", wide value.height; "round", number value.round;
  "step", encoded value.step;
  "step_timeout_sec", option bits value.step_timeout_sec;
]
let run input =
  match string "op" input with
  | "record" ->
    let initial = match member "seed" input with
      | `Null -> Q.create ~now:(floating "created_at" input)
      | value -> read_state value in
    let current = ref initial in
    let rows = member "samples" input |> to_list |> List.map (fun input ->
      let value = sample input in
      let direct = Q.record !current value in
      let driver : Q.driver_snapshot = {
        height = value.height; round = value.round; step = value.step;
        step_timeout_sec = value.step_timeout_sec;
      } in
      let projected = Q.record_snapshot !current driver
        ~expected:value.expected ~now:value.now ~source:value.source
        ~stall_sec:value.stall_sec ~observer:value.observer ~voting:value.voting
        ~catchup_active:value.catchup_active
        ~quarantine_active:value.quarantine_active
        ~state_attested:value.state_attested ~pending_finalized:value.pending_finalized
        ~proposal_active:value.proposal_active in
      current := direct.state;
      `Assoc ["protocol", option bits (Q.protocol_realign_sec value);
        "stall", bits (Q.effective_stall_sec value);
        "blocked_true", `Bool (Q.blocked value ~stalled:true);
        "blocked_false", `Bool (Q.blocked value ~stalled:false);
        "result", result direct; "snapshot_result", result projected]) in
    `Assoc ["initial", state initial; "rows", `List rows; "final", state !current]
  | "timeout" ->
    let step = match string "step" input with
      | "propose" -> C.C_types.ProposeStep
      | "prevote" -> C.C_types.PrevoteStep
      | "precommit" -> C.C_types.PrecommitStep
      | _ -> failwith "unknown native round step" in
    let round = integer "round" input in
    let milliseconds = C.C_engine.timeout_ms_with ~round ~step
      ~base:(integer "base" input) ~propose:(integer "propose" input)
      ~per_round:(integer "per_round" input) in
    let value : Q.driver_snapshot = {
      height = int64 "height" input; round; step = Q.step_label step;
      step_timeout_sec = Some (float_of_int milliseconds /. 1000.0);
    } in
    `Assoc ["milliseconds", number milliseconds; "snapshot", snapshot value]
  | op -> failwith ("unknown liveness oracle operation: " ^ op)

let () =
  let rows = Yojson.Safe.from_channel stdin |> to_list |> List.map (fun input ->
    `Assoc ["input", input; "expected", run input]) in
  Yojson.Safe.to_channel stdout (`List rows);
  print_newline ()
