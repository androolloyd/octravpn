(* The generator compiles unchanged adopted health_probe and selected native
   configuration modules. Only dependency types and environment acquisition
   are adapted; this executable never runs a consensus driver or recovery. *)
open Yojson.Safe.Util
module H = Consensus_health_probe
module D = Octra_consensus.C_driver

let integer value = `String (string_of_int value)
let number name input = member name input |> to_string |> int_of_string
let flag name input = member name input |> to_bool
let raw value = value |> to_string |> Base64.decode_exn
let bytes value = `String (Base64.encode_exn value)
let kind name = `Assoc ["kind", `String name]
let majority (value : H.majority) =
  `Assoc ["root", bytes value.root; "count", integer value.count]
let optional_majority = function None -> `Null | Some value -> majority value
let with_majority name value = `Assoc ["kind", `String name; "majority", majority value]
let root_quorum = function
  | H.No_root -> kind "none"
  | H.Missing_quorum value -> with_majority "missing" value
  | H.Matching_quorum value -> with_majority "matching" value
  | H.Mismatching_quorum value -> with_majority "mismatching" value
let in_sync = function
  | H.Peer_root_mismatch value -> with_majority "mismatch" value
  | H.Accept_genesis -> kind "genesis"
  | H.Missing_peer_root_quorum count -> `Assoc ["kind", `String "missing"; "count", integer count]
  | H.Accept_current_root -> kind "current"
let retry = function
  | H.Retry_probe value -> `Assoc ["kind", `String "retry"; "remaining", integer value]
  | H.Stop_probe -> kind "stop"
let ahead_current = function
  | H.Current_root_matches -> kind "matches"
  | H.Current_root_mismatch value -> with_majority "mismatch" value
  | H.Wait_current_root_quorum -> kind "wait"
let ahead_quorum = function
  | H.Stay_active { wake_ready } -> `Assoc ["kind", `String "stay"; "wake", `Bool wake_ready]
  | H.Delay_quarantine { wake_ready } -> `Assoc ["kind", `String "delay"; "wake", `Bool wake_ready]
  | H.Quarantine_ahead -> kind "quarantine"
let lag = function
  | H.Snapshot_fallback value -> `Assoc ["kind", `String "snapshot"; "lag", integer value]
  | H.Lagging_soft value -> `Assoc ["kind", `String "soft"; "lag", integer value]
  | H.Lagging_quarantine value -> `Assoc ["kind", `String "quarantine"; "lag", integer value]

let run input =
  match member "op" input |> to_string with
  | "required" -> integer (H.required_attesters
      ~active_f:(number "f" input) ~validator_count:(number "n" input)
      ~configured:(number "configured" input))
  | "roots" ->
    let responses = member "roots" input |> to_list |> List.map (fun value ->
      D.{ state_root = (match value with `Null -> None | value -> Some (raw value)) }) in
    let required = number "required" input in
    let selected = H.peer_root_majority responses in
    let quorum = H.peer_root_quorum ~required ~local_root:(member "local" input |> raw) responses in
    `Assoc [
      "majority", optional_majority selected;
      "with_quorum", optional_majority (H.root_with_quorum ~required selected);
      "peer_with_quorum", optional_majority (H.peer_root_with_quorum ~required responses);
      "quorum", root_quorum quorum;
      "count", integer (H.root_quorum_count quorum);
      "has_quorum", `Bool (H.root_quorum_has_quorum quorum);
      "in_sync", in_sync (H.in_sync_plan ~required
        ~has_committed_root:(flag "committed" input) ~genesis_attested:(flag "genesis" input) quorum);
      "ahead_current", ahead_current (H.ahead_current_root_plan quorum);
    ]
  | "retry" ->
    let stale_retries = number "retries" input in
    `Assoc ["moving", retry (H.moving_head_plan ~stale_retries);
      "stale", retry (H.stale_sample_plan ~live_head_attested:(flag "attested" input) ~stale_retries)]
  | "ahead" ->
    let head = number "head" input and ahead_by = number "ahead" input in
    let grace_epochs = number "grace" input and drift_tolerance = number "tolerance" input in
    let quarantine_active = flag "quarantined" input in
    `Assoc [
      "within", `Bool (H.within_ahead_grace ~head ~ahead_by ~grace_epochs ~drift_tolerance);
      "without_quorum", kind (match H.ahead_no_quorum_plan
        ~head ~ahead_by ~grace_epochs ~drift_tolerance ~quarantine_active with
        | H.Wait_current_head -> "wait" | H.Probe_current_head -> "probe");
      "with_quorum", ahead_quorum (H.ahead_quorum_plan
        ~head ~ahead_by ~streak:(number "streak" input) ~grace_epochs ~drift_tolerance
        ~streak_threshold:(number "threshold" input) ~quarantine_active);
    ]
  | "lag" ->
    let value = number "lag" input and soft_lag = number "soft" input in
    `Assoc [
      "mode", kind (match H.classify_lag_mode ~lag:value ~soft_lag with
        | H.Soft_lag -> "soft" | H.Quarantine_lag -> "quarantine");
      "snapshot", lag (H.snapshot_plan ~lag:value);
      "catchup", lag (H.catchup_lag_plan ~lag:value ~soft_lag);
    ]
  | "config" ->
    Env.Health_oracle_env.values := member "environment" input |> to_assoc
      |> List.filter_map (fun (name, value) -> match value with
        | `Null -> None | value -> Some (name, raw value));
    let limits = Startup_runtime_limits.consensus_limits
      { int_value = Env.int_value; opt = Env.Health_oracle_env.getenv_opt } in
    `Assoc [
      "state_attest_min_peers", integer (Env.int_value "OCTRA_STATE_ATTEST_MIN_PEERS" 0);
      "ahead_streak_threshold", integer limits.quarantine_ahead_streak_threshold;
      "ahead_grace_epochs", integer limits.quarantine_ahead_grace_epochs;
      "ahead_drift_tolerance", integer limits.quarantine_ahead_drift_tolerance;
      "soft_catchup_max_lag", integer limits.soft_catchup_max_lag;
    ]
  | op -> failwith ("unknown health oracle operation: " ^ op)

let () =
  let cases = Yojson.Safe.from_channel stdin |> to_list |> List.map (fun input ->
    `Assoc ["input", input; "expected", run input]) in
  Yojson.Safe.to_channel stdout (`List cases);
  print_newline ()
