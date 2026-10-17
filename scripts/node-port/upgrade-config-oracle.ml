(* Only environment acquisition is injected. P2p_upgrade_plan's original
   function bodies are retained verbatim after the recorded test-only prefix. *)
open Yojson.Safe.Util
module U = Octra_net.P2p_upgrade_plan

let raw value = Base64.decode_exn (to_string value)
let bytes value = `String (Base64.encode_exn value)
let integer value = `String (Int64.to_string value)
let failure reason = `Assoc ["error", bytes reason]
let catch run =
  try run () with
  | Failure reason | Invalid_argument reason -> failure reason
  | error -> failure (Printexc.to_string error)

let rollback_json (value : U.rollback) =
  `Assoc [
    "epoch", integer value.rollback_epoch;
    "binary", bytes value.rollback_binary_hash;
    "config", bytes value.rollback_config_hash;
  ]

let plan_json = function
  | None -> `Null
  | Some (value : U.t) ->
    `Assoc [
      "epoch", integer value.activate_epoch;
      "binary", bytes value.target_binary_hash;
      "config", bytes value.target_config_hash;
      "rollback", (match value.rollback with
        | None -> `Null
        | Some rollback -> rollback_json rollback);
    ]

let observe plan input = catch (fun () ->
  let epoch = member "epoch" input |> to_string |> Int64.of_string in
  let config_hash = member "config" input |> raw in
  let binary_hash = member "binary" input |> raw in
  let require_binary_hash = member "required" input |> to_bool in
  `Assoc [
    "handshake", bytes (U.handshake_hash
      ~epoch ~config_hash ~binary_hash ~require_binary_hash plan);
    "active", `Bool (U.active ~epoch plan);
    "rollback", `Bool (U.rollback_active ~epoch plan);
    "required", `Bool (U.binary_required ~epoch ~require_binary_hash plan);
    "expected", bytes (U.expected_binary_hash ~epoch ~binary_hash plan);
    "ready", (match U.ready
      ~epoch ~config_hash ~binary_hash ~require_binary_hash plan with
      | U.Ready -> `Null
      | U.Not_ready reason -> `String reason);
    "schedule", (match plan with
      | None -> `Null
      | Some value -> bytes (U.schedule_hash ~base_config_hash:config_hash value));
  ])

let run input =
  U.Octra_upgrade_env.values :=
    member "environment" input |> to_assoc |> List.filter_map (fun (name, value) ->
      match value with `Null -> None | value -> Some (name, raw value));
  U.Octra_upgrade_env.reads := [];
  let result = catch (fun () ->
    let current_config_hash = member "base_config" input |> raw in
    let require_binary_hash = member "required" input |> to_bool in
    match U.of_env ~current_config_hash ~require_binary_hash with
    | Error reason -> failure reason
    | Ok plan -> `Assoc [
        "plan", plan_json plan;
        "observations", `List (member "probes" input |> to_list |> List.map (observe plan));
      ])
  in
  (* Getter evaluation order is not an observable configuration guarantee.
     Preserve duplicate reads, but sort names before comparing Rust and OCaml. *)
  let reads = List.sort String.compare !(U.Octra_upgrade_env.reads) in
  `Assoc ["result", result; "reads", `List (List.map (fun name -> `String name) reads)]

let () =
  let cases = Yojson.Safe.from_channel stdin |> to_list |> List.map (fun input ->
    `Assoc ["input", input; "expected", run input]) in
  Yojson.Safe.to_channel stdout (`List cases);
  print_newline ()
