open Yojson.Safe.Util
let raw value = value |> to_string |> Base64.decode_exn
let mode = function R.Active -> `Bool true | R.Prior -> `Bool false
let run input =
  let chain = raw (member "chain" input) and epoch = member "epoch" input |> to_int in
  let plans = activations chain in
  let root_at height =
    let kind = match member (string_of_int height) (member "roots" input) with
      | `String kind -> kind | _ -> member "default" input |> to_string in
    match kind with
    | "missing" -> R.Missing | "bad" -> R.Root "wrong-root"
    | "unreadable" -> R.Unreadable "disk unavailable"
    | "good" ->
      begin match Array.to_list plans |> List.find_map (function
        | Some plan when plan.R.anchor_epoch = height -> Some plan.anchor_state_root
        | _ -> None) with
      | None -> R.Missing | Some root -> R.Root root
      end
    | _ -> assert false in
  let rules = match member "config" input with
    | `Null -> R.create ~chain_id:chain ~root_at
    | config -> R.create_ready ~chain_id:chain ~root_at ~ready_config_hash:(raw config) in
  let parent_commit = match member "parent" input with
    | `Null -> None | encoded -> Some (Octra_consensus.C_codec.decode_parent_commit (raw encoded)) in
  let env = Octra_core.Epoch_exec.{chain_id=chain;epoch_id=epoch;proposer_addr="unused";
    validator_addrs=[];validator_pubkeys=[];prev_state_root="unused";epoch_ts=1.;
    ready_state_root_at=None;ready_max_lag=2} in
  match Lwt_main.run (Selection.select ~rules ~epoch_id:epoch ~env ~parent_commit) with
  | Error error -> `Assoc ["error", `String error]
  | Ok (circle,compute,object_cost,owner,cipher,private_payload,ctx) ->
    `Assoc ["manifest", `String (if compute = R.Active then "manifest" else "compute");
      "update_policy",mode circle;"object_cost",`Bool object_cost;
      "owner_migration",mode owner;"cipher_migration",mode cipher;
      "private_payload",mode private_payload;"math",`Bool ctx.math;
      "proof_exec",mode ctx.proof_exec;"float",mode ctx.wasm_float;
      "inspect",mode ctx.vm_bytes;"storage_proof",mode ctx.standard_mode]
let () = Yojson.Safe.from_channel stdin |> to_list
  |> List.map (fun input -> `Assoc ["input", input; "expected", run input])
  |> fun cases -> Yojson.Safe.to_channel stdout (`List cases); print_newline ()
