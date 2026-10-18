(* The native Epochlog parser and epoch_source bodies are unchanged. Inputs
   provide independently selected historical policy and encoded validator keys. *)
open Yojson.Safe.Util
module C = Octra_consensus
module EL = Octra_core.Epochlog
module R = Octra_node_runtime.Consensus_reward_attribution
let hex s = String.concat "" (List.init (String.length s) (fun i -> Printf.sprintf "%02x" (Char.code s.[i])))
let unhex s = String.init (String.length s / 2) (fun i -> Char.chr (int_of_string ("0x" ^ String.sub s (i * 2) 2)))
let raw name j = j |> member name |> to_string |> unhex
let run j =
  Unix.putenv C.C_protocol.activation_env (j |> member "protocol_activation" |> to_string);
  let weighted = match j |> member "validator_activation" with
    | `Null -> None | value -> Some (int_of_string (to_string value)) in
  let keys = j |> member "keys" |> to_list |> List.map (fun pair ->
    match to_list pair with
    | [address; key] -> unhex (to_string address), unhex (to_string key)
    | _ -> failwith "fixture key pair") in
  match EL.epoch_of_json (raw "header" j) with
  | None -> `Assoc ["decoded", `Bool false]
  | Some header ->
    let source = match R.epoch_source ~validator_activation_epoch:weighted ~validator_pubkeys:keys header with
      | Ok source -> `Assoc ["ok", `String (hex (Octra_net.Oce1.encode (fun b -> C.C_reward_source.encode_into b source)))]
      | Error error -> `Assoc ["error", `String (hex error)] in
    `Assoc ["decoded", `Bool true; "epoch", `String (string_of_int header.id);
      "root", `String (hex header.state_root); "previous_root", `String (hex header.prev_state_root);
      "parent_commit", `String (hex header.parent_commit);
      "start_txid", `String (Int64.to_string header.start_txid); "count", `String (string_of_int header.tx_count);
      "source", source]
let () =
  let cases = Yojson.Safe.from_channel stdin |> to_list |> List.map (fun input ->
    `Assoc ["input", input; "expected", run input]) in
  Yojson.Safe.to_channel stdout (`List cases); print_newline ()
