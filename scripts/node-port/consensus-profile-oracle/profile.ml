(* Calls only public, unchanged adopted native modules. No hash/validator/proof
   callback is substituted. One sanitized process is used per environment. *)
module P = Octra_node_runtime.Consensus_profile
module T = Octra_core.Transaction
module L = Octra_node_runtime.Startup_runtime_limits
module R = Octra_core.Rule_graph
let hex raw =
  String.to_seq raw |> Seq.map (fun c -> Printf.sprintf "%02x" (Char.code c))
  |> List.of_seq |> String.concat ""
let field name = function
  | `Assoc fields -> List.assoc name fields
  | _ -> invalid_arg "case must be an object"
let string = function `String value -> value | _ -> invalid_arg "expected string"
let strings = function `List values -> List.map string values | _ -> invalid_arg "expected list"
let assoc = function `Assoc values -> List.map (fun (key,value) -> key,string value) values | _ -> invalid_arg "expected environment object"
let bool = function `Bool value -> value | _ -> invalid_arg "expected bool"
let valid_digest raw = String.length raw = 64 && String.for_all (function '0'..'9'|'a'..'f' -> true | _ -> false) raw
let mode = function R.Prior -> `String "prior" | R.Active -> `String "active"
let actual_octra_env () =
  Unix.environment () |> Array.to_list |> List.filter_map (fun row ->
    match String.index_opt row '=' with
    | None -> None
    | Some index ->
      let key = String.sub row 0 index in
      if String.starts_with ~prefix:"OCTRA_" key then
        Some (key,String.sub row (index+1) (String.length row-index-1))
      else None)
  |> List.sort compare
let operations names =
  `List (List.map (fun name ->
    match T.op_type_of_string name with
    | Error reason -> `Assoc ["operation",`String name;"error",`String reason]
    | Ok op -> `Assoc [
        "operation",`String name;
        "admits",`Bool (T.bft_admits_op op);
        "consensus_admits",`Bool (T.bft_consensus_admits_op op);
      ]) names)
let settings getenv =
  let env : L.env = {
    int_value = (fun name fallback -> match getenv name with
      | None -> fallback | Some value -> (try int_of_string value with _ -> fallback));
    opt = getenv;
  } in
  let private_limits : L.private_limits = L.private_limits env in
  let proposal : Octra_node_runtime.Consensus_proposal.limits =
    L.proposal_limits env ~default_max_ou:Octra_core.Tx_staging.max_ou_per_epoch in
  `Assoc [
    "proposal_txs",`Int proposal.max_txs;
    "proposal_bytes",`Int proposal.max_bytes;
    "proposal_ou",`String (Z.to_string proposal.max_ou);
    "stealth_defer",`Int private_limits.max_stealth_defer;
    "stealth_slots",`Int private_limits.max_stealth_per_epoch;
    "fhe_slots",`Int private_limits.max_fhe_per_epoch;
    "inline_verify",`Bool private_limits.stealth_inline_verify_allowed;
    "multi_exec",`Int (L.multi_exec_max env);
    "minimum_epoch_ms",`Int Octra_node_runtime.Epoch_cadence.minimum_ms;
    "receipt_activation",`Int (Octra_core.Preverify_receipt_policy.activation_epoch_of getenv);
    "private_result_activation",`Int (Result.get_ok (Octra_core.Private_result_policy.activation_epoch_of getenv));
    "release",`String (T.bft_release_profile_of getenv |> T.bft_release_profile_name);
    "crypto",`String (T.bft_crypto_profile_of getenv |> T.bft_crypto_profile_name);
    "crypto_engine",`String (Octra_core.Pvac_registry.expected_kat ());
  ]
let epoch_rows chain_id getenv =
  let epochs = R.profile_epochs ~chain_id in
  let probes = List.sort_uniq compare
    ([0;1;max_int] @ List.concat_map (fun epoch ->
      (if epoch > 0 then [epoch-1] else []) @ [epoch] @ (if epoch < max_int then [epoch+1] else [])) epochs) in
  let private_activation = Result.get_ok (Octra_core.Private_result_policy.activation_epoch_of getenv) in
  `List (List.map (fun epoch -> `Assoc [
    "epoch",`Int epoch;
    "compat_hash",`String (hex (P.compat_hash getenv));
    "standard_hash",`String (hex (P.standard_hash ~chain_id ~epoch getenv));
    "selected_hash",`String (hex (P.hash ~chain_id ~epoch getenv));
    "switch_after",`Bool (P.switch_after ~chain_id ~applied_epoch:epoch);
    "standard",mode (R.standard_at ~chain_id ~epoch);
    "math",mode (R.math_at ~chain_id ~epoch);
    "cipher_migration",mode (R.cipher_migration_at ~chain_id ~epoch);
    "private_result",`String (match Octra_core.Private_result_policy.for_epoch ~activation_epoch:private_activation epoch with
      | Octra_core.Private_result_policy.Legacy -> "legacy"
      | Octra_core.Private_result_policy.Recoverable -> "recoverable");
  ]) probes)
let () =
  assert (Array.length Sys.argv = 4);
  assert (valid_digest Sys.argv.(2) && valid_digest Sys.argv.(3));
  let channel = open_in_bin Sys.argv.(1) in
  let size = in_channel_length channel in
  assert (size <= 1_048_576);
  let raw = really_input_string channel size in close_in channel;
  let input = Yojson.Safe.from_string raw in
  let values = field "env" input |> assoc |> List.sort compare in
  assert (List.for_all (fun (key,_) -> String.starts_with ~prefix:"OCTRA_" key) values);
  assert (actual_octra_env () = values);
  let getenv name = List.assoc_opt name values in
  let chain_id = field "chain_id" input |> string in
  let names = field "operations" input |> strings in
  let expected_valid = field "expect_valid" input |> bool in
  let valid, reason = match P.validate getenv with Ok () -> true,`Null | Error reason -> false,`String reason in
  assert (valid = expected_valid);
  let result = `Assoc [
    "schema",`String "octra_native_consensus_profile_case_v1";
    "native_pin",`String "7f9be4489870645cfcc95439638cde40f5da9f50";
    "native_sources_sha256",`String Sys.argv.(2);
    "oracle_source_sha256",`String Sys.argv.(3);
    "id",field "id" input;
    "chain_id",`String chain_id;
    "env",field "env" input;
    "valid",`Bool valid;
    "error",reason;
    "settings",(if valid then settings getenv else `Null);
    "operations",(if valid then operations names else `Null);
    "activation_graph_hash",(if valid then `String (hex (P.activation_graph_hash ~chain_id)) else `Null);
    "epochs",(if valid then epoch_rows chain_id getenv else `Null);
    "selector_scope",`String "epoch-only compatibility profile; not authenticated execution-rule activation";
  ] in
  print_endline (Yojson.Safe.to_string result)
