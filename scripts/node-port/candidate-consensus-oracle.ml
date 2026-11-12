open Yojson.Safe
module Q = C_quorum_policy
module T = C_types
module R = Rule_graph
let b64 s = `String (Base64.encode_exn s)
let int n = `Int n
let bool b = `Bool b
let i64 n = `String (Int64.to_string n)
let opt f = function None -> `Null | Some x -> f x
let list f xs = `List (List.map f xs)
let mode = function R.Prior -> `Bool false | Active -> `Bool true
let checked f = function Ok x -> f x | Error e -> `Assoc ["error", b64 (R.fault_message e)]
let plan p = `List [int p.R.anchor_epoch; b64 p.anchor_state_root; int p.activation_epoch]
let plans chain = [
  R.circle_activation_for_chain chain; R.wasm_compute_activation_for_chain chain;
  R.validator_quorum_activation_for_chain chain; R.epoch_time_activation_for_chain chain;
  R.owner_migration_activation_for_chain chain; R.private_payload_activation_for_chain chain;
  R.set_fold_activation_for_chain chain; R.validator_ready_activation_for_chain chain;
  R.ready_ref_activation_for_chain chain; R.set_live_activation_for_chain chain;
  R.set_fold_cap_activation_for_chain chain; R.set_open_activation_for_chain chain;
  R.object_cost_activation_for_chain chain; R.account_pack_activation_for_chain chain;
  R.standard_activation_for_chain chain; R.set_plan_activation_for_chain chain;
  R.math_activation_for_chain chain; R.exit_activation_for_chain chain;
  R.ready_exec_activation_for_chain chain; R.program_source_activation_for_chain chain;
  R.tx_envelope_activation_for_chain chain; R.fhe_work_activation_for_chain chain;
  R.wasm_float_activation_for_chain chain; R.batch_activation_for_chain chain;
  R.proof_activation_for_chain chain; R.vm_bytes_activation_for_chain chain;
  R.cipher_activation_for_chain chain; R.settle_activation_for_chain chain;
  R.stake_activation_for_chain chain; R.program_records_activation_for_chain chain;
  R.duty_marks_activation_for_chain chain; R.proof_key_activation_for_chain chain;
  R.tx_network_activation_for_chain chain]
let modes = [R.circle; R.wasm_compute; R.validator_quorum; R.epoch_time;
  R.owner_migration; R.private_payload; R.set_fold; R.validator_ready;
  R.ready_ref; R.set_live; R.set_fold_cap; R.set_open; R.object_cost;
  R.account_pack; R.standard; R.set_plan; R.math; R.exit; R.ready_exec;
  R.program_source; R.tx_envelope; R.fhe_work; R.wasm_float; R.circle_batch;
  R.proof_exec; R.vm_bytes; R.cipher_migration; R.settle; R.stake;
  R.program_records; R.duty_marks; R.proof_key; R.tx_network]
let member id = T.{address = "v" ^ string_of_int id; pubkey = String.make 32 (Char.chr id)}
let validator_set skew =
  List.init 4 (fun n -> member (n+1), Z.of_int (if skew && n=0 then 1000 else 1))
  |> T.make_weighted_validator_set |> Result.get_ok
let rule = function Q.Prior -> `String "prior" | Capped -> `String "capped" | Stake -> `String "stake"
let policy_case chain epoch skew authors =
  let q = Q.for_chain chain in
  let set = validator_set skew in
  let set = if authors then {set with authors = Some (1740000L, [member 5, Z.of_int 17])} else set in
  let effective = T.validator_set_for_epoch ~chain_id:chain ~epoch_id:epoch set in
  let encoded = C_codec.encode_validator_set effective in
  let decoded = C_codec.decode_validator_set encoded in
  let config_hash = C_config.hash ~chain_id:chain ~validator_set:effective () in
  let light = C_light_validator_set.of_validator_set ~chain_id:chain ~config_hash effective in
  let subsets = List.init 16 (fun bits ->
    List.init 4 (fun n -> n) |> List.filter_map (fun n ->
      if bits land (1 lsl n) <> 0 then Some (member(n+1)).address else None)) in
  `Assoc ["input", `Assoc ["chain", b64 chain; "epoch", i64 epoch;
                          "skew", bool skew; "authors", bool authors];
    "expected", `Assoc [
      "rule", rule (Q.select q epoch); "id", `String (Q.id_at q ~chain_id:chain ~epoch_id:epoch);
      "round_wait", bool(Q.round_wait q epoch); "epochs", list i64 (Q.epochs q);
      "wire", b64 encoded; "hash", b64(C_config.validator_set_hash effective);
      "roundtrip", bool (C_codec.encode_validator_set decoded = encoded);
      "light_verified", bool (C_light_validator_set.verify light);
      "light_config_hash", opt b64 (C_light_validator_set.recomputed_config_hash light);
      "weights", list (fun (v,w) -> `List[b64 v.T.address; `String(Z.to_string w)]) (T.weights_of_set effective);
      "leader", b64 (T.leader_of effective ~epoch_id:epoch ~round:7).T.address;
      "source_wire", opt (fun vs -> b64(C_codec.encode_validator_set vs)) (T.source_set ~chain_id:chain ~epoch_id:epoch effective);
      "author", bool(T.is_author ~chain_id:chain ~epoch_id:epoch effective (member 5).address);
      "quorums", list (fun addresses -> bool(T.has_quorum_at ~chain_id:chain ~epoch_id:epoch effective addresses)) subsets;
      "rewind", bool(Q.rewind_allowed ~chain_id:chain ~from_epoch:epoch ~to_epoch:(Int64.pred epoch))]]
let graph_case chain epoch root_kind floor =
  let ps = plans chain in
  let root_at height = match root_kind with
    | "missing" -> R.Missing | "bad" -> R.Root "wrong-root" | "unreadable" -> R.Unreadable "disk unavailable"
    | _ -> (match List.find_map (function Some p when p.R.anchor_epoch = height -> Some p.anchor_state_root | _ -> None) ps with None -> R.Missing | Some r -> R.Root r) in
  let graph = R.create ~chain_id:chain ~root_at in
  let probes = 0 :: 1 :: 1692238 :: 1740001 :: List.filter_map (Option.map (fun p -> p.R.anchor_epoch)) ps |> List.sort_uniq compare in
  `Assoc ["input", `Assoc ["chain", b64 chain; "epoch", int epoch; "root", `String root_kind; "floor", int floor; "probes", list int probes];
    "expected", `Assoc ["plans", list (opt plan) ps;
      "modes", list (fun f -> checked mode (f graph ~epoch)) modes;
      "overlap", checked bool(R.program_overlap graph ~epoch);
      "profiles", list int(R.profile_epochs ~chain_id:chain); "live", bool(R.live_chain ~chain_id:chain);
      "id", b64(R.consensus_id ~chain_id:chain ~epoch);
      "program_inputs", mode(R.program_inputs_at ~chain_id:chain ~epoch);
      "floor", list (fun probe -> opt b64(R.root_after_floor ~chain_id:chain ~floor_epoch:floor ~epoch:probe)) probes]]
let () =
  let chains = [Q.devnet_chain_id; "octra-mainnet"; "isolated-candidate"] in
  let policy = List.concat_map (fun chain ->
    [0L; 1306546L; 1306547L; 1737332L; 1737333L; 1739999L; 1740000L; 1740001L]
    |> List.concat_map (fun epoch -> [false;true] |> List.concat_map (fun skew ->
      [false;true] |> List.map (policy_case chain epoch skew)))) chains in
  let graph = List.concat_map (fun chain ->
    let epochs = [0;1737332;1737333;1739999;1740000;1740001] @
      (plans chain |> List.filter_map (Option.map(fun p -> p.R.activation_epoch))
       |> List.concat_map(fun e -> [e-1;e;e+1])) |> List.sort_uniq compare in
    List.concat_map (fun epoch ->
      ["good";"missing";"bad";"unreadable"] |> List.concat_map(fun roots ->
        [0;1692238] |> List.map(graph_case chain epoch roots))) epochs) chains in
  Yojson.Safe.to_channel stdout (`Assoc["policy", `List policy; "graph", `List graph]);
  print_newline ()
