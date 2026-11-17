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
  R.tx_network_activation_for_chain chain; R.scalar_work_activation_for_chain chain;
  R.source_plan chain; R.program_result_plan chain; R.seatless_activation_for_chain chain]
let modes = [R.circle; R.wasm_compute; R.validator_quorum; R.epoch_time;
  R.owner_migration; R.private_payload; R.set_fold; R.validator_ready;
  R.ready_ref; R.set_live; R.set_fold_cap; R.set_open; R.object_cost;
  R.account_pack; R.standard; R.set_plan; R.math; R.exit; R.ready_exec;
  R.program_source; R.tx_envelope; R.fhe_work; R.wasm_float; R.circle_batch;
  R.proof_exec; R.vm_bytes; R.cipher_migration; R.settle; R.stake;
  R.program_records; R.duty_marks; R.proof_key; R.tx_network;
  R.scalar_work; R.source_create; R.program_result; R.seatless]
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
(* Quorum measure: every ask over a grid of seats and weights, per rule. *)
module M = C_measure
let str s = `String s
let z v = `String (Z.to_string v)
let bits bs = `String (String.concat "" (List.map (fun b -> if b then "1" else "0") bs))
let guard f = try f () with exn -> `Assoc ["raised", str (Printexc.to_string exn)]
let asks = [M.Quorum; M.Skip; M.Source; M.Pair; M.Ahead; M.Start; M.Promise]
let named ws = List.mapi (fun i w -> "v" ^ string_of_int (i + 1), Z.of_int w) ws
let weight_sets = [[]; [1]; [1;1]; [1;1;1]; [1;1;1;1]; [1000;1;1;1]; [5;4;3;2;1];
  [7;7;7;7;7;7;7]; [1;2;3;4;5;6;7;8;9;10]; [100;1;1;1;1;1;1]; [3;3;3;1]; [34;33;33]]
let targets = List.map named weight_sets @ [
  ["v1", Z.zero; "v2", Z.one]; ["v1", Z.one; "v1", Z.one]; ["v1", Z.of_int (-1); "v2", Z.of_int 5];
  ["v1", Z.of_int 2; "v2", Z.of_int 2; "v3", Z.of_int 2; "v4", Z.of_int 2; "v5", Z.of_int 2]]
let gap = function Ok () -> str "ok" | Error M.Few_seats -> str "few_seats"
  | Error M.Low_weight -> str "low_weight" | Error M.No_proof -> str "no_proof"
let measure_case epoch declared ws =
  let weights = named ws in
  let space = M.space (Q.for_chain Q.devnet_chain_id) epoch ~declared weights in
  let shape = M.shape ~seats:(List.length ws)
    ~total:(List.fold_left (fun t (_, w) -> Z.add t w) Z.zero weights) in
  let probes = [Z.of_int (-1); Z.zero; Z.one; Z.pred (M.minority shape); M.minority shape;
    Z.pred shape.quorum_weight; shape.quorum_weight; shape.total_weight; Z.succ shape.total_weight] in
  let seats = List.init (List.length ws + 2) (fun n -> n) in
  let grid f = bits (List.concat_map (fun s -> List.map (fun w -> f s w) probes) seats) in
  `Assoc ["input", `Assoc ["epoch", i64 epoch; "declared", bool declared;
      "weights", list int ws; "probes", list z probes];
    "expected", `Assoc [
      "shape", `List [int shape.n; int shape.f; int shape.quorum; z shape.total_weight; z shape.quorum_weight];
      "minority", z (M.minority shape); "valid", bool (M.valid space); "label", str (M.label space);
      "start", str (M.start_text space); "promise", str (M.promise_text space);
      "wave", int (M.wave space); "fanout", int (M.fanout space);
      "replies", list (fun c -> int (M.replies space ~configured:c)) [0;1;2;5;100];
      "meets", list (fun ask -> grid (fun seats weight -> M.meets space ask ~seats ~weight)) asks;
      "attested", list (fun required ->
        grid (fun seats weight -> M.attested space ~required ~seats ~weight)) [0;1;2;List.length ws];
      "live", bits (List.map (fun lost -> M.live ~total:shape.total_weight ~lost) probes);
      "overlap", list (fun target -> gap (M.overlap space target)) targets]]
(* Validator-set shape, seat cap, eviction and pending-set selection. *)
let wset ws = List.mapi (fun i w -> member (i + 1), Z.of_int w) ws
  |> T.make_weighted_validator_set |> Result.get_ok
let set_json (s : T.validator_set) = `Assoc [
  "validators", list (fun v -> `List [b64 v.T.address; b64 v.pubkey]) s.validators;
  "weights", list (fun (a, w) -> `List [b64 a; z w]) s.weights;
  "n", int s.n; "f", int s.f; "quorum", int s.quorum; "total", z s.total_weight;
  "quorum_weight", z s.quorum_weight; "weighted", bool s.weighted;
  "authors", opt (fun (h, entries) -> `List [i64 h;
    list (fun (v, w) -> `List [b64 v.T.address; b64 v.pubkey; z w]) entries]) s.authors]
let digest (s : T.validator_set) = `List [
  (* A set returned unchecked before seatless voting may still lack a weight. *)
  (try b64 (C_config.validator_set_hash s) with Invalid_argument _ -> `Null);
  `List [int s.n; int s.f; int s.quorum; z s.total_weight; z s.quorum_weight; bool s.weighted];
  list (fun v -> b64 v.T.address) s.validators; list (fun (a, w) -> `List [b64 a; z w]) s.weights;
  opt (fun (h, entries) -> `List [i64 h;
    list (fun (v, w) -> `List [b64 v.T.address; b64 v.pubkey; z w]) entries]) s.authors]
let res f = function Ok v -> f v | Error e -> `Assoc ["error", str e]
let set_err = function Ok v -> digest v | Error (T.Set_shape e) -> `Assoc ["error", str e]
  | Error T.Seat_cap -> `Assoc ["seat_cap", bool true]
let mutations epoch (s : T.validator_set) = [
  "base", s; "unweighted", {s with weighted = false};
  "drop_weight", {s with weights = List.tl s.weights};
  "rename_weight", {s with weights = ("zz", snd (List.hd s.weights)) :: List.tl s.weights};
  "reversed", {s with validators = List.rev s.validators; weights = List.rev s.weights};
  "n", {s with n = s.n + 1}; "f", {s with f = s.f + 1}; "quorum", {s with quorum = s.quorum + 1};
  "total", {s with total_weight = Z.succ s.total_weight};
  "quorum_weight", {s with quorum_weight = Z.succ s.quorum_weight};
  "authors", {s with authors = Some (epoch, [member 99, Z.of_int 5])};
  "authors_overlap", {s with authors = Some (epoch, [member 1, Z.one])};
  "authors_dupkey", {s with authors = Some (epoch, [T.{address = "zz"; pubkey = (member 1).pubkey}, Z.one])};
  "authors_other_height", {s with authors = Some (Int64.pred epoch, [member 99, Z.of_int 5])}]
let set_case epoch ws (name, (s : T.validator_set)) =
  let chain_id = Q.devnet_chain_id and epoch_id = epoch in
  let base = wset ws in
  let addresses = List.map (fun v -> v.T.address) base.validators in
  let rec prefixes = function [] -> [[]] | x :: rest -> [] :: List.map (fun p -> x :: p) (prefixes rest) in
  let heaviest = fst (List.fold_left (fun (a, w) (b, v) -> if Z.gt v w then (b, v) else (a, w))
    ("", Z.zero) base.weights) in
  let signer_sets = prefixes addresses @ [["zz"]; ["v1"; "v1"]; [heaviest]; List.rev addresses] in
  let offender_sets = [[]; ["v1"]; ["v1"; "v1"]; ["zz"]; ["v1"; "v2"]; addresses; [heaviest]] in
  let choice = function
    | Ok (T.Active_set v) -> `Assoc ["active", digest v]
    | Ok (T.Pending_set v) -> `Assoc ["pending", digest v]
    | Error (T.Set_shape e) -> `Assoc ["error", str e]
    | Error T.Seat_cap -> `Assoc ["seat_cap", bool true] in
  let known signers = List.sort_uniq String.compare signers |> List.fold_left (fun sum a ->
    Z.add sum (Option.value (T.weight_of_addr s a) ~default:Z.zero)) Z.zero in
  `Assoc ["input", `Assoc ["epoch", i64 epoch; "name", str name; "base", list int ws; "set", set_json s;
      "signers", list (list b64) signer_sets; "offenders", list (list b64) offender_sets];
    "expected", `Assoc [
      "shape", guard (fun () -> set_err (T.validate_validator_set_shape s));
      "structural", guard (fun () -> set_err (T.structural_validator_set_for_epoch ~chain_id ~epoch_id s));
      "validate", guard (fun () -> set_err (T.validate_validator_set_for_epoch ~chain_id ~epoch_id s));
      "checked", guard (fun () -> res digest (T.checked_validator_set_for_epoch ~chain_id ~epoch_id s));
      "same_base", guard (fun () -> bool (T.same_voting_set base s));
      "pending_active", guard (fun () -> choice (T.pending_set_for_epoch ~chain_id ~epoch_id ~active:(Some base) s));
      "pending_alone", guard (fun () -> choice (T.pending_set_for_epoch ~chain_id ~epoch_id ~active:None s));
      "plans", list (fun offenders -> guard (fun () -> match T.plan_eviction ~offenders s with
        | Ok (T.Remove_set (next, w)) -> `Assoc ["remove", digest next; "weight", z w]
        | Ok (T.Retain_set w) -> `Assoc ["retain", z w]
        | Error e -> `Assoc ["error", str e])) offender_sets;
      "evict", list (fun offenders -> guard (fun () ->
        res (fun (next, w) -> `Assoc ["set", digest next; "weight", z w])
          (T.evict_validator_set ~offenders s))) offender_sets;
      "skip_weight", guard (fun () -> z (T.round_skip_weight s));
      "quorum", list (fun signers -> guard (fun () ->
        bool (T.has_quorum_at ~chain_id ~epoch_id s signers))) signer_sets;
      "pair", list (fun signers -> guard (fun () -> bool (T.pair_at ~chain_id ~epoch_id s signers))) signer_sets;
      "promise", list (fun signers -> guard (fun () ->
        bool (T.promise_at ~chain_id ~epoch_id s signers))) signer_sets;
      "reached", list (fun signers -> guard (fun () -> bool (T.quorum_reached_at ~chain_id ~epoch_id s
        ~signer_count:(List.length signers) ~signed_weight:(known signers)))) signer_sets;
      "skip", list (fun signers -> guard (fun () -> bool (T.round_skip_reached_at ~chain_id ~epoch_id s
        ~signer_count:(List.length signers) ~signed_weight:(known signers)))) signer_sets]]
let () =
  let chains = [Q.devnet_chain_id; "octra-mainnet"; "isolated-candidate"] in
  let policy = List.concat_map (fun chain ->
    [0L; 1306546L; 1306547L; 1737332L; 1737333L; 1739999L; 1740000L; 1740001L;
     1844999L; 1845000L; 1845001L]
    |> List.concat_map (fun epoch -> [false;true] |> List.concat_map (fun skew ->
      [false;true] |> List.map (policy_case chain epoch skew)))) chains in
  let graph = List.concat_map (fun chain ->
    let epochs = [0;1737332;1737333;1739999;1740000;1740001] @
      (plans chain |> List.filter_map (Option.map(fun p -> p.R.activation_epoch))
       |> List.concat_map(fun e -> [e-1;e;e+1])) |> List.sort_uniq compare in
    List.concat_map (fun epoch ->
      ["good";"missing";"bad";"unreadable"] |> List.concat_map(fun roots ->
        [0;1692238] |> List.map(graph_case chain epoch roots))) epochs) chains in
  let measure = List.concat_map (fun epoch -> List.concat_map (fun declared ->
    List.map (measure_case epoch declared) weight_sets) [false; true])
    [0L; 1306547L; 1737333L; 1844999L; 1845000L] in
  let sets = List.concat_map (fun epoch -> List.concat_map (fun ws ->
    List.map (set_case epoch ws) (mutations epoch (wset ws)))
    [[1]; [1;1;1;1]; [1000;1;1;1]; [5;4;3;2;1]; [3;3;3;1]; [34;33;33]; [33;33;33;1];
     [1;2;3;4;5;6;7;8;9;10]]) [1737333L; 1844999L; 1845000L] in
  let target (name, weight) = `List [b64 name; z weight] in
  Yojson.Safe.to_channel stdout (`Assoc["policy", `List policy; "graph", `List graph;
    "measure", `List measure; "measure_targets", list (list target) targets; "sets", `List sets]);
  print_newline ()
