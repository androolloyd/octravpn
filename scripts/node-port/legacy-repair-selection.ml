(* SPDX-License-Identifier: BSD-3-Clause *)
(* Legacy-only acquisition/staging adapter. All consensus and physical repair
   decisions call the unchanged adopted implementation. No service is started. *)
module Core = Octra_core
module Runtime = Octra_node_runtime
module C = Octra_consensus
module SC = Core.Store_chaindata
module SI = Core.Store_irmin
module Fork = Core.Fork_head_repair
module HM = Core.Head_manifest
module FL = C.Finality_log
module Journal = Runtime.Consensus_finality_journal
let unwrap = function Ok value -> value | Error reason -> failwith reason
let require reason condition = if not condition then failwith reason
let some reason = function Some value -> value | None -> failwith reason
let head dir = match HM.load_result dir with
 | HM.Present head -> head | HM.Missing -> failwith "HEAD is missing"
 | HM.Corrupt reason -> failwith reason
let no_plan dir =
 require "repair marker already exists"
  (match Fork.read_plan dir with Ok None -> true | _ -> false);
 require "orphan staged repair exists"
  (not (Sys.file_exists (Filename.concat dir "fork_repair.json.staged")))
let settings json =
 let fields = Yojson.Safe.Util.to_assoc json in
 require "ambiguous captured settings"
  (List.length fields = List.length (List.sort_uniq String.compare (List.map fst fields)));
 List.map (fun (name,value) ->
  require "invalid captured setting" (String.starts_with ~prefix:"OCTRA_" name);
  let value = Yojson.Safe.Util.to_string value |> Base64.decode_exn in
  require "invalid captured setting bytes" (not (String.contains name '\000') && not (String.contains value '\000'));
  name,value) fields
let relief_json = function
 | None -> `Null
 | Some mark -> `Assoc [
   "height", `String (Int64.to_string mark.C.C_relief.height);
   "round", `Int mark.round;
   "activate_epoch", `String (Int64.to_string mark.activate_epoch);
   "source_hash", `String (Base64.encode_exn mark.source_hash);
   "target_hash", `String (Base64.encode_exn mark.target_hash);
   "fingerprint", `String mark.fingerprint;
   "proof", `List (List.map (fun value -> `String (Base64.encode_exn (C.C_codec.encode_round_sync value))) mark.proof)]
let encoded set = `String (Base64.encode_exn (C.C_codec.encode_validator_set set))
let capture dir chain store chain_id configuration origin =
 let open Yojson.Safe.Util in
 no_plan dir;
 let origin_epoch = member "epoch" origin |> to_int in
 let origin_root = member "root" origin |> to_string |> Base64.decode_exn in
 require "invalid trusted network origin" (origin_epoch >= 0 && String.length origin_root = 32);
 require "legacy source differs from trusted network origin" (Fork.target_matches chain ~target:origin_epoch ~root:origin_root);
 List.iter (fun (name,value) -> Unix.putenv name value) configuration;
 let getenv name = List.assoc_opt name configuration in
 require "captured chain differs" (getenv "OCTRA_CHAIN_ID" = Some chain_id);
 let source = head dir in
 require "source epoch out of range" (source.epoch_id >= 0 && source.epoch_id < max_int);
 let epoch = Int64.succ (Int64.of_int source.epoch_id) in
 let active = Lwt_main.run (SI.get_meta store Core.Validator_set_update.active_meta_key) in
 let pending = Lwt_main.run (SI.get_meta store Core.Validator_set_update.pending_meta_key) in
 let relief = C.C_relief_log.disk ~data_dir:dir in
 let mark = unwrap (C.C_relief_log.latest relief ~through_height:epoch) in
 let anchor = Runtime.Consensus_validator_anchor.{
   getenv; chain_id; current_height=(fun () -> Int64.of_int source.epoch_id);
   active_raw=(fun () -> active); pending_raw=(fun () -> pending);
   relief=(fun height -> C.C_relief_log.latest relief ~through_height:height);
 } in
 let active_set = unwrap (Runtime.Consensus_validator_anchor.expected_set anchor ~epoch) in
 let stake = unwrap (Runtime.Consensus_validator_anchor.stake_set anchor ~epoch) in
 let startup = unwrap (Runtime.P2p_config.node_startup_config ~getenv ~chain_id
   ~consensus_mode:true ~current_height:(Int64.of_int source.epoch_id)
   ~chain_active_raw:active ~chain_pending_raw:pending
   ~chain_pending_entries:(Runtime.Validator_config.pending_entries_of_raw pending)) in
 require "invalid trusted validator identities" (startup.validator.identity_errors = []);
 require "unsafe validator quorum" (match Runtime.Validator_config.quorum_admission
   ~allow_unsafe:false startup.validator with Runtime.Validator_config.Quorum_ok -> true | _ -> false);
 let live = some "live store root missing" (Lwt_main.run (SI.get_head_hash store)) in
 let boundary = unwrap (SC.epoch_boundary chain source.epoch_id) in
 let folded = Core.Epoch_index_commitment.folded_state_root
   ~ledger_state_root:live ~epoch_index_root:boundary.index_root in
 require "live source root differs" (source.state_root = folded && Fork.target_matches chain ~target:source.epoch_id ~root:(Fork.hex_raw folded));
 require "source transaction boundary differs" (source.txid_hi = boundary.txid_hi && source.txid_hi <> Int64.max_int && SC.next_txid chain = Int64.succ source.txid_hi);
 let nullable = function None -> `Null | Some value -> `String (Base64.encode_exn value) in
 let binding = `Assoc ["head", `String (Base64.encode_exn (HM.to_json source));
   "live", `String live; "active_meta", nullable active; "pending_meta", nullable pending;
   "relief", relief_json mark; "active", encoded active_set; "stake", encoded stake;
   "settings", `Assoc (List.map (fun (name,value) -> name,`String (Base64.encode_exn value)) configuration)] in
 let token = Digestif.SHA256.(to_hex (digest_string (Yojson.Safe.to_string binding))) in
 let wire = startup.handshake in
 `Assoc ["token", `String token; "head", `String (Base64.encode_exn (HM.to_json source)); "origin", origin;
   "active", encoded active_set; "stake", encoded stake;
   "config_hash", `String (Base64.encode_exn wire.config_hash);
   "binary_hash", `String (Base64.encode_exn wire.binary_hash);
   "require_binary_hash", `Bool wire.require_binary_hash;
   "allowed_keys", `List (List.map (fun key -> `String (Base64.encode_exn key)) wire.handshake_allowed_pubkeys);
   "profiles", `List (List.map (fun (p : Octra_net.P2p_swarm.profile) ->
     `Assoc ["epoch", `String (Int64.to_string p.epoch);
       "config_hash", `String (Base64.encode_exn p.config_hash);
       "profile_hash", `String (Base64.encode_exn p.profile_hash)]) wire.profile_plan)]
let stage dir chain store chain_id configuration selected json =
 let open Yojson.Safe.Util in
 require "legacy source or authority changed" (capture dir chain store chain_id configuration (member "origin" selected) = selected);
 require "selected source token differs" (member "token" json = member "token" selected);
 let target = member "target" json |> to_int in
 let root = member "root" json |> to_string |> Base64.decode_exn in
 require "invalid target root" (String.length root = 32);
 let source = head dir in
 require "rule activation rewind refused" (C.C_quorum_policy.rewind_allowed
   ~chain_id ~from_epoch:(Int64.of_int source.epoch_id) ~to_epoch:(Int64.of_int target));
 let decision = C.C_catchup.decide_fork_repair ~our_head:(Int64.of_int source.epoch_id)
   ~target:(Int64.of_int target) ~current_root_quorum:false ~target_root_quorum:true
   ~target_local_matches:(Fork.target_matches chain ~target ~root)
   ~empty_fork:(Fork.empty_after chain ~target ~head:source.epoch_id) in
 require "native fork repair selection refused" (match decision with C.C_catchup.Rollback_fork_head _ -> true | _ -> false);
 let entry = some "target finality entry missing" (FL.find (FL.index dir) target) in
 require "target finality root differs" (entry.FL.state_root = Core.Epoch_index_commitment.root_hex root);
 require "target finality txid differs" (source.txid_hi = entry.txid_hi);
 if Journal.committed dir then unwrap (Journal.committed_for ~chain_id ~entry dir);
 match Lwt_main.run (Fork.stage_empty ~data_dir:dir ~store ~chaindata:chain ~target ~root) with
 | Fork.Snapshot_required reason -> failwith reason
 | Fork.Staged value -> `Assoc ["old_head", `Int value.old_head; "target", `Int value.target;
     "root", `String (Base64.encode_exn value.root); "restart_required", `Bool true]
