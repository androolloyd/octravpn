(* Calls the complete unchanged adopted C_driver implementation. The real
   dormant driver is constructed only to expose its generation to msg_id;
   none of its host callbacks or networking tasks is executed. *)
open Yojson.Safe.Util
module C = Octra_consensus
module D = C.C_driver
module T = C.C_types

let text key input = member key input |> to_string
let integer key input = text key input |> int_of_string
let wide key input = text key input |> Int64.of_string
let hex raw = String.concat "" (List.init (String.length raw) (fun i -> Printf.sprintf "%02x" (Char.code raw.[i])))
let unhex raw = String.init (String.length raw / 2) (fun i -> Char.chr (int_of_string ("0x" ^ String.sub raw (i * 2) 2)))
let unused () = failwith "oracle host callback must not execute"

let driver () =
  let chain = "driver-round-recovery-fixture" in
  let address = "validator-1" in
  let public = String.make 32 '\001' in
  let swarm = Octra_net.P2p_swarm.create {
    listen_port = 0; chain_id = chain; node_id = public; node_addr = address;
    pubkey_raw = public; consensus_config_hash = String.make 32 '\002';
    binary_hash = String.make 32 '\003'; require_binary_hash = false;
    upgrade_plan = None; profile_plan = []; allowed_pubkeys = [public];
    bootstrap_peers = []; max_peers = 1; sign_fn = (fun _ -> unused ());
    best_epoch_fn = (fun () -> 0L); best_root_fn = (fun () -> String.make 32 '\000');
  } in
  let config : D.config = {
    chain_id = chain; my_addr = address; sign_fn = (fun _ -> unused ());
    verify_fn = (fun _ _ _ -> unused ()); role_can_vote = (fun () -> false);
    can_vote = (fun () -> false); execute_fn = (fun _ -> unused ());
    verify_proposal = (fun _ -> unused ());
    verify_parent_commit = (fun ~epoch_id:_ _ -> unused ());
    on_finalized = (fun ~validator_set:_ _ -> unused ());
    make_proposal = (fun _ -> unused ());
    before_precommit_broadcast = (fun ~epoch_id:_ ~round:_ ~proposal_id:_
      ~proposed_state_root:_ ~txid_hi:_ ~proposal_wire:_ ~vote_wire:_ -> unused ());
    lookup_epoch_root = (fun _ -> unused ()); local_head_epoch = (fun () -> 0L);
    lookup_bundle = (fun _ -> unused ());
    lookup_catchup_range = (fun ~from_epoch:_ ~max_epochs:_ -> unused ());
    on_resource_attestation = (fun _ -> unused ());
    scheduled_validator_set_config = None;
    load_scheduled_validator_set_config = (fun () -> unused ());
    resource_committee_config = None;
  } in
  D.create ~config ~validator_set:(T.make_validator_set [{ address; pubkey = public }])
    ~swarm ~start_height:7L ~sync_log:(C.C_sync_log.memory ())
    ~relief_log:(C.C_relief_log.memory ()) ~vote_log:(C.C_vote_log.memory ())

let past input : D.past_round = {
  epoch_id = wide "epoch" input; target = integer "target" input;
  sent_at = wide "sent" input; tries = integer "tries" input;
}
let evidence input =
  let vote : T.vote = {
    chain_id = "driver-round-recovery-fixture"; epoch_id = wide "epoch" input;
    round = (match member "round" input with `Null -> 0 | _ -> integer "round" input);
    vote_type = T.Prevote; proposal_id = String.make 32 '\000';
    validator = "validator-1"; signature = String.make 64 '\000';
  } in
  let value = match member "value" input with `Null -> 1 | value -> to_int value in
  Option.get (C.C_evidence.vote_conflict vote { vote with proposal_id = String.make 32 (Char.chr value) })
let run driver input =
  if text "group" input = "frame" then begin
    driver.D.engine.generation <- integer "generation" input;
    `String (D.msg_id driver (member "message" input |> to_int)
      (text "payload" input |> unhex) |> hex)
  end else if text "group" input = "evidence-window" then
    `Bool (D.vote_evidence_in_window ~current:(wide "current" input) (evidence input))
  else if text "group" input = "evidence-pool" then begin
    Hashtbl.reset driver.D.vote_evidence;
    `List (member "steps" input |> to_list |> List.map (fun input ->
      let accepted = D.remember_vote_evidence driver (evidence input) in
      `Assoc ["accepted", `Bool accepted; "count", `Int (Hashtbl.length driver.D.vote_evidence)]))
  end else
    let prior = match member "prior" input with `Null -> None | value -> Some (past value) in
    match D.next_past_round ~height:(wide "height" input) ~round:(integer "round" input)
      ~limit:(integer "limit" input) ~prior ~now:(wide "now" input) with
    | None -> `Null
    | Some (target, tries) -> `List [`String (string_of_int target); `String (string_of_int tries)]

let () =
  Octra_log._set_level Octra_log.FATAL;
  let driver = driver () in
  let cases = Yojson.Safe.from_channel stdin |> to_list |> List.map (fun input ->
    `Assoc ["input", input; "expected", run driver input]) in
  Yojson.Safe.to_channel stdout (`List cases);
  print_newline ()
