(* Isolated test host only. All consensus, execution, signature, storage and
   commitment modules below are the unchanged adopted native implementations.
   This file recreates Rust devnet's explicit PRIVATE genesis; it does not
   pretend the stock native live-chain launcher accepts this configuration. *)
open Yojson.Safe.Util
module Core = Octra_core
module S = Core.Store_irmin
module L = Core.Ledger
module T = Core.Transaction
module E = Core.Epoch_exec
module HM = Core.Head_manifest
module SC = Core.Store_chaindata
module EI = Core.Epoch_index_commitment
module N = Octra_consensus
module P = Octra_node_runtime.Consensus_proposal
module J = Octra_node_runtime.Consensus_finality_journal
let ok = function Ok value -> value | Error reason -> failwith reason
let str j key = member key j |> to_string
let int j key = member key j |> to_int
let raw_hex value = String.concat "" (List.init (String.length value) (fun i -> Printf.sprintf "%02x" (Char.code value.[i])))
let raw value =
  if String.length value = 32 then value
  else if String.length value = 64
    && String.for_all (function '0'..'9'|'a'..'f'|'A'..'F'->true|_->false) value
  then String.init 32 (fun i -> Char.chr(int_of_string("0x"^String.sub value (2*i) 2)))
  else failwith "invalid strict fixture hash"
let b64 value = `String (Base64.encode_exn value)
let rec canonical = function
  | `Assoc rows -> `Assoc (List.map (fun (k,v) -> k,canonical v) rows |> List.sort (fun (a,_) (b,_) -> String.compare a b))
  | `List values -> `List (List.map canonical values)
  | value -> value
let json value = Yojson.Safe.to_string value
let private_read path =
  let stat = Unix.lstat path in
  if stat.Unix.st_kind <> Unix.S_REG || stat.st_perm land 0o077 <> 0 then failwith "private fixture key permissions";
  let c = open_in_bin path in Fun.protect ~finally:(fun()->close_in c) (fun()->really_input_string c (in_channel_length c))
let atomic path data =
  let tmp = path ^ ".staged" in
  let fd = Unix.openfile tmp [Unix.O_WRONLY;Unix.O_CREAT;Unix.O_EXCL] 0o600 in
  Fun.protect ~finally:(fun()->Unix.close fd) (fun()->
    let bytes = Bytes.of_string data in
    let rec loop off = if off < Bytes.length bytes then let n=Unix.write fd bytes off (Bytes.length bytes-off) in if n=0 then failwith "short fixture write" else loop (off+n) in
    loop 0;Unix.fsync fd);
  Unix.rename tmp path;
  let d=Unix.openfile (Filename.dirname path) [Unix.O_RDONLY] 0 in Fun.protect ~finally:(fun()->Unix.close d) (fun()->Unix.fsync d)
let time_lexeme config_path genesis =
  (* Both init-devnet's config and its commitment use serde_json for this same
     f64. Preserve only that input number lexeme; derive every leaf/root here. *)
  let member name = function
    | `Assoc rows ->
      (match List.filter(fun(key,_)->key=name)rows with [(_,value)]->value
       | _->failwith "missing or repeated raw genesis time path")
    | _->failwith "raw genesis time is not in an object"in
  let value=Yojson.Raw.from_file config_path |>member "genesis" |>member "time"in
  let literal=match value with `Floatlit raw|`Intlit raw->raw
    |_->failwith "raw genesis time must be numeric"in
  if String.length literal>64 then failwith "raw genesis time is oversized";
  let decoded=Yojson.Safe.from_string literal |>to_number in
  if not(Float.is_finite decoded) || decoded<>(Yojson.Safe.Util.member "time" genesis |>to_number)
  then failwith "genesis time lexical/value disagreement";
  literal
let genesis_leaves ~time_lexeme genesis =
  if member "activated_applications" genesis <> `Bool false then failwith "initial mixed fixture requires unchanged Prior application graph";
  let chain = member "chain" genesis in
  let chain_id = str chain "chain_id" in
  if not (String.starts_with ~prefix:"octra-rust-local-" chain_id) then failwith "private mixed chain required";
  let commitment_rows = ["chain_id",`String chain_id;"time",member "time" genesis;
    "validators",member "validators" genesis;"profile",`String "devnet_full_v1";
    "proposal_activation",`Int 2;"receipts_activation",`Int 0;
    "upstream",`String "7f9be4489870645cfcc95439638cde40f5da9f50"]in
  let commitment="{"^(List.sort(fun(a,_)(b,_)->String.compare a b)commitment_rows
    |>List.map(fun(key,value)->json(`String key)^":"^(if key="time"then time_lexeme else json(canonical value)))
    |>String.concat ",")^"}"in
  let funded = str genesis "funded_public" in
  let address = Core.Crypto.Address.address_from_pubkey funded in
  let account = L.{empty_account with balance=Z.of_string "100000000000";public_key=Some funded} in
  let circle = str genesis "circle" in
  let path=Core.Circles.asset_path_key "/index.html" in
  let body="<!doctype html><html><meta charset=utf-8><title>Octra Rust devnet</title><h1>Octra Rust devnet</h1><p>This Circle asset is served from the committed state of your local Rust node.</p><p>VPN escrow is not configured on this development chain.</p></html>" in
  let text value = `String value in
  let meta = `Assoc ["path_key",text path;"canonical_path",text "/index.html";
    "content_type",text "text/html";"encoding",text "identity";
    "size_bytes",text (string_of_int (String.length body));
    "blob_hash",text Digestif.SHA256.(digest_string body |> to_hex);
    "body_mode",text "public_resources";"plaintext_hash",`Null;"key_id",`Null;"padding_class",`Null;
    "resource_key",text path;"locator_mode",text "path";"slot_ref",`Null;
    "activate_after_epoch",`Null;"expire_after_epoch",`Null;"metadata_mode",text "reveal"] |> json in
  [ ["meta";"local_devnet"],commitment;["meta";"last_epoch"],"0";
    ["meta";"emission_remaining"],"0";["meta";"total_supply"],"100000000000";
    ["accounts";address;"data"],json (L.account_to_yojson account);
    ["circles";circle;"browser";"mode"],"gateway_allowed";
    ["circles";circle;"resources";"mode"],"public_resources";
    ["circles";circle;"assets";"by_hash";path;"meta"],meta;
    ["circles";circle;"assets";"by_hash";path;"body_b64"],Base64.encode_exn body ]
let genesis_root genesis =
  let values=member "genesis_root" (member "chain" genesis) |> to_list in
  if List.length values<>32 then failwith "private genesis root must have32 bytes";
  values |> List.map (fun value -> let byte=to_int value in
    if byte<0 || byte>255 then failwith "private genesis byte out of range";
    String.make 1 (Char.chr byte)) |> String.concat "" |> raw_hex
let index0 () = EI.next_root ~prev:EI.genesis_root ~epoch_id:0 []
let initialize ~time_lexeme data genesis store chain =
  let open Lwt.Syntax in
  let* prior = S.get_head_hash store in
  match HM.load_result data,prior with
  | HM.Missing,None ->
    let* ()=S.begin_epoch_batch store in
    let leaves=genesis_leaves ~time_lexeme genesis in
    let* ()=Lwt_list.iter_s (fun (path,value)->S.write store path value) leaves in
    let* ()=S.commit_epoch_batch store "explicit shared private mixed genesis" in
    let* ledger=S.state_hash store in
    let eh,eic=index0() in
    let folded=EI.folded_state_root ~ledger_state_root:ledger ~epoch_index_root:eic in
    if folded<>genesis_root genesis then failwith "independent native/Rust genesis root differs";
    SC.begin_batch chain;
    SC.set_epoch chain {Core.Epochlog.empty_epoch_header with id=0;state_root=folded;start_txid=0L;finalized_at=member "time" genesis |> to_number};
    SC.set_epoch_index_commitment chain ~epoch_id:0 ~epoch_hash:eh ~root:eic;
    SC.commit_batch chain;SC.fsync chain;
    let* ()=S.tag_epoch store 0 in
    S.Store.flush store.repo;S.sync_branches store.store_path;
    let* irmin=S.get_commit_hash store in
    let head=HM.{schema_version=3;generation=0;epoch_id=0;state_root=folded;ledger_state_root=Some ledger;irmin_commit=irmin;
      txid_hi=(-1L);txlog_seg=None;txlog_off=None;epochlog_off=Some(SC.epochlog_offset chain);
      commit_id="explicit-mixed-private-genesis";ts=member "time" genesis |> to_number;
      quorum_cert_hash=None;epoch_index_hash=Some eh;epoch_index_root=Some eic} in
    Core.Commit_journal.append data (Prepare {commit_id=head.commit_id;prev_generation=(-1);epoch_id=0;planned_txid_hi=(-1L);planned_state_root=folded;ts=head.ts});
    HM.atomic_write data head;
    Core.Commit_journal.append data (Commit {commit_id=head.commit_id;generation=0;ts=head.ts});
    HM.set_cached head;
    atomic (Filename.concat data "genesis-proof.json") (json (`Assoc ["scope",`String "independent explicit private genesis adapter";
      "ledger_root",`String ledger;"epoch_index_root",`String eic;"folded_root",`String folded;
      "leaves",`List(List.map(fun(p,v)->`Assoc["path",`List(List.map b64 p);"value",b64 v])leaves)]));
    Lwt.return head
  | HM.Present head,Some ledger ->
    if HM.ledger_state_root head<>ledger then failwith "native restart ledger/head mismatch";
    if head.epoch_id>0 then
      (match J.read_committed_epoch_validated ~validator_set:(N.C_types.make_validator_set (List.map(fun entry->
        let split=String.index entry ':' in N.C_types.{address=String.sub entry 0 split;pubkey=Base64.decode_exn(String.sub entry(split+1)(String.length entry-split-1))})
        (member "validators" genesis |>to_list |>List.map to_string))) ~chain_id:(str(member "chain" genesis)"chain_id") ~epoch:(Int64.of_int head.epoch_id) data with
       | J.Valid record when raw_hex record.finalize.header.proposed_state_root=head.state_root -> ()
       | _ -> failwith "native restart authenticated certificate missing");
    HM.set_cached head;Lwt.return head
  | _ -> Lwt.fail_with "refuse incomplete native mixed store; preserve for inspection"
