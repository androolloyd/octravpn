(* SPDX-License-Identifier: BSD-3-Clause *)
module Tx = Octra_core.Transaction
module Envelope = Native_envelope
module Ledger = Octra_core.Ledger
module Store = Octra_core.Store_irmin
open Yojson.Safe.Util
let field value key = member key value
let text value key = field value key |> to_string
let bytes value key = text value key |> Base64.decode_exn
let opt_bytes value key = match field value key with `String v -> Some (Base64.decode_exn v) | _ -> None
let b64 v = `String (Base64.encode_exn v)
let nonce value key = text value key |> int_of_string
let integer value key = text value key |> Z.of_string
let tx_of value = Tx.{ from = bytes value "from"; to_ = bytes value "to"; amount = integer value "amount";
  nonce = nonce value "nonce"; ou = integer value "ou"; timestamp = Int64.float_of_bits (Int64.of_string ("0x" ^ text value "timestamp_bits"));
  signature = bytes value "signature"; public_key = opt_bytes value "public_key"; message = opt_bytes value "message";
  op_type = Tx.op_type_of_string (text value "op_type") |> Result.get_ok; encrypted_data = opt_bytes value "encrypted_data" }
let unit_result = function Ok () -> `Null | Error e -> `String e
let account_of value = Ledger.{ balance = integer value "balance"; nonce = nonce value "nonce";
  public_key = opt_bytes value "public_key"; encrypted_balance = opt_bytes value "encrypted_balance";
  decrypt_allowance = integer value "decrypt_allowance" }
let sorted table convert = Hashtbl.fold (fun k v acc -> (k, v) :: acc) table [] |> List.sort compare |> List.map convert
let snapshot ledger = `Assoc [
  "accounts", `List (sorted ledger.Ledger.cache (fun (address, account) -> `List [b64 address; b64 (Yojson.Safe.to_string (Ledger.account_to_yojson account))]));
  "supply", `String (Z.to_string ledger.total_supply); "active", `Int ledger.active_accounts; "dirty", `Bool ledger.dirty;
  "dirty_addresses", `List (sorted ledger.dirty_addrs (fun (address, ()) -> b64 address));
  "spent", `List (sorted ledger.spent_nonces (fun ((address, nonce), ()) -> `List [b64 address; `String (string_of_int nonce)]));
  "journal_active", `Bool (Ledger.journal_active ledger) ]
let trace index input =
  let store = Lwt_main.run (Store.open_store ~fresh:true (Printf.sprintf "/tmp/tx-state-oracle-%d" index)) in
  List.iter (fun entry -> Lwt_main.run (Store.set_account store (bytes entry "address") (account_of entry))) (field input "accounts" |> to_list);
  let result = try
    let ledger = Ledger.create_from_store store in
    let initial = snapshot ledger in
    let steps = field input "steps" |> to_list |> List.map (fun step ->
      let addr () = bytes step "address" and amount () = integer step "amount" in
      let outcome = match text step "op" with
      | "begin" -> Ledger.begin_journal ledger |> unit_result
      | "commit" -> Ledger.commit_journal ledger |> unit_result
      | "abort" -> Ledger.abort_journal ledger |> unit_result
      | "clear_spent" -> Ledger.clear_spent_nonces ledger; `Null
      | "freeze" -> Ledger.freeze ledger |> Result.map (fun _ -> ()) |> unit_result
      | "flush" -> Lwt_main.run (Ledger.flush_dirty_lwt ledger); `Null
      | "add" -> (match opt_bytes step "public_key" with None -> Ledger.add_account ledger (addr ()) (amount ()) | Some pk -> Ledger.add_account_with_pubkey ledger (addr ()) (amount ()) pk) |> unit_result
      | "credit" -> Ledger.credit ?encrypted_balance:(opt_bytes step "encrypted_balance") ledger (addr ()) (amount ()) |> unit_result
      | "debit" -> Ledger.debit ?encrypted_balance:(opt_bytes step "encrypted_balance") ledger (addr ()) (amount ()) (nonce step "nonce") |> unit_result
      | "debit_only" -> Ledger.debit_amount_only ledger (addr ()) (amount ()) |> unit_result
      | "key" -> Ledger.register_public_key ledger (addr ()) (bytes step "public_key"); `Null
      | "allowance" -> Ledger.update_decrypt_allowance ledger (addr ()) (amount ()); `Null
      | "cipher" -> Ledger.update_enc_balance ledger (addr ()) (bytes step "encrypted_balance") |> unit_result
      | "transfer" -> (match Ledger.transfer ledger ~from:(bytes step "from") ~to_:(bytes step "to") ~amount:(amount ()) ~fee:(integer step "fee") (nonce step "nonce") with
        | Ok () -> `Null | Error (Ledger.Debit_rejected e) -> `List [`String "debit"; `String e] | Error (Ledger.Credit_rejected e) -> `List [`String "credit"; `String e])
      | op -> failwith ("unknown trace op: " ^ op) in
      `Assoc ["outcome", outcome; "state", snapshot ledger]) in
    `Assoc ["initial", initial; "steps", `List steps]
  with Failure reason -> `Assoc ["load_error", `String reason] in
  Lwt_main.run (Store.close store); result
let run index input = match text input "operation" with
| "float" -> `String (Yojson.Safe.to_string (`Float (Int64.float_of_bits (Int64.of_string ("0x" ^ text input "bits")))))
| "transaction" ->
  let tx = tx_of input in
  let tx = match opt_bytes input "seed" with None -> tx | Some seed -> Tx.sign_with_privkey tx (Base64.encode_exn seed) in
  `Assoc ["signing", b64 (Tx.serialize_for_signing tx); "json", b64 (Yojson.Safe.to_string (Tx.to_yojson tx));
    "hash", `String (Tx.hash tx); "signature", b64 tx.signature; "verified", `Bool (match tx.public_key with None -> false | Some key -> Tx.verify tx key)]
| "envelope" ->
  let tx = tx_of input in
  let normalized = match Envelope.normalize ~sender_pk:(opt_bytes input "sender_key") tx with
    | Ok tx -> `Assoc ["signature", b64 tx.signature; "public_key", b64 (Option.get tx.public_key)]
    | Error (tag, reason) -> `Assoc ["tag", `String tag; "reason", `String reason] in
  `Assoc ["normalize", normalized; "check", unit_result (Envelope.check tx)]
| "base64" -> (match Base64.decode (bytes input "value") with Ok raw -> b64 raw | Error _ -> `Null)
| "address" -> `Assoc ["address", b64 (Octra_core.Crypto.Address.address_from_pubkey (bytes input "key")); "valid", `Bool (Octra_core.Crypto.Address.is_valid_address (bytes input "address"))]
| "ledger" -> trace index input
| op -> failwith ("unknown case: " ^ op)
let () =
  let inputs = Yojson.Safe.from_file Sys.argv.(1) |> to_list in
  let outputs = List.mapi (fun index input -> `Assoc ["input", input; "output", (try run index input with Yojson.Json_error reason -> `Assoc ["error", `String reason])]) inputs in
  print_endline ("ORACLE_RESULT=" ^ Yojson.Safe.to_string (`List outputs))
