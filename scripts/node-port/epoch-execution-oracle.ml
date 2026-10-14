(* Real Epoch_exec.run_core, live ledger/Irmin commit, native standard/validator
   operations. Explicit fault inputs probe the transaction savepoint boundary. *)
open Yojson.Safe.Util
module C = Octra_core
module S = C.Store_irmin
module L = C.Ledger
module E = C.Epoch_exec
module Tx = C.Transaction
let s j k = member k j |> to_string
let n j k = member k j |> to_int
let z j k = Z.of_string (s j k)
let b64 s = `String (Base64.encode_exn s)
let list j k = member k j |> to_list
let optional j k = match member k j with `Null -> None | v -> Some (to_string v)
let pub id = Mirage_crypto_ec.Ed25519.(priv_of_octets (String.make 32 (Char.chr id)) |> Result.get_ok |> pub_of_priv |> pub_to_octets)
let address id = pub id |> Base64.encode_exn |> C.Crypto.Address.address_from_pubkey
let transaction chain j =
 let id = n j "from" in
 let op_type = Tx.op_type_of_string (s j "op") |> Result.get_ok in
 let to_ = match member "to" j with `Int id -> address id | `String "escrow" -> C.Validator_registry.escrow_address | v -> to_string v in
 let tx = Tx.{ from = address id; to_; amount = z j "amount"; nonce = n j "nonce"; ou = z j "ou";
   timestamp = member "time" j |> to_float; signature = ""; public_key = (if member "key" j = `Bool false then None else Some (Base64.encode_exn (pub id)));
   message = optional j "message"; encrypted_data = optional j "encrypted"; op_type } in
 let tx = if op_type = Tx.ValidatorBond then
   let msg = C.Validator_registry.bond_message ~chain_id:chain ~address:tx.from ~amount:tx.amount ~nonce:tx.nonce ~pubkey:(pub id) in
   let key = Mirage_crypto_ec.Ed25519.priv_of_octets (String.make 32 (Char.chr id)) |> Result.get_ok in
   { tx with message = Some (Yojson.Safe.to_string (`Assoc ["consensus_pubkey",b64 (pub id); "proof",b64 (Mirage_crypto_ec.Ed25519.sign ~key msg)])) }
   else tx in
 Tx.sign_with_privkey tx (Base64.encode_exn (String.make 32 (Char.chr id)))
let accounts ledger =
 Hashtbl.fold (fun a v xs -> (a,v)::xs) ledger.L.cache [] |> List.sort compare
 |> List.map (fun (a,v) -> `List [b64 a; b64 (Yojson.Safe.to_string (L.account_to_yojson v))])
let run index input =
 let store = Lwt_main.run (S.open_store ~fresh:true (Printf.sprintf "/tmp/epoch-execution-%d" index)) in
 store.S.batch_tree <- Some (S.Store.Tree.empty ());
 List.iter (fun a -> Lwt_main.run (S.set_account store (address (n a "id")) L.{empty_account with balance=z a "balance"; nonce=n a "nonce"; public_key=optional a "key"; encrypted_balance=optional a "encrypted"})) (list input "accounts");
 List.iter (fun row -> match to_list row with [k;v] -> Lwt_main.run (S.set_meta store (to_string k) (to_string v)) | _ -> assert false) (list input "meta");
 Lwt_main.run (S.commit_epoch_batch store "initial epoch fixture");
 let ledger = L.create store in
 let initial_accounts = accounts ledger in
 let before = Lwt_main.run (S.state_hash store) in
 let chain = s input "chain" and epoch = n input "epoch" in
 let txs = List.map (transaction chain) (list input "transactions") in
 let find tx = let rec loop i = function [] -> assert false | t::rest -> if Tx.hash t = Tx.hash tx then i else loop (i+1) rest in loop 0 txs in
 let mode name = if member name input = `Bool true then C.Rule_graph.Active else Prior in
 let fold height = if member "fold_fail" input = `Bool true then Error "fixture anchor unavailable" else
   E.prior_fold height |> Result.map (fun (f:E.fold_ctx) -> { f with account_mode=mode "packed"; vm_bytes=mode "vm" }) in
 let validator_policy = if member "bonded" input = `Bool true then C.Validator_policy.Bonded {
   activation_epoch=64; parameters=C.Validator_policy.parameters; snapshot_interval=64L; evidence_epochs=86400L }
   else C.Validator_policy.Inactive in
 let backend = E.make_live_backend ~fold ~validator_policy
   ~emission_policy:(if member "guard" input = `Bool true then C.Emission_policy.Guard else Allow)
   ~emission_schedule:C.Emission_schedule.Inactive store ledger in
 let backend = { backend with sender_key_activation_epoch=(match member "key_activation" input with `Null -> None | v -> Some (to_int v)) } in
 let env = E.{ chain_id=chain; epoch_id=epoch; proposer_addr=address 4; validator_addrs=[address 4]; validator_pubkeys=[];
   prev_state_root=before; epoch_ts=1.; ready_state_root_at=None; ready_max_lag=2 } in
 let reward = E.{ proposer_addr=address 4; proposer_public_key=None; validators=[{address=address 4; public_key=None; weight=Z.one}] } in
 let process_tx ~backend ~env tx =
   let open Lwt.Syntax in
   let injection = member "fault" (List.nth (list input "transactions") (find tx)) in
   match injection with
   | `String fault ->
     begin match backend.E.ops.debit tx.Tx.from tx.ou tx.nonce with
     | Error reason -> Lwt.return_error ("insufficient_balance",reason)
     | Ok () ->
       let* () = S.set_meta store "fixture_effect" (Tx.hash tx) in
       if fault = "abort" then Lwt.fail_with "fixture operation unavailable"
       else if fault = "reject" then Lwt.return_error ("fixture_refusal","after write")
       else Lwt.return_ok (E.Rejected_after_fee {fee=tx.ou;error_type="fixture_charged";reason="after fee"})
     end
   | _ -> let* result = E.process_standard_tx ~backend ~env tx in
     Lwt.return (Result.map (fun fee -> E.Confirmed fee) result)
 in
 let result = Lwt_main.run (E.run_core ~reward:(Some reward) ~preverify:None ~backend ~env ~txs ~process_tx) in
 let result = match result with
 | Error e -> `Assoc ["error",`String e]
 | Ok r -> `Assoc ["root",`String r.post_state_root; "fees",`String (Z.to_string r.artifacts.confirmed_fees);
    "count",`Int r.artifacts.tx_count;
    "confirmed",`List (List.map (fun (tx,pos) -> `List [`Int (find tx);`Int pos]) r.artifacts.confirmed);
    "rejected",`List (List.map (fun (r:E.tx_reject) -> `Assoc ["index",`Int (find r.tx);"type",b64 r.error_type;"reason",b64 r.reason;"charged",`Bool r.charged]) r.artifacts.rejected)] in
 let output = `Assoc ["initial_accounts",`List initial_accounts; "transactions",`List (List.map (fun t -> b64 (Yojson.Safe.to_string (Tx.to_yojson t))) txs);
   "before",`String before; "result",result; "root",`String (Lwt_main.run (S.state_hash store)); "accounts",`List (accounts ledger);
   "supply",`String (Z.to_string ledger.L.total_supply); "spent",`Int (Hashtbl.length ledger.spent_nonces); "journal",`Bool (L.journal_active ledger)] in
 Lwt_main.run (S.close store); output
let () =
 let inputs = Yojson.Safe.from_channel stdin |> to_list in
 Yojson.Safe.to_channel stdout (`List (List.mapi (fun index input -> `Assoc ["input",input;"expected",run index input]) inputs)); print_newline ()
