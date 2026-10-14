(* Read-only native-store adapter. No consensus or execution rules are changed. *)
open Lwt.Syntax
module Core = Octra_core
module SC = Core.Store_chaindata
module SI = Core.Store_irmin
module HM = Core.Head_manifest
module Eic = Core.Epoch_index_commitment

let require message condition = if not condition then failwith message
let unwrap = function Ok value -> value | Error reason -> failwith reason
let some reason = function Some value -> value | None -> failwith reason
let max_bytes = 64 * 1024 * 1024
let max_transactions = 100_000

let require_retired_auxiliary chain head =
  let index = chain.SC.index in
  let auxiliary = Core.Chaindata_index.auxiliary index in
  match Lmdb.Txn.go Lmdb.Ro index.env (fun txn ->
    match Core.Aux_index.journal auxiliary txn with
    | None -> ()
    | Some journal ->
      let selected = Some (SC.head_anchor head) in
      match unwrap (Core.Aux_delta.decide ~head:selected journal) with
      | Core.Aux_delta.Retire -> ()
      | Core.Aux_delta.Restore ->
        failwith "native auxiliary recovery must complete before history export") with
  | Some () -> ()
  | None -> failwith "native auxiliary inspection unavailable"

(* Transaction.hash includes null optional fields; to_yojson omits them.
   Exact exports use this canonical identity representation for both fields. *)
let exact_identity tx =
  let fields = match Core.Transaction.to_yojson tx with
    | `Assoc fields -> fields | _ -> assert false in
  let keys = ["from"; "to_"; "amount"; "nonce"; "ou"; "timestamp";
    "signature"; "op_type"; "public_key"; "message"; "encrypted_data"] in
  `Assoc (List.map (fun key -> key,
    Option.value ~default:`Null (List.assoc_opt key fields)) keys)
  |> Yojson.Safe.to_string

let signed_identity tx operation =
  let fields = match Core.Transaction.to_yojson tx with
    | `Assoc fields -> fields | _ -> assert false in
  let keys = ["from"; "to_"; "amount"; "nonce"; "ou"; "timestamp"]
    @ (if operation then ["op_type"] else []) in
  `Assoc (List.map (fun key -> key, List.assoc key fields) keys)
  |> Yojson.Safe.to_string

let archived_transaction chain ~epoch ~hash ~remaining =
  let segment, offset, length, indexed_epoch =
    some "transaction payload missing" (Core.Chaindata_index.get_tx_loc chain.SC.index hash) in
  require "transaction payload range rejected"
    (segment >= 0 && offset >= Core.Txlog.header_size && length > 8
     && length <= SC.max_txlog_record_len && length <= remaining);
  let stored_epoch, payload = Core.Txlog.read_record chain.SC.txlog
    ~seg_id:segment ~offset ~len:length in
  let stored_hash, raw = SC.split_payload payload in
  require "transaction payload binding differs"
    (indexed_epoch = epoch && stored_epoch = epoch && stored_hash = hash);
  let archive = unwrap (Core.Tx_archive.decode ~hash ~json:raw) in
  let tx = Core.Tx_archive.tx archive in
  let proof, identity, transaction = match Core.Tx_archive.proof archive with
    | Core.Tx_archive.Exact ->
      let identity = exact_identity tx in "exact", identity, identity
    | Core.Tx_archive.Signed ->
      "signed", signed_identity tx false,
      Yojson.Safe.to_string (Core.Transaction.to_yojson tx)
    | Core.Tx_archive.Signed_operation ->
      "signed_operation", signed_identity tx true,
      Yojson.Safe.to_string (Core.Transaction.to_yojson tx) in
  require "transaction identity digest differs"
    (Digestif.SHA256.(to_hex (digest_string identity)) = hash);
  proof, identity, transaction

let boundary chain store epoch =
  let header = unwrap (SC.get_bound_epoch_header chain epoch) in
  let index_hash, index_root = SC.get_epoch_index_commitment chain epoch in
  let index_hash = some "epoch index hash unavailable" index_hash in
  let index_root = some "epoch index root unavailable" index_root in
  let* binding = SI.epoch_binding store epoch in
  let binding = unwrap binding in
  let txid_hi = unwrap (SC.epoch_txid_hi header) in
  require "epoch root differs from Irmin and index"
    (header.state_root = Eic.folded_state_root ~ledger_state_root:binding.root
      ~epoch_index_root:index_root);
  Lwt.return (`Assoc ["epoch", `Int epoch; "state_root", `String header.state_root;
    "ledger_root", `String binding.root; "irmin_commit", `String binding.commit;
    "index_hash", `String index_hash; "index_root", `String index_root;
    "txid_hi", `Intlit (Int64.to_string txid_hi)])

let export ~data_dir ~chain ~store ~after_epoch ~limit =
  require "invalid history range" (after_epoch >= 0 && limit >= 1 && limit <= 64);
  let* _, plan, _, disk_head = Core.Startup_recovery.inspect ~data_dir ~chaindata:chain ~store in
  (* A forward publication or cut must complete through native recovery first.
     Stay also covers a crash after HEAD publication but before journal COMMIT. *)
  let head = match plan, disk_head with
    | Core.Recovery_phase.Stay (head, _), Some disk when head = disk -> head
    | _ -> failwith "native recovery must complete before history export" in
  require_retired_auxiliary chain head;
  require "history anchor exceeds HEAD" (after_epoch <= head.epoch_id);
  let* anchor = boundary chain store after_epoch in
  let* head_boundary = boundary chain store head.epoch_id in
  let open Yojson.Safe.Util in
  require "HEAD differs from retained epoch binding"
    (head.state_root = (head_boundary |> member "state_root" |> to_string)
     && head.irmin_commit = Some (head_boundary |> member "irmin_commit" |> to_string)
     && head.txid_hi = unwrap (SC.epoch_txid_hi (unwrap (SC.get_bound_epoch_header chain head.epoch_id))));
  let stop = after_epoch + min limit (head.epoch_id - after_epoch) in
  let count = ref 0 and bytes = ref 0 in
  let transaction epoch txid =
    incr count;
    require "history transaction limit exceeded" (!count <= max_transactions);
    let hash, actual_epoch = some "transaction index missing" (SC.read_tx_hash_at_txid chain txid) in
    require "transaction index epoch differs" (actual_epoch = epoch);
    let proof, identity, transaction = archived_transaction chain ~epoch ~hash
      ~remaining:(max_bytes / 8 - !bytes) in
    let receipt = SC.get_contract_receipt_raw chain ~tx_hash:hash in
    bytes := !bytes + String.length identity + String.length transaction
      + Option.fold ~none:0 ~some:String.length receipt;
    require "history byte limit exceeded" (!bytes <= max_bytes / 8);
    `Assoc ["txid", `Intlit (Int64.to_string txid); "hash", `String hash;
      "transaction", `String (Base64.encode_exn transaction);
      "identity", `String (Base64.encode_exn identity);
      "proof", `String proof;
      "receipt", (match receipt with None -> `Null | Some value -> `String (Base64.encode_exn value))] in
  let rec epochs epoch previous acc =
    if epoch > stop then Lwt.return (List.rev acc)
    else
      let header = unwrap (SC.get_bound_epoch_header chain epoch) in
      let* current = boundary chain store epoch in
      let previous_root = previous |> member "state_root" |> to_string in
      let previous_commit = previous |> member "irmin_commit" |> to_string in
      require "history predecessor differs" (header.prev_state_root = previous_root
        && header.parent_commit = previous_commit);
      require "history transaction limit exceeded"
        (header.tx_count >= 0 && header.tx_count <= max_transactions - !count);
      let prior_index = previous |> member "index_root" |> to_string in
      let verified = SC.verify_epoch_index_commitment_raw chain ~epoch_id:epoch
        ~start_txid:header.start_txid ~tx_count:header.tx_count ~prev_root:prior_index in
      require "epoch transaction commitment differs" verified.eic_ok;
      let transactions = List.init header.tx_count (fun index ->
        transaction epoch (Int64.add header.start_txid (Int64.of_int index))) in
      let row = `Assoc ["boundary", current; "parent_root", `String header.prev_state_root;
        "parent_commit", `String header.parent_commit;
        "start_txid", `Intlit (Int64.to_string header.start_txid);
        "transactions", `List transactions] in
      epochs (epoch + 1) current (row :: acc) in
  let* rows = epochs (after_epoch + 1) anchor [] in
  require "HEAD changed during history export" (HM.load data_dir = Some head);
  let result = `Assoc ["format", `String "octra-exex-history-v1";
    "head_commit_id", `String head.commit_id; "head", head_boundary;
    "anchor", anchor; "epochs", `List rows] |> Yojson.Safe.to_string in
  require "history output limit exceeded" (String.length result <= max_bytes);
  Lwt.return result

let read data_dir after_epoch limit =
  let directory name =
    let path = Filename.concat data_dir name in
    require "native store directory unavailable" ((Unix.stat path).Unix.st_kind = Unix.S_DIR);
    path in
  let chain_path = directory "chaindata" in
  let owner = Core.Store_lock.acquire chain_path in
  Lwt.finalize (fun () ->
    let* store = SI.open_store ~readonly:true (directory "irmin_store") in
    Lwt.finalize
      (fun () ->
        let chain = SC.open_chaindata ~readonly:true chain_path in
        Lwt.finalize
          (fun () -> export ~data_dir ~chain ~store ~after_epoch ~limit)
          (fun () -> SC.close chain; Lwt.return_unit))
      (fun () -> SI.close store))
    (fun () -> Core.Store_lock.release owner; Lwt.return_unit)
