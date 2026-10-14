(* Test-only oracle: invoke the pinned implementation without changing it. *)
module E = Octra_net.Epoch_index_commitment
let field name json = Yojson.Safe.Util.member name json
let text name json = field name json |> Yojson.Safe.Util.to_string
let bytes name json = Base64.decode_exn (text name json)
let integer name json = Int64.of_string (text name json)
let items json =
  field "items" json |> Yojson.Safe.Util.to_list |> List.map (fun value ->
    { E.txid = integer "txid" value; hash = bytes "hash_b64" value })
let pair (epoch_hash, root) = `List [`String epoch_hash; `String root]
let run json =
  try
    let result = match text "operation" json with
    | "genesis" -> `String E.genesis_root
    | "normalize_hash" -> `String (E.norm_hash (bytes "hash_b64" json))
    | "root_hex" -> `String (E.root_hex (bytes "root_b64" json))
    | "epoch" -> `String (E.epoch_hash_i64 ~epoch_id:(integer "epoch" json) (items json))
    | "root" -> `String (E.root_hash ~prev:(bytes "previous_b64" json) ~epoch_hash:(bytes "hash_b64" json))
    | "next" -> pair (E.next_root_i64 ~prev:(bytes "previous_b64" json) ~epoch_id:(integer "epoch" json) (items json))
    | "next_from_hashes" ->
      let hashes = field "hashes_b64" json |> Yojson.Safe.Util.to_list
        |> List.map (fun value -> Base64.decode_exn (Yojson.Safe.Util.to_string value)) in
      pair (E.next_root_from_hashes_i64 ~prev:(bytes "previous_b64" json)
        ~epoch_id:(integer "epoch" json) ~start_txid:(integer "start_txid" json) hashes)
    | "fold" -> `String (E.folded_state_root ~ledger_state_root:(bytes "ledger_b64" json)
        ~epoch_index_root:(bytes "index_b64" json))
    | _ -> failwith "unknown oracle operation"
    in `Assoc ["ok", result]
  with Invalid_argument reason -> `Assoc ["error", `String reason]
let () =
  let cases = Yojson.Safe.from_file Sys.argv.(1) |> Yojson.Safe.Util.to_list in
  let results = List.map (fun input -> `Assoc ["input", input; "expected", run input]) cases in
  print_endline (Yojson.Safe.to_string (`List results))
