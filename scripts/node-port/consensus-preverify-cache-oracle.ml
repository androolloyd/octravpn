(* Calls the full unchanged adopted native cache. Verdicts are supplied; proof
   execution and native weak-table GC timing are outside this corpus. *)
open Yojson.Safe.Util
module C = Octra_node_runtime.Consensus_bundle_cache
module T = Octra_core.Transaction
module W = Octra_core.Preverify_worker
let unhex value =
  let value = to_string value in
  String.init (String.length value / 2) (fun i ->
    Char.chr (int_of_string ("0x" ^ String.sub value (i * 2) 2)))
let hex value =
  String.to_seq value |> Seq.map (fun c -> Printf.sprintf "%02x" (Char.code c))
  |> List.of_seq |> String.concat ""
let purpose value = match to_string value with
  | "build" -> C.Build_proposal | "validate" -> C.Validate_proposal
  | _ -> failwith "fixture purpose"
let kind = function W.Invalid -> "invalid" | Unavailable -> "unavailable" | Deferred -> "deferred"
let verdict tx = function
  | "ready" -> W.Checked_ready {tx; receipt=None}
  | "invalid" -> W.Checked_skip {tx; reason="fixture reason"; kind=Invalid}
  | "unavailable" -> W.Checked_skip {tx; reason="fixture reason"; kind=Unavailable}
  | "deferred" -> W.Checked_skip {tx; reason="fixture reason"; kind=Deferred}
  | _ -> failwith "fixture error"
let run input =
  if member "group" input = `String "key" then
    `String (C.preverify_item_key ~epoch:(member "epoch" input |> to_string |> int_of_string)
      ~purpose:(purpose (member "purpose" input)) ~state_root:(unhex (member "root" input))
      ~tx_hash:(unhex (member "tx_hash" input)) |> hex)
  else
    let cache = C.create_with_limits ~cap:(member "capacity" input |> to_int)
      ~check_limit:(member "limit" input |> to_int) ~shared_cap:1 ~shared_limit:1 in
    let txs = member "transactions" input |> to_list |> List.map (fun raw ->
      raw |> to_string |> Base64.decode_exn |> Yojson.Safe.from_string |> T.of_yojson |> Result.get_ok) in
    if member "group" input = `String "shared" then
      let cache = C.create_with_limits ~cap:1 ~check_limit:1
        ~shared_cap:(member "capacity" input |> to_int) ~shared_limit:(member "limit" input |> to_int) in
      `List (member "steps" input |> to_list |> List.map (fun step ->
        let announced = C.share cache (to_list step |> List.map (fun i -> List.nth txs (to_int i))) in
        `Assoc ["announced", `List (List.map (fun h -> `String h) announced);
          "available", `List (List.map (fun tx -> `Bool (Option.is_some (C.find_shared cache (T.hash tx)))) txs)]))
    else
    let calls = ref 0 in
    `List (member "steps" input |> to_list |> List.map (fun step ->
      let tx = List.nth txs (member "tx" step |> to_int) in
      let verify _ values =
        incr calls;
        W.run_checked (fun tx ->
          try Lwt.return (verdict tx (member "verdict" step |> to_string))
          with exn -> Lwt.fail exn) values in
      let outcome = try
        let batch = Lwt_main.run (C.run_preverify_once cache
          ~epoch:(member "epoch" step |> to_string |> int_of_string)
          ~purpose:(purpose (member "purpose" step)) ~state_root:(unhex (member "root" step))
          ~tx_hashes:[T.hash tx] ~txs:[tx] verify) in
        match batch.W.ready, batch.W.skipped with
        | [_], [] -> "ready" | [], [item] -> kind item.W.kind
        | _ -> failwith "fixture unexpected batch"
      with _ -> "error" in
      let stats = C.stats cache in
      `Assoc ["outcome", `String outcome; "calls", `Int !calls;
        "entries", `Int stats.preverify_size; "queue", `Int stats.preverify_queue;
        "bytes", `Int stats.preverify_bytes]))
let () =
  let inputs = Yojson.Safe.from_channel stdin |> to_list in
  Yojson.Safe.to_channel stdout (`List (List.map (fun input ->
    `Assoc ["input", input; "expected", run input]) inputs));
  print_newline ()
