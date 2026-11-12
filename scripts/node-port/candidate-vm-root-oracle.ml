open Yojson.Safe.Util
let encode raw = `String (Base64.encode_exn raw)
let run value =
  let root = Base64.decode_exn (to_string value) in
  let expected = try
    let converted = Vm_root.tree_hash root in
    `Assoc ["raw",encode converted;"json",encode (Yojson.Safe.to_string (`String converted))]
  with Vm_root.Policy_unavailable reason -> `Assoc ["error",`String reason] in
  `Assoc ["input",value;"expected",expected]
(* Replay the unchanged native emission accounting, changing only TREEHASH.
   Numeric conversion and all other VM work stay in the historical total. *)
let event_cost root convert receipt =
  let budget = Byte_work.create Byte_work.consensus_limits in
  List.fold_left (fun used event ->
    let values = event |> member "values" |> to_list |> List.map to_string in
    let values = List.map (fun value -> if convert && value = root
      then Vm_root.tree_hash value else value) values in
    let size = Byte_work.event_size ~limit:(Byte_work.event_left budget - 1)
      ~address:(event |> member "contract" |> to_string)
      ~depth:(event |> member "depth" |> to_int)
      ~name:(event |> member "event" |> to_string) ~values |> Option.get in
    Byte_work.emit budget ~used ~limit:max_int (size + 1) |> Option.get
  ) 0 (receipt |> member "events" |> to_list)
let receipt_cost input =
  let receipt = input |> member "receipt" |> to_string |> Base64.decode_exn
    |> Yojson.Safe.from_string in
  let root = input |> member "root" |> to_string in
  `Assoc ["fixture", member "fixture" input; "case", member "case" input;
    "tx_hash", member "tx_hash" input;
    "old", `Int (event_cost root false receipt);
    "new", `Int (event_cost root true receipt)]
let () =
  let input = Yojson.Safe.from_channel stdin in
  `Assoc ["roots", `List (input |> member "roots" |> to_list |> List.map run);
    "receipts", `List (input |> member "receipts" |> to_list |> List.map receipt_cost)]
  |> Yojson.Safe.to_channel stdout; print_newline ()
