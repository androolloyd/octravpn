open Yojson.Safe.Util
module R = Octra_node_runtime.Rest_view
let run input =
  let settings = member "settings" input |> to_assoc in
  let get name = List.assoc_opt name settings |> Option.map to_string in
  Unix.putenv "OCTRA_STEALTH_MIN_OU" (Option.value (get "OCTRA_STEALTH_MIN_OU") ~default:"5000");
  let get_int name default = match get name with
    | None -> default | Some raw -> (try int_of_string raw with _ -> default) in
  let range = ref `Null in
  let jitter () = R.recommended_fee_jitter ~get_int ~pick:(fun bound ->
    range := `Int bound; if member "last" input = `Bool true then bound-1 else 0) in
  let staging_ou = member "staging_ou" input |> to_string |> Z.of_string in
  let response = R.recommended_fee_response ~params:(member "params" input)
    ~is_heavy:Octra_node_runtime.Tx_view.requires_heavy_preverify
    ~stealth_floor:(Octra_core.Transaction.stealth_min_ou_of get) ~jitter ~staging_ou
    ~capacity:(Z.of_string "10000000000") ~usage_pct:(Z.(to_int (staging_ou * of_int 100 / of_string "10000000000")))
    ~staging_size:(member "staging_size" input |> to_int) in
  `Assoc ["response",`String (Yojson.Safe.to_string response); "pick_range",!range]
let () = Yojson.Safe.from_channel stdin |> to_list
  |> List.map(fun input->`Assoc["input",input;"expected",run input])
  |> fun rows -> Yojson.Safe.to_channel stdout (`List rows);print_newline ()
