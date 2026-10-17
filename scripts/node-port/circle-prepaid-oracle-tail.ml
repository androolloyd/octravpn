(* App-specific inputs; all compiler, admission, Circle and epoch code is unchanged. *)
let replace token value text = Str.global_replace (Str.regexp_string token) value text
let compile source =
  match Octra_vm.Aml_source.compile ~loops:true ~syntax:Octra_vm.Oct_gen.Source source with
  | Ok value -> value.octb
  | Error reason -> failwith reason
let hydrate domain input =
  let rows = member "transactions" input |> to_list in
  let parent = derived (List.hd rows) in
  previous := parent;
  let child = if member "spawned" input = `Bool true then
    let call = tx 1 (List.nth rows 1) in
    let payload_json = match Yojson.Safe.from_string (Option.get call.T.message) with
      | `List [`String encoded] -> Base64.decode_exn encoded
      | _ -> failwith "fixture spawn payload" in
    C.Circles.circle_id_of_spawn ~parent ~caller:call.from
      ~tx_hash:(T.hash call) ~spawn_nonce:0
      ~owner_mode:C.Circles.Spawn_owner_parent ~payload_json
    else parent in
  let key = Mirage_crypto_ec.Ed25519.priv_of_octets (String.make 32 (Char.chr 21)) |> Result.get_ok in
  let public = Base64.encode_exn Mirage_crypto_ec.Ed25519.(pub_to_octets (pub_of_priv key)) in
  let sign message = Base64.encode_exn (Mirage_crypto_ec.Ed25519.sign ~key message) in
  let caller = "oct" ^ String.make 44 '2' in
  let registration = String.concat "|" ["Octranet register v1";domain;child;caller;"1"] in
  let purchase = String.concat "|" ["Octranet prepaid v1";domain;child;caller;"1";"0";"0";String.make 64 'b';"0";"1";"1048576"] in
  let expand text = text |> replace "$REGISTER_KEY" public
    |> replace "$REGISTER_SIGNATURE" (sign registration)
    |> replace "$CLAIM_SIGNATURE" (sign purchase) in
  let rows = List.map (function `Assoc fields -> `Assoc (List.map (fun (name,value) ->
    if name="to" && bytes value="$child" then name,b64 child
    else if name="to" && bytes value="$previous" then name,b64 parent
    else if name="params" && value<>`Null then name,b64 (expand (bytes value))
    else name,value) fields) | _ -> failwith "fixture transaction") rows in
  match input with `Assoc fields -> `Assoc (("transactions",`List rows)::List.remove_assoc "transactions" fields)
    | _ -> failwith "fixture case"
let split count values =
  let rec loop n taken rest = if n=0 then List.rev taken,rest else match rest with
    | item::tail -> loop (n-1) (item::taken) tail | [] -> failwith "phase transactions missing" in
  loop count [] values
let scenario domain index input =
  let phases = member "phases" input |> to_list in
  let transactions = phases |> List.concat_map (fun phase -> member "transactions" phase |> to_list) in
  let flattened = match input with `Assoc fields -> `Assoc (("transactions",`List transactions)::List.remove_assoc "transactions" fields)
    | _ -> failwith "fixture scenario" in
  let hydrated = hydrate domain flattened in
  let remaining = ref (member "transactions" hydrated |> to_list) in
  let saved = ref None in
  let rows = List.mapi (fun step phase ->
    let count = member "transactions" phase |> to_list |> List.length in
    let transactions, rest = split count !remaining in remaining := rest;
    let fields = match hydrated with `Assoc fields -> fields | _ -> assert false in
    let fields = List.filter (fun (name,_) -> not (List.mem name ["phases";"transactions";"now";"epoch";"name"])) fields in
    let input = `Assoc (("name",`String (to_string (member "name" hydrated)^" / epoch "^string_of_int step))::
      ("continuation",`Bool (step>0))::("epoch",`Int (to_int (member "epoch" hydrated)+step))::
      ("now",member "now" phase)::("transactions",`List transactions)::fields) in
    let expected, state = run_saved index input !saved in
    saved := Some state;
    `Assoc ["input",input;"expected",expected]) phases in
  if !remaining<>[] then failwith "unused phase transactions";
  Option.iter (fun (store,_) -> Lwt_main.run (S.close store)) !saved;
  rows
let () =
  let input = Yojson.Safe.from_channel stdin in
  let app = compile (member "source" input |> to_string) in
  let factory = compile (member "factory_source" input |> to_string) in
  if app <> bytes (member "bytecode" input) then failwith "native Circle app emitter differs";
  if factory <> bytes (member "factory_bytecode" input) then failwith "native factory emitter differs";
  wasm := member "wasm_b64" input |> to_string;
  let rows = member "cases" input |> to_list |> List.mapi (scenario (member "domain" input |> to_string)) |> List.concat in
  Yojson.Safe.to_channel stdout (`List rows);
  print_newline ()
