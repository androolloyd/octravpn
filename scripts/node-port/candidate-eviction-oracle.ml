(* Validator eviction updates, observed from the unchanged native
   Validator_set_update: construction, canonical encoding, and what the
   stored-update parser accepts and refuses. Serialization only. *)
module C = Octra_consensus.C_types
module U = Validator_set_update
let str s = `String s
let b64 s = `String (Base64.encode_exn s)
let i64 n = `String (Int64.to_string n)
let key i = String.make 32 (Char.chr i)
let address i = Crypto.Address.address_from_pubkey (Base64.encode_exn (key i))
let set weights = List.mapi (fun i w -> C.{address = address (i + 1); pubkey = key (i + 1)}, Z.of_int w) weights
  |> C.make_weighted_validator_set |> Result.get_ok
let res f = function Ok v -> f v | Error e -> `Assoc ["error", str e]
let guard f = try f () with exn -> `Assoc ["raised", str (Printexc.to_string exn)]
let chain = Octra_consensus.C_quorum_policy.devnet_chain_id
let epochs = [1844999L; 1845000L; 1845001L; 1900000L]
let parsed raw = guard (fun () -> res (fun (u : U.t) -> `Assoc [
  "fingerprint", str u.fingerprint; "activate", i64 u.activate_epoch;
  "eviction", (match u.eviction with None -> `Null
    | Some e -> `List [i64 e.epoch; `List (List.map str e.offenders)]);
  "bytes", b64 (U.to_string u);
  "set_at", `List (List.map (fun epoch_id -> guard (fun () ->
    res (fun () -> `Bool true) (U.check_set_at ~chain_id:chain ~epoch_id u))) epochs)])
  (U.of_string raw))
let fields = function `Assoc fields -> fields | _ -> failwith "object"
let replace name value json =
  `Assoc (List.map (fun (key, old) -> key, if key = name then value old else old) (fields json))
let witness f json = replace "eviction" f json
let mutations other raw =
  let json = Yojson.Safe.from_string raw in
  let out json = Yojson.Safe.to_string json in
  let eviction = List.assoc "eviction" (fields json) in
  let epoch = match List.assoc "epoch" (fields eviction) with `String s -> s | _ -> failwith "epoch" in
  let offenders = match List.assoc "offenders" (fields eviction) with `List l -> l | _ -> failwith "offenders" in
  let source = match List.assoc "source" (fields eviction) with `String s -> s | _ -> failwith "source" in
  let stranger = str (address 200) in
  ["exact", raw;
   "no_eviction", out (`Assoc (List.remove_assoc "eviction" (fields json)));
   "duplicate_eviction", out (`Assoc (fields json @ ["eviction", eviction]));
   "eviction_first", out (`Assoc (("eviction", eviction) :: List.remove_assoc "eviction" (fields json)));
   "spaced", "{ " ^ String.sub raw 1 (String.length raw - 1);
   "trailing_newline", raw ^ "\n";
   "epoch_int", out (witness (replace "epoch" (fun _ -> `Intlit epoch)) json);
   "epoch_padded", out (witness (replace "epoch" (fun _ -> str ("0" ^ epoch))) json);
   "epoch_hex", out (witness (replace "epoch" (fun _ -> str (Printf.sprintf "0x%Lx" (Int64.of_string epoch)))) json);
   "epoch_next", out (witness (replace "epoch" (fun _ -> str (Int64.to_string (Int64.succ (Int64.of_string epoch))))) json);
   "epoch_text", out (witness (replace "epoch" (fun _ -> str "soon")) json);
   "offenders_empty", out (witness (replace "offenders" (fun _ -> `List [])) json);
   "offenders_reversed", out (witness (replace "offenders" (fun _ -> `List (List.rev offenders))) json);
   "offenders_repeated", out (witness (replace "offenders" (fun _ -> `List (offenders @ offenders))) json);
   "offender_malformed", out (witness (replace "offenders" (fun _ -> `List [str "not-an-address"])) json);
   "offender_number", out (witness (replace "offenders" (fun _ -> `List [`Int 7])) json);
   "offender_stranger", out (witness (replace "offenders" (fun _ -> `List [stranger])) json);
   "offender_added", out (witness (replace "offenders" (fun _ ->
     `List (List.sort_uniq compare (offenders @ [str (address 1); str (address 2)])))) json);
   "source_cut", out (witness (replace "source" (fun _ -> str (String.sub source 0 (String.length source - 4)))) json);
   "source_noise", out (witness (replace "source" (fun _ -> str "!!!!")) json);
   "source_unpadded", out (witness (replace "source" (fun _ ->
     str (String.concat "" (String.split_on_char '=' source)))) json);
   "source_other", out (witness (replace "source" (fun _ ->
     b64 (Octra_consensus.C_codec.encode_validator_set other))) json);
   "source_number", out (witness (replace "source" (fun _ -> `Int 1)) json);
   "witness_extra", out (witness (fun e -> `Assoc (fields e @ ["note", str "x"])) json);
   "witness_missing", out (witness (fun e -> `Assoc (List.remove_assoc "source" (fields e))) json);
   "witness_list", out (witness (fun _ -> `List []) json);
   "activate_later", out (replace "activate_epoch" (fun _ ->
     str (Int64.to_string (Int64.add 2L (Int64.of_string epoch)))) json);
   "source_epoch_earlier", out (replace "source_epoch" (fun _ ->
     str (Int64.to_string (Int64.pred (Int64.of_string epoch)))) json);
   "fingerprint_other", out (replace "fingerprint" (fun _ -> str (String.make 64 'a')) json);
   "validators_kept", out (replace "validators" (fun _ ->
     List.assoc "validators" (fields (U.to_yojson (Result.get_ok (U.make_weighted
       ~source_epoch:(Int64.of_string epoch) ~activate_epoch:(Int64.succ (Int64.of_string epoch))
       (List.map (fun (m, weight) -> Validator_entry.{address = m.C.address; pubkey = m.pubkey; weight})
         (C.weights_of_set other))))))) json)]
let case weights ids source_epoch gap =
  let current = set weights in
  let offenders = List.map address ids in
  let activate_epoch = Int64.add source_epoch gap in
  let made = guard (fun () -> match U.make_eviction ~source_epoch ~activate_epoch ~offenders current with
    | Error e -> `Assoc ["error", str e]
    | Ok (update, weight) ->
      let raw = U.to_string update in
      let other = set (List.map (fun w -> w + 1) weights) in
      `Assoc ["raw", b64 raw; "weight", str (Z.to_string weight);
        "check", guard (fun () -> res (fun (next, weight) -> `List [
          b64 (Octra_consensus.C_config.validator_set_hash next); str (Z.to_string weight)])
          (U.check_eviction ~source_epoch ~offenders ~current update));
        "check_other", guard (fun () -> res (fun _ -> `Bool true)
          (U.check_eviction ~source_epoch ~offenders ~current:other update));
        "parsed", `List (List.map (fun (name, raw) ->
          `Assoc ["name", str name; "raw", b64 raw; "result", parsed raw]) (mutations other raw))]) in
  `Assoc ["input", `Assoc ["weights", `List (List.map (fun w -> `Int w) weights);
      "offenders", `List (List.map (fun i -> `Int i) ids);
      "source_epoch", i64 source_epoch; "gap", i64 gap];
    "expected", made]
let () =
  let cases = List.concat_map (fun (weights, groups) ->
    List.concat_map (fun ids ->
      List.concat_map (fun (source_epoch, gap) -> [case weights ids source_epoch gap])
        [1845000L, 1L; 1844999L, 1L; 1845000L, 2L; -1L, 1L; Int64.pred Int64.max_int, 1L])
      groups) [
    [1;1;1;1], [[1]; [1;2]; [4;1]; [1;1]; []; [9]];
    [5;4;3;2;1], [[5]; [1]; [4;5]; [2;3;4;5]];
    [10;10;10;10;10;10;10], [[1;2]; [1;2;3]; [7]];
    [34;33;33], [[1]; [3]];
    [1], [[1]]] in
  Yojson.Safe.to_channel stdout (`Assoc ["epochs", `List (List.map i64 epochs); "cases", `List cases]);
  print_newline ()
