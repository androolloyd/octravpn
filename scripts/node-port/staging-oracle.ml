(* Only the queue wall clock is injected; native admission and selection are unchanged. *)
open Yojson.Safe.Util
module C = Octra_core
module T = C.Transaction
module P = C.Tx_staging
let raw v = Base64.decode_exn (to_string v)
let b v = `String (Base64.encode_exn v)
let n j k = member k j |> to_int
let z j k = member k j |> to_string |> Z.of_string
let f j k = member k j |> to_string |> float_of_string
let optional j k = match member k j with `Null -> None | v -> Some (raw v)
let bits v = `String (Printf.sprintf "%016Lx" (Int64.bits_of_float v))
let opt fn = function None -> `Null | Some x -> fn x
let make j : T.t = {
  from=raw (member "from" j); to_=raw (member "to" j);
  amount=z j "amount"; nonce=n j "nonce"; ou=z j "ou"; timestamp=f j "timestamp";
  signature=raw (member "signature" j); public_key=None;
  message=optional j "message"; encrypted_data=optional j "encrypted";
  op_type=T.op_type_of_string (member "op" j |> to_string) |> Result.get_ok }
let hash tx = b (T.hash tx)
let hashes txs = `List (List.map hash txs)
let drop d = `Assoc ["hash",b d.P.d_hash; "from",b d.d_from; "to",b d.d_to;
  "nonce",`Int d.d_nonce; "ou",`String (Z.to_string d.d_ou); "op",`String (T.op_type_to_string d.d_op_type);
  "reason",`String (match d.d_reason with P.Evicted -> "evicted" | P.Expired -> "expired");
  "detail",`String d.d_detail; "time",bits d.d_ts]
let drops ds = `List (List.map drop ds)
let sorted_drops ds = ds |> List.sort (fun a b -> String.compare a.P.d_hash b.P.d_hash) |> drops
let result fn = function Ok v -> `Assoc ["ok",fn v] | Error e -> `Assoc ["error",`String e]
let head base j = match member "head" j with `Null -> None | v -> Some (Int64.add base (Int64.of_string (to_string v)))
let message base hash j =
  let h = head base j in
  match member "kind" j |> to_string with
  | "check" -> P.Preview.Check (h,hash)
  | "ready" -> P.Preview.Ready (h,hash)
  | "refuse" -> P.Preview.Refuse {head=Option.get h; epoch=Int64.add base (Int64.of_string (member "epoch" j |> to_string)); hash}
  | _ -> P.Preview.Hold {head=Option.get h; epoch=Int64.add base (Int64.of_string (member "epoch" j |> to_string)); hash}
let run base j =
 if member "mode" j = `String "preview" then begin
  let state = ref P.Preview.empty in
  `List (member "steps" j |> to_list |> List.map (fun step ->
    let next,out = P.Preview.step ~limit:(n j "limit") !state (message 0L (raw (member "hash" step)) step) in
    state:=next; result (fun () -> `Null) out))
 end else begin
  P.clear (); Hashtbl.clear P.dropped_cache;
  ignore (P.Preview.send (Check (Some base,"reset")));
  let txs = member "transactions" j |> to_list |> List.map make in
  let senders = List.map (fun tx -> tx.T.from) txs |> List.sort_uniq String.compare in
  let accounts = Hashtbl.create 10 in
  let account a = let sender=raw (member "sender" a) in
    if member "balance" a = `Null then Hashtbl.remove accounts sender
    else Hashtbl.replace accounts sender (z a "balance",n a "nonce") in
  member "accounts" j |> to_list |> List.iter account;
  let lookup = Hashtbl.find_opt accounts in
  let confirmed sender = Option.map snd (lookup sender) in
  let minimum = member "minimum" j |> to_string in Unix.putenv "OCTRA_STEALTH_MIN_OU" minimum;
  let snapshot step =
    let capacity = z step "capacity" in
    let excluded = member "exclude" step |> to_list |> List.map (fun v -> T.hash (List.nth txs (to_int v))) in
    let status h = match P.queue_state ~confirmed:(Option.value (confirmed (Option.get (P.find_by_hash h)).T.from) ~default:0) h with
      | None -> `Null
      | Some (Ready {expires_at}) -> `List [`String "ready";bits expires_at]
      | Some (Wait_nonce {expected;expires_at}) -> `List [`String "wait";`Int expected;bits expires_at]
      | Some (Nonce_used {confirmed;expires_at}) -> `List [`String "used";`Int confirmed;bits expires_at] in
    `Assoc ["all",hashes (P.all ()); "sample",`List (List.map (fun (h,_) -> b h) (P.sample 5));
      "recent",`List (List.map (fun (h,_) -> b h) (P.recent 5));
      "epoch",hashes (P.get_epoch_txs ~capacity);
      "ready",hashes (P.ready_epoch_txs ~capacity ~confirmed_nonce:confirmed ~accept:(fun tx -> not (List.mem (T.hash tx) excluded)));
      "total",`String (Z.to_string (P.staging_total_ou ())); "size",`Int (P.staging_size ()); "usage",`Int (P.staging_usage_pct ());
      "states",`List (List.map (fun tx -> let h=T.hash tx in `List [b h;status h]) (P.all ()));
      "senders",`List (List.map (fun sender -> let nonce=Option.value (confirmed sender) ~default:0 in
        `Assoc ["sender",b sender;"balance",opt (fun z -> `String (Z.to_string z)) (Hashtbl.find_opt P.virtual_balances sender);
          "expected",`Int (P.get_expected_nonce sender);"missing",`Int (P.first_missing_nonce sender nonce);
          "pending",`Int (P.pending_nonce sender nonce);"duty",opt (fun v -> `Int v) (P.duty_nonce sender nonce)]) senders);
      "fees",`List (List.map (fun tx -> `String (Z.to_string (P.min_relay_fee tx))) txs);
      "drops",sorted_drops (Hashtbl.fold (fun _ d ds -> d::ds) P.dropped_cache [])] in
  `List (member "steps" j |> to_list |> List.map (fun step ->
    P.oracle_time := f step "now";
    let tx = List.nth txs (n step "index") in
    let out = match member "kind" step |> to_string with
      | "add" -> result drops (P.add_smart ?head:(head base step) ~ou_limit:(z step "limit") ~tx_limit:(n step "count") ~lookup tx)
      | "remove" -> `Bool (P.remove_by_hash (T.hash tx))
      | "processed" -> P.remove_processed (member "indices" step |> to_list |> List.map (fun v -> T.hash (List.nth txs (to_int v)))); `Null
      | "clear" -> P.clear (); `Null
      | "account" -> account step; `Null
      | "expire" -> sorted_drops (P.expire_old ~confirmed_nonce:confirmed ())
      | "cleanup" -> P.cleanup_dropped (); `Null
      | "drop_preview" -> opt drop (P.drop_preview tx)
      | "duty" -> drops (P.expire_duty ?sender:(optional step "sender") ~head:(head 0L step)
          ~mode:(if member "active" step = `Bool true then C.Rule_graph.Active else Prior) ())
      | "inspect" -> `Null
      | _ -> result (fun () -> `Null) (P.Preview.send (message base (T.hash tx) step)) in
    `Assoc ["result",out;"state",snapshot step]))
 end
let () =
 let cases = Yojson.Safe.from_channel stdin |> to_list |> List.mapi (fun i input ->
  let base = Int64.of_int ((i+1)*10000) in
  `Assoc ["input",input;"base",`String (Int64.to_string base);"expected",run base input]) in
 Yojson.Safe.to_channel stdout (`List cases); print_newline ()
