(* Exercise unmodified outcome and envelope helpers from the adopted node. *)
open Yojson.Safe.Util
module O = Native_outcome
module T = Octra_core.Transaction
module E = Native_envelope
let bytes j = Base64.decode_exn (to_string j)
let b64 s = `String (Base64.encode_exn s)
let tx j = match T.of_yojson (Yojson.Safe.from_string (bytes j)) with Ok t -> t | Error e -> failwith e
let txs j = List.map tx (to_list j)
let strings j = List.map bytes (to_list j)
let rejection j : O.rejection = {
  position=j|>member "position"|>to_int;tx=tx (j|>member "tx");
  error_type=bytes (j|>member "error_type");reason=bytes (j|>member "reason");charged=j|>member "charged"|>to_bool }
let rejected j = let r=rejection j in r.tx,r.error_type,r.reason
let hashes ts = `List (List.map (fun t -> `String (T.hash t)) ts)
let rejections rs = `List (List.map (fun r -> b64 (O.encode_rejection r)) rs)
let partition p = `Assoc ["preverify",`List (List.map b64 p.O.preverify);"rejections",rejections p.rejections]
let result f = function Ok value -> f value | Error e -> `Assoc ["error",`String e]
let mode j key = if j|>member key|>to_bool then Octra_core.Rule_graph.Active else Octra_core.Rule_graph.Prior
let prepare j =
  let raw = function
  | `String _ as s -> s
  | value ->
    let encoded=O.encode_rejection (rejection value) in
    let mutation=try value|>member "mutation"|>to_string with _ -> "none" in
    let fields=match Yojson.Safe.from_string encoded with `Assoc f -> f | _ -> assert false in
    let replace k v = `Assoc (List.map (fun (key,value)->key,if key=k then v else value) fields) |> Yojson.Safe.to_string in
    b64 (match mutation with
    | "none" -> encoded | "space" -> " "^encoded | "trailing" -> encoded^"\n"
    | "unknown" -> Yojson.Safe.to_string (`Assoc (fields@["unknown",`Int 0]))
    | "order" -> Yojson.Safe.to_string (`Assoc (List.rev fields))
    | "duplicate" -> Yojson.Safe.to_string (`Assoc (fields@["position",`Int 0]))
    | "false" -> Yojson.Safe.to_string (`Assoc (List.remove_assoc "charged" fields@["charged",`Bool false]))
    | "hash" -> replace "hash" (`String (String.make 64 '0'))
    | "position_float" -> replace "position" (`Float 0.)
    | "position_literal" -> replace "position" (`Intlit "4611686018427387904")
    | "txbad" -> replace "tx" `Null
    | _ -> assert false)
  in
  match j with `Assoc fields -> `Assoc (List.map (fun (k,v)->k,match k with "raw"->raw v|"raws"->`List (List.map raw (to_list v))|_->v) fields) | _ -> assert false
let run j = match j|>member "op"|>to_string with
| "normalize" -> `List [b64 (O.normalize_error_type (bytes (j|>member "error_type")));b64 (O.normalize_reason ~error_type:(bytes (j|>member "error_type")) (bytes (j|>member "reason")))]
| "encode" -> b64 (O.encode_rejection (rejection (j|>member "rejection")))
| "parse" -> let admit=j|>member "admit"|>to_bool in
  result (function O.Preverify p->`Assoc ["preverify",b64 p]|O.Rejection r->`Assoc ["rejection",b64 (O.encode_rejection r)])
    (O.parse_with (fun value -> if admit then Octra_core.Tx_payload.decode_admit value else Octra_core.Tx_payload.decode_final value) (bytes (j|>member "raw")))
| "split" -> result partition ((if j|>member "admit"|>to_bool then O.split_admit else O.split) (strings (j|>member "raws")))
| "decode" -> result partition ((if j|>member "admit"|>to_bool then O.decode_admit else O.decode_final) ~confirmed:(txs (j|>member "confirmed")) (strings (j|>member "raws")))
| "build" -> result rejections (O.build ~inputs:(txs (j|>member "inputs")) ~charged:(txs (j|>member "charged")) (List.map rejected (j|>member "rejected"|>to_list)))
| "merge" -> let confirmed=txs (j|>member "confirmed") and rs=List.map rejection (j|>member "rejections"|>to_list) in
  `Assoc ["merge",result hashes (O.merge ~confirmed ~rejections:rs);"executed",hashes (O.executed ~confirmed rs)]
| "envelope" ->
  let confirmed=txs (j|>member "confirmed") and raws=strings (j|>member "raws") in
  let outcome=if mode j "envelope"=Octra_core.Rule_graph.Prior then Ok () else
    let (let*) = Result.bind in
    let* p=O.decode_final ~confirmed raws in
    let canonical_rejections=List.map (fun (r:O.rejection) -> Octra_core.Tx_outcome.{position=r.position;tx=r.tx;error_type=r.error_type;reason=r.reason;charged=r.charged}) p.rejections in
    let* ()=E.check_charged (mode j "compute") canonical_rejections in
    let* inputs=O.merge ~confirmed ~rejections:p.rejections in
    let* ()=E.check_compute ~settle:(mode j "settle") (mode j "compute") inputs in
    E.check_mode (mode j "envelope") inputs in
  result (fun () -> `Null) outcome
| _ -> failwith "unknown operation"
let () =
 let cases=Yojson.Safe.from_channel stdin |> to_list |> List.map (fun input -> let input=prepare input in `Assoc ["input",input;"expected",run input]) in
 Yojson.Safe.to_channel stdout (`List cases); print_newline ()
