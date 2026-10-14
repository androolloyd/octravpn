(* Call the actual native partition verifier and finalized input selectors.
   Artifacts are supplied fixtures, not a claim of operation implementation. *)
open Yojson.Safe.Util
module C = Octra_core
module T = C.Transaction
module O = C.Tx_outcome
module E = C.Epoch_exec
let bytes v = Base64.decode_exn (to_string v)
let b64 v = `String (Base64.encode_exn v)
let list j k = member k j |> to_list
let run input =
 let txs = list input "transactions" |> List.map (fun v -> bytes v |> Yojson.Safe.from_string |> T.of_yojson |> Result.get_ok) in
 let at i = List.nth txs i in
 let confirmed = list input "confirmed" |> List.map (fun v -> at (to_int v)) in
 let rejected = list input "rejected" |> List.map (fun r -> E.{tx=at (member "index" r |> to_int);error_type=bytes (member "type" r);reason=bytes (member "reason" r);charged=member "charged" r |> to_bool}) in
 let charged rs = List.filter_map (fun (r:E.tx_reject) -> if r.charged then Some r.tx else None) rs in
 let tuples rs = List.map (fun (r:E.tx_reject) -> r.tx,r.error_type,r.reason) rs in
 let mode k = if member k input = `Bool true then C.Rule_graph.Active else Prior in
 let ( let* ) = Result.bind in
 let prepare =
   let* rejections = O.build ~inputs:txs ~charged:(charged rejected) (tuples rejected) in
   let* inputs = O.merge ~confirmed ~rejections in
   if member "finalized" input <> `Bool true then Ok (inputs,rejections) else
   let* () = C.Tx_envelope.check_charged (mode "compute") rejections in
   let* () = C.Tx_envelope.check_compute ~settle:(mode "settle") (mode "compute") inputs in
   (* The public epoch gate selects active envelopes and active compute here;
      the requested compute/settle checks have already run above. *)
   let* () = if member "envelope" input = `Bool true then
     C.Tx_envelope.check_epoch ~chain_id:"octra-devnet-9871-cluster" ~epoch:1688734L inputs
     else Ok () in
   let inputs = O.executed ~confirmed rejections in
   let rejected = List.filter (fun (r:E.tx_reject) -> r.charged) rejected in
   let* rejections = O.build ~inputs ~charged:(charged rejected) (tuples rejected) in
   Ok (inputs,rejections) in
 match prepare with
 | Error e -> `Assoc ["error",`String e]
 | Ok (inputs,rejections) ->
   let actual_confirmed = ref (List.map (fun tx -> tx,999) confirmed) in
   let actual_rejected = ref (List.map (fun (r:O.rejection) -> E.{tx=r.tx;error_type=r.error_type;reason=r.reason;charged=r.charged}) rejections) in
   let mutation = member "mutation" input |> to_string in
   let tail = function [] -> [] | _::xs -> xs in
   begin match mutation with
   | "drop_confirmed" -> actual_confirmed := tail !actual_confirmed
   | "reverse_confirmed" -> actual_confirmed := List.rev !actual_confirmed
   | "drop_rejected" -> actual_rejected := tail !actual_rejected
   | "duplicate_rejected" -> actual_rejected := !actual_rejected @ !actual_rejected
   | "charged" -> actual_rejected := List.map (fun (r:E.tx_reject) -> {r with charged=not r.charged}) !actual_rejected
   | "reason" -> actual_rejected := List.map (fun (r:E.tx_reject) -> {r with reason="different"}) !actual_rejected
   | "type" -> actual_rejected := List.map (fun (r:E.tx_reject) -> {r with error_type="different"}) !actual_rejected
   | "exception" -> actual_rejected := List.map (fun (r:E.tx_reject) -> {r with error_type="vm_exception";reason="sensitive detail\000"}) !actual_rejected
   | "none" | "error" -> ()
   | _ -> failwith "unknown mutation"
   end;
   let result = if mutation="error" then Error "operation unavailable" else Ok E.{post_state_root="unused";artifacts={confirmed= !actual_confirmed;rejected= !actual_rejected;confirmed_fees=Z.zero;tx_count=List.length inputs}} in
   let verified = Octra_node_runtime.Consensus_proposal.verify_preview_partition ~inputs ~confirmed ~rejections result in
   let index tx = let rec find i = function [] -> failwith "artifact outside input" | t::rest -> if T.hash tx=T.hash t then i else find (i+1) rest in find 0 inputs in
   `Assoc ["inputs",`List (List.map (fun tx -> `String (T.hash tx)) inputs);
     "rejections",`List (List.map (fun r -> b64 (O.encode_rejection r)) rejections);
     "actual_confirmed",`List (List.map (fun (tx,pos) -> `List [`Int(index tx);`Int pos]) !actual_confirmed);
     "actual_rejected",`List (List.map (fun (r:E.tx_reject) -> `Assoc ["index",`Int(index r.tx);"type",b64 r.error_type;"reason",b64 r.reason;"charged",`Bool r.charged]) !actual_rejected);
     "verify",`String (match verified with Ok () -> "ok" | Error e -> e)]
let () =
 let inputs = Yojson.Safe.from_channel stdin |> to_list in
 Yojson.Safe.to_channel stdout (`List (List.map (fun input -> `Assoc ["input",input;"expected",run input]) inputs)); print_newline ()
