(* Call native selection/precheck with supplied proof verdicts. This qualifies
   dependency and resource policy, not the cryptographic callback itself. *)
open Yojson.Safe.Util
module T = Octra_core.Transaction
module W = Octra_core.Preverify_worker
let bytes j = Base64.decode_exn (to_string j)
let run input =
 let txs = member "transactions" input |> to_list |> List.map (fun j ->
   bytes j |> Yojson.Safe.from_string |> T.of_yojson |> Result.get_ok) in
 let verdicts = member "verdicts" input |> to_list |> List.map to_string in
 let values = List.map2 (fun tx verdict -> T.hash tx,verdict) txs verdicts in
 let calls = ref [] in
 let verify tx =
   let hash = T.hash tx in calls := hash :: !calls;
   let verdict = List.assoc hash values in
   Lwt.return (match verdict with
   | "ready" -> W.Checked_ready {tx;receipt=None}
   | "unavailable" -> W.Checked_skip {tx;reason="fixture unavailable";kind=Unavailable}
   | "invalid" -> W.Checked_skip {tx;reason="fixture invalid";kind=Invalid}
   | _ -> failwith "unexpected fixture verdict") in
 let batch = Lwt_main.run (Octra_node_runtime.Consensus_proposal.precheck
   ~ordered:(member "ordered" input |> to_bool)
   ~run_many:(W.run_checked verify) txs) in
 let kind = function W.Deferred -> "deferred" | Unavailable -> "unavailable" | Invalid -> "invalid" in
 `Assoc ["ready",`List(List.map (fun (r:W.ready) -> `String(T.hash r.tx)) batch.ready);
   "skipped",`List(List.map (fun (s:W.skip) -> `Assoc[
     "hash",`String(T.hash s.tx);"reason",`String s.reason;"kind",`String(kind s.kind)]) batch.skipped);
   "calls",`List(List.map (fun h -> `String h) (List.rev !calls));
   "retry",`Bool(W.may_retry ~inputs:txs batch)]
let () =
 let inputs=Yojson.Safe.from_channel stdin |> to_list in
 Yojson.Safe.to_channel stdout (`List(List.map (fun input -> `Assoc["input",input;"expected",run input]) inputs));
 print_newline ()
