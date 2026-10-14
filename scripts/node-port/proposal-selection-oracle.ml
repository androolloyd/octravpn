(* Calls unmodified native caps, slots, Circle turns and parent classification.
   Dummy signatures exercise selection only, not transaction admission or QC authentication. *)
open Yojson.Safe.Util
module T = Octra_core.Transaction
module P = Octra_node_runtime.Consensus_proposal
module R = Octra_node_runtime.Circle_refill
module Turn = Octra_node_runtime.Circle_turn
module C = Octra_consensus.C_types
let int j k = member k j |> to_int
let tx j = T.{from=member "sender" j |> to_string; to_="oct_receiver";
 amount=Z.zero; nonce=int j "nonce"; ou=Z.of_int(int j "fee"); timestamp=1.;
 signature="sig";public_key=Some "pub";message=Some(member "message" j |> to_string);
 encrypted_data=None;op_type=Result.get_ok(T.op_type_of_string(member "op" j |> to_string))}
let hashes txs = `List(List.map(fun t -> `String(T.hash t))txs)
let root txs = Octra_net.Hash_domain.hash "octra:tx_list:v1" (String.concat "" (List.map T.hash txs))
let parent mode txs =
 if mode="none" then None else
 let chain_id=if mode="chain" then "other" else "selection" in
 let epoch_id=if mode="epoch" then 10L else 11L in
 let header=C.{proto_version=C.proto_version_current;chain_id;epoch_id;prev_state_root=String.make 32 'p';
  tx_list_hash=root(if mode="empty" then [] else txs);receipt_root=String.make 32 'r';
  proposed_state_root=String.make 32 's';parent_commit_hash=String.make 32 'c';
  creator_addr="creator";txid_hi=0L;ts=10.} in
 let proposal_id=if mode="hash" then String.make 32 'x' else Octra_consensus.C_hash.proposal_id header in
 Some C.{certificate={chain_id;epoch_id;commit_round=0;header;proposal_id;precommits=[]};
  validator_set=C.build_validator_set ~weighted:false []}
let run j =
 let txs=member "txs" j |> to_list |> List.map tx in
 let subset key=member key j |> to_list |> List.map(fun i -> List.nth txs (to_int i)) in
 let ready=subset "ready" and ordinary=subset "ordinary" in
 let mode=member "parent" j |> to_string in
 let previous=Turn.previous ~chain_id:"selection" ~epoch:(Int64.of_int(int j "epoch"))
  ~lookup:(fun _ -> if mode="missing" then None else Some(if mode="mismatch" then [] else txs)) (parent mode txs) in
 let max_bytes=match member "byte_offset" j with
  | `Int offset -> (P.totals [List.hd txs]).bytes + offset
  | _ -> int j "bytes" in
 let limits=P.limits ~max_txs:(int j "count") ~max_bytes ~max_ou:(Z.of_int(int j "ou")) in
 let slots=Octra_core.Private_slots.select ~limits:{fhe=int j "fhe";stealth=int j "stealth"} ~inputs:txs ~ready in
 let capped=P.cap ~limits txs in
 `Assoc["byte_limit",`Int max_bytes;"transactions",`List(List.map(fun t -> `String(Yojson.Safe.to_string(T.to_yojson t)))txs);
  "expected",`Assoc["cap",hashes capped.txs;"within",`Bool(P.within_limits ~limits txs);
   "slots",hashes slots;"without",hashes(R.without txs);
   "previous",(match previous with None->`Null | Some b->`Bool b);
   "turn",hashes(Turn.select ~ordered:(member "ordered" j |> to_bool) ~epoch:(Int64.of_int(int j "epoch")) ~previous ~ordinary txs)]]
let () = Yojson.Safe.from_channel stdin |> to_list |> List.map(fun input ->
 match run input with `Assoc output -> `Assoc(("input",input)::output) | _ -> assert false)
 |> fun out -> Yojson.Safe.to_channel stdout (`List out);print_newline()
