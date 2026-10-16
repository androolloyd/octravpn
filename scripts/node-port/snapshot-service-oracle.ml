(* Pinned native local service policies. Lease markers are fresh temp fixtures. *)
module C=Octra_bootstrap.Sync_cycle
module P=Octra_node_runtime.Sync_publish
module L=Octra_node_runtime.Sync_lease
module F=Octra_consensus.Resource_attestation_flow
open Yojson.Safe.Util
let ok value=`Assoc["ok",value]
let error reason=`Assoc["error",`String reason]
let int value=Int64.of_int(to_int value)
let opt value=match value with `Null->None|value->Some(int value)
let number value=match value with `Float f->f|value->float_of_int(to_int value)
let maybe value=match value with None->`Null|Some value->`Int(Int64.to_int value)
let effects values=`List(List.map(function C.Capture epoch->`List[`String "capture";`Int(Int64.to_int epoch)]|C.Retain n->`List[`String "retain";`Int n])values)
let event value=match to_list value with
 | [`String "head";epoch]->C.Finalized(int epoch)
 | [`String "after";epoch;minimum]->C.Finalized_after{epoch=int epoch;minimum=int minimum}
 | [`String "complete";epoch;outcome]->let outcome=match to_list outcome with [`String "failed"]->C.Failed|[_;value]->C.Published(int value)|_->failwith "outcome" in C.Completed{epoch=int epoch;outcome}
 | _->failwith "event"
let run j=match member "op" j|>to_string with
 | "policy"->begin match C.policy ~interval:(member "interval" j|>int) ~retain:(member "retain" j|>to_int) with Error reason->error reason|Ok policy->ok (`List[`Int(Int64.to_int(C.interval policy));`Int(C.retention policy)]) end
 | "cycle"->
   let rec loop state=function []->[]|item::rest->match C.step C.default state (event item) with Error reason->[error reason]|Ok(next,eff)->ok(`Assoc["published",maybe(C.published next);"running",maybe(C.running next);"effects",effects eff])::loop next rest in
   ok(`List(loop(C.init ~published:(opt(member "published" j)))(member "events" j|>to_list)))
 | "override"->begin match P.publisher_override (match member "value" j with `Null->None|v->Some(to_string v)) with Ok value->ok(`Bool value)|Error reason->error reason end
 | "retention"->let items=member "items" j|>to_list|>List.map(fun row->match to_list row with [id;epoch]->to_string id,to_int epoch|_->failwith "row") in
   ok(`List(List.map(fun id->`String id)(P.retention_plan ~retain:(member "retain" j|>to_int) ~current:(member "current" j|>to_string) items)))
 | "lease"->
   let root=Filename.temp_file "snapshot-lease-oracle-" "" in Unix.unlink root;Unix.mkdir root 0o700;
   let path=Filename.concat root "download.lease" in
   let out=open_out_bin path in close_out out;let last=member "last_seen" j|>number in Unix.utimes path last last;
   let result=L.read ~now:(member "now" j|>number) ~published_at:(member "published" j|>number) ~snapshot_id:"fixture" root in
   Unix.unlink path;Unix.rmdir root;ok(`Bool(Option.is_some result))
 | "leases"->let items=member "items" j|>to_list|>List.map(fun row->match to_list row with [id;last]->L.{snapshot_id=to_string id;last_seen=number last}|_->failwith "row") in
   ok(`List(List.map(fun id->`String id)(L.retained items)))
 | "disabled_gossip"->let gossip=F.decode_gossip(member "raw" j|>to_string|>Base64.decode_exn) in
   let chain=member "chain" j|>to_string in ok(`String(if gossip.F.chain_id<>chain then "resource_attestation_chain_mismatch" else "invalid_resource_attestation"))
 | _->failwith "unknown operation"
let case j=let expected=try run j with exn->error(Printexc.to_string exn) in match j with `Assoc fields->`Assoc(fields@["expected",expected])|_->assert false
let ()=Yojson.Safe.from_channel stdin|>to_list|>List.map case|>fun cases->Yojson.Safe.to_channel stdout(`List cases);print_newline()
