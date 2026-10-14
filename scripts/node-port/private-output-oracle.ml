(* Exact native stealth storage and mutation/query semantics. *)
let ()=Octra_log._set_level Octra_log.FATAL
open Lwt.Syntax
open Yojson.Safe.Util
module S=Octra_core.Store_irmin
module L=Octra_core.Ledger_types
let raw j k=member k j |> to_string |> Base64.decode_exn
let b64 v=`String(Base64.encode_exn v)
let option f=function None->`Null|Some v->f v
let run i input=
 let* store=S.open_store ~fresh:true(Printf.sprintf "/tmp/private-output-%d" i) in
 Lwt.finalize(fun ()->
 let* ()=S.begin_epoch_batch store in
 let* ()=Lwt_list.iter_s(fun row->let key=member "key" row |> to_list |> List.map to_string in S.write store key(raw row "value"))(member "state" input |> to_list) in
 let* results=Lwt_list.map_s(fun op->
  Lwt.catch(fun ()->match member "operation" op |> to_string with
   |"insert"->let* result=S.insert_stealth_output store ~stealth_tag:(raw op "tag") ~eph_pub:(raw op "ephemeral") ~enc_amount:(raw op "encrypted") ~amount:(raw op "amount")
      ~epoch_id:(member "epoch" op |> to_int) ~tx_hash:(raw op "hash") ~sender_addr:(raw op "sender") ~claim_pub:(raw op "claim") ~delta_cipher_stored:(raw op "delta") ~amount_hash:(raw op "amount_hash") ~amount_commitment:(raw op "commitment") in
      Lwt.return(match result with Ok id->`Assoc["id",`String(Int64.to_string id)]|Error e->`Assoc["error",b64 e])
   |"claim"->let* result=S.mark_stealth_claimed store (member "id" op |> to_int)(raw op "hash") in
      Lwt.return(match result with Ok ()->`Bool true|Error e->`Assoc["error",b64 e])
   |_ ->failwith "unknown operation")
  (fun e->Lwt.return(`Assoc["exception",b64(Printexc.to_string e)]))) (member "operations" input |> to_list) in
 let root=Irmin.Type.to_string S.Store.Hash.t(S.Store.Tree.hash(Option.get store.batch_tree)) in
 let* rows=Lwt_list.map_s(fun id->let id=to_int id in let* raw=S.read store ["stealth";string_of_int id] in
  let* output=S.get_stealth_output_by_id store id in Lwt.return(`Assoc["id",`Int id;"raw",option b64 raw;"output",option(fun v->b64(Yojson.Safe.to_string(L.stealth_output_to_yojson v)))output]))(member "ids" input |> to_list) in
 let* sum=S.get_unclaimed_stealth_amount store in
 let* claims=S.get_claimed_stealth_claim_tx_hashes store in
 let* since=S.get_stealth_outputs_since store (member "since" input |> to_int) in
 let* counter=S.read store ["index";"stealth_counter"] in
 Lwt.return(`Assoc["input",input;"expected",`Assoc["results",`List results;"root",`String root;"rows",`List rows;"counter",option b64 counter;"sum",`String(Z.to_string sum);"claims",`List(List.map b64 claims);"since",b64(Yojson.Safe.to_string(`List since))]]))
 (fun ()->S.close store)
let ()=let inputs=Yojson.Safe.from_channel stdin |> to_list in
 let rows=Lwt_main.run(Lwt_list.mapi_s run inputs) in Yojson.Safe.to_channel stdout(`List rows);print_newline()
