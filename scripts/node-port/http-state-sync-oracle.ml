(* Pinned, offline native HTTP codecs; no ledger/store opens or network I/O. *)
module S = Octra_bootstrap.State_sync
module P = Octra_bootstrap.Range_part
module H = Octra_core.Head_manifest
module R = Octra_node_runtime.State_sync_http
module V = Octra_node_runtime.Rest_view
open Yojson.Safe.Util
let ok value = `Assoc ["ok",value]
let failure reason = `Assoc ["error",`String reason]
let raw value = value |> to_string |> Base64.decode_exn
let hash value = Digestif.SHA256.(digest_string value |> to_hex)
let text value = `String (Base64.encode_exn value)
let quoted size = "\"" ^ String.make (size-2) 'a' ^ "\""
let set_head j =
 H.cached := None;
 match member "head" j with
 | `Null -> ()
 | value -> H.set_cached H.{schema_version=3;generation=1;epoch_id=member "epoch" value |> to_int;
   state_root=member "root" value |> to_string;ledger_state_root=None;irmin_commit=None;
   txid_hi=member "txid_hi" value |> to_string |> Int64.of_string;txlog_seg=None;txlog_off=None;
   epochlog_off=None;commit_id="fixture";ts=1.;quorum_cert_hash=None;epoch_index_hash=None;epoch_index_root=None}
let run j = match member "op" j |> to_string with
 | "head" ->
   set_head j; Unix.putenv "OCTRA_STATE_SYNC_ENABLE" "1"; Unix.putenv "OCTRA_VALIDATORS" "";
   let current_epoch=ref (member "current_epoch" j |> to_int) in
   let action=R.handle_head ~data_dir:"/no-http-oracle-store" ~chain_id:"fixture" ~config_hash:""
     ~validator_set:(Octra_consensus.C_types.make_validator_set []) ~current_epoch in
   let response,body=Lwt_main.run action in
   let body=Lwt_main.run (Cohttp_lwt.Body.to_string body) in
   ok (`Assoc ["status",`Int (Cohttp.Code.code_of_status (Cohttp.Response.status response));"raw",text body])
 | "error" -> ok (text (V.error_response ~error_type:(member "type" j |> to_string) ~reason:(member "reason" j |> to_string) |> Yojson.Safe.to_string))
 | "query" ->
   let query=Uri.query (Uri.of_string ("http://localhost/?" ^ (member "query" j |> to_string))) in
   ok (`Assoc ["selected",`List (List.map (fun name -> match List.assoc_opt name query with Some (value::_)->text value|_->`Null) ["from_epoch";"path";"bare"]);
     "rows",`List(List.map (fun (name,values)->`List[text name;`List(List.map text values)]) query)])
 | "progress" ->
   begin match S.progress_of_yojson (member "raw" j |> raw |> Yojson.Safe.from_string) with
   | Error reason -> failure reason
   | Ok progress -> ok (text (S.progress_to_yojson progress |> Yojson.Safe.to_string)) end
 | ("range_missing" | "range_error") as op ->
   let result=if op="range_missing" then `NotFound else `Internal (member "reason" j |> to_string) in
   ok (text (S.range_response ~head:None ~from_epoch:(member "from_epoch" j |> to_string |> Int64.of_string)
     ~max_epochs:(member "max_epochs" j |> to_int) result |> Yojson.Safe.to_string))
 | "part_view" ->
   begin match P.view (member "raw" j |> raw |> Yojson.Safe.from_string) with
   | Error reason -> failure reason
   | Ok (P.Full _) -> ok (`String "full")
   | Ok (P.Part part) -> ok (`Assoc ["sha256",`String part.hash;"index",`Int part.index;"count",`Int part.count;
       "data",text (Base64.decode_exn part.data)]) end
 | "multipart" ->
   let raw=quoted (member "size" j |> to_int) in
   begin match P.encode (Yojson.Safe.from_string raw) with
   | Error reason -> failure reason
   | Ok encoded ->
     let index=match member "index" j with `Null->None|value->Some(to_int value) in
     begin match P.render ?index encoded with
     | Error reason -> failure reason
     | Ok rendered -> begin match P.view (Yojson.Safe.from_string rendered) with
       | Error reason -> failure reason
       | Ok (P.Full _) -> ok (`Assoc ["kind",`String "full";"size",`Int(String.length rendered);"sha256",`String(hash rendered)])
       | Ok (P.Part part) ->
         let parts=List.init part.count (fun index -> match P.render ~index encoded with
           | Error reason -> failwith reason
           | Ok body -> match P.view (Yojson.Safe.from_string body) with Ok (P.Part part)->part|_->failwith "not part") in
         begin match P.join parts with Error reason->failure reason|Ok joined->let joined=Yojson.Safe.to_string joined in
           ok (`Assoc ["kind",`String "part";"size",`Int(String.length joined);"sha256",`String(hash joined);
             "index",`Int part.index;"count",`Int part.count;"data_size",`Int(String.length(Base64.decode_exn part.data))]) end
       end end end
 | _ -> failwith "unknown HTTP oracle operation"
let case j = let expected=try run j with exn->failure (Printexc.to_string exn) in
 match j with `Assoc fields -> `Assoc(fields@["expected",expected])|_->assert false
let () = Yojson.Safe.from_channel stdin |> to_list |> List.map case |> fun cases ->
 Yojson.Safe.to_channel stdout (`List cases); print_newline ()
