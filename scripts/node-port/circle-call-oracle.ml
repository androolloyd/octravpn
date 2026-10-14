(* Exercise adopted host decoders; no runtime source changes. *)
open Yojson.Safe.Util
module H=Octra_core.Circle_wasm_host
module C=Octra_core.Circle_wasm_codec
module T=Octra_core.Circle_hfhe_transcript
module P=Octra_circle_runtime.Circle_program
let b64 s=`String(Base64.encode_exn s)
let bytes j k=Base64.decode_exn(j|>member k|>to_string)
let raw j=Yojson.Safe.from_string(bytes j "json")
let error e=`Assoc["error",b64 e]
let opt f=function None->`Null|Some v->f v
let int n=`String(string_of_int n)
let i64 n=`String(Int64.to_string n)
let response=function
 | C.Resp_null->`Assoc["tag",`Int 0;"value",`Null]
 | C.Resp_bool b->`Assoc["tag",`Int(if b then 2 else 1);"value",`Null]
 | C.Resp_int s->`Assoc["tag",`Int 3;"value",b64 s]
 | C.Resp_string s->`Assoc["tag",`Int 4;"value",b64 s]
let storage tbl=`List(Hashtbl.to_seq tbl|>List.of_seq|>List.sort compare|>List.map(fun(k,v)->`List[b64 k;b64 v]))
let result (r:H.exec_result)=`Assoc[
 "success",`Bool r.success;"effort",int r.effort_used;"status",int r.response_status;
 "trace",opt b64 r.compute_trace_root;"steps",opt i64 r.compute_steps;"operations",opt i64 r.compute_operations;
 "exit",opt int r.compute_exit;"fault",opt b64 r.compute_fault;"response",opt response r.response_value;
 "storage",storage r.storage_tbl;"storage_order",`List(List.of_seq(Hashtbl.to_seq_keys r.storage_tbl)|>List.map b64);
 "events",`List(List.map(fun(e:H.wasm_event)->`List[b64 e.topic;b64 e.data])r.events);
 "spawns",`List(List.map(fun(e:H.spawn)->`Assoc["circle",b64 e.circle_id;"owner",`String(Octra_core.Circles.string_of_spawn_owner e.owner_mode);"nonce",int e.spawn_nonce;"payload",b64 e.payload_json])r.spawns);
 "assets",`List(List.map(fun(e:H.asset_put)->`Assoc["circle",b64 e.circle_id;"path",b64 e.path;"type",b64 e.content_type;"encoding",opt b64 e.encoding;"body",b64 e.body_b64])r.assets);
 "encrypted",`List(List.map(fun(e:H.encrypted_asset_put)->`Assoc["circle",b64 e.circle_id;"path",opt b64 e.path;"slot",opt b64 e.slot_ref;"state",opt b64 e.state_ref;"type",b64 e.content_type;"encoding",opt b64 e.encoding;"key",b64 e.key_id;"hash",b64 e.plaintext_hash;"padding",opt b64 e.padding_class;"activate",opt i64 e.activate_after_epoch;"expire",opt i64 e.expire_after_epoch;"metadata",opt(fun m->`String(Octra_core.Circles.string_of_metadata_mode m))e.metadata_mode;"body",b64 e.ciphertext_b64])r.encrypted_assets);
 "transcript",b64(T.canonical r.hfhe_transcript);"error",opt b64 r.error]
let run j=match j|>member "op"|>to_string with
|"base64"->(match Base64.decode(bytes j "bytes")with Ok value->`Assoc["bytes",b64 value]|Error(`Msg e)->error e)
|"request"->let params=raw j|>to_list in (match C.encode_request ~method_name:(bytes j "method")params with Ok s->`Assoc["bytes",b64 s]|Error e->error e)
|"literal"->(match C.encode_request ~method_name:(bytes j "method") [`Intlit(bytes j "literal")]with Ok s->`Assoc["bytes",b64 s]|Error e->error e)
|"response"->(match C.decode_response(bytes j "bytes")with Ok r->response r|Error e->error e)
|"transcript"->(match T.entries_of_json(raw j)with Error e->error e|Ok entries->`Assoc["canonical",b64(T.canonical entries);"hash",`String(T.hash entries)])
|"methods"->(match H.descriptor_of_yojson(raw j)with Error e->error e|Ok d->match P.methods_of_wasm_descriptor d with Error e->error e|Ok methods->`List(List.map(fun(m:P.method_info)->`Assoc["name",b64 m.name;"view",`Bool m.view;"execution",`String(P.execution_name m.execution)])methods))
|"execution"->let tbl=Hashtbl.create 8 in
 List.iter(fun pair->match pair with `List[`String k;`String v]->Hashtbl.replace tbl(Base64.decode_exn k)(Base64.decode_exn v)|_->failwith "pair")(j|>member "before"|>to_list);
 (match Lwt_main.run(H.decode_execution ~storage_tbl:tbl (Ok(raw j)))with Ok r->result r|Error(H.Rejected e)->error e|Error(H.Unavailable e)->`Assoc["unavailable",b64 e])
|_->failwith "operation"
let ()=let inputs=Yojson.Safe.from_channel stdin|>to_list in
 let results=List.map(fun input->`Assoc["input",input;"expected",run input])inputs in
 Yojson.Safe.to_channel stdout(`List results);print_newline()
