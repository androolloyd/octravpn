(* Read-only native Circle asset and policy oracle; adopted code is unmodified. *)
open Lwt.Syntax
module Store=Octra_core.Store_irmin
module S=Store.Store
module C=Octra_core.Circles
module P=Octra_core.Circle_wasm_public_read
module V=Octra_core.Circle_policy_value
open Yojson.Safe.Util
let bytes j k=Base64.decode_exn(j|>member k|>to_string)
let b64 raw=`String(Base64.encode_exn raw)
let error raw=`Assoc["error",b64 raw]
let metadata raw=try C.asset_meta_of_yojson(Yojson.Safe.from_string raw) with
 |Yojson.Json_error _->Error "circle asset metadata JSON refused"
 |Failure _->Error "circle asset metadata integer refused"
let meta_json m=b64(Yojson.Safe.to_string(C.yojson_of_asset_meta m))
let optional j k=match member k j with `Null->None|`String s->Some(Base64.decode_exn s)|_->failwith "optional"
let run store j=match j|>member "op"|>to_string with
|"path"->Lwt.return(match C.path_key_of_raw_path(bytes j "path") with Error e->error e|Ok(path,key)->`Assoc["path",b64 path;"key",`String key;"resource",`String(C.resource_key_of_path ~circle_id:(bytes j "circle") ~canonical_path:path);"stable",`String(C.stable_key_hash path)])
|"meta"->Lwt.return(match metadata(bytes j "meta")with Error e->error e|Ok m->`Assoc["meta",meta_json m])
|"policy"->Lwt.return(match metadata(bytes j "meta")with Error e->error e|Ok m->
 let p:P.policy={activate_after_epoch=V.int64_value(optional j "activate");expire_after_epoch=V.int64_value(optional j "expire");tombstone=V.bool_value(optional j "tombstone");revoked=V.bool_value(optional j "revoked")}in
 `Bool(P.visible_at(Int64.of_string(j|>member "epoch"|>to_string))m p))
|"asset"->
 let* tree=Lwt_list.fold_left_s(fun tree entry->let path=entry|>member "path"|>to_list|>List.map(fun v->Base64.decode_exn(to_string v))in S.Tree.add tree path (bytes entry "value"))(S.Tree.empty())(j|>member "entries"|>to_list)in
 let root=Irmin.Type.to_string S.Hash.t(S.Tree.hash tree)in
 let snapshot:Store.read_snapshot={read_repo=store.Store.repo;tree;state_root=root;commit_hash="";epoch_id=3L}in
 let* asset=Store.get_circle_public_asset_at ~max_bytes:(j|>member "max_bytes"|>to_int) snapshot (bytes j "circle")(bytes j "path")in
 let found=match asset with Error e->error e|Ok a->`Assoc["path",b64 a.Store.canonical_path;"key",`String a.path_key;"browser",b64 a.browser_mode;"resource",b64 a.resource_mode;"meta",meta_json a.meta;"body",b64 a.body_b64]in
 Lwt.return(`Assoc["root",`String root;"found",found])
|_->failwith "operation"
let ()=let cases=Yojson.Safe.from_channel stdin|>to_list in
 let results=Lwt_main.run(let* store=Store.open_store ~fresh:true "/tmp/circle-assets-data"in
 Lwt.finalize(fun()->Lwt_list.map_s(fun input->let* expected=run store input in Lwt.return(`Assoc["input",input;"expected",expected]))cases)(fun()->Store.close store))in
 Yojson.Safe.to_channel stdout(`List results);print_newline()
