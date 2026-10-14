(* Qualify canonical Circle records and public reads against unmodified sources. *)
open Lwt.Syntax
open Yojson.Safe.Util
module S=Octra_core.Store_irmin
module T=S.Store
module C=Octra_core.Circles
module P=Octra_core.Circle_wasm_public_read
let bytes j k=Base64.decode_exn(j|>member k|>to_string)
let b64 v=`String(Base64.encode_exn v)
let err s=`Assoc["error",b64 s]
let number n=`String(Int64.to_string n)
let opt f=function None->`Null|Some v->f v
let info (i:C.circle_info)=`Assoc[
 "circle",b64 i.circle_id;"runtime",b64(C.string_of_runtime i.runtime);"version",number i.version;
 "owner",b64 i.owner;"code_hash",b64 i.code_hash;"stable_root",b64 i.stable_root;"assets_root",b64 i.assets_root;
 "privacy",b64(C.string_of_privacy_class i.privacy_class);"browser",b64(C.string_of_browser_mode i.browser_mode);
 "resource",b64(C.string_of_resource_mode i.resource_mode);"policy_hash",opt b64 i.policy_hash;
 "members_root",opt b64 i.members_root;"export_policy",opt b64 i.export_policy;
 "limits",`List(List.map number [i.limits.max_stable_bytes;i.limits.max_assets_bytes;i.limits.max_inline_value;i.limits.max_wasm_bytes])]
let declarations ds=`List(List.map(fun(d:P.declaration)->`Assoc[
 "method",b64 d.method_name;"circle",b64 d.circle_id;"path",b64 d.canonical_path;"key",`String d.path_key;
 "offset",`String(string_of_int d.offset);"max_bytes",`String(string_of_int d.max_bytes)])ds)
let manifest j=match Yojson.Safe.from_string(bytes j "descriptor")|>member "manifest" with `Null->None|v->Some v
let caught op = function
 |Yojson.Json_error _->err(if op="storage" || op="inline" then "circle stable entry JSON refused" else "circle asset metadata JSON refused")
 |Failure _->err(if op="info" then "circle info integer refused" else if op="storage" || op="inline" then "circle stable entry integer refused" else "circle asset metadata integer refused")
 |e->raise e
let run store j=
 let op=j|>member "op"|>to_string in
 if op="declarations" then Lwt.return(match P.declarations_of_manifest(manifest j)with Ok d->declarations d|Error e->err e)
 else
 let* tree=Lwt_list.fold_left_s(fun tree e->T.Tree.add tree(e|>member "path"|>to_list|>List.map(fun v->Base64.decode_exn(to_string v)))(bytes e "value"))(T.Tree.empty())(j|>member "entries"|>to_list)in
 let root=Irmin.Type.to_string T.Hash.t(T.Tree.hash tree)in
 let snapshot:S.read_snapshot={read_repo=store.S.repo;tree;state_root=root;commit_hash="";epoch_id=3L}in
 let spent=ref 0 in
 let charge=match j|>member "budget" with `Null->None|v->let limit=to_int v in Some(fun cost->if cost<0 || cost>limit- !spent then false else(spent:= !spent+cost;true))in
 let* found=Lwt.catch(fun()->match op with
 |"info"->let* i=S.get_circle_info ~snapshot store(bytes j "circle")in Lwt.return(opt info i)
 |"inline"->let* v=S.read_circle_stable_inline_value ~snapshot store(bytes j "circle")(bytes j "key")in Lwt.return(opt b64 v)
 |"storage"->let* values=S.load_circle_stable_storage ~snapshot store(bytes j "circle")in Lwt.return(match values with Error e->err e|Ok values->`List(Hashtbl.fold(fun k v acc->(k,v)::acc)values[]|>List.sort compare|>List.map(fun(k,v)->`List[b64 k;b64 v])))
 |"reads"->begin match P.declarations_of_manifest(manifest j)with Error e->Lwt.return(err e)|Ok ds->
   let ds=P.for_method ds(bytes j "method")in
   let* result=P.load ~snapshot ?charge store(Int64.of_string(j|>member "epoch"|>to_string))ds in
   Lwt.return(match result with Error e->err e|Ok b->`Assoc["effort",`Int b.effort_used;"reads",`List(List.map(fun s->b64(Yojson.Safe.to_string(P.yojson_of_snapshot s)))b.snapshots)])end
 |_->failwith "unknown operation") (fun e->Lwt.return(caught op e))in
 Lwt.return(`Assoc["root",`String root;"found",found;"spent",`Int !spent])
let ()=
 let inputs=Yojson.Safe.from_channel stdin|>to_list in
 let result=Lwt_main.run(let* store=S.open_store ~fresh:true "/tmp/circle-state-data"in
 Lwt.finalize(fun()->Lwt_list.map_s(fun input->let* expected=run store input in Lwt.return(`Assoc["input",input;"expected",expected]))inputs)(fun()->S.close store))in
 Yojson.Safe.to_channel stdout(`List result);print_newline()
