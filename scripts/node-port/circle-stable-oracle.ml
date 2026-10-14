(* Native storage loading, accounting and persistence on a speculative Irmin tree. *)
open Lwt.Syntax
open Yojson.Safe.Util
module S=Octra_core.Store_irmin
module T=S.Store
module C=Octra_core.Circles
module J=Octra_vm.Program_journal
let bytes v=Base64.decode_exn(to_string v)
let b64 s=`String(Base64.encode_exn s)
let err s=`Assoc["error",b64 s]
let table j=
 let t=Hashtbl.create ~random:false (j|>member "capacity"|>to_int)in
 List.iter(fun p->match to_list p with[k;v]->Hashtbl.replace t(bytes k)(bytes v)|_->assert false)(j|>member "pairs"|>to_list);t
let describe t=`Assoc[
 "keys",`List(List.of_seq(Hashtbl.to_seq_keys t)|>List.map b64);
 "values",`List(Hashtbl.fold(fun k v acc->(k,v)::acc)t[]|>List.sort compare|>List.map(fun(k,v)->`List[b64 k;b64 v]));
 "storage_effort",`String(Z.to_string(J.storage_effort t));"write_effort",`String(Z.to_string(J.write_effort t))]
let caught=function
 |Yojson.Json_error _->err "circle stable entry JSON refused"
 |Failure _->err "circle stable entry integer refused"
 |e->raise e
let run store j=
 let* tree=Lwt_list.fold_left_s(fun t e->T.Tree.add t(e|>member "path"|>to_list|>List.map bytes)(bytes(e|>member "value")))(T.Tree.empty())(j|>member "entries"|>to_list)in
 store.S.batch_tree<-Some tree;
 let circle=bytes(j|>member "circle")in
 let spent=ref 0 in
 let charge=match j|>member "budget"with `Null->None|v->let limit=Z.of_string(to_string v)in Some(fun cost->if Z.sign cost<0 || Z.gt cost Z.(sub limit (of_int !spent))then false else(spent:= !spent+Z.to_int cost;true))in
 let* found=Lwt.catch(fun()->match j|>member "op"|>to_string with
 |"load"->let* v=S.load_circle_stable_storage ?charge store circle in Lwt.return(match v with Ok t->describe t|Error e->err e)
 |"save"->let t=table(j|>member "table")in
   let limits={C.max_stable_bytes=Int64.of_string(j|>member "max_stable"|>to_string);max_inline_value=Int64.of_string(j|>member "max_inline"|>to_string);max_assets_bytes=0L;max_wasm_bytes=0L}in
   let* v=S.save_circle_stable_storage_checked store circle limits t in Lwt.return(match v with Ok root->`Assoc["stable_root",`String root;"table",describe t]|Error e->err e)
 |_->failwith "unknown operation") (fun e->Lwt.return(caught e))in
 let tree=Option.get store.S.batch_tree in
 let root=Irmin.Type.to_string T.Hash.t(T.Tree.hash tree)in
 let* stable=S.read store["circles";circle;"stable_root"]in
 store.S.batch_tree<-None;
 Lwt.return(`Assoc["found",found;"root",`String root;"stable",(match stable with None->`Null|Some v->b64 v);"spent",`Int !spent])
let ()=let inputs=Yojson.Safe.from_channel stdin|>to_list in
 let results=Lwt_main.run(let* store=S.open_store ~fresh:true "/tmp/circle-stable-data"in
 Lwt.finalize(fun()->Lwt_list.map_s(fun input->let* expected=run store input in Lwt.return(`Assoc["input",input;"expected",expected]))inputs)(fun()->S.close store))in
 Yojson.Safe.to_channel stdout(`List results);print_newline()
