(* Execute and apply real upstream WASM updates through the complete OCaml host. *)
open Lwt.Syntax
open Yojson.Safe.Util
module S=Octra_core.Store_irmin
module T=S.Store
module VM=Octra_vm.Contract_vm
module E=Octra_circle_runtime.Circle_exec
let bytes v=Base64.decode_exn(to_string v)
let b64 v=`String(Base64.encode_exn v)
let table t=`List(Hashtbl.fold(fun k v acc->(k,v)::acc)t[]|>List.sort compare|>List.map(fun(k,v)->`List[b64 k;b64 v]))
let root t=`String(Irmin.Type.to_string T.Hash.t(T.Tree.hash t))
let run store j=
 let* tree=Lwt_list.fold_left_s(fun tree e->T.Tree.add tree(e|>member "path"|>to_list|>List.map bytes)(bytes(e|>member "value")))(T.Tree.empty())(j|>member "entries"|>to_list)in
 let code=let ch=open_in_bin "/oracle/counter.wasm"in let v=really_input_string ch(in_channel_length ch)in close_in ch;v in
 let circle=j|>member "circle"|>to_string in
 let* tree=T.Tree.add tree["circles";circle;"program";"code_b64"](Base64.encode_exn code)in
 let* tree=T.Tree.add tree["circles";circle;"code_hash"](Octra_core.Circles.sha256_hex code)in
 store.S.batch_tree<-Some tree;
 E.clear_wasm_view_storage_cache();Hashtbl.clear Octra_circle_runtime.Circle_program.loaded_cache;
 let mode name=if j|>member name|>to_bool then Octra_core.Rule_graph.Active else Octra_core.Rule_graph.Prior in
 let ctx={VM.default_ctx with byte_work=(if j|>member "budget"|>to_bool then Some(Octra_vm.Byte_work.create Octra_vm.Byte_work.consensus_limits)else None);proof_exec=mode "proof";wasm_float=mode "float";math=(j|>member "math"|>to_bool);current_epoch=(j|>member "epoch"|>to_int);tx_hash=(j|>member "tx_hash"|>to_string)}in
 let* call=E.execute_call ~ctx ~limit:(j|>member "limit"|>to_int) ~depth:(j|>member "depth"|>to_int) ~inspect_mode:(mode "inspect") ~hfhe_strict:true ~update_policy:(j|>member "update_policy"|>to_bool) store circle (j|>member "method"|>to_string)(j|>member "params"|>to_list)(j|>member "caller"|>to_string) Z.zero in
 let receipt=call.E.receipt in
 let* commit=E.commit_call_result ~float_mode:(mode "float") ~inspect_mode:(mode "inspect") ~proof_mode:(mode "storage_proof") store circle call in
 let* stable=S.read store["circles";circle;"stable_root"]in
 let found=`Assoc[
 "before_root",root tree;"root",root(Option.get store.S.batch_tree);
 "commit",(match commit with Ok _->`Null|Error e->b64 e);"stable",(match stable with None->`Null|Some v->b64 v);
 "receipt",`Assoc["success",`Bool receipt.Octra_vm.Contract.success;"result",Octra_vm.Receipt_view.return_json receipt.return_value;"effort",`Int receipt.effort_used;"error",(match receipt.error with None->`Null|Some e->b64 e);"events",`List(List.map(fun(e:VM.event_record)->`List[b64 e.event;`List(List.map(fun v->b64(VM.to_string v))e.values)])receipt.events)];
 "storage",table call.storage_tbl]in
 store.S.batch_tree<-None;Lwt.return found
let ()=let inputs=Yojson.Safe.from_channel stdin|>to_list in
 let results=Lwt_main.run(let* store=S.open_store ~fresh:true "/tmp/circle-update-data"in
 Lwt.finalize(fun()->Lwt_list.map_s(fun input->let* expected=run store input in Lwt.return(`Assoc["input",input;"expected",expected]))inputs)(fun()->S.close store))in
 Yojson.Safe.to_channel stdout(`List results);print_newline()
