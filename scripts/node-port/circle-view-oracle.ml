(* Execute the adopted counter through the complete native Circle view host. *)
open Lwt.Syntax
open Yojson.Safe.Util
module S=Octra_core.Store_irmin
module T=S.Store
module VM=Octra_vm.Contract_vm
module E=Octra_circle_runtime.Circle_exec
let bytes j k=Base64.decode_exn(j|>member k|>to_string)
let err s=`Assoc["error",`String s]
let run store j=
 let* tree=Lwt_list.fold_left_s(fun tree e->T.Tree.add tree(e|>member "path"|>to_list|>List.map(fun v->Base64.decode_exn(to_string v)))(bytes e "value"))(T.Tree.empty())(j|>member "entries"|>to_list)in
 let code=let ch=open_in_bin "/oracle/counter.wasm"in let data=really_input_string ch(in_channel_length ch)in close_in ch;data in
 let circle=j|>member "circle"|>to_string in
 let* tree=if j|>member "code"=`Bool true then
   let* tree=T.Tree.add tree["circles";circle;"program";"code_b64"](Base64.encode_exn code)in
   T.Tree.add tree["circles";circle;"code_hash"](Octra_core.Circles.sha256_hex code)
 else Lwt.return tree in
 let root=Irmin.Type.to_string T.Hash.t(T.Tree.hash tree)in
 let snapshot:S.read_snapshot={read_repo=store.S.repo;tree;state_root=root;commit_hash="";epoch_id=0L}in
 E.clear_wasm_view_storage_cache();Hashtbl.clear Octra_circle_runtime.Circle_program.loaded_cache;
 let active name=if j|>member name=`Bool true then Octra_core.Rule_graph.Active else Octra_core.Rule_graph.Prior in
 let ctx={VM.default_ctx with byte_work=Some(Octra_vm.Byte_work.create Octra_vm.Contract_rpc.view_byte_limits);proof_exec=active "proof";wasm_float=active "float";math=(j|>member "math"=`Bool true)}in
 let* receipt=E.execute_view_call ~snapshot ~ctx ~limit:20_000_000 ~inspect_mode:Octra_core.Rule_graph.Active store circle(j|>member "method"|>to_string)(j|>member "params"|>to_list)"oct00000000000000000000000000000000000000000000"in
 let found=if receipt.Octra_vm.Contract.success then `Assoc["result",Octra_vm.Receipt_view.return_json receipt.return_value]
 else err(Option.value ~default:"execution failed" receipt.error)in
 Lwt.return(`Assoc["root",`String root;"found",found;"effort",`Int receipt.effort_used])
let ()=let inputs=Yojson.Safe.from_channel stdin|>to_list in
 let results=Lwt_main.run(let* store=S.open_store ~fresh:true "/tmp/circle-view-data"in
 Lwt.finalize(fun()->Lwt_list.map_s(fun input->let* expected=run store input in Lwt.return(`Assoc["input",input;"expected",expected]))inputs)(fun()->S.close store))in
 Yojson.Safe.to_channel stdout(`List results);print_newline()
