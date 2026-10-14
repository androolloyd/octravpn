open Lwt.Syntax
open Yojson.Safe.Util
module S=Octra_core.Store_irmin
module T=S.Store
module C=Octra_node_runtime.Circle_read_rpc
module R=Octra_core.Rpc
let result=function Ok value->`Assoc["ok",value]|Error (e:R.rpc_error)->`Assoc["error",`String e.message;"code",`Int e.code;"data",Option.value ~default:`Null e.data]
let clock store j=
 let* tree=match member "epoch" j with `Null->Lwt.return(T.Tree.empty())|`String raw->T.Tree.add(T.Tree.empty())["meta";"last_epoch"]raw|_->assert false in
 let* ()=S.commit_bulk store tree "Circle RPC epoch probe" in
 let ledger=Octra_core.Ledger.create store in
 let called=ref None in
 let profile ~epoch=called:=Some epoch;Error(R.err (-32005) "profile probe" None) in
 let* program=C.program_rpc ~authenticated:false ~describe:true ~profile store `Null in
 let program_epoch=Option.fold ~none:`Null ~some:(fun n->`String(string_of_int n)) !called in
 called:=None;
 let* view=C.view_rpc ~authenticated:false ~trusted:[] ~profile ~store ~ledger `Null in
 let view_epoch=Option.fold ~none:`Null ~some:(fun n->`String(string_of_int n)) !called in
 let* asset=C.asset_ciphertext_params store (`List[`String "circle";`String "/index.html"]) ~current_epoch:99 ~reveal_sensitive_fields:false in
 Lwt.return(`Assoc["input",j;"expected",`Assoc["program_epoch",program_epoch;"program",result program;"view_epoch",view_epoch;"view",result view;"asset",result asset]])
module G=Octra_core.Rule_graph
let plans graph=[G.standard_activation graph;G.math_activation graph;G.object_cost_activation graph;G.fhe_work_activation_for_chain "octra-devnet-9871-cluster";G.proof_activation_for_chain "octra-devnet-9871-cluster";G.wasm_float_activation_for_chain "octra-devnet-9871-cluster"]
let graph j=
 let chain=Base64.decode_exn(member "chain" j|>to_string) in
 let plan=plans(G.create ~chain_id:chain ~root_at:(fun _->G.Missing)) in
 let root_at epoch=
  let kind=match member(string_of_int epoch)(member "roots" j) with `String v->v|_->member "default" j|>to_string in
  match kind with
  | "missing"->G.Missing|"bad"->G.Root "wrong-root"|"unreadable"->G.Unreadable "disk unavailable"
  | _->(match List.find_map(function Some p when p.G.anchor_epoch=epoch->Some p.anchor_state_root|_->None)plan with Some root->G.Root root|None->G.Missing) in
 G.create ~chain_id:chain ~root_at
let profile j=
 let epoch=member "epoch" j|>to_int in
 match Octra_vm.Contract_rpc.view_profile(graph j)~epoch with
 | Error fault->`Assoc["error",`String(Base64.encode_exn(G.fault_message fault))]
 | Ok p->let active v=`Bool(v=G.Active) in `Assoc["epoch",`String(string_of_int p.epoch);"point_ops",`Bool p.point_ops;"math",`Bool p.math;"object_cost",`Bool p.object_cost;"int_work",`Bool(p.int_work=Octra_vm.Int_work.Active);"fhe_work",active p.fhe_work;"proof_exec",active p.proof_exec;"wasm_float",active p.wasm_float]
let view store j=
 let* tree=Lwt_list.fold_left_s(fun tree e->T.Tree.add tree(e|>member "path"|>to_list|>List.map(fun x->Base64.decode_exn(to_string x)))(Base64.decode_exn(member "value" e|>to_string)))(T.Tree.empty())(member "entries" j|>to_list) in
 let* ()=S.commit_bulk store tree "Circle RPC view boundary" in
 let ledger=Octra_core.Ledger.create store in
 let profile ~epoch=Result.map_error(fun fault->R.err (-32005)(G.fault_message fault)None)(Octra_vm.Contract_rpc.view_profile(G.create ~chain_id:"local" ~root_at:(fun _->G.Missing))~epoch) in
 Octra_circle_runtime.Circle_exec.clear_wasm_view_storage_cache();Hashtbl.clear Octra_circle_runtime.Circle_program.loaded_cache;
 let* response=C.view_rpc ~authenticated:false ~trusted:[] ~profile ~store ~ledger (`List[member "circle" j;member "method" j;member "params" j]) in
 let found=match response with Ok v->v|Error e->`Assoc["error",`String e.R.message] in
 Lwt.return(`Assoc["input",j;"expected",`Assoc["root",`String(Irmin.Type.to_string T.Hash.t(T.Tree.hash tree));"found",found]])
let run store j=match member "kind" j|>to_string with
 | "profile"->Lwt.return(`Assoc["input",j;"expected",profile j])
 | "view"->view store j
 | _->clock store j
let ()=let inputs=Yojson.Safe.from_channel stdin|>to_list in
 let output=Lwt_main.run(let* store=S.open_store ~fresh:true "/tmp/circle-clock" in Lwt.finalize(fun()->Lwt_list.map_s(run store)inputs)(fun()->S.close store)) in
 Yojson.Safe.to_channel stdout(`List output);print_newline()
