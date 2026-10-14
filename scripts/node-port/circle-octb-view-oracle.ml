(* Native Circle views under Contract_rpc.make_view_ctx and an immutable tree. *)
let () = Octra_log._set_level Octra_log.FATAL
open Lwt.Syntax
open Yojson.Safe.Util
module C = Octra_core
module S = C.Store_irmin
module T = S.Store
module V = Octra_vm.Contract_vm
module R = Octra_vm.Contract_rpc
module P = Octra_circle_runtime.Circle_program
let raw v = Base64.decode_exn (to_string v)
let b64 v = `String (Base64.encode_exn v)
let mode j k = if member k j = `Bool true then C.Rule_graph.Active else C.Rule_graph.Prior
let run store input =
 let* tree = Lwt_list.fold_left_s (fun tree row -> T.Tree.add tree
   (member "path" row |> to_list |> List.map raw) (member "value" row |> raw))
   (T.Tree.empty ()) (member "entries" input |> to_list) in
 let root = Irmin.Type.to_string T.Hash.t (T.Tree.hash tree) in
 let snapshot:S.read_snapshot = {read_repo=store.S.repo;tree;state_root=root;commit_hash="";epoch_id=0L} in
 Octra_circle_runtime.Circle_exec.clear_wasm_view_storage_cache (); Hashtbl.clear P.loaded_cache;
 let profile:R.view_profile = {epoch=member "epoch" input |> to_int;
   point_ops=member "point" input |> to_bool;math=false;object_cost=false;
   int_work=(if member "integer_work" input = `Bool true then Octra_vm.Int_work.Active else Octra_vm.Int_work.Prior);
   fhe_work=mode input "fhe_work";proof_exec=mode input "proof";wasm_float=C.Rule_graph.Prior} in
 let ctx=R.make_view_ctx ~snapshot ~trusted:[] ~profile ~store ~ledger:(C.Ledger.create store) ~get_fhe_pubkey:(fun _ -> None) () in
 let circle=member "circle" input |> raw in
 let params=member "params" input |> raw |> Yojson.Safe.from_string |> to_list in
 let* receipt=Octra_circle_runtime.Circle_exec.execute_view_call ~snapshot ~ctx
   ~limit:(member "limit" input |> to_int) ~inspect_mode:C.Rule_graph.Active store circle
   (member "method" input |> raw) params (member "caller" input |> raw) in
 let* descriptor=P.describe ~snapshot ~inspect_mode:C.Rule_graph.Active store circle in
 let descriptor=match descriptor with Ok d -> `Assoc["ok",b64(Yojson.Safe.to_string(P.yojson_of_descriptor d))]
   | Error e -> `Assoc["error",b64 e] in
 let events=List.map(fun (e:V.event_record)->`Assoc["contract",b64 e.contract;"depth",`Int e.depth;
   "name",b64 e.event;"values",`List(List.map(fun v->b64(V.to_string v))e.values)])receipt.Octra_vm.Contract.events in
 let result=`Assoc["success",`Bool receipt.success;"effort",`Int receipt.effort_used;
   "result_json",b64(Yojson.Safe.to_string(Octra_vm.Receipt_view.return_json receipt.return_value));
   "error",(match receipt.error with None->`Null|Some e->b64 e);"events",`List events] in
 Lwt.return(`Assoc["input",input;"expected",`Assoc["root",`String root;"after",`String(Irmin.Type.to_string T.Hash.t(T.Tree.hash snapshot.tree));"receipt",result;"descriptor",descriptor]])
let () =
 let inputs=Yojson.Safe.from_channel stdin |> to_list in
 let rows=Lwt_main.run(let* store=S.open_store ~fresh:true "/tmp/circle-octb-view" in
   Lwt.finalize(fun ()->Lwt_list.map_s(run store) inputs)(fun ()->S.close store)) in
 Yojson.Safe.to_channel stdout (`List rows);print_newline ()
