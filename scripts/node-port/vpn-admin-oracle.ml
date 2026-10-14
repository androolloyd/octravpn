(* Existing VPN AML and public DEVELOPMENT proof; no credential or proving key. *)
module V = Octra_vm.Contract_vm
module R = Octra_core.Rule_graph
open Yojson.Basic.Util
let bytes s = `String (Base64.encode_exn s)
let cell = function `String s -> V.VString s | `Int n -> V.VInt (Z.of_int n) | _ -> failwith "parameter"
let render = function V.VBool b -> `Bool b | V.VInt n -> `String (Z.to_string n) | v -> `String (V.to_string v)
let storage table = Hashtbl.to_seq table |> List.of_seq |> List.sort compare
 |> List.map (fun (k,v) -> `List [bytes k;bytes v]) |> fun rows -> `List rows
let run j =
 let program = match Octra_vm.Aml_source.compile ~loops:true ~syntax:Octra_vm.Oct_gen.Source (member "source" j |> to_string) with
  | Ok program -> program | Error e -> failwith e in
 let committed = ref (Hashtbl.create 0) in
 let cases = member "calls" j |> to_list |> List.map (fun call ->
  let ctx = {V.default_ctx with proof_exec=R.Active;fhe_work=R.Active;math=true;async_exec=true;
   point_ops=true;int_work=Octra_vm.Int_work.Active; current_epoch=2000000} in
  let st = V.create_state ~ctx ~limit:1000000 ~caller:"relayer" ~origin:"relayer"
   ~address:(member "program" call |> to_string) ~value:Z.zero ~storage:(Hashtbl.copy !committed) () in
  Hashtbl.replace st.memory.data 999 (V.VString (if member "method" call = `String "constructor" then "constructor" else "call"));
  Hashtbl.replace st.memory.data 1000 (cell (member "method" call));
  List.iteri (fun i p -> Hashtbl.replace st.memory.data (1001+i) (cell p)) (member "params" call |> to_list);
  let ok = Lwt_main.run (V.run_async st (Octra_vm.Contract.fix_jumps program.code)) in
  if ok then committed := Hashtbl.copy st.storage;
  `Assoc ["call",call;"expected",`Assoc ["ok",`Bool ok;"effort",`Int st.effort_used;"result",render st.regs.(0);
   "storage",storage !committed;"events",`List (List.rev !(st.logs) |> List.map(fun (e:V.event_record) -> `List[bytes e.event;`List(List.map(fun v->bytes(V.to_string v))e.values)]))]]) in
 `Assoc ["bytecode",bytes program.octb;"cases",`List cases]
let () =
 if Sys.command "opam exec -- dune build bin/octra_pvac_worker.exe >&2" <> 0 then failwith "native worker build";
 Unix.putenv "OCTRA_PVAC_VERIFY_WORKER" "_build/default/bin/octra_pvac_worker.exe";
 Yojson.Basic.from_channel stdin |> run |> Yojson.Basic.to_channel stdout; print_newline ()
