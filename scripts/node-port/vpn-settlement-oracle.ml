(* Production AML bodies plus isolated security-method fragments. Transfers are
   recorded, explicit successful callbacks; this is not a funded ledger gate. *)
module V = Octra_vm.Contract_vm
module R = Octra_core.Rule_graph
open Yojson.Basic.Util
let bytes raw = `String (Base64.encode_exn raw)
let storage table = Hashtbl.to_seq table |> List.of_seq |> List.sort compare
  |> List.map (fun (key,value) -> `List [bytes key;bytes value]) |> fun rows -> `List rows
let render = function V.VBool value -> `Bool value | value -> `String (V.to_string value)
let run input =
 let cases = member "methods" input |> to_list |> List.map (fun method_json ->
  let program = match Octra_vm.Aml_source.compile ~loops:true ~syntax:Octra_vm.Oct_gen.Source
    (member "source" method_json |> to_string) with Ok program -> program | Error reason -> failwith reason in
  let code = Octra_vm.Contract.fix_jumps program.code in
  let name = member "method" method_json |> to_string in
  let transfers = ref [] in
  let ctx = {V.default_ctx with proof_exec=R.Active;fhe_work=R.Active;math=true;async_exec=true;
   point_ops=true;int_work=Octra_vm.Int_work.Active;current_epoch=2000000;
   do_transfer=(fun sender recipient amount ->
    transfers := `List [bytes sender;bytes recipient;`String (Z.to_string amount)] :: !transfers; true)} in
  let caller = "oct" ^ String.make 44 '1' in
  let state = V.create_state ~ctx ~limit:5000000 ~caller ~origin:caller
   ~address:"program" ~value:Z.zero ~storage:(Hashtbl.create 0) () in
  Hashtbl.replace state.memory.data 999 (V.VString "call");
  Hashtbl.replace state.memory.data 1000 (V.VString name);
  let ok = Lwt_main.run (V.run_async state code) in
  `Assoc ["input",`Assoc ["method",`String name;"refusal",member "refusal" method_json;
    "fragment",member "fragment" method_json];
   "bytecode",bytes program.octb;"expected",`Assoc ["ok",`Bool ok;"effort",`Int state.effort_used;
   "result",render state.regs.(0);"storage",storage state.storage;
   "transfers",`List (List.rev !transfers);
   "events",`List (List.rev !(state.logs) |> List.map(fun (event:V.event_record) ->
      `List [bytes event.event;`List (List.map(fun value -> bytes(V.to_string value)) event.values)]))]]) in
 `List cases
let () = Yojson.Basic.from_channel stdin |> run |> Yojson.Basic.to_channel stdout; print_newline ()
