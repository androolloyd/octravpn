(* SPDX-License-Identifier: BSD-3-Clause *)
(* Copyright (c) 2023-2026 Octra Labs <dev@octra.org> *)
module V = Octra_vm.Contract_vm
module R = Octra_core.Rule_graph
open Yojson.Basic.Util
let raw j = Base64.decode_exn (to_string j)
let bytes s = `String (Base64.encode_exn s)
let flag j k = member k j = `Bool true
let mode j k = if flag j k then R.Active else R.Prior
let value = function
 | `Assoc ["int", `Int v] -> V.VInt (Z.of_int v)
 | `Assoc ["str", v] -> V.VString (raw v)
 | `Assoc ["bytes", v] -> V.VBytes (raw v)
 | `Assoc ["addr", v] -> V.VAddr (raw v)
 | _ -> failwith "fixture value"
let render = function
 | V.VInt n -> `Assoc ["int", `String (Z.to_string n)]
 | V.VBool v -> `Assoc ["bool", `Bool v]
 | _ -> failwith "unexpected output"
let run stepped j =
 let budget = if flag j "bytes" then Some (Octra_vm.Byte_work.create Octra_vm.Byte_work.consensus_limits) else None in
 let ctx = {V.default_ctx with byte_work=budget;proof_exec=mode j "proof_exec";
  fhe_work=mode j "fhe_work";math=flag j "math";async_exec=flag j "async"} in
 let state = V.create_state ~ctx ~limit:(member "limit" j |> to_int)
  ~is_view:(flag j "view") ~strict_values:(flag j "strict")
  ~caller:"sender" ~origin:"sender" ~address:"program" ~value:Z.zero ~storage:(Hashtbl.create 0) () in
 List.iteri (fun i v -> state.regs.(i+1) <- value v) (member "args" j |> to_list);
 let program = [|V.GROTH16_VERIFY_BN254 (0,1,2,3); V.STOP|] in
 Unix.putenv "OCTRA_PVAC_VERIFY_WORKER" (if flag j "unavailable" then "/missing-worker" else "_build/default/bin/octra_pvac_worker.exe");
 let result = try
   let ok = if flag j "async" then Lwt_main.run (V.run_async state program)
    else if not stepped then V.run state program else
     let rec loop () = match V.step state program with V.Running -> loop () | V.Finished -> true | V.Refused -> false in loop () in
   `Bool ok
  with Octra_core.Exec_resource.Unavailable _ -> `String "unavailable" in
 `Assoc ["ok",result;"pc",`Int state.pc;"effort",`Int state.effort_used;
  "reverted",`Bool state.reverted;"output_ready",`Bool state.output_ready;"result",render state.regs.(0);
  "events",`List (List.rev !(state.logs) |> List.map (fun (e:V.event_record) ->
   `List [bytes e.event;`List (List.map (fun v -> bytes (V.to_string v)) e.values)]));
  "budget",(match budget with None -> `Null | Some b -> `List [`Int (Octra_vm.Byte_work.remaining b);`Int (Octra_vm.Byte_work.available b);`Int (Octra_vm.Byte_work.event_left b)])]
let case j =
 let expected = run false j in
 if expected <> run true j then failwith "native step mismatch";
 match j with `Assoc fields -> `Assoc (fields@["expected",expected]) | _ -> assert false
let () =
 if Sys.command "opam exec -- dune build bin/octra_pvac_worker.exe >&2" <> 0 then failwith "native worker build";
 Zk_ffi.initialize ();
 Yojson.Basic.from_channel stdin |> to_list |> List.map case |> fun cases ->
 Yojson.Basic.to_channel stdout (`List cases); print_newline ()
