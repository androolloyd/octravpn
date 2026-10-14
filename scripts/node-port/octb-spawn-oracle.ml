(* SPDX-License-Identifier: BSD-3-Clause *)
(* Copyright (c) 2023-2026 Octra Labs <dev@octra.org> *)
let () = Octra_log._set_level Octra_log.FATAL
module V = Octra_vm.Contract_vm
module W = Octra_vm.Byte_work
open Yojson.Basic.Util
let text s = `String s
let bytes s = text (Base64.encode_exn s)
let raw j = Base64.decode_exn (to_string j)
let get j k default = match member k j with `Null -> default | v -> v
let flag j k = get j k (`Bool false) |> to_bool
let integer j k default = get j k (`Int default) |> to_int
let rows j k = get j k (`List []) |> to_list
let cap j : V.cap = {scope=raw (member "scope" j);kind=member "kind" j |> to_int;
  id=member "id" j |> to_int;rev=member "revision" j |> to_int}
let cap_json (c:V.cap) = `Assoc ["scope",bytes c.scope;"kind",`Int c.kind;"id",`Int c.id;"revision",`Int c.rev]
let value j = match to_assoc j with
 | ["int",v] -> V.VInt (Z.of_string (to_string v))
 | ["bool",v] -> V.VBool (to_bool v)
 | ["str",v] -> V.VString (raw v)
 | ["bytes",v] -> V.VBytes (raw v)
 | ["bytes32",v] -> V.VBytes32 (raw v)
 | ["u64",v] -> V.VU64 (Z.of_string (to_string v))
 | ["u128",v] -> V.VU128 (Z.of_string (to_string v))
 | ["u256",v] -> V.VU256 (Z.of_string (to_string v))
 | ["addr",v] -> V.VAddr (raw v)
 | ["cap",v] -> V.VCap (cap v)
 | _ -> failwith "fixture value"
let value_json v = let k,x = match v with
 | V.VInt n -> "int",text (Z.to_string n)
 | V.VBool b -> "bool",`Bool b
 | V.VString s -> "str",bytes s
 | V.VBytes s -> "bytes",bytes s
 | V.VBytes32 s -> "bytes32",bytes s
 | V.VU64 n -> "u64",text (Z.to_string n)
 | V.VU128 n -> "u128",text (Z.to_string n)
 | V.VU256 n -> "u256",text (Z.to_string n)
 | V.VAddr s -> "addr",bytes s
 | V.VCap c -> "cap",cap_json c
 | _ -> failwith "unexpected private handle" in `Assoc [k,x]
let kind = function
 | 0 -> V.StorageInt | 1 -> V.StorageBool | 2 -> V.StorageString
 | 3 -> V.StorageBytes | 4 -> V.StorageBytes32 | 5 -> V.StorageU64
 | 6 -> V.StorageU128 | 7 -> V.StorageU256 | 8 -> V.StorageAddr
 | _ -> failwith "fixture kind"
let pairs j = List.map (function `List [k;v] -> raw k,raw v | _ -> assert false) j
let bindings render_key render_value table =
 Hashtbl.to_seq table |> List.of_seq |> List.sort (fun (a,_) (b,_) -> compare a b)
 |> List.map (fun (k,v) -> `List [render_key k;render_value v]) |> fun xs -> `List xs
let budget case = if not (flag case "bytes") then None else
 let limits = match member "limits" case with
 | `List [k;v;c;w;a;u] -> W.limits ~key_bytes:(to_int k) ~value_bytes:(to_int v)
     ~copy_bytes:(to_int c) ~write_bytes:(to_int w) ~alloc_bytes:(to_int a) ~unit_bytes:(to_int u) |> Option.get
 | `Null -> W.consensus_limits | _ -> assert false in
 Some (W.create limits)
let run stepped case =
 let b = budget case in
 let host_calls = ref [] in
 let record j = host_calls := j :: !host_calls in
 let deploy parent code nonce (scope:V.call_scope) params =
  record (`List [text "spawn";bytes parent;bytes code;`Int nonce;`List (List.map value_json params);`Int (Option.value scope.limit ~default:1000000)]);
  if flag case "spawn_ok" then Ok V.{spawned_addr="oct" ^ String.make 44 '5';effort_used=integer case "spawn_effort" 0;
    events=[{contract=parent;depth=scope.depth;event="spawned";values=[VString "child\255"]}]}
  else Error "fixture refusal" in
 let ctx = {V.default_ctx with
  async_exec=flag case "async";
  fhe_work=(if flag case "fhe_work" then Octra_core.Rule_graph.Active else Octra_core.Rule_graph.Prior);
  deploy_contract=deploy;deploy_async=(fun parent code nonce scope params -> Lwt.return(deploy parent code nonce scope params));
  byte_work=b;point_ops=flag case "point";
  int_work=(if flag case "integer_work" then Octra_vm.Int_work.Active else Octra_vm.Int_work.Prior);
  current_epoch=123;epoch_time_ms=1791930000123L;tree_hash="fixture-tree";node_id="fixture-node";tx_hash="fixture-tx";
  get_balance=(fun addr -> record (`List [text "balance";bytes addr]);Z.of_int 123456);
  do_transfer=(fun from target amount -> record (`List [text "transfer";bytes from;bytes target;text (Z.to_string amount)]);flag case "transfer_ok");
  cap_live=(fun c -> record (`List [text "cap";cap_json c]);flag case "cap_live")} in
 let storage=Hashtbl.of_seq (List.to_seq (pairs (rows case "storage"))) in
 let kinds=List.map (function `List [key;tag] -> raw key,kind (to_int tag) | _ -> assert false) (rows case "kinds") in
 let st=V.create_state ~ctx ~limit:(integer case "limit" 1000000)
  ~strict_values:(flag case "strict") ~is_view:(flag case "view") ~storage_kinds:kinds
  ~depth:(integer case "depth" 0) ~byte_result:(if flag case "typed" then V.Typed_bytes else V.String_bytes)
  ~caller:("oct" ^ String.make 44 '2') ~origin:("oct" ^ String.make 44 '3') ~address:("oct" ^ String.make 44 '4')
  ~value:(Z.of_int 456) ~storage () in
 List.iter (function `List [index;v] -> st.regs.(to_int index) <- value v | _ -> assert false) (rows case "regs");
 List.iter (function `List [index;v] -> let i=to_int index in Hashtbl.replace st.memory.data i (value v);st.memory.size <- max st.memory.size (i+1) | _ -> assert false) (rows case "memory");
 st.effort_used <- integer case "used" 0;
 st.pc <- integer case "pc" 0;
 let code=match Octra_vm.Bytecode.decode ~active:true (raw (member "raw" case)) with Ok code -> Octra_vm.Contract.fix_jumps code | Error e -> failwith e in
 let ok=if flag case "async" then Lwt_main.run(V.run_async st code) else if not stepped then V.run st code else
   let rec loop () = match V.step st code with V.Running -> loop () | V.Finished -> true | V.Refused -> false in loop () in
 let registers=Array.to_list st.regs |> List.mapi (fun i v -> i,v)
   |> List.filter (function _,V.VInt z -> not (Z.equal z Z.zero) | _ -> true)
   |> List.map (fun (i,v) -> `List [`Int i;value_json v]) in
 let logs=List.rev !(st.logs) |> List.map (fun (e:V.event_record) ->
  `Assoc ["contract",bytes e.contract;"depth",`Int e.depth;"name",bytes e.event;"values",`List (List.map value_json e.values)]) in
 `Assoc ["ok",`Bool ok;"pc",`Int st.pc;"effort",`Int st.effort_used;"reverted",`Bool st.reverted;
  "output_ready",`Bool st.output_ready;"regs",`List registers;"memory",bindings (fun i -> `Int i) value_json st.memory.data;
  "memory_size",`Int st.memory.size;"storage",bindings bytes bytes st.storage;"blobs",bindings bytes bytes st.blobs;
  "events",`List logs;"closes",`List (List.map cap_json st.closes);"host_calls",`List (List.rev !host_calls);
  "budget",(match b with None -> `Null | Some b -> `List [`Int (W.remaining b);`Int (W.available b);`Int (W.event_left b)])]
let case j =
 let expected=run false j in
 if expected <> run true j then failwith ("native run/step mismatch: " ^ to_string (member "name" j));
 match j with `Assoc fields -> `Assoc (fields@["expected",expected]) | _ -> assert false
let () = let cases=Yojson.Basic.from_channel stdin |> to_list in
 Yojson.Basic.to_channel stdout (`List (List.map case cases));print_newline ()
