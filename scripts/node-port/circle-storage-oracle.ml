(* Exercise the unmodified native storage guards, including Hashtbl traversal. *)
open Yojson.Safe.Util
module S = Octra_circle_runtime.Circle_runtime_storage
let bytes v = Base64.decode_exn (to_string v)
let b64 v = `String (Base64.encode_exn v)
let result = function Ok () -> `Null | Error (code,key,detail) -> `List [`String code;b64 key;b64 detail]
let table j =
  let t=Hashtbl.create ~random:false (j|>member "capacity"|>to_int) in
  List.iter (fun pair->match to_list pair with [k;v]->Hashtbl.replace t (bytes k) (bytes v)|_->assert false) (j|>member "pairs"|>to_list);
  List.iter (fun key->Hashtbl.remove t (bytes key)) (j|>member "remove"|>to_list);t
let keys t = `List (List.of_seq (Hashtbl.to_seq_keys t) |> List.map b64)
let run j = match j|>member "op"|>to_string with
| "write" -> result (S.validate_runtime_key_write (bytes (j|>member "key")) (bytes (j|>member "value")))
| "delete" -> result (S.validate_runtime_key_delete (bytes (j|>member "key")))
| "hash" -> `Int (Hashtbl.hash (bytes (j|>member "key")))
| "table" -> let t=table (j|>member "table") in `Assoc ["keys",keys t;"result",result (S.validate_runtime_storage_keys t)]
| "delta" -> let before=table (j|>member "before") and after=table (j|>member "after") in
  let proof_mode=if j|>member "active"|>to_bool then Octra_core.Rule_graph.Active else Octra_core.Rule_graph.Prior in
  `Assoc ["before",keys before;"after",keys after;"result",result (S.validate_runtime_storage_delta ~proof_mode before after)]
| _ -> failwith "unknown operation"
let () =
 let cases=Yojson.Safe.from_channel stdin |> to_list |> List.map (fun input -> `Assoc ["input",input;"expected",run input]) in
 Yojson.Safe.to_channel stdout (`List cases); print_newline ()
