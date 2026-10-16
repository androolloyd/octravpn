(* Native Irmin read-proof oracle. No node source instrumentation. *)
open Lwt.Syntax
open Yojson.Safe.Util
module I = Octra_core.Store_irmin
module S = I.Store
module P = S.Tree.Proof
let raw j = Base64.decode_exn (to_string j)
let encoded s = `String (Base64.encode_exn s)
let path j = to_list j |> List.map raw
let expected root path proof =
  try match I.verify_merkle_proof_det ~ledger_state_root:root ~path ~proof with
    | Ok value -> `Assoc ["ok", (match value with None -> `Null | Some v -> encoded v)]
    | Error error -> `Assoc ["error", `String error]
  with error -> `Assoc ["error", `String (Printexc.to_string error)]
let check root path proof =
  `Assoc ["root", `String root; "path", `List (List.map encoded path);
          "proof", `String proof; "expected", expected root path proof]
let hash p = match P.before p with `Node h | `Contents (h, _) -> h
let rec reverse = function
 | P.Node entries -> P.Node (List.rev_map (fun (s,t) -> s,reverse t) entries)
 | state -> state
let case index input =
 let* store = I.open_store ~fresh:true ~sync:false (Printf.sprintf "/tmp/irmin-proof-%d" index) in
 let* tree = Lwt_list.fold_left_s (fun tree entry ->
    S.Tree.add tree (member "path" entry |> path) (member "value" entry |> raw))
    (S.Tree.empty ()) (member "entries" input |> to_list) in
 let* () = I.commit_bulk store tree "native proof fixture" in
 let* key = I.tree_key store tree in
 let key = Option.get key in
 let query = member "query" input |> path in
 let* proof, _ = S.Tree.produce_proof store.repo key (fun tree ->
    let* value = S.Tree.find tree query in Lwt.return (tree,value)) in
 let root = Irmin.Type.to_string S.Hash.t (S.Tree.hash tree) in
 let bytes = I.proof_bin proof in
 let encoded = Base64.encode_exn bytes in
 let checks = List.map (fun q -> check root (path q) encoded) (member "reads" input |> to_list) in
 let checks = check root query encoded :: checks in
 let checks = if member "adversarial" input = `Bool false then checks else
   let mutated = [
     Base64.encode_exn (bytes ^ "x");
     Base64.encode_exn (String.sub bytes 0 (String.length bytes - 1));
     Base64.encode_exn (String.mapi (fun i c -> if i = String.length bytes - 1 then Char.chr (Char.code c lxor 1) else c) bytes);
     "!"; ""; encoded ^ "====";
   ] in
   let replace state = P.v ~before:(P.before proof) ~after:(P.after proof) state |> I.proof_bin |> Base64.encode_exn in
   let alternatives = [P.Blinded_node (hash proof); reverse (P.state proof); P.Node [];
     P.Node ["duplicate", P.Contents ("one",()); "duplicate",P.Contents ("two",())]] in
   let checks = List.map (check root query) (mutated @ List.map replace alternatives) @ checks in
   check (String.make 128 '0') query encoded :: checks in
 let* () = I.close store in
 Lwt.return (`Assoc ["input",input;"checks",`List checks])
let () =
 let inputs = Yojson.Safe.from_channel stdin |> to_list in
 let results = Lwt_main.run (Lwt_list.mapi_s case inputs) in
 Yojson.Safe.to_channel stdout (`List results); print_newline ()
