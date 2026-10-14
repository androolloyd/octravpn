(* Native storage hash oracle; no node source modifications. *)
open Lwt.Syntax
module S = Octra_core.Store_irmin.Store
module Schema = Irmin.Schema.KV(Irmin.Contents.String)
module H = Schema.Hash
module K = Irmin.Key.Of_hash(H)
module N = Schema.Node(K)(K)
module C = Schema.Commit(K)(K)
let field key json = Yojson.Safe.Util.member key json
let string = Yojson.Safe.Util.to_string
let bytes key json = Base64.decode_exn (string (field key json))
let array = Yojson.Safe.Util.to_list
let preimage typ value =
  let buffer = Buffer.create 256 in
  Irmin.Type.(unstage (pre_hash typ)) value (Buffer.add_string buffer);
  Buffer.contents buffer
let result raw = `Assoc ["preimage", `String (Base64.encode_exn raw);
  "hash", `String (Irmin.Type.to_string H.t (H.hash (fun f -> f raw)))]
let root tree = `String (Irmin.Type.to_string S.Hash.t (S.Tree.hash tree))
let path operation = field "path" operation |> array |> List.map (fun value -> Base64.decode_exn (string value))
let run json = match string (field "op" json) with
| "contents" -> Lwt.return (result (preimage Irmin.Contents.String.t (bytes "value" json)))
| "step" -> Lwt.return (result (preimage Irmin.Type.string (bytes "value" json)))
| "node" ->
  let entries = field "entries" json |> array |> List.map (fun entry ->
    let hash = H.unsafe_of_raw_string (bytes "hash" entry) in
    bytes "name" entry, (if string (field "kind" entry) = "node" then `Node hash else `Contents (hash, ()))) in
  Lwt.return (result (preimage N.t (N.of_list entries)))
| "commit" ->
  let node = H.unsafe_of_raw_string (bytes "node" json) in
  let parents = field "parents" json |> array |> List.map (fun p -> H.unsafe_of_raw_string (Base64.decode_exn (string p))) in
  let info = Schema.Info.v ~author:(bytes "author" json) ~message:(bytes "message" json)
    (Int64.of_string (string (field "date" json))) in
  Lwt.return (result (preimage C.t (C.v ~info ~node ~parents)))
| "tree" ->
  let rec apply tree roots = function
  | [] -> Lwt.return (`List (List.rev roots))
  | operation :: rest ->
    let* tree = match string (field "op" operation) with
    | "set" -> S.Tree.add tree (path operation) (bytes "value" operation)
    | "remove" -> S.Tree.remove tree (path operation)
    | _ -> failwith "unknown tree operation" in
    apply tree (root tree :: roots) rest in
  let empty = S.Tree.empty () in
  apply empty [root empty] (field "operations" json |> array)
| _ -> failwith "unknown oracle operation"
let () =
  let inputs = Yojson.Safe.from_channel stdin |> array in
  let outputs = Lwt_main.run (Lwt_list.map_s (fun input ->
    let* expected = run input in Lwt.return (`Assoc ["input", input; "expected", expected])) inputs) in
  Yojson.Safe.to_channel stdout (`List outputs); print_newline ()
