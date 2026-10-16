open Octra_core
open Yojson.Safe.Util
let blob s = `String (Base64.encode_exn s)
let decode j key = j |> member key |> to_string |> Base64.decode_exn
let node j = match Node.of_yojson (Yojson.Safe.from_string (decode j "node_b64")) with
  | Ok n -> n | Error e -> failwith e
let tree_bytes t = blob (Tree.to_yojson t |> Yojson.Safe.to_string)
let run j =
  let n = node j in
  match j |> member "operation" |> to_string with
  | "node" -> `Assoc [
      "encoded_b64", blob (Node.to_yojson n |> Yojson.Safe.to_string);
      "hash", `String (Node.hash n);
      "score", `String (string_of_float (Node.score n.Node.metrics));
      "signature", `String (Node.sign n (Base64.encode_exn (String.make 32 '\009')))]
  | "tree" ->
      let t = Tree.create ~epoch_id:(j |> member "epoch" |> to_string |> int_of_string)
          ~parent_commit:"prior\000commit" in
      let first = Tree.add_node t n in
      let duplicate = Tree.add_node t n in
      Tree.add_commit_signature t "z" "first";
      Tree.add_commit_signature t "a" "second";
      Tree.add_commit_signature t "z" "ignored";
      let before = tree_bytes t in
      let finalized = Tree.finalize t "validator-final" [] in
      let frozen = tree_bytes finalized in
      let child = { n with Node.id = "child"; parent = Some (Node.hash n) } in
      let child_added = Tree.add_node t child in
      let root = { n with Node.id = "later-root"; parent = None } in
      let root_added = Tree.add_node t root in
      `Assoc ["first", `Bool first; "duplicate", `Bool duplicate;
        "child", `Bool child_added; "root", `Bool root_added;
        "before_b64", before; "final_b64", frozen;
        "shared_final_b64", tree_bytes finalized; "after_b64", tree_bytes t;
        "final_hash", `String (Tree.hash finalized);
        "original_roots", `Int (Tree.root_count t);
        "final_roots", `Int (Tree.root_count finalized)]
  | _ -> failwith "unknown legacy operation"
let () = Yojson.Safe.from_channel stdin |> to_list |> List.map run
  |> fun cases -> print_endline (Yojson.Safe.to_string (`List cases))
