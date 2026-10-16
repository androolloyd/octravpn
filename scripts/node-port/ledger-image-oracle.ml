open Yojson.Safe.Util
module S = Octra_core.Store_irmin
module I = Octra_core.Ledger_image
let b64 raw = `String (Base64.encode_exn raw)
let run index input =
  let store = Lwt_main.run (S.open_store ~fresh:true (Printf.sprintf "/tmp/ledger-image-%d" index)) in
  store.S.batch_tree <- Some (S.Store.Tree.empty ());
  input |> member "rows" |> to_list |> List.iter (fun row ->
    let path = row |> member "path" |> to_list |> List.map (fun value -> value |> to_string |> Base64.decode_exn) in
    let value = row |> member "value" |> to_string |> Base64.decode_exn in
    Lwt_main.run (S.write store path value));
  Lwt_main.run (S.commit_epoch_batch store "ledger-image fixture");
  let selected = Lwt_main.run (S.Store.Head.get store.S.store) in
  let commit = Irmin.Type.to_string S.Store.Hash.t (S.Store.Commit.hash selected) in
  let write suffix format =
    let path = Printf.sprintf "/tmp/ledger-image-%d-%s.dat" index suffix in
    let report = Lwt_main.run (I.write ~format store ~commit ~path) |> Result.get_ok in
    let ch = open_in_bin path in
    let body = really_input_string ch (in_channel_length ch) in close_in ch;
    `Assoc ["image_b64", b64 body; "root", `String report.I.root;
      "records", `String (Int64.to_string report.records); "bytes", `String (Int64.to_string report.bytes);
      "pvac_hashes", `List (List.map (fun s -> `String s) report.pvac_hashes)] in
  let flat = write "flat" I.Flat in
  let shared = write "shared" I.Shared in
  Lwt_main.run (S.close store);
  `Assoc ["flat", flat; "shared", shared]
let () = Yojson.Safe.from_channel stdin |> to_list |> List.mapi run
  |> fun output -> print_endline (Yojson.Safe.to_string (`List output))
