let () =
  try
    if Array.length Sys.argv <> 4 then failwith "usage: native-history-export OFFLINE_DATA_DIR AFTER_EPOCH LIMIT";
    let result = Lwt_main.run (Native_history_export.read Sys.argv.(1)
      (int_of_string Sys.argv.(2)) (int_of_string Sys.argv.(3))) in
    print_endline result
  with error ->
    Printf.eprintf "native history export refused: %s\n%!" (Printexc.to_string error);
    exit 2
