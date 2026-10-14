(* Test adapter only. Production compiler, contract engine, journal, storage,
   spawn/upgrade policy, and native Groth16 worker are used unchanged.
   Selects the EXISTING Active/Prior VM modes; it is not a chain or consensus fork. *)
module V = Octra_vm
module VM = V.Contract_vm
module S = Octra_core.Store_irmin
module J = V.Program_journal
open Yojson.Safe.Util

let read_file path = let channel = open_in_bin path in
  Fun.protect ~finally:(fun () -> close_in channel)
    (fun () -> really_input_string channel (in_channel_length channel))

let value_json = function
  | VM.VBool value -> `Bool value
  | VM.VInt value -> `String (Z.to_string value)
  | value -> `String (VM.to_string value)

let receipt_json (result : V.Contract.exec_result) = `Assoc [
  "success", `Bool result.success;
  "result", Option.fold ~none:`Null ~some:value_json result.return_value;
  "error", Option.fold ~none:`Null ~some:(fun text -> `String text) result.error;
  "effort", `Int result.effort_used;
  "events", `List (List.map (fun (event : VM.event_record) ->
    `Assoc ["name", `String event.event; "values", `List (List.map value_json event.values)]) result.events);
]

let param = function `String text -> text | value -> Yojson.Safe.to_string value
let optional key default json = match member key json with `Null -> default | value -> value

let () =
  (* Preserve a dedicated response channel; native logging uses stdout. *)
  let protocol = Unix.out_channel_of_descr (Unix.dup Unix.stdout) in
  Unix.dup2 Unix.stderr Unix.stdout;
  (match Octra_core.Pvac_verify_worker.classified_result_sync ~math:true Octra_core.Pvac_verify_protocol.Ping with
  | Ok () -> Printf.eprintf "native proof worker: ready\n%!"
  | Error error -> failwith (Octra_core.Pvac_verify_worker.verification_failure_message error));
  if Array.length Sys.argv <> 3 && Array.length Sys.argv <> 4 then failwith "expected VPN, factory AML paths and optional test store directory";
  let compile path = match V.Aml_source.compile ~loops:true ~syntax:V.Oct_gen.Source (read_file path) with
    | Ok program -> program | Error reason -> failwith reason in
  let vpn = compile Sys.argv.(1) in
  let factory = compile Sys.argv.(2) in
  let root = if Array.length Sys.argv = 4 then Sys.argv.(3) else
    Filename.concat (Filename.get_temp_dir_name ()) ("private-admin-store-" ^ string_of_int (Unix.getpid ())) in
  if not (Sys.file_exists root) then Unix.mkdir root 0o700;
  let store = Lwt_main.run (S.open_store (Filename.concat root "irmin")) in
  at_exit (fun () -> Lwt_main.run (S.close store));
  let persist journal =
    List.iter (fun (entry : J.deploy) ->
      Lwt_main.run (S.deploy_contract store ~address:entry.address ~code_hash:entry.code_hash
        ~version:entry.version ~owner:entry.owner ~ctype:entry.ctype ~admission:entry.admission ~bytecode_b64:entry.bytecode_b64);
      Lwt_main.run (S.save_contract_storage store entry.address entry.storage)) (J.deploys journal);
    List.iter (fun (address, storage) -> Lwt_main.run (S.save_contract_storage store address storage)) (J.storage_entries journal)
  in
  let balance = Hashtbl.create 16 in
  let context journal request =
    let mode = if optional "profile" (`String "active") request = `String "prior" then Octra_core.Rule_graph.Prior else Active in
    let rec ctx = {VM.default_ctx with
      point_ops = true; math = true; int_work = V.Int_work.Active;
      fhe_work = mode; proof_exec = mode; current_epoch = 2_000_000;
      get_balance = (fun address -> Option.value (Hashtbl.find_opt balance address) ~default:Z.zero);
      do_transfer = (fun from into amount ->
        if optional "fail_transfer" (`Bool false) request = `Bool true then false else
        let funds = Option.value (Hashtbl.find_opt balance from) ~default:Z.zero in
        if Z.sign amount < 0 || Z.compare funds amount < 0 then false else begin
          Hashtbl.replace balance from (Z.sub funds amount);
          Hashtbl.replace balance into (Z.add amount (Option.value (Hashtbl.find_opt balance into) ~default:Z.zero)); true
        end);
      deploy_contract = (fun deployer bytecode_raw nonce scope params ->
        V.Contract.deploy_internal ~journal ~ctx:{ctx with fhe_memory = scope.VM.memory; byte_work = scope.bytes}
          ~depth:scope.depth ~limit:(Option.value scope.limit ~default:1_000_000) ~params store ~deployer ~bytecode_raw ~nonce);
    } in ctx
  in
  let handle request =
    let journal = J.create () in
    let ctx = context journal request in
    match member "op" request |> to_string with
    | "deploy_factory" ->
      let caller = member "caller" request |> to_string in
      let address, result = V.Contract.deploy ~journal ~ctx store caller "CUSTOM" factory.code factory.octb 0 in
      if result.success then persist journal;
      `Assoc ["address", `String address; "receipt", receipt_json result]
    | "spawn" ->
      let address = member "factory" request |> to_string in
      let caller = member "caller" request |> to_string in
      let params = `String (Base64.encode_exn vpn.octb) :: (member "params" request |> to_list) in
      let result = V.Contract.execute_call ~journal ~ctx store address "deploy_vpn" params caller Z.zero in
      if result.success then persist journal;
      `Assoc ["receipt", receipt_json result]
    | "call" ->
      let address = member "address" request |> to_string in
      let method_name = member "method" request |> to_string in
      let caller = member "caller" request |> to_string in
      let params = member "params" request |> to_list in
      let saved = Hashtbl.copy balance in
      let value = optional "value" (`Int 0) request |> param |> Z.of_string in
      if Z.sign value < 0 then failwith "negative fixture attached value";
      if Z.sign value > 0 && not (ctx.do_transfer caller address value) then failwith "fixture caller unfunded";
      let result = V.Contract.execute_call ~journal ~ctx store address method_name params caller value in
      if result.success then persist journal else begin Hashtbl.reset balance; Hashtbl.iter (Hashtbl.replace balance) saved end;
      receipt_json result
    | "storage" ->
      let table = Lwt_main.run (S.load_contract_storage store (member "address" request |> to_string)) in
      `Assoc (Hashtbl.fold (fun key value result -> (key, `String value) :: result) table [])
    | "metadata" ->
      (match Lwt_main.run (S.get_contract_meta store (member "address" request |> to_string)) with
      | None -> `Null | Some meta -> `Assoc ["owner", `String meta.owner; "code_hash", `String meta.code_hash])
    | "upgrade" ->
      let address = member "address" request |> to_string in
      let meta = Option.get (Lwt_main.run (S.get_contract_meta store address)) in
      (match V.Contract.upgrade ~journal ~ctx store ~address ~caller:(member "caller" request |> to_string)
        ~expected_code_hash:meta.code_hash ~bytecode_raw:factory.octb with
      | Error reason -> `Assoc ["success", `Bool false; "error", `String reason]
      | Ok _ -> `Assoc ["success", `Bool true])
    | "fund_fixture" ->
      Hashtbl.replace balance (member "address" request |> to_string) (member "amount" request |> param |> Z.of_string);
      `Bool true
    | "balance" ->
      value_json (VM.VInt (Option.value (Hashtbl.find_opt balance (member "address" request |> to_string)) ~default:Z.zero))
    | "seed_nonce_fixture" ->
      let address = member "address" request |> to_string in
      let table = Lwt_main.run (S.load_contract_storage store address) in
      Hashtbl.replace table "admin_nonce" (member "nonce" request |> param);
      Lwt_main.run (S.save_contract_storage store address table); `Bool true
    | _ -> failwith "unknown test adapter operation"
  in
  let rec loop () = match input_line stdin with
    | line ->
      let response = try handle (Yojson.Safe.from_string line) with error ->
        `Assoc ["adapter_error", `String (Printexc.to_string error)] in
      output_string protocol (Yojson.Safe.to_string response ^ "\n"); flush protocol; loop ()
    | exception End_of_file -> ()
  in loop ()
