(* SPDX-License-Identifier: BSD-3-Clause *)
(* Adapted native startup closures, Copyright (c) 2023-2026 Octra Labs. *)
(* Actual native storage checks between chain resume and finality retirement.
   Offline maintenance does not initialize wallet accounts or start services. *)
module Core = Octra_core
module Boot = Octra_node_runtime.Startup_node_boot_shell
module Recovery = Octra_node_runtime.Startup_recovery_shell
module Store = Octra_node_runtime.Startup_store_shell
module History = Octra_node_runtime.Startup_history_shell
module Process = Octra_node_runtime.Startup_process_shell
module SC = Core.Store_chaindata
module SI = Core.Store_irmin
module HM = Core.Head_manifest

let verify data_dir store chaindata =
  let exit_fatal () =
    failwith "native startup storage verification refused"
  in
  let get_meta key = Boot.run_s (SI.get_meta store key) in
  let chain_last_epoch () =
    match SC.last_epoch_id chaindata with
    | Ok value -> value
    | Error reason -> failwith reason
  in
  let total_tx_count = ref 0 in
  Recovery.run_atomic_recovery {
    skip_recovery = (fun () -> false);
    run_recovery = (fun () ->
      Boot.run_s
        (Core.Startup_recovery.recover ~data_dir ~chaindata ~store));
    txlog_position = (fun () -> SC.txlog_position chaindata);
    tx_count = (fun () -> SC.tx_count chaindata);
    set_total_tx_count = (fun count -> total_tx_count := count);
  };
  Store.run_integrity {
    head_state = (fun () ->
      match HM.load_result data_dir with
      | HM.Missing -> Store.Head_missing
      | HM.Corrupt reason -> Store.Head_corrupt reason
      | HM.Present head ->
        Store.Head_ready {
          epoch = head.HM.epoch_id;
          root = HM.ledger_state_root head;
        });
    store_root = (fun () -> Boot.run_s (SI.get_head_hash store));
    epoch_root = (fun epoch ->
      match Boot.run_s (SI.epoch_binding store epoch) with
      | Ok binding -> Some binding.SI.root
      | Error _ -> None);
    rollback_epoch = (fun epoch ->
      Boot.run_s (SI.rollback_to_epoch store epoch));
    verify_integrity = (fun () -> Boot.run_s (SI.verify_integrity store));
    save_state_root = (fun () -> Boot.run_s (SI.save_state_root store));
    exit_fatal;
  };
  Store.run_epoch_tags {
    list_epoch_tags = (fun () -> Boot.run_s (SI.list_epoch_tags store));
    last_epoch = (fun () -> get_meta "last_epoch");
    tag_epoch = (fun epoch -> Boot.run_s (SI.tag_epoch store epoch));
  };
  Recovery.run_reconciliation {
    irmin_last_epoch = (fun () ->
      Boot.meta_int ~default:(-1) (get_meta "last_epoch"));
    chain_last_epoch = (fun () ->
      Option.value ~default:(-1) (chain_last_epoch ()));
    skip_reconcile = (fun () -> false);
    exit_fatal;
  };
  History.run_startup_checks {
    int_value = (fun _ default -> default);
    first_epoch = (fun () ->
      match SC.first_history_epoch chaindata with
      | Ok epoch -> epoch
      | Error reason -> failwith reason);
    last_epoch = chain_last_epoch;
    status_at = (fun epoch -> SC.get_epoch_index_status chaindata epoch);
    marker_path = Filename.concat data_dir "chaindata/.reindex_in_progress";
    marker_exists = Sys.file_exists;
    irmin_stealth_counter = (fun () ->
      get_meta "stealth_counter"
      |> Option.map (Process.parse_int64 ~default:0L)
      |> Option.value ~default:0L);
    chaindata_next_txid = (fun () -> SC.next_txid chaindata);
    exit_fatal;
  }
