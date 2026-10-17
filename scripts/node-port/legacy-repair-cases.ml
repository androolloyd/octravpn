(* SPDX-License-Identifier: BSD-3-Clause *)
(* Adapted native storage fixtures, Copyright (c) 2023-2026 Octra Labs. *)
(* Genuine native physical legacy stores; no compiled production body changes.
   These legacy finality entries are storage fixtures, not network certificates. *)
module C = Recovery_case
module Fork = Octra_core.Fork_head_repair
module Plan = Octra_core.Fork_repair_log
module J = Octra_core.Commit_journal
module FL = Octra_consensus.Finality_log
module Boot = Octra_node_runtime.Fork_repair_boot
module Journal = Octra_node_runtime.Consensus_finality_journal
let unwrap = function Ok value -> value | Error reason -> failwith reason
let head dir = Option.get (C.HM.load dir)
let write_finality dir (value:C.HM.t) =
 FL.write dir (FL.make ~height:value.epoch_id ~round:0 ~proposal_id:(C.hash '1')
   ~tx_list_hash:(C.hash '2') ~state_root:value.state_root ~creator_addr:"legacy-fixture"
   ~txid_hi:value.txid_hi ~ts:0. ())
let prepare dir =
 Unix.mkdir dir 0o700;
 let base,_ = C.prepare dir in
 J.append dir (J.Prepare {commit_id=base.commit_id;prev_generation=(-1);epoch_id=0;
   planned_txid_hi=base.txid_hi;planned_state_root=base.state_root;ts=0.});
 J.append dir (J.Commit {commit_id=base.commit_id;generation=0;ts=0.});
 write_finality dir base;
 C.with_stores dir (fun chain store ->
  Lwt_main.run (C.SI.tag_epoch store 0);
  Lwt_main.run (C.SI.begin_epoch_batch store);
  Lwt_main.run (C.SI.set_meta store "last_epoch" "1");
  Lwt_main.run (C.SI.set_meta store "current_epoch" "2");
  Lwt_main.run (C.SI.commit_epoch_batch store "unjournaled empty legacy epoch");
  let ledger=Option.get (Lwt_main.run (C.SI.get_head_hash store)) in
  let epoch_hash,root=C.Eic.next_root ~prev:(Option.get base.epoch_index_root) ~epoch_id:1 [] in
  let state_root=C.Eic.folded_state_root ~ledger_state_root:ledger ~epoch_index_root:root in
  C.SC.begin_batch chain;
  C.SC.set_epoch chain {C.EL.empty_epoch_header with id=1;state_root;
    prev_state_root=base.state_root;parent_commit=Option.get base.irmin_commit;
    start_txid=Int64.succ base.txid_hi;tx_count=0};
  C.SC.set_epoch_index_commitment chain ~epoch_id:1 ~epoch_hash ~root;
  C.SC.commit_batch chain;C.SC.fsync chain;
  let source={base with C.HM.epoch_id=1;generation=1;state_root;ledger_state_root=Some ledger;
    irmin_commit=Lwt_main.run (C.SI.get_commit_hash store);epochlog_off=Some(C.SC.epochlog_offset chain);
    commit_id="legacy-empty-one";epoch_index_hash=Some epoch_hash;epoch_index_root=Some root} in
  C.HM.atomic_write dir source;
  write_finality dir source;
  let result=Lwt_main.run (Fork.stage_empty ~data_dir:dir ~store ~chaindata:chain ~target:0 ~root:base.state_root) in
  C.expect "native empty legacy fixture was not staged" (match result with Fork.Staged _ ->true|_->false));
 (* Real native future signing floor, mark and serialized vote survive repair. *)
 let votes_native=Octra_consensus.C_vote_log.disk ~data_dir:dir in
 ignore(unwrap(Octra_consensus.C_vote_log.set_floor votes_native ~through_epoch:99L));
 ignore(unwrap(Octra_consensus.C_vote_log.set_round_mark votes_native ~epoch_id:100L ~round:7));
 ignore(unwrap(Octra_consensus.C_vote_log.keep votes_native Octra_consensus.C_types.{
   chain_id="legacy-repair-fixture";epoch_id=100L;round=7;vote_type=Precommit;
   proposal_id=String.make 32 '3';validator=String.make 32 '4';signature=String.make 64 '5'}));
 (* An unrelated opaque local lock sentinel is also preserved, not interpreted. *)
 let votes=Filename.concat dir "consensus" in Unix.mkdir votes 0o700;
 List.iter (fun (name,bytes)->let f=open_out_bin (Filename.concat votes name) in output_string f bytes;close_out f)
  ["vote_floor","99\n";"round_mark","retained future round\n";"pending.lock","opaque retained lock\n"]
let finish dir =
 unwrap (Boot.run Boot.{read_plan=(fun()->Fork.read_plan dir);head=(fun()->C.HM.load dir);
  finality_at=(fun target->FL.find (FL.index dir) target);journal_committed=(fun()->Journal.committed dir);
  committed_for=(fun entry->Journal.committed_for ~chain_id:"legacy-repair-fixture" ~entry dir);
  rewind_journal=(fun entry->Journal.rewind_committed ~chain_id:"legacy-repair-fixture" ~entry dir);
  drop_after=FL.drop_after dir;clear=(fun()->Fork.clear dir)})
let phase ?(crash=false) dir name = C.with_stores dir (fun chain store ->
 (match name with
 | "stage" -> ()
 | "pack" -> ignore(unwrap(Lwt_main.run(C.SI.rollback_to_epoch store 0)))
 | "store" -> ignore(unwrap(Lwt_main.run(Fork.resume_store ~data_dir:dir ~store)))
 | "chain" -> ignore(unwrap(Lwt_main.run(Fork.resume_store ~data_dir:dir ~store)));
   ignore(unwrap(Fork.resume_chain ~data_dir:dir ~chaindata:chain))
 | "trim" -> ignore(unwrap(Lwt_main.run(Fork.resume_store ~data_dir:dir ~store)));
   ignore(unwrap(Fork.resume_chain ~data_dir:dir ~chaindata:chain));ignore(FL.drop_after dir 0)
 | "finish" -> ignore(unwrap(Lwt_main.run(Fork.resume_store ~data_dir:dir ~store)));
   ignore(unwrap(Fork.resume_chain ~data_dir:dir ~chaindata:chain));
   Legacy_repair_storage.verify dir store chain;ignore(finish dir)
 | _ -> failwith "unknown native fixture phase");
 if crash then begin Unix.kill(Unix.getpid())Sys.sigkill;Unix._exit 99 end)
let inspect dir = C.with_stores dir (fun chain store ->
 let current=head dir in
 let root=Option.get(Lwt_main.run(C.SI.get_head_hash store)) in
 let tags=Lwt_main.run(C.SI.list_epoch_tags store) in
 let commit=Option.get(Lwt_main.run(C.SI.get_commit_hash store)) in
 let bindings=List.map(fun epoch->let binding=unwrap(Lwt_main.run(C.SI.epoch_binding store epoch))in
   `Assoc["epoch",`Int epoch;"root",`String binding.root;"commit",`String binding.commit])tags in
 `Assoc["head",Yojson.Safe.from_string(C.HM.to_json current);"chain_head",`Int(Option.get(unwrap(C.SC.last_epoch_id chain)));
  "ledger_root",`String root;"irmin_commit",`String commit;"bindings",`List bindings;"next_txid",`String(Int64.to_string(C.SC.next_txid chain));
  "epochlog_offset",`Int(C.SC.epochlog_offset chain);"tags",`List(List.map(fun n->`Int n)tags);
  "plan_present",`Bool(Sys.file_exists(Plan.path dir));
  "finality",`List(List.map(fun e->`Int e.FL.height)(FL.read dir));
  "target_tx_present",`Bool(C.SC.get_tx_by_hash chain (C.hash 'a')<>None)])
let mutate dir name =
 let selected=Option.get(unwrap(Fork.read_plan dir)) in
 let path=Plan.path dir in
 let change plan=Plan.write dir plan in
 match name with
 | "protected-prepare" -> J.append dir(J.Prepare {commit_id="late";prev_generation=0;epoch_id=1;
   planned_txid_hi=selected.head.txid_hi;planned_state_root=selected.source.state_root;ts=0.})
 | "protected-aborted" -> J.append dir(J.Prepare {commit_id="late";prev_generation=0;epoch_id=1;
   planned_txid_hi=selected.head.txid_hi;planned_state_root=selected.source.state_root;ts=0.});
   J.append dir(J.Abort{commit_id="late";reason="aborted but still protected";ts=0.})
 | "protected-commit" -> J.append dir(J.Commit{commit_id="late";generation=1;ts=0.})
 | "torn-journal" -> let f=open_out_gen[Open_wronly;Open_append;Open_binary]0o600(J.path dir)in output_string f "{";close_out f
 | "missing-finality" -> Unix.unlink(FL.path dir)
 | "bad-finality-root" -> FL.replace dir [{(List.hd(FL.read dir))with FL.state_root=C.hash 'f'}]
 | "bad-finality-txid" -> FL.replace dir [{(List.hd(FL.read dir))with FL.txid_hi=99L}]
 | "bad-index" -> change {selected with head={selected.head with epoch_index_root=Some(C.hash 'f')}}
 | "bad-txlog" -> change {selected with head={selected.head with txlog_off=Some(1+Option.get selected.head.txlog_off)}}
 | "bad-offset" -> change {selected with head={selected.head with epochlog_off=Some(1+Option.get selected.head.epochlog_off)}}
 | "missing-tag" -> C.with_stores dir(fun _ store->ignore(Lwt_main.run(C.SI.drop_epoch_tags_after store (-1))))
 | "source-changed" -> C.HM.atomic_write dir {selected.source with C.HM.ts=1.}
 | "orphan-staged" -> Unix.rename path (Plan.staged_path dir)
 | "corrupt-plan" -> let f=open_out_bin path in output_string f "{";close_out f
 | _ -> failwith "unknown native mutation"
let certify dir =
 let module T=Octra_consensus.C_types in
 let module H=Octra_consensus.C_hash in
 let selected=Option.get(unwrap(Fork.read_plan dir))in
 let key n=Mirage_crypto_ec.Ed25519.priv_of_octets(String.make 32(Char.chr n))|>Result.get_ok in
 let public n=Mirage_crypto_ec.Ed25519.(pub_to_octets(pub_of_priv(key n)))in
 let address n=Octra_core.Crypto.Address.address_from_pubkey(Base64.encode_exn(public n))in
 let validators=T.make_validator_set(List.init 4(fun i->T.{address=address(i+1);pubkey=public(i+1)}))in
 let certificate (value:C.HM.t) previous : T.finalize =
  let header:T.epoch_header={proto_version=T.proto_version_parent_legacy;
   chain_id="legacy-repair-fixture";epoch_id=Int64.of_int value.epoch_id;
   prev_state_root=previous;tx_list_hash=Octra_consensus.C_engine.tx_list_hash_for_header
     (if value.epoch_id=0 then [Fork.hex_raw(C.hash 'a')] else []);receipt_root=H.receipt_root[];
   proposed_state_root=Fork.hex_raw value.state_root;parent_commit_hash=H.parent_commit_hash_opt None;
   creator_addr=address 1;txid_hi=value.txid_hi;ts=value.ts}in
  let proposal_id=H.proposal_id header in
  let votes=List.init 3(fun i->let id=i+1 in
   let vote:T.vote={chain_id=header.chain_id;epoch_id=header.epoch_id;round=0;vote_type=T.Precommit;
    proposal_id;validator=address id;signature=""}in
   {vote with T.signature=Mirage_crypto_ec.Ed25519.sign ~key:(key id)(H.vote_sign_bytes vote)})in
  T.{chain_id=header.chain_id;epoch_id=header.epoch_id;commit_round=0;
   header;proposal_id;precommits=votes;parent_commit=None}in
 let target=certificate selected.head(String.make 32 '\000')in
 let source=certificate selected.source(Fork.hex_raw selected.target_root)in
 (* Public staging checks the existing finality entry before writing. Replace
    the fixture-only unsigned entries with the genuine certificates first. *)
 FL.replace dir [FL.of_finalize target;FL.of_finalize source];
 (match Journal.seed ~chain_id:target.chain_id ~validator_set:validators ~finalize:target dir with
 | Ok _ -> ()
 | Error Journal.Seed_pending -> failwith "target certificate seed is pending"
 | Error (Journal.Seed_invalid reason | Journal.Seed_conflict reason | Journal.Seed_io reason) ->
   failwith ("target certificate seed refused: " ^ reason));
 let bundle:Journal.bundle={tx_hashes=[];txs=[];receipts_json=[]}in
 let source=Journal.stage dir ~chain_id:source.chain_id ~validator_set:validators ~bundle source in
 Journal.promote_applied dir ~epoch:source.epoch_id ~state_root:source.header.proposed_state_root;
 ignore(unwrap(Journal.committed_for ~chain_id:target.chain_id ~entry:(FL.of_finalize target) dir));
 ignore(unwrap(Journal.committed_for ~chain_id:source.chain_id ~entry:(FL.of_finalize source) dir))
let tamper_qc dir =
 let chain_id="legacy-repair-fixture"in
 let record=match Journal.read_committed_epoch ~chain_id ~epoch:0L dir with
 | Journal.Valid record -> record
 | Journal.Missing -> failwith "target certificate fixture is missing"
 | Journal.Invalid reason -> failwith ("target certificate fixture is invalid: " ^ reason)in
 let finalize=record.Journal.finalize in
 let first=List.hd finalize.precommits in
 let altered={first with Octra_consensus.C_types.signature=String.make 64 '0'}in
 let finalize={finalize with Octra_consensus.C_types.precommits=altered::List.tl finalize.precommits}in
 (* Deliberate fixture corruption, not a production persistence adapter: keep
    every native JSON field except the encoded signature-bearing Finalize. *)
 let path=Filename.concat(Filename.concat(Filename.concat dir "finality")"committed")"0.json"in
 let fields=match Yojson.Safe.from_file path with `Assoc fields->fields|_->failwith "target proof is not an object"in
 C.expect "target proof finalize is ambiguous" (List.length(List.filter(fun(name,_)->name="finalize")fields)=1);
 let encoded=Base64.encode_exn(Octra_consensus.C_codec.encode_finalize finalize)in
 let changed=`Assoc(List.map(fun(name,value)->name,if name="finalize"then `String encoded else value)fields)in
 let output=open_out_bin path in
 Fun.protect ~finally:(fun()->close_out_noerr output)(fun()->
  Yojson.Safe.to_channel output changed;output_char output '\n';flush output);
 C.expect "tampered quorum signature was accepted"
  (match Journal.read_committed_epoch ~chain_id ~epoch:0L dir with Journal.Invalid _->true|_->false)
let () =
 try
  let op=Sys.argv.(1)and dir=Sys.argv.(2)in
  let result=match op with
  |"prepare"->prepare dir;inspect dir
  |"phase"->phase dir Sys.argv.(3);inspect dir
  |"crash"->phase ~crash:true dir Sys.argv.(3);inspect dir
  |"inspect"->inspect dir
  |"mutate"->(if Sys.argv.(3)="tampered-qc" then tamper_qc dir else mutate dir Sys.argv.(3));`Null
  |"certify"->certify dir;`Bool true
  |"unstage"->Fork.clear dir;inspect dir
  |"verify-committed"->let value=head dir in let entry=Option.get(FL.find(FL.index dir)value.epoch_id)in
    ignore(unwrap(Journal.committed_for ~chain_id:"legacy-repair-fixture" ~entry dir));`Bool true
  |"advance"->C.advance dir (head dir);
    C.with_stores dir(fun chain store->ignore(Lwt_main.run(C.Recovery.recover ~data_dir:dir ~chaindata:chain ~store)));
    write_finality dir (head dir);inspect dir
  |"hold"->C.with_stores dir(fun _ _->print_endline "owned";flush stdout;ignore(read_line()));`Null
  |_ ->failwith "unknown fixture operation" in
  print_endline(Yojson.Safe.to_string result)
 with error->Printf.eprintf "legacy fixture refused: %s\n%!"(Printexc.to_string error);exit 2
