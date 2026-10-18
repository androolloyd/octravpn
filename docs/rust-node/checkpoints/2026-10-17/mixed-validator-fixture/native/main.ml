(* Explicit isolated fixture launcher, NOT the stock native full-node startup.
   It supplies the same committed local genesis/profile as unchanged Rust
   init-devnet, while all wire, votes, QC and execution modules stay native. *)
open Lwt.Syntax
open Yojson.Safe.Util
open Fixture
module X = Execution
module D = N.C_driver
module Types = N.C_types
module Codec = N.C_codec
module Hash = N.C_hash
module Swarm = Octra_net.P2p_swarm
let config_path=ref ""
let barrier_path=ref ""
let argument_error why=raise(Arg.Bad why)
let ()=Arg.parse ["--config",Arg.Set_string config_path,"isolated devnet config";
                 "--barrier",Arg.Set_string barrier_path,"host admission barrier"]
  (fun _->argument_error "unexpected argument") "mixed native fixture"
let require cond why=if not cond then failwith why
let read_json path=Yojson.Safe.from_file path
let save_bundle state pid bundle =
  let path=Filename.concat state.X.data ("bundle-"^raw_hex pid^".json") in
  let value=`Assoc["tx_hashes",`List(List.map b64 bundle.X.hashes);
    "txs",`List(List.map T.to_yojson bundle.txs);
    "receipts",`List(List.map(fun s->`String s)bundle.receipts)] |> json in
  if Sys.file_exists path then require (read_json path=Yojson.Safe.from_string value) "immutable bundle conflict"
  else atomic path value;
  Hashtbl.replace state.bundles pid bundle
let load_bundle state pid =
  match Hashtbl.find_opt state.X.bundles pid with Some value->Some value|None->
  let path=Filename.concat state.data("bundle-"^raw_hex pid^".json") in
  if not(Sys.file_exists path)then None else
    let value=read_json path in
    let txs=member "txs" value |>to_list |>List.map(fun v->ok(Core.Tx_payload.decode_final v)) in
    let bundle=X.{hashes=member "tx_hashes" value |>to_list |>List.map(fun v->Base64.decode_exn(to_string v));
      txs;receipts=member "receipts" value |>to_list |>List.map to_string} in
    Hashtbl.replace state.bundles pid bundle;Some bundle
let root_at state genesis epoch =
  if epoch=0L then Some(raw(genesis_root genesis))
  else match X.load_final state epoch with None->None|Some final->X.verify_qc state final;Some final.Types.header.proposed_state_root
let catchup state ~from_epoch ~max_epochs =
  if from_epoch<1L || max_epochs<1 || max_epochs>16 then `NotFound
  else
    let head=Int64.of_int state.X.head.epoch_id in
    if from_epoch>head then `NotFound else
    try
      let through=Int64.min head (Int64.add from_epoch(Int64.of_int(max_epochs-1)))in
      let rec collect epoch rows =
        if epoch>through then List.rev rows else
        let final=Option.get(X.load_final state epoch)in X.verify_qc state final;
        let bundle=Option.get(load_bundle state final.proposal_id)in
        ignore(X.verify_bundle state final.header bundle);
        let reward=ok(X.R.resolve_for_epoch ~chain_id:state.chain_id ~epoch_id:epoch
          ~proposer_addr:final.header.creator_addr ~validator_pubkeys:state.keys final.parent_commit)in
        let source=ok(X.R.to_source reward)in
        let row=Codec.{epoch_id=epoch;prev_state_root=final.header.prev_state_root;
          state_root=final.header.proposed_state_root;tx_list_hash=final.header.tx_list_hash;
          tx_hashes=bundle.hashes;txs_json=List.map(fun tx->json(T.to_yojson tx))bundle.txs;
          receipt_root=final.header.receipt_root;receipts_json=bundle.receipts;
          epoch_ts=final.header.ts;creator_addr=final.header.creator_addr;commit_round=final.commit_round;
          reward_source=Some source;finality=Some {finalize=final;validator_set=state.validators}}in
        collect(Int64.succ epoch)(row::rows)in
      `Ok(collect from_epoch [],if through<head then Some(Int64.succ through)else None)
    with error->`Internal(Printexc.to_string error)
let audit state genesis =
  let history=List.init state.X.head.epoch_id(fun i->
    let epoch=Int64.of_int(i+1)in
    let final=Option.get(X.load_final state epoch)in X.verify_qc state final;
    let bundle=Option.get(load_bundle state final.proposal_id)in
    `Assoc["epoch",`Int(i+1);"state_root",`String(raw_hex final.header.proposed_state_root);
      "prev_state_root",`String(raw_hex final.header.prev_state_root);"creator",`String final.header.creator_addr;
      "txid_hi",`String(Int64.to_string final.header.txid_hi);"signers",`List(List.map(fun(v:Types.vote)->`String v.Types.validator)final.precommits);
      "finalize_wire_b64",b64(Codec.encode_finalize final);
      "validator_set_wire_b64",b64(Codec.encode_validator_set state.validators);
      "parent_commit_wire_b64",(match final.parent_commit with None->`Null|Some p->b64(N.C_parent_commit.encode p));
      "txhashes",`List(List.map(fun tx->`String(T.hash tx))bundle.txs);
      "txs",`List(List.map T.to_yojson bundle.txs);"receipts",`List(List.map(fun r->`String r)bundle.receipts)])in
  `Assoc["implementation",`String"unchanged-native-library-fixture-host";
    "scope",`String"Explicit private genesis/Prior profile host adapter; empty+Standard execution only; clean restart, no stock-launcher/apps/private proof claim";
    "chain_id",`String state.chain_id;"genesis_root",`String(genesis_root genesis);
    "validator_set_hash",`String(raw_hex(N.C_config.validator_set_hash state.validators));
    "consensus_config_hash",`String(raw_hex(N.C_config.hash ~chain_id:state.chain_id ~validator_set:state.validators()));
    "proposal_activation",`Int 2;"receipts_activation",`Int 0;"profile",`String"devnet_full_v1";
    "head",Yojson.Safe.from_string(HM.to_json state.head);"history",`List history]
let main () =
  require(!config_path<>"" && !barrier_path<>"")"config/barrier required";
  Mirage_crypto_rng_unix.use_default();
  let cfg=read_json !config_path in
  let genesis=member "genesis" cfg in
  let genesis_time_lexeme=time_lexeme !config_path genesis in
  let data=str cfg "data" in
  require(Filename.is_relative data=false)"absolute isolated data required";
  require(Sys.file_exists data && Sys.is_directory data)"existing private devnet directory required";
  let key=private_read(str cfg "key") in require(String.length key=32)"private Ed25519 seed length";
  let signing=Mirage_crypto_ec.Ed25519.priv_of_octets key |>Result.get_ok in
  let public=Mirage_crypto_ec.Ed25519.(pub_of_priv signing |>pub_to_octets)in
  let address=Core.Crypto.Address.address_from_pubkey(Base64.encode_exn public)in
  let entries=member "validators" genesis |>to_list |>List.map to_string in
  require(List.length entries=4)"exactlyfour private validators required";
  let keys=List.map(fun entry->let p=String.index entry ':'in
    let a=String.sub entry 0 p and b=String.sub entry(p+1)(String.length entry-p-1)in
    require(Core.Crypto.Address.address_from_pubkey b=a)"validator address/key mismatch";a,b)entries in
  require(List.assoc_opt address keys=Some(Base64.encode_exn public))"native signer not in configured set";
  let validators=Types.make_validator_set(List.map(fun(a,b)->Types.{address=a;pubkey=Base64.decode_exn b})keys)in
  require(validators.n=4 && validators.quorum=3)"native quorum differs";
  (* Same ordered public-key view as Consensus_proposal.validator_pubkeys_from_driver. *)
  let keys=List.map(fun(v:Types.validator_info)->v.address,Base64.encode_exn v.pubkey)validators.validators in
  let chain_id=str(member "chain" genesis)"chain_id"in
  (* The compiled native modules stay byte-identical. These are explicit fixture
     host inputs matching Rust devnet.rs; no production activation is changed. *)
  let environment=["OCTRA_PROPOSAL_PROTOCOL_ACTIVATION_EPOCH","2";
    "OCTRA_PREVERIFY_RECEIPT_ACTIVATION_EPOCH","0";"OCTRA_PRIVATE_RESULT_ACTIVATION_EPOCH","0";
    "OCTRA_BFT_RELEASE_PROFILE","devnet_full_v1";"OCTRA_EMISSION_GUARD","1";
    "OCTRA_SENDER_KEY_ACTIVATION_EPOCH","0"]in
  List.iter(fun(k,v)->Unix.putenv k v)environment;
  let genesis_path=Filename.concat data "fixture-genesis.json"in
  if Sys.file_exists genesis_path then require(read_json genesis_path=genesis)"genesis changed on restart"
  else atomic genesis_path(json genesis);
  let* store=S.open_store(Filename.concat data "irmin")in
  let chain=SC.open_chaindata(Filename.concat data "chaindata")in
  let* head=initialize ~time_lexeme:genesis_time_lexeme data genesis store chain in
  let ledger=L.create store in
  let state=X.{data;chain_id;validators;keys;store;ledger;chain;head;
    bundles=Hashtbl.create 32;verified=Hashtbl.create 32;lock=Lwt_mutex.create()}in
  let sign bytes=Mirage_crypto_ec.Ed25519.sign ~key:signing bytes in
  let stopping=ref false in
  let barrier ()=let value=int(read_json !barrier_path)"max_epoch"in
    require(value>=state.head.epoch_id && value<=64)"invalid bounded host barrier";value in
  let p2p=Octra_net.P2p_endpoint.of_string(str cfg "p2p") |>Option.get in
  require(p2p.host="127.0.0.1")"fixture P2P must be loopback in network-none container";
  let peers=member "peers" cfg |>to_list |>List.map to_string in
  List.iter(fun p->let e=Octra_net.P2p_endpoint.of_string p |>Option.get in require(e.host="127.0.0.1")"external fixture peer refused")peers;
  let consensus_hash=N.C_config.hash ~chain_id ~validator_set:validators ()in
  let swarm=Swarm.create Swarm.{listen_port=p2p.port;chain_id;node_id=Octra_net.P2p_handshake.node_id_of_pubkey public;
    node_addr=address;pubkey_raw=public;consensus_config_hash=consensus_hash;
    binary_hash=Digestif.SHA256.(digest_string "octra-rust-local-devnet-v1" |>to_raw_string);
    require_binary_hash=false;upgrade_plan=None;profile_plan=[];allowed_pubkeys=List.map(fun(_,v)->Base64.decode_exn v)keys;
    bootstrap_peers=peers;max_peers=16;sign_fn=sign;
    best_epoch_fn=(fun()->Int64.of_int state.head.epoch_id);best_root_fn=(fun()->raw state.head.state_root)}in
  let driver=ref None in
  let ready ()=not !stopping && state.head.epoch_id<barrier() && Swarm.connected_count swarm>=2 in
  let fetch header =
    let pid=Hash.proposal_id header in match load_bundle state pid with
    |Some bundle->Lwt.return_some bundle
    |None when header.Types.tx_list_hash=P.tx_list_hash[] && header.receipt_root=Hash.receipt_root[]->
      Lwt.return_some X.{hashes=[];txs=[];receipts=[]}
    |None->let d=Option.get !driver in
      let* value=D.query_bundle d ~epoch_id:header.epoch_id ~proposal_id:pid ~timeout_seconds:5.
        ~validate:(fun row->try
          let txs=List.map(fun raw->ok(Core.Tx_payload.decode_final(Yojson.Safe.from_string raw)))row.D.txs_json in
          ignore(X.verify_bundle state header X.{hashes=row.tx_hashes;txs;receipts=row.receipts_json});true
          with _->false)in
      Lwt.return(Option.map(fun row->X.{hashes=row.D.tx_hashes;
        txs=List.map(fun raw->ok(Core.Tx_payload.decode_final(Yojson.Safe.from_string raw)))row.txs_json;receipts=row.receipts_json})value)
  in
  let verify_proposal (proposal:Types.propose) =
    let* bundle=fetch proposal.Types.header in
    match bundle with None->Lwt.return D.Proposal_wait|Some bundle->
      Lwt.catch(fun()->Lwt_mutex.with_lock state.lock(fun()->
        let* ()=X.validate state proposal bundle in save_bundle state(Hash.proposal_id proposal.header)bundle;
        Lwt.return D.Proposal_accept))
      (fun error->Printf.eprintf"MIXED_NATIVE_REFUSE epoch=%Ld reason=%s\n%!"proposal.epoch_id(Printexc.to_string error);Lwt.return D.Proposal_reject)
  in
  let make_proposal epoch = Lwt_mutex.with_lock state.lock(fun()->
    if not(ready()) || epoch<>Int64.of_int(state.head.epoch_id+1)
      || N.Epoch_time.next_delay_ms ~now:(Unix.gettimeofday()) ~previous:state.head.ts>0L
    then Lwt.return_none else
    let parent=X.parent state epoch and ts=Unix.gettimeofday()in
    let provisional=P.build_header ~chain_id ~epoch_id:epoch ~prev_state_root:(raw state.head.state_root)
      ~final_hashes:[] ~receipts_json:[] ~proposed_state_root:(String.make 32 '\000') ~creator_addr:address
      ~next_txid:(SC.next_txid chain) ~head_txid_hi:(Some state.head.txid_hi)
      ~parent_commit_hash:(Hash.parent_commit_hash_opt parent) ~ts in
    let bundle=X.{hashes=[];txs=[];receipts=[]}in
    let* _,_,_,_,folded=X.preview state provisional parent bundle in
    let envelope=P.build_proposal_envelope ~chain_id ~epoch_id:epoch ~prev_state_root:(raw state.head.state_root)
      ~final_hashes:[] ~final_txs:[] ~receipts_json:[] ~proposed_state_root:(raw folded)
      ~creator_addr:address ~next_txid:(SC.next_txid chain) ~head_txid_hi:(Some state.head.txid_hi) ~parent_commit:parent ~ts in
    save_bundle state envelope.proposal_id bundle;
    Hashtbl.replace state.verified envelope.proposal_id state.head.state_root;
    Lwt.return_some D.{header=envelope.header;tx_hashes=[];parent_commit=parent})in
  let on_finalized ~validator_set (final:Types.finalize) =
    require(N.C_config.validator_set_hash validator_set=N.C_config.validator_set_hash validators)"finality validator authority changed";
    X.verify_qc state final;
    if final.Types.epoch_id<=Int64.of_int state.head.epoch_id then
      (let prior=Option.get(X.load_final state final.epoch_id)in
       require(prior.proposal_id=final.proposal_id && prior.header=final.header)
         "finality conflicts with immutable native history";Lwt.return_unit)
    else let* bundle=fetch final.header in match bundle with None->Lwt.fail_with"finalized native bundle unavailable"|Some bundle->
      Lwt_mutex.with_lock state.lock(fun()->
        let* ()=X.publish state final bundle in save_bundle state final.proposal_id bundle;
        atomic(Filename.concat data "audit.json")(json(audit state genesis));
        Printf.printf"MIXED_NATIVE_FINALIZED epoch=%d root=%s txid=%Ld\n%!"state.head.epoch_id state.head.state_root state.head.txid_hi;
        Lwt.return_unit)in
  let config=D.{chain_id;my_addr=address;sign_fn=sign;
    verify_fn=(fun who bytes signature->match Types.pubkey_of_addr validators who with None->false|Some key->Octra_ed25519.verify ~pub:key ~msg:bytes signature);
    role_can_vote=(fun()->not !stopping);can_vote=ready;
    execute_fn=(fun proposal->Hashtbl.find_opt state.verified(Hash.proposal_id proposal.Types.header)=Some state.head.state_root);
    verify_proposal;verify_parent_commit=X.verify_parent state;on_finalized;make_proposal;
    before_precommit_broadcast=(fun ~epoch_id ~round ~proposal_id ~proposed_state_root ~txid_hi ~proposal_wire ~vote_wire->
      match load_bundle state proposal_id with None->Lwt.return_false|Some bundle->
      (try
        require(Hashtbl.find_opt state.verified proposal_id=Some state.head.state_root)"precommit lacks verified current execution";
        let encode b=(List.map T.hash b.X.txs,List.map(fun tx->json(T.to_yojson tx))b.txs,b.receipts)in
        let deps=P.{chain_id;validator_set=(fun()->validators);
          current_tx_hashes=(fun()->List.map T.hash bundle.txs);
          cached_bundle=(fun pid->Option.map encode(load_bundle state pid));
          sync_bundle=(fun ~tx_hashes ~txs ~receipts_json->
            require(tx_hashes=List.map T.hash txs)"native precommit synchronization differs";
            save_bundle state proposal_id X.{hashes=List.map raw tx_hashes;txs;receipts=receipts_json});
          mark_unsynced=(fun()->Hashtbl.remove state.verified proposal_id);
          write_pending=(Core.Wal.write_pending_commit data);now=Unix.gettimeofday}in
        Lwt.return(P.handle_before_precommit deps ~epoch_id ~round ~proposal_id
          ~proposed_state_root ~txid_hi ~validator_addr:address ~proposal_wire ~vote_wire)
       with _->Lwt.return_false));
    lookup_epoch_root=root_at state genesis;local_head_epoch=(fun()->Int64.of_int state.head.epoch_id);
    lookup_bundle=(fun pid->Option.map(fun b->b.X.hashes,List.map(fun tx->json(T.to_yojson tx))b.txs,b.receipts)(load_bundle state pid));
    lookup_catchup_range=catchup state;
    on_resource_attestation=(fun _->Lwt.return_unit);scheduled_validator_set_config=None;
    load_scheduled_validator_set_config=(fun()->Lwt.return_none);resource_committee_config=None}in
  let d=D.create ~config ~validator_set:validators ~swarm ~start_height:(Int64.of_int(state.head.epoch_id+1))
    ~sync_log:(N.C_sync_log.disk ~data_dir:data) ~relief_log:(N.C_relief_log.disk ~data_dir:data)
    ~vote_log:(N.C_vote_log.disk ~data_dir:data)in
  driver:=Some d;
  let stopped,stop=Lwt.wait()in
  let signal _=stopping:=true;if Lwt.is_sleeping stopped then Lwt.wakeup_later stop()in
  let term=Lwt_unix.on_signal Sys.sigterm signal and interrupt=Lwt_unix.on_signal Sys.sigint signal in
  let rpc=Octra_net.P2p_endpoint.of_string(str cfg "rpc") |>Option.get in
  require(rpc.host="127.0.0.1")"fixture RPC must be loopback";
  let callback _conn request _body =
    let path=Cohttp.Request.uri request |>Uri.path in
    let value=if path="/fixture/audit"then audit state genesis else
      `Assoc["implementation",`String"native-fixture";"epoch",`Int state.head.epoch_id;
        "state_root",`String state.head.state_root;"txid_hi",`String(Int64.to_string state.head.txid_hi);
        "serving",`Bool true;"voting",`Bool(ready());"genesis_root",`String(genesis_root genesis)]in
    Cohttp_lwt_unix.Server.respond_string ~status:`OK ~body:(json value)()in
  let http=Cohttp_lwt_unix.Server.create ~mode:(`TCP(`Port rpc.port))(Cohttp_lwt_unix.Server.make ~callback())in
  let network=Swarm.start swarm ~on_message:(D.on_p2p_message d)in
  Lwt.async(fun()->D.start d);
  Printf.printf"MIXED_NATIVE_READY address=%s root=%s\n%!"address state.head.state_root;
  Lwt.finalize(fun()->Lwt.pick[stopped;network;http])
    (fun()->stopping:=true;Lwt_unix.disable_signal_handler term;Lwt_unix.disable_signal_handler interrupt;
      let* ()=D.stop d in let* ()=Swarm.stop swarm in Lwt.cancel http;
      atomic(Filename.concat data "audit.json")(json(audit state genesis));SC.close chain;S.close store)
let ()=try Lwt_main.run(main())with error->Printf.eprintf"MIXED_NATIVE_FATAL %s\n%!"(Printexc.to_string error);exit 1
