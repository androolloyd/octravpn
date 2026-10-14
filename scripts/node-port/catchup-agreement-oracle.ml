open Yojson.Safe.Util
open Octra_consensus
module D=C_driver
let s j k=member k j|>to_string
let n j k=member k j|>to_int
let i j k=Int64.of_string(s j k)
let unhex s=String.init(String.length s/2)(fun i->Char.chr(int_of_string("0x"^String.sub s(i*2)2)))
let hex s=String.concat ""(List.init(String.length s)(fun i->Printf.sprintf "%02x"(Char.code s.[i])))
let key id=match Mirage_crypto_ec.Ed25519.priv_of_octets(String.make 32(Char.chr id))with Ok k->k|Error _->failwith"key"
let pub id=Mirage_crypto_ec.Ed25519.(pub_to_octets(pub_of_priv(key id)))
let sign id bytes=Mirage_crypto_ec.Ed25519.sign ~key:(key id) bytes
let address id="v"^string_of_int id
let rec remove path=match(Unix.lstat path).Unix.st_kind with Unix.S_DIR->Array.iter(fun n->remove(Filename.concat path n))(Sys.readdir path);Unix.rmdir path|_->Unix.unlink path
let run j=
 let open Lwt.Syntax in
 let dir=Filename.temp_file "catchup-agreement" "" in Unix.unlink dir;Unix.mkdir dir 0o700;
 Lwt.finalize (fun ()->
 let chain=s j"chain"in
 let validators=let entries=member"weights"j|>to_list|>List.mapi(fun i v->C_types.{address=address(i+1);pubkey=pub(i+1)},Z.of_string(to_string v))in
 if member"weighted"j=`Bool true then C_types.make_weighted_validator_set entries|>Result.get_ok else C_types.make_validator_set(List.map fst entries)in
 let persist=ref true and role=ref true and ready=ref true and calls=ref[]in
 let plan=match member"activation"j with `Null->None|x->Some D.{activate_epoch=Int64.of_string(to_string x);validator_set=validators;fingerprint="fixture"}in
 let local=address(n j"local")in
 let swarm=Octra_net.P2p_swarm.create Octra_net.P2p_swarm.{listen_port=0;chain_id=chain;node_id=Octra_net.P2p_handshake.node_id_of_pubkey(pub 1);node_addr=local;pubkey_raw=pub 1;consensus_config_hash=String.make 32 '\000';binary_hash=String.make 32 '\000';require_binary_hash=false;upgrade_plan=None;profile_plan=[];allowed_pubkeys=[];bootstrap_peers=[];max_peers=0;sign_fn=sign 1;best_epoch_fn=(fun()->0L);best_root_fn=(fun()->String.make 32 '\000')}in
 let config=D.{chain_id=chain;my_addr=local;sign_fn=sign 1;verify_fn=(fun _ _ _->false);role_can_vote=(fun()-> !role);can_vote=(fun()-> !ready);execute_fn=(fun _->false);verify_proposal=(fun _->Lwt.return Proposal_reject);verify_parent_commit=(fun ~epoch_id:_ _->Error"unused");on_finalized=(fun ~validator_set:_ _->Lwt.return_unit);make_proposal=(fun _->Lwt.return_none);
 before_precommit_broadcast=(fun ~epoch_id ~round ~proposal_id ~proposed_state_root ~txid_hi ~proposal_wire ~vote_wire->calls:= !calls@[`Assoc["epoch",`String(Int64.to_string epoch_id);"round",`Int round;"pid",`String(hex proposal_id);"root",`String(hex proposed_state_root);"txid",`String(Int64.to_string txid_hi);"proposal",`String(hex proposal_wire);"vote",`String(hex vote_wire)]];Lwt.return !persist);
 lookup_epoch_root=(fun _->None);local_head_epoch=(fun()->0L);lookup_bundle=(fun _->None);lookup_catchup_range=(fun ~from_epoch:_ ~max_epochs:_->`NotFound);on_resource_attestation=(fun _->Lwt.return_unit);scheduled_validator_set_config=plan;load_scheduled_validator_set_config=(fun()->Lwt.return_none);resource_committee_config=None}in
 let driver=D.create ~config ~validator_set:validators ~swarm ~start_height:(i j"height") ~sync_log:(C_sync_log.memory()) ~relief_log:(C_relief_log.memory()) ~vote_log:(C_vote_log.disk ~data_dir:dir)in

 let seed=C_codec.decode_catchup_range_response_v2(unhex(s j "wire"))in
 let base=List.hd seed.records in
 assert(Option.is_some base.finality && Option.is_some base.reward_source);
 let specs=member "responses" j|>to_list in
 let responses=List.map(fun spec->
  let records=member"records"spec|>to_list|>List.mapi(fun index variant->
   let r={base with epoch_id=Int64.add(i j "from")(Int64.of_int index);state_root=String.make 32(Char.chr(to_int variant))}in
   if member"incomplete"spec=`Bool true then {r with finality=None}else r)in
  D.{responder_addr=s spec "responder";request_id="";status=s spec "status";records;next_epoch=(match member"next"spec with `Null->None|v->Some(Int64.of_string(to_string v)))})specs in
 let rejected=List.filter(fun spec->member"valid"spec=`Bool false)specs|>List.map(fun spec->s spec "responder")in
 let validated=ref[]in
 let pending=D.query_catchup_range driver ~from_epoch:(i j "from") ~max_epochs:(n j "max") ~timeout_seconds:0.21 ~validate:(fun r->validated:=r.D.responder_addr::!validated;not(List.mem r.responder_addr rejected))in
 let ids=Hashtbl.fold(fun id _ out->id::out)driver.catchup_query_windows []in
 let id=List.hd ids in
 let limit=(Hashtbl.find driver.catchup_query_windows id).D.max_epochs in
 Hashtbl.replace driver.catchup_responses id responses;
 let* chosen=pending in
 let show (r:D.catchup_range_response_record)=`Assoc["responder",`String r.D.responder_addr;"status",`String r.status;"next",(match r.next_epoch with None->`Null|Some e->`String(Int64.to_string e));"roots",`List(List.map(fun r->`String(hex r.C_codec.state_root))r.records)]in
 let effective=C_types.validator_set_for_epoch ~chain_id:chain ~epoch_id:(i j "from") validators in
 let peers=List.init(n j "peers")Fun.id in
 Lwt.return(`Assoc["chosen",(match chosen with None->`Null|Some r->show r);"limit",`Int limit;
 "waves",`List(List.map(fun wave->`List(List.map(fun n->`Int n)wave))(D.catchup_query_waves effective peers));
 "delay",`Float(D.catchup_wave_delay ~budget:(member"budget"j|>to_float) ~wave_count:(n j "wave_count"));
 "rejected_calls",`List(List.map(fun addr->`List[`String addr;`Int(List.length(List.filter((=)addr)!validated))])rejected);
 "clean",`Bool(Hashtbl.length driver.catchup_query_windows=0 && Hashtbl.length driver.catchup_responses=0)]))
 (fun()->remove dir;Lwt.return_unit)
let ()=
 let cases=Yojson.Safe.from_channel stdin|>to_list in
 let output=Lwt_main.run(Lwt_list.map_s(fun input->let open Lwt.Syntax in let* expected=run input in Lwt.return(`Assoc["input",input;"expected",expected]))cases)in
 Yojson.Safe.to_channel stdout(`List output);print_newline()
