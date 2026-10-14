open Yojson.Safe.Util
open Octra_consensus
module D=C_driver
let s j k=member k j|>to_string
let n j k=member k j|>to_int
let i j k=Int64.of_string(s j k)
let hex s=String.concat ""(List.init(String.length s)(fun i->Printf.sprintf "%02x"(Char.code s.[i])))
let key id=match Mirage_crypto_ec.Ed25519.priv_of_octets(String.make 32(Char.chr id))with Ok k->k|Error _->failwith"key"
let pub id=Mirage_crypto_ec.Ed25519.(pub_to_octets(pub_of_priv(key id)))
let sign id bytes=Mirage_crypto_ec.Ed25519.sign ~key:(key id) bytes
let address id="v"^string_of_int id
let rec remove path=match(Unix.lstat path).Unix.st_kind with Unix.S_DIR->Array.iter(fun n->remove(Filename.concat path n))(Sys.readdir path);Unix.rmdir path|_->Unix.unlink path
let run j=
 let dir=Filename.temp_file"vote-guard"""in Unix.unlink dir;Unix.mkdir dir 0o700;
 Fun.protect ~finally:(fun()->remove dir)(fun()->
 let chain=s j"chain"in
 let validators=let entries=member"weights"j|>to_list|>List.mapi(fun i v->C_types.{address=address(i+1);pubkey=pub(i+1)},Z.of_string(to_string v))in
 if member"weighted"j=`Bool true then C_types.make_weighted_validator_set entries|>Result.get_ok else C_types.make_validator_set(List.map fst entries)in
 let persist=ref true and role=ref true and ready=ref true and calls=ref[]in
 let local=address(n j"local")in
 let swarm=Octra_net.P2p_swarm.create Octra_net.P2p_swarm.{listen_port=0;chain_id=chain;node_id=Octra_net.P2p_handshake.node_id_of_pubkey(pub 1);node_addr=local;pubkey_raw=pub 1;consensus_config_hash=String.make 32 '\000';binary_hash=String.make 32 '\000';require_binary_hash=false;upgrade_plan=None;profile_plan=[];allowed_pubkeys=[];bootstrap_peers=[];max_peers=0;sign_fn=sign 1;best_epoch_fn=(fun()->0L);best_root_fn=(fun()->String.make 32 '\000')}in
 let config=D.{chain_id=chain;my_addr=local;sign_fn=sign 1;verify_fn=(fun _ _ _->false);role_can_vote=(fun()-> !role);can_vote=(fun()-> !ready);execute_fn=(fun _->false);verify_proposal=(fun _->Lwt.return Proposal_reject);verify_parent_commit=(fun ~epoch_id:_ _->Error"unused");on_finalized=(fun ~validator_set:_ _->Lwt.return_unit);make_proposal=(fun _->Lwt.return_none);
 before_precommit_broadcast=(fun ~epoch_id ~round ~proposal_id ~proposed_state_root ~txid_hi ~proposal_wire ~vote_wire->calls:= !calls@[`Assoc["epoch",`String(Int64.to_string epoch_id);"round",`Int round;"pid",`String(hex proposal_id);"root",`String(hex proposed_state_root);"txid",`String(Int64.to_string txid_hi);"proposal",`String(hex proposal_wire);"vote",`String(hex vote_wire)]];Lwt.return !persist);
 lookup_epoch_root=(fun _->None);local_head_epoch=(fun()->0L);lookup_bundle=(fun _->None);lookup_catchup_range=(fun ~from_epoch:_ ~max_epochs:_->`NotFound);on_resource_attestation=(fun _->Lwt.return_unit);scheduled_validator_set_config=None;load_scheduled_validator_set_config=(fun()->Lwt.return_none);resource_committee_config=None}in
 let driver=D.create ~config ~validator_set:validators ~swarm ~start_height:(i j"height") ~sync_log:(C_sync_log.memory()) ~relief_log:(C_relief_log.memory()) ~vote_log:(C_vote_log.disk ~data_dir:dir)in
 let records=member"records"j|>to_list|>List.map(fun r:D.epoch_root_response_record->{responder_addr=s r"addr";responder_head_epoch=0L;state_root=(match member"root"r with`Null->None|v->Some(to_string v))})in
 `Assoc["source",`Bool(D.epoch_root_wait_reached driver ~epoch_id:(i j"epoch") ~wait_for:D.Source_agreement records);"quorum",`Bool(D.epoch_root_wait_reached driver ~epoch_id:(i j"epoch") ~wait_for:D.Consensus_quorum records)] )
let ()=let cases=Yojson.Safe.from_channel stdin|>to_list|>List.map(fun input->`Assoc["input",input;"expected",run input])in Yojson.Safe.to_channel stdout(`List cases);print_newline()
