open Yojson.Safe.Util
open Octra_consensus
module D=C_driver
let s j k=member k j|>to_string
let n j k=member k j|>to_int
let i j k=Int64.of_string(s j k)
let b j k=member k j|>to_bool
let hex s=String.concat ""(List.init(String.length s)(fun i->Printf.sprintf "%02x"(Char.code s.[i])))
let raw j k=let s=s j k in String.init(String.length s/2)(fun i->Char.chr(int_of_string("0x"^String.sub s(i*2)2)))
let key id=match Mirage_crypto_ec.Ed25519.priv_of_octets(String.make 32(Char.chr id))with Ok k->k|Error _->failwith"key"
let pub id=Mirage_crypto_ec.Ed25519.(pub_to_octets(pub_of_priv(key id)))
let sign id bytes=Mirage_crypto_ec.Ed25519.sign ~key:(key id) bytes
let address id="v"^string_of_int id
let chain="vote-guard-fixture"
let result f=function Ok v->f v|Error e->`Assoc["error",`String e]
let catch f=try f()with e->`Assoc["error",`String(Printexc.to_string e)]
let option f=function None->`Null|Some v->f v
let validators=C_types.make_validator_set(List.init 4(fun n->C_types.{address=address(n+1);pubkey=pub(n+1)}))
let proposal j=
 let chain_id=raw j"chain"and epoch_id=i j"epoch"and round=n j"round"in
 let header=C_types.{proto_version=C_protocol.version_for_epoch epoch_id;chain_id;epoch_id;prev_state_root=String.make 32 '\000';tx_list_hash=C_engine.tx_list_hash_for_header [];receipt_root=C_hash.receipt_root [];proposed_state_root=String.make 32 '\003';parent_commit_hash=String.make 32 '\000';creator_addr="v1";txid_hi=7L;ts=1.}in
 let p=C_types.{chain_id;epoch_id;round;valid_round=None;header;tx_hashes=[];parent_commit=None;proposer="v1";signature=String.make 64 '\000'}in
 {p with signature=sign 1(C_hash.propose_sign_bytes p)}
let vote j=
 let p=proposal j in
 let proposal_id=match s j"pid"with"nil"->String.make 32 '\000'|"other"->String.make 32 '\004'|_->C_hash.proposal_id p.header in
 let v=C_types.{chain_id=p.chain_id;epoch_id=p.epoch_id;round=p.round;vote_type=(if n j"type"=1 then Prevote else Precommit);proposal_id;validator=address(n j"signer");signature=String.make 64 '\000'}in
 {v with signature=if b j"corrupt"then String.make 64 '\000'else sign(n j"signer")(C_hash.vote_sign_bytes v)}
let proposed j=let p=proposal j in match s j"proposal"with
 |"missing"->None|"round"->Some{p with round=p.round+1}|"chain"->Some{p with chain_id="other"}|"header"->Some{p with header={p.header with chain_id="other"}}|_->Some p
let rec remove path=match(Unix.lstat path).Unix.st_kind with Unix.S_DIR->Array.iter(fun n->remove(Filename.concat path n))(Sys.readdir path);Unix.rmdir path|_->Unix.unlink path
let run j=
 let dir=Filename.temp_file"vote-guard"""in Unix.unlink dir;Unix.mkdir dir 0o700;
 Fun.protect ~finally:(fun()->remove dir)(fun()->
 let persist=ref true and role=ref true and ready=ref true and calls=ref[]in
 let local=address(n j"local")in
 let swarm=Octra_net.P2p_swarm.create Octra_net.P2p_swarm.{listen_port=0;chain_id=chain;node_id=Octra_net.P2p_handshake.node_id_of_pubkey(pub 1);node_addr=local;pubkey_raw=pub 1;consensus_config_hash=String.make 32 '\000';binary_hash=String.make 32 '\000';require_binary_hash=false;upgrade_plan=None;profile_plan=[];allowed_pubkeys=[];bootstrap_peers=[];max_peers=0;sign_fn=sign 1;best_epoch_fn=(fun()->0L);best_root_fn=(fun()->String.make 32 '\000')}in
 let config=D.{chain_id=chain;my_addr=local;sign_fn=sign 1;verify_fn=(fun _ _ _->false);role_can_vote=(fun()-> !role);can_vote=(fun()-> !ready);execute_fn=(fun _->false);verify_proposal=(fun _->Lwt.return Proposal_reject);verify_parent_commit=(fun ~epoch_id:_ _->Error"unused");on_finalized=(fun ~validator_set:_ _->Lwt.return_unit);make_proposal=(fun _->Lwt.return_none);
 before_precommit_broadcast=(fun ~epoch_id ~round ~proposal_id ~proposed_state_root ~txid_hi ~proposal_wire ~vote_wire->calls:= !calls@[`Assoc["epoch",`String(Int64.to_string epoch_id);"round",`Int round;"pid",`String(hex proposal_id);"root",`String(hex proposed_state_root);"txid",`String(Int64.to_string txid_hi);"proposal",`String(hex proposal_wire);"vote",`String(hex vote_wire)]];Lwt.return !persist);
 lookup_epoch_root=(fun _->None);local_head_epoch=(fun()->0L);lookup_bundle=(fun _->None);lookup_catchup_range=(fun ~from_epoch:_ ~max_epochs:_->`NotFound);on_resource_attestation=(fun _->Lwt.return_unit);scheduled_validator_set_config=None;load_scheduled_validator_set_config=(fun()->Lwt.return_none);resource_committee_config=None}in
 let driver=D.create ~config ~validator_set:validators ~swarm ~start_height:(i j"height") ~sync_log:(C_sync_log.memory()) ~relief_log:(C_relief_log.memory()) ~vote_log:(C_vote_log.disk ~data_dir:dir)in
 `List(member"steps"j|>to_list|>List.map(fun step->
  let answer=catch(fun()->match s step"op"with
   |"prepare"->let wires=match member"restore_error"step with `String error->Error error|_->Ok(member"wires"step|>to_list|>List.map(fun j->if member"raw"j<>`Null then raw j"raw"else C_codec.encode_vote(vote j)))in result(fun()->`Null)(D.prepare_vote_log driver wires)
   |"save"->persist:=b step"persist";let v=vote(member"vote"step)in option(fun v->`String(hex(C_codec.encode_vote v)))(Lwt_main.run(D.saved_vote ?proposal:(proposed(member"vote"step)) driver v))
   |"floor"->result(fun()->`Null)(C_vote_log.set_floor driver.vote_log ~through_epoch:(i step"epoch"))
   |"flags"->driver.running<-b step"running";role:=b step"role";ready:=b step"ready";driver.finality_proof_needed:=b step"finality";`Null
   |_->`Null)in
  let allowed,reason=D.vote_state driver in
  `Assoc["result",answer;"issue",option(fun s->`String s)driver.vote_log_issue;"fault",option(fun(f:D.vote_fault)->`Assoc["epoch",`String(Int64.to_string f.epoch_id);"round",`Int f.round;"reason",`String f.reason])driver.vote_fault;
   "state",`List[`Bool allowed;option(fun s->`String s)reason];"allowed",`Bool(D.vote_allowed driver);"bootstrap",`Bool(D.vote_log_bootstrap_pending driver);"round",`Int driver.engine.state.round;
   "floor",result(option(fun n->`String(Int64.to_string n)))(C_vote_log.floor driver.vote_log);"calls",`List !calls])))
let ()=let cases=Yojson.Safe.from_channel stdin|>to_list|>List.map(fun input->`Assoc["input",input;"expected",run input])in Yojson.Safe.to_channel stdout(`List cases);print_newline()
