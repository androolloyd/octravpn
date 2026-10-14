open Yojson.Safe.Util
module N=Octra_node_runtime
module C=Octra_consensus
module T=Octra_core.Transaction
module W=Octra_core.Wal
let s j k=member k j|>to_string
let n j k=member k j|>to_int
let hex s=String.concat ""(List.init(String.length s)(fun i->Printf.sprintf "%02x"(Char.code s.[i])))
let unhex s=String.init(String.length s/2)(fun i->Char.chr(int_of_string("0x"^String.sub s(i*2)2)))
let key id=match Mirage_crypto_ec.Ed25519.priv_of_octets(String.make 32(Char.chr id))with Ok k->k|Error _->failwith"key"
let pub id=Mirage_crypto_ec.Ed25519.(pub_to_octets(pub_of_priv(key id)))
let sign id bytes=Mirage_crypto_ec.Ed25519.sign ~key:(key id)bytes
let validators=C.C_types.make_validator_set(List.init 4(fun i->C.C_types.{address="v"^string_of_int(i+1);pubkey=pub(i+1)}))
let tx i op=
 let public=Base64.encode_exn(pub 1)in
 let t:T.t={from=Octra_core.Crypto.Address.address_from_pubkey public;to_="receiver";amount=Z.one;nonce=i+1;ou=Z.of_int 5000;timestamp=1.;signature="";public_key=Some public;message=None;encrypted_data=None;op_type=T.op_type_of_string op|>Result.get_ok}in
 {t with signature=Base64.encode_exn(sign 1(T.serialize_for_signing t))}
let output_hashes hs=`List(List.map(fun h->`String(hex h))hs)
let output_bundle(b:N.Consensus_bundle_validation.accepted)=`Assoc["hashes",output_hashes b.tx_hashes;"txs",output_hashes(List.map(fun tx->Yojson.Safe.to_string(T.to_yojson tx))b.txs);"receipts",output_hashes b.receipts_json;"rejections",`Int(List.length b.rejections)]
let result f=function Ok v->f v|Error e->`Assoc["error",`String e]
let run j=
 Unix.putenv"OCTRA_BFT_RELEASE_PROFILE""off";Unix.putenv"OCTRA_BFT_CRYPTO_PROFILE""off";Unix.putenv"OCTRA_STEALTH_MIN_OU""5000";
 let chain=s j"chain"and epoch=n j"epoch"and round=n j"round"in
 let txs=member"ops"j|>to_list|>List.mapi(fun i v->tx i(to_string v))in
 let hashes=List.map T.hash txs and jsons=List.map(fun t->Yojson.Safe.to_string(T.to_yojson t))txs in
 let raws=member"receipts"j|>to_list|>List.map(fun v->unhex(to_string v))in
 let proposer=(C.C_types.leader_of validators ~epoch_id:(Int64.of_int epoch) ~round).address in
 let proposer_id=int_of_string(String.sub proposer 1(String.length proposer-1))in
 let header:C.C_types.epoch_header={proto_version=C.C_protocol.version_for_epoch(Int64.of_int epoch);chain_id=chain;epoch_id=Int64.of_int epoch;prev_state_root=String.make 32 '\000';tx_list_hash=C.C_engine.tx_list_hash_for_header hashes;receipt_root=C.C_hash.receipt_root raws;proposed_state_root=String.make 32 '\003';parent_commit_hash=String.make 32 '\000';creator_addr=proposer;txid_hi=Int64.of_int(7+List.length txs);ts=1.}in
 let p:C.C_types.propose={chain_id=chain;epoch_id=Int64.of_int epoch;round;valid_round=None;header;tx_hashes=List.map unhex hashes;parent_commit=None;proposer;signature=String.make 64 '\000'}in
 let mutate=s j"mutate"in
 let p=match mutate with
 |"proposal_chain"->{p with chain_id="other"}|"header_chain"->{p with header={header with chain_id="other"}}|"version"->{p with header={header with proto_version=1}}
 |"creator"->{p with header={header with creator_addr="v9"}}|"proposer"->{p with proposer="v9"}|"valid_round"->{p with valid_round=Some round}
 |"tx_root"->{p with header={header with tx_list_hash=String.make 32 '\005'}}|"receipt_root"->{p with header={header with receipt_root=String.make 32 '\005'}}|"parent_root"->{p with header={header with parent_commit_hash=String.make 32 '\005'}}|_->p in
 let p={p with signature=if mutate="proposal_signature"then String.make 64 '\000'else sign proposer_id(C.C_hash.propose_sign_bytes p)}in
 let pid=C.C_hash.proposal_id p.header in
 let v:C.C_types.vote={chain_id=chain;epoch_id=Int64.of_int epoch;round;vote_type=Precommit;proposal_id=pid;validator="v1";signature=String.make 64 '\000'}in
 let v=match mutate with"vote_chain"->{v with chain_id="other"}|"vote_epoch"->{v with epoch_id=Int64.succ v.epoch_id}|"vote_round"->{v with round=round+1}|"vote_type"->{v with vote_type=Prevote}|"vote_pid"->{v with proposal_id=String.make 32 '\005'}|"vote_validator"->{v with validator="v9"}|_->v in
 let v={v with signature=if mutate="vote_signature"then String.make 64 '\000'else sign 1(C.C_hash.vote_sign_bytes v)}in
 let r=N.Consensus_proposal.pending_commit ~epoch_id:(Int64.of_int epoch)~round ~proposal_id:pid ~proposed_state_root:p.header.proposed_state_root ~txid_hi:p.header.txid_hi ~ts:2. ~validator_addr:"v1"~proposal_wire:(C.C_codec.encode_propose p)~vote_wire:(C.C_codec.encode_vote v)~tx_hashes:hashes~txs_json:jsons~receipts_json:raws in
 let r=match mutate with
 |"epoch"->{r with epoch_id=epoch+1}|"round"->{r with round=round+1}|"pid"->{r with proposal_id=String.make 64 '0'}|"root"->{r with proposed_state_root=String.make 64 '0'}|"txid"->{r with txid_hi=Int64.succ r.txid_hi}|"validator"->{r with validator_addr="other"}
 |"legacy_proposal"->{r with proposal_b64=None}|"legacy_vote"->{r with vote_b64=None}|"base64"->{r with proposal_b64=Some"!"}
 |"tx_length"->{r with txs_json=[]}|"tx_invalid"->{r with txs_json=["{}"]}|"tx_other"->{r with txs_json=[Yojson.Safe.to_string(T.to_yojson(tx 10"standard"))]}
 |"hashes"->{r with tx_hashes=[String.make 64 'a']}|"receipts"->{r with receipts_json=["{}"]}|_->r in
 let recovered=N.Consensus_pending_commit_recovery.recover_record ~chain_id:chain ~validator_set:validators r in
 let response:C.C_driver.bundle_response_record={responder_addr="test";tx_hashes=r.tx_hashes;txs_json=r.txs_json;receipts_json=r.receipts_json}in
 let mode=function Octra_core.Rule_graph.Prior->false|Active->true in
 `Assoc["proposal",`String(hex(C.C_codec.encode_propose p));"vote",`String(hex(C.C_codec.encode_vote v));"record",`String(hex(W.pending_commit_to_json r));
 "rules",`Assoc["envelope",`Bool(mode(Octra_core.Rule_graph.tx_envelope_at ~chain_id:chain ~epoch:(Int64.of_int epoch)));"compute",`Bool(mode(Octra_core.Rule_graph.vm_bytes_at ~chain_id:chain ~epoch));"settle",`Bool(mode(Octra_core.Rule_graph.settle_at ~chain_id:chain ~epoch))];
 "recover",result(fun(r:N.Consensus_pending_commit_recovery.recovered)->`Assoc["proposal",`String(hex(C.C_codec.encode_propose r.proposal));"vote",`String(hex(C.C_codec.encode_vote r.vote));"hashes",output_hashes r.tx_hashes;"txs",output_hashes(List.map(fun t->Yojson.Safe.to_string(T.to_yojson t))r.txs);"receipts",output_hashes r.receipts_json])recovered;
 "host",(let calls=ref[]and saved=ref None and unsynced=ref false in
 let deps:N.Consensus_proposal.before_precommit_deps={chain_id=chain;validator_set=(fun()->validators);current_tx_hashes=(fun()->[]);cached_bundle=(fun _->Some(r.tx_hashes,r.txs_json,r.receipts_json));sync_bundle=(fun ~tx_hashes:_ ~txs:_ ~receipts_json:_->calls:= !calls@["sync"]);mark_unsynced=(fun()->unsynced:=true);write_pending=(fun p->calls:= !calls@["write"];saved:=Some(W.pending_commit_to_json p));now=(fun()->3.)}in
 let ok=N.Consensus_proposal.handle_before_precommit deps ~epoch_id:(Int64.of_int r.epoch_id)~round:r.round ~proposal_id:(unhex r.proposal_id)~proposed_state_root:(unhex r.proposed_state_root)~txid_hi:r.txid_hi ~validator_addr:r.validator_addr ~proposal_wire:(C.C_codec.encode_propose p)~vote_wire:(C.C_codec.encode_vote v)in
 `Assoc["ok",`Bool ok;"unsynced",`Bool !unsynced;"calls",`List(List.map(fun s->`String s)!calls);"saved",(match !saved with None->`Null|Some s->`String(hex s))]);
 "bundle",result output_bundle(N.Consensus_bundle_validation.finalized ~header:p.header response)]
let ()=let cases=Yojson.Safe.from_channel stdin|>to_list|>List.map(fun input->`Assoc["input",input;"expected",run input])in Yojson.Safe.to_channel stdout(`List cases);print_newline()
