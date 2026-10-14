open Yojson.Safe.Util
open Octra_consensus
open C_types
module C = C_codec
module H = C_hash
module O = Octra_net.Oce1
let hex raw = String.concat "" (List.init (String.length raw) (fun i -> Printf.sprintf "%02x" (Char.code raw.[i])))
let unhex text = String.init (String.length text / 2) (fun i -> Char.chr (int_of_string ("0x" ^ String.sub text (i*2) 2)))
let raw name value = value |> member name |> to_string |> unhex
let str name value = value |> member name |> to_string
let error = function Failure s | Invalid_argument s -> s | exn -> Printexc.to_string exn
let catch f = try f () with exn -> `Assoc["error",`String(error exn)]
let h bytes = `String(hex bytes)
let key i = match Mirage_crypto_ec.Ed25519.priv_of_octets (String.make 32 (Char.chr i)) with Ok k->k|Error _->failwith "key"
let public i = Mirage_crypto_ec.Ed25519.(pub_of_priv(key i)|>pub_to_octets)
let sign i msg = Mirage_crypto_ec.Ed25519.sign ~key:(key i) msg
let addr i = "validator-" ^ string_of_int i
let zeros = String.make 64 '\000'
let hash i = String.make 32 (Char.chr i)
let qc = function C_qc.Valid -> `Null | C_qc.Invalid s -> `String s
let vote_verifier vs (v:vote) = match pubkey_of_addr vs v.validator with None->false|Some pubkey_raw->H.verify_vote ~pubkey_raw v
let execute value = catch(fun()->
 let wire=raw "wire" value in
 let pub=raw "public" value in
 let chain=raw "chain" value in
 let vs=C.decode_validator_set(raw "validators" value) in
 let out wire fields=`Assoc(("wire",h wire)::fields) in
 match str "kind" value with
 | "header"->let x=O.decode C.decode_epoch_header wire in out (O.encode(fun b->C.encode_epoch_header b x)) ["hash",h(H.proposal_id x)]
 | "vote"->let x=C.decode_vote wire in out(C.encode_vote x)["hash",h(H.vote_sign_bytes x);"valid",`Bool(H.verify_vote ~pubkey_raw:pub x);"slot",h(C_evidence.vote_slot_id x)]
 | "sync"->let x=C.decode_round_sync wire in out(C.encode_round_sync x)["hash",h(H.round_sync_sign_bytes x);"valid",`Bool(H.verify_round_sync ~pubkey_raw:pub x)]
 | "fetch"->let x=C.decode_round_fetch wire in out(C.encode_round_fetch x)[]
 | "proposal"->let x=C.decode_propose wire in out(C.encode_propose x)["hash",h(H.propose_sign_bytes x);"valid",`Bool(H.verify_propose ~pubkey_raw:pub x);"shape",`Bool(proposal_is_well_formed ~chain_id:chain ~validator_set:vs x)]
 | "certificate"->let x=C.decode_commit_certificate wire in out(C.encode_commit_certificate x)["valid",qc(C_qc.validate_certificate ~chain_id:chain ~validator_set:vs ~verify_vote:(vote_verifier vs) x);"strict",qc(C_qc.validate_certificate_with_policy ~strict_quorum:true ~chain_id:chain ~validator_set:vs ~verify_vote:(vote_verifier vs) x)]
 | "parent"->let x=C_parent_commit.decode wire in let expected:C_parent_commit.expected={chain_id=chain;epoch_id=x.certificate.epoch_id;proposal_id=x.certificate.proposal_id;state_root=x.certificate.header.proposed_state_root;validator_set_hash=C_config.validator_set_hash vs} in
   out(C_parent_commit.encode x)["hash",h(H.parent_commit_hash x);"valid",(match C_parent_commit.validate expected x with C_parent_commit.Valid->`Null|C_parent_commit.Invalid s->`String s)]
 | "finalize"->let x=C.decode_finalize wire in out(C.encode_finalize x)["live",qc(C_qc.validate_finalize ~chain_id:chain ~validator_set:vs ~verify_vote:(vote_verifier vs) x);"persisted",qc(C_qc.validate_persisted_finalize ~chain_id:chain ~validator_set:vs ~verify_vote:(vote_verifier vs) x);"strict",qc(C_qc.validate_persisted_finalize_strict ~chain_id:chain ~validator_set:vs ~verify_vote:(vote_verifier vs) x)]
 | "root_query"->let x=C.decode_epoch_root_query wire in out(C.encode_epoch_root_query x)[]
 | "root_response"->let x=C.decode_epoch_root_response wire in out(C.encode_epoch_root_response x)["hash",h(H.epoch_root_response_sign_bytes ~chain_id:x.chain_id ~epoch_id:x.epoch_id ~state_root:x.state_root ~responder_addr:x.responder_addr ~responder_head_epoch:x.responder_head_epoch)]
 | "bundle_query"->let x=C.decode_bundle_query wire in out(C.encode_bundle_query x)[]
 | "bundle_response"->let x=C.decode_bundle_response wire in out(C.encode_bundle_response x)["hash",h(H.bundle_response_sign_bytes x);"tx_hash",h(H.tx_list_hash x.tx_hashes);"receipt_hash",h(H.receipt_root x.receipts_json)]
 | "catchup_query"->let x=C.decode_catchup_query_range wire in out(C.encode_catchup_query_range x)["complete",`Bool(H.catchup_request_is_complete x.request_id);"marked",catch(fun()->h(H.mark_complete_catchup_request x.request_id))]
 | "catchup_v1"|"catchup_v2" as kind ->let v2=kind="catchup_v2" in let x=(if v2 then C.decode_catchup_range_response_v2 else C.decode_catchup_range_response_v1) wire in
  let root=if v2 then H.catchup_records_root x.records else H.catchup_records_root_v1_wire x.records in
  out((if v2 then C.encode_catchup_range_response_v2 else C.encode_catchup_range_response_v1)x)["root",h root;"hash",h(H.catchup_range_response_sign_bytes ~chain_id:x.chain_id ~request_id:x.request_id ~responder_addr:x.responder_addr ~from_epoch:12L ~records_root:root);"complete_hash",catch(fun()->h(H.catchup_range_response_complete_sign_bytes ~from_epoch:12L x));"times",`List(List.map(fun (r:C.catchup_epoch_record)->`String(Int64.to_string(Int64.bits_of_float r.epoch_ts)))x.records)]
 | "evidence"->let x=C_evidence.decode_vote_conflict wire in out(C_evidence.encode_vote_conflict x)["hash",h(C_evidence.vote_conflict_id x);"root",h(C_evidence.vote_conflict_root[x;x]);"valid",`Bool(C_evidence.verify_vote_conflict ~pubkey_raw:pub x)]
 | "reward"->let x=O.decode C_reward_source.decode_from wire in out(O.encode(fun b->C_reward_source.encode_into b x))[]
 | _->failwith "kind")
let seeds () =
 let items=ref [] in
 let add ?(pub=public 1) chain vs kind wire = items:=`Assoc["kind",`String kind;"chain",h chain;"validators",h(C.encode_validator_set vs);"public",h pub;"wire",h wire]::!items in
 List.iter(fun weighted->List.iter(fun (chain,epoch)->
  let validators=List.init 4(fun i->{address=addr(i+1);pubkey=public(i+1)}) in
  let vs=if weighted then (match make_weighted_validator_set(List.mapi(fun i v->v,Z.of_int(if i=0 then 1000 else 1))validators) with Ok x->x|Error e->failwith e) else make_validator_set validators in
  List.iter(fun version->
   let header:epoch_header={proto_version=version;chain_id=chain;epoch_id=epoch;prev_state_root=hash 1;tx_list_hash=hash 2;receipt_root=hash 3;proposed_state_root=hash 4;parent_commit_hash=hash 0;creator_addr=addr 1;txid_hi=Int64.max_int;ts=1234567.125} in
   let pid=H.proposal_id header in
   let make_vote i proposal_id = let v:vote={chain_id=chain;epoch_id=epoch;round=2;vote_type=Precommit;proposal_id;validator=addr i;signature=zeros} in {v with signature=sign i (H.vote_sign_bytes v)} in
   let votes=List.init 4(fun i->make_vote(i+1)pid) in
   let certificate:commit_certificate={chain_id=chain;epoch_id=epoch;commit_round=2;header;proposal_id=pid;precommits=votes} in
   let parent:parent_commit={certificate;validator_set=vs} in
   let f:finalize={chain_id=chain;epoch_id=epoch;commit_round=2;header;proposal_id=pid;precommits=votes;parent_commit=None} in
   add chain vs "header" (O.encode(fun b->C.encode_epoch_header b header));
   List.iter(fun v->add chain vs "vote"(C.encode_vote v))[List.hd votes;{(List.hd votes)with vote_type=Prevote};{(List.hd votes)with signature=zeros};{(List.hd votes)with validator="other"}];
   let p:propose={chain_id=chain;epoch_id=epoch;round=2;valid_round=Some 0;header;tx_hashes=[hash 3;hash 4];parent_commit=None;proposer=addr 1;signature=zeros} in
   add chain vs "proposal"(C.encode_propose{p with signature=sign 1(H.propose_sign_bytes p)});
   List.iter(fun certificate->add chain vs "certificate"(C.encode_commit_certificate certificate);add chain vs "finalize"(C.encode_finalize{f with precommits=certificate.precommits;header=certificate.header;proposal_id=certificate.proposal_id;chain_id=certificate.chain_id;epoch_id=certificate.epoch_id;commit_round=certificate.commit_round}))[
    certificate;{certificate with precommits=[]};{certificate with precommits=[List.hd votes]};{certificate with precommits=List.tl votes};
    {certificate with precommits=List.hd votes::votes};{certificate with precommits=List.rev votes};
    {certificate with precommits=List.map(fun (v:vote)->{v with signature=zeros})votes};
    {certificate with precommits=List.map(fun (v:vote)->{v with vote_type=Prevote})votes};
    {certificate with chain_id="other"};{certificate with epoch_id=Int64.succ epoch};{certificate with commit_round=3};
    {certificate with proposal_id=hash 0};{certificate with proposal_id=hash 9};
    {certificate with header={header with chain_id="other"}};{certificate with header={header with creator_addr="unknown"}};
    {certificate with header={header with proto_version=(if version=3 then 4 else 3)}}];
   add chain vs "parent" (C_parent_commit.encode parent);
   let bad={parent with certificate={certificate with precommits=List.map(fun (v:vote)->{v with signature=zeros})votes}} in add chain vs "parent"(C_parent_commit.encode bad);
   if version=4 then begin
    let f={f with parent_commit=Some parent;header={header with parent_commit_hash=H.parent_commit_hash parent}} in
    let pid=H.proposal_id f.header in
    let f={f with proposal_id=pid;precommits=List.init 4(fun i->make_vote(i+1)pid)} in
    add chain vs "finalize"(C.encode_finalize f);
    add chain vs "finalize"(C.encode_finalize{f with header={f.header with parent_commit_hash=hash 0}})
   end;
   let first=List.hd votes and second=make_vote 1 (hash 12) in
   let evidence=Option.get(C_evidence.vote_conflict first second) in
   add chain vs "evidence"(C_evidence.encode_vote_conflict evidence);
   add chain vs "evidence"(C_evidence.encode_vote_conflict{first=evidence.second;second=evidence.first});
   add chain vs "evidence"(C_evidence.encode_vote_conflict{evidence with second=evidence.first});
   let reward:reward_source={reward_proposer_addr=addr 1;reward_proposer_public_key=Some(public 1);reward_members=List.mapi(fun i (v:validator_info)->{reward_address=v.address;reward_public_key=Some v.pubkey;reward_weight=Z.of_int(i+1)})validators} in
   add chain vs "reward"(O.encode(fun b->C_reward_source.encode_into b reward));
   let record:C.catchup_epoch_record={epoch_id=epoch;prev_state_root=header.prev_state_root;state_root=header.proposed_state_root;tx_list_hash=header.tx_list_hash;tx_hashes=[hash 3;hash 4];txs_json=["{}";"{\"x\":1}"];receipt_root=header.receipt_root;receipts_json=["{\"ok\":true}"];epoch_ts=header.ts;creator_addr=addr 1;commit_round=2;reward_source=Some reward;finality=Some{finalize=f;validator_set=vs}} in
   let response:C.catchup_range_response={chain_id=chain;request_id=H.mark_complete_catchup_request(hash 5);status="ok";error_code=None;records=[record];next_epoch=Some(Int64.succ epoch);responder_addr=addr 1;signature=zeros} in
   add chain vs "catchup_v1"(C.encode_catchup_range_response_v1 response);add chain vs "catchup_v2"(C.encode_catchup_range_response_v2 response);
  )[3;4];
  List.iter(fun step->let x:C.round_sync={chain_id=chain;epoch_id=epoch;round=1000000;step;request=true;validator=addr 1;signature=zeros} in add chain vs "sync"(C.encode_round_sync{x with signature=sign 1(H.round_sync_sign_bytes x)}))[ProposeStep;PrevoteStep;PrecommitStep];
  List.iter(fun after_round->add chain vs "fetch"(C.encode_round_fetch{chain_id=chain;epoch_id=epoch;after_round;through_round=2}))[-1;0;2;3;1000001];
  add chain vs "root_query"(C.encode_epoch_root_query{chain_id=chain;epoch_id=epoch});
  List.iter(fun state_root->add chain vs "root_response"(C.encode_epoch_root_response{chain_id=chain;epoch_id=epoch;state_root;responder_addr=addr 1;responder_head_epoch=Int64.max_int;signature=zeros}))[None;Some(hash 3)];
  add chain vs "bundle_query"(C.encode_bundle_query{chain_id=chain;epoch_id=epoch;proposal_id=hash 2});
  add chain vs "bundle_response"(C.encode_bundle_response{chain_id=chain;epoch_id=epoch;proposal_id=hash 2;responder_addr=addr 1;tx_hashes=[hash 2;hash 3];txs_json=["{}";"\000\255"];receipts_json=["[]";"{\"ok\":true}"];signature=zeros});
  List.iter(fun max_epochs->add chain vs "catchup_query"(C.encode_catchup_query_range{chain_id=chain;request_id=hash 8;from_epoch=epoch;max_epochs}))[0;1;16;17; -1];
 )[("octra-mainnet",12L);("octra-devnet-9871-cluster",1306546L);("octra-devnet-9871-cluster",1306547L)])[false;true];
 List.rev !items
let () = let values=Yojson.Safe.from_file Sys.argv.(1)|>to_list in
 let result=if values=[] then `List(seeds()) else `List(List.map(fun value->`Assoc["input",value;"expected",execute value])values) in Yojson.Safe.to_channel stdout result
