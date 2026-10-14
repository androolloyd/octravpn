open Yojson.Safe.Util
open Octra_consensus
module F=Octra_core.Set_fold
module P=Octra_core.Validator_participation
module R=Octra_core.Validator_ready_policy
let s j k=member k j|>to_string
let n j k=member k j|>to_int
let i j k=Int64.of_string(s j k)
let raw j k=Base64.decode_exn(s j k)
let b64 s=`String(Base64.encode_exn s)
let number v=`String(Int64.to_string v)
let opt f=function None->`Null|Some v->f v
let result f=function Ok v->f v|Error e->`Assoc["error",`String e]
let bytes_list j k=member k j|>to_list|>List.map(fun v->Base64.decode_exn(to_string v))
let key id=Mirage_crypto_ec.Ed25519.priv_of_octets(String.make 32(Char.chr id))|>Result.get_ok
let pub id=Mirage_crypto_ec.Ed25519.(pub_of_priv(key id)|>pub_to_octets)
let sign id msg=Mirage_crypto_ec.Ed25519.sign ~key:(key id)msg
let addr id="v"^string_of_int id
let cfg j=F.{window=i j"window";challenge=i j"challenge";rejoin_span=i j"rejoin";pulse_gap=i j"gap";cadence=i j"cadence";delay=i j"delay";max_members=n j"max";minimum=(match member"share"j with `Null->P.Any|v->P.Share{numerator=n v"n";denominator=n v"d"})}
let parent j=
 let chain_id=raw j"chain"and epoch_id=i j"epoch"and round=n j"round"in
 let validators=List.init(n j"members")(fun k->C_types.{address=addr(k+1);pubkey=pub(k+1)})in
 let validator_set=C_types.make_validator_set validators in
 let header=C_types.{proto_version=C_protocol.version_for_epoch epoch_id;chain_id;epoch_id;prev_state_root=String.make 32 '\001';tx_list_hash=String.make 32 '\002';receipt_root=String.make 32 '\003';proposed_state_root=String.make 32 '\004';parent_commit_hash=String.make 32 '\000';creator_addr=addr 1;txid_hi=7L;ts=1.}in
 let proposal_id=C_hash.proposal_id header in
 let precommits=member"signers"j|>to_list|>List.map(fun id->let id=to_int id in let v=C_types.{chain_id;epoch_id;round;vote_type=Precommit;proposal_id;validator=addr id;signature=""}in {v with signature=(if member"corrupt"j=`Bool true then String.make 64 '\000'else sign id(C_hash.vote_sign_bytes v))})in
 let certificate=C_types.{chain_id;epoch_id;commit_round=round;header;proposal_id;precommits}in
 C_types.{certificate;validator_set}
let final j=F.{epoch=i j"epoch";proposal_id=raw j"pid";set_hash=raw j"set"}
let parent_final p=F.{epoch=p.C_types.certificate.epoch_id;proposal_id=p.certificate.proposal_id;set_hash=C_config.validator_set_hash p.validator_set}
let exclusion=function
 |F.Member_missing->`String"member"|Pulse_missing->`String"pulse"|Pulse_future n->`List[`String"future";number n]|Pulse_old n->`List[`String"old";number n]
 |Pulse_short{first;last}->`List[`String"short";number first;number last]
 |Marks_short{low;high;signed;required}->`List[`String"marks";number low;number high;`Int signed;`Int required]
let rec run input=let config=cfg(member"cfg"input)in match s input"kind"with
 |"native_exception"->(try ignore(run(member"trace"input));`Null with e->`Assoc["exception",`String(Printexc.to_string e)])
 |"config"->`Assoc["valid",result(fun()->`Null)(F.validate_cfg config);"id",`String(F.consensus_id config);"replacement",number(F.replacement_limit config)]
 |"decode"->F.of_string(raw input"raw")|>result(fun s->b64(F.to_string s))
 |"claim"->let optional k=match member k input with `Null->None|`String v->Some(Base64.decode_exn v)|_->assert false in
  let runtime=R.{chain_id=raw input"chain";config_hash=raw input"config"}in
  let claim=R.{chain_id=optional "claim_chain";config_hash=optional "claim_config";catchup_head_epoch=(match member"catchup"input with `Null->None|v->Some(Int64.of_string(to_string v)))}in
  (if member"prior"input=`Bool true then R.validate_prior else R.validate) ~runtime ~head_epoch:(i input"head") claim |>result(fun()->`Null)
 |"trace"->let state=ref(match member"initial"input with `Null->F.empty|`String v->F.of_string(Base64.decode_exn v)|>Result.get_ok|_->assert false)in
 `List(member"steps"input|>to_list|>List.map(fun step->
  let cap=if member"prune"step=`Bool true then F.Prune else Reject in
  let update r=result(fun v->state:=v;`Null)r in
  let answer=match s step"op"with
   |"set"->update(F.note_set config ~epoch:(i step"at") ~active:(bytes_list step"active") !state)
   |"lock"->F.lock config ~active:(bytes_list step"active") !state|>result(fun(v,changed)->state:=v;`Bool changed)
   |"delay"->update(F.delay config ~at:(i step"at") !state)
   |"pulse"->update(F.note_pulse ~cap_mode:cap ?credit:(match member"credit"step with `Null->None|v->Some(Int64.of_string(to_string v))) config ~epoch:(i step"at") ~active:(member"active"step|>to_bool) ~address:(raw step"address") !state)
   |"final"->update(F.note_final ~cap_mode:cap config ~at:(i step"at") ~active:(bytes_list step"active") ~final:(final(member"final"step)) ~signers:(bytes_list step"signers") !state)
   |"parent_final"->let p=parent(member"parent"step)in update(F.note_final ~cap_mode:cap config ~at:(i step"at") ~active:(bytes_list step"active") ~final:(parent_final p) ~signers:(bytes_list step"signers") !state)
   |"advance"->F.advance ~cap_mode:cap config ~chain_id:(raw step"chain") ~start:(i step"start") ~at:(i step"at") ~parent:(match member"parent"step with `Null->None|j->Some(parent j)) !state|>result(fun(v,reason,changed)->state:=v;`List[opt(fun s->`String s)reason;`Bool changed])
   |"proof"->let commit=parent(member"parent"step)in let j=member"vote"step in
    let vote=C_types.{chain_id=raw j"chain";epoch_id=i j"epoch";round=n j"round";vote_type=(if n j"type"=2 then Precommit else Prevote);proposal_id=(if member"other_pid"j=`Bool true then String.make 32 '\009'else commit.certificate.proposal_id);validator=raw j"owner";signature=""}in
    let vote={vote with signature=(if member"corrupt"j=`Bool true then String.make 64 '\000'else sign(n j"signer")(C_hash.vote_sign_bytes vote))}in
    let proof=F.{vote;commit}in
    update(F.apply_proof ~cap_mode:cap config ~chain_id:(raw step"chain") ~epoch:(i step"at") ~active:(member"active"step|>to_bool) ~address:(raw step"address") proof !state)
   |"reference"->R.reference ~epoch:(i step"at") ~head:(i step"head") ~proposal:(match member"proposal"step with `String"auto"->Some(let p=parent(member"parent"step)in String.concat ""(List.init 32(fun i->Printf.sprintf "%02x"(Char.code p.certificate.proposal_id.[i]))))|`String v->Some(Base64.decode_exn v)|_->None) ~parent:(match member"parent"step with `Null->None|j->Some(parent j)) ~state:!state |>result(fun()->`Null)
   |"reload"->update(F.of_string(F.to_string !state))
   |"query"->`Null
   |_->failwith"step"
  in
  let source=i step"source"and start=i input"start"in
  let probes=bytes_list input"probes"in
  let candidates=List.map(fun address->Octra_core.Validator_admission.{address;pubkey=String.make 32 '\000';bond=Z.one;bonded_epoch=0L;ready_epoch=None;exit_epoch=None})probes in
  let selected,counts=F.filter config ~start ~source candidates !state in
  `Assoc["result",answer;"state",b64(F.to_string !state);"seats",opt(fun n->`Int n)(F.seats !state);
   "probes",`List(List.map(fun address->let receipt=F.receipt ~address !state in `Assoc["allows",`Bool(F.allows config ~start ~source ~address !state);"exclude",opt exclusion(F.exclusion config ~start ~source ~address !state);"marks",`List(List.map number receipt.marked);"pulse",opt number receipt.pulse])probes);
   "filter",`List[`List(List.map(fun(c:Octra_core.Validator_admission.candidate)->b64 c.address)selected);`Int counts.live;`Int counts.shadow;`Int counts.allowed]]))
 |_->failwith"kind"
let ()=let cases=Yojson.Safe.from_channel stdin|>to_list in let out=List.mapi(fun index input->try `Assoc["input",input;"expected",run input]with e->Printf.eprintf "case=%d error=%s\n%!"index(Printexc.to_string e);raise e)cases in Yojson.Safe.to_channel stdout(`List out);print_newline()
