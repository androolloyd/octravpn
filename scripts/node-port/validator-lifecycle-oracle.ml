open Yojson.Safe.Util
open Octra_consensus
module A=Octra_core.Validator_admission
module R=Octra_core.Validator_registry
module P=Octra_core.Validator_policy
module E=Octra_core.Validator_evidence
let s j k=member k j|>to_string
let n j k=member k j|>to_int
let i j k=Int64.of_string(s j k)
let z j k=Z.of_string(s j k)
let raw j k=Base64.decode_exn(s j k)
let b64 s=`String(Base64.encode_exn s)
let number n=`String(Int64.to_string n)
let opt f=function None->`Null|Some v->f v
let result f=function Ok v->f v|Error e->`Assoc["error",`String e]
let key id=Mirage_crypto_ec.Ed25519.priv_of_octets(String.make 32(Char.chr id))|>Result.get_ok
let pub id=Mirage_crypto_ec.Ed25519.(pub_to_octets(pub_of_priv(key id)))
let sign id msg=Mirage_crypto_ec.Ed25519.sign ~key:(key id) msg
let address id=pub id|>Base64.encode_exn|>Octra_core.Crypto.Address.address_from_pubkey
let params j=A.{min_bond=z j"min";max_validators=n j"max";activation_delay=i j"delay";unbonding_epochs=i j"wait"}
let candidate j=A.{address=raw j"address";pubkey=raw j"key";bond=z j"bond";bonded_epoch=i j"bonded";ready_epoch=(match member"ready"j with `Null->None|v->Some(Int64.of_string(to_string v)));exit_epoch=(match member"exit"j with `Null->None|v->Some(Int64.of_string(to_string v)))}
let snapshot s=A.( `Assoc["source",number s.source_epoch;"activate",number s.activate_epoch;"validators",`List(List.map(fun(v:member)->`List[b64 v.address;b64 v.pubkey;`String(Z.to_string v.weight)])s.validators);"total",`String(Z.to_string s.total_weight);"quorum",`String(Z.to_string s.quorum_weight);"fingerprint",`String s.fingerprint])
let snapshot_output input snap=
 let signers=member"signers"input|>to_list|>List.map(fun v->Base64.decode_exn(to_string v))in
 `Assoc["snapshot",snapshot snap;"signed",result(fun v->`String(Z.to_string v))(A.signed_weight snap signers);"quorum",result(fun v->`Bool v)(A.has_quorum snap signers);"leader",result(fun(v:A.member)->b64 v.address)(A.leader snap ~seed:(raw input"seed") ~epoch_id:(i input"epoch") ~round:(n input"round"))]
let vote step id pid=
 let v=C_types.{chain_id=raw step"chain";epoch_id=i step"vote_epoch";round=n step"round";vote_type=Precommit;proposal_id=String.make 32(Char.chr pid);validator=address(n step"offender");signature=""}in
 {v with signature=(if member"corrupt"step=`Bool true then String.make 64 '\000' else sign id(C_hash.vote_sign_bytes v))}
let run input=match s input"kind"with
 |"decode"->R.of_string(raw input"raw")|>result(fun v->b64(R.to_string v))
 |"policy"->let raw=match member"raw"input with `Null->None|`String v->Some(Base64.decode_exn v)|_->assert false in
 P.of_env(fun _->raw)|>result(fun p->let mode=if member"active"input=`Bool true then Octra_core.Rule_graph.Active else Prior in
  `Assoc["id",`String(P.consensus_id p);"activation",opt(fun n->`String(string_of_int n))(P.activation_epoch p);"lifecycle",`Bool(P.lifecycle_enabled p);"snapshot",opt number(P.snapshot_activation p ~source_epoch:(i input"source"));"custom",(try opt number(P.snapshot_at p ~source_epoch:(i input"source") ~cadence:(i input"cadence") ~delay:(i input"delay"))with Division_by_zero->`Assoc["error",`String"Division_by_zero"]);"wait",number(P.exit_parameters mode P.parameters).unbonding_epochs;"evidence",number(P.evidence_age mode(i input"window"))])
 |"snapshot"->A.snapshot ~incumbents:(member"incumbents"input|>to_list|>List.map(fun v->Base64.decode_exn(to_string v))) (params(member"parameters"input)) ~activate_epoch:(i input"activate") (member"candidates"input|>to_list|>List.map candidate)|>result(snapshot_output input)
 |"sequence"->let registry=ref R.empty in let parameters=params(member"parameters"input)in
 `List(member"steps"input|>to_list|>List.map(fun step->
  let update r=result(fun next->registry:=next;`Null)r in
  let payout r=result(fun(next,amount)->registry:=next;`String(Z.to_string amount))r in
  let out=match s step"op"with
   |"bond"->let id=n step"key"and addr=address(n step"address")and amount=z step"amount"and nonce=n step"nonce"and chain=raw step"chain"in
     let msg=R.bond_message ~chain_id:chain ~address:addr ~amount:(if member"proof_amount"step=`Null then amount else z step"proof_amount") ~nonce ~pubkey:(pub id)in
     let payload=R.{consensus_pubkey_b64=Base64.encode_exn(pub id);proof_b64=(if member"corrupt"step=`Bool true then "bad"else Base64.encode_exn(sign id msg))}in
     let sender=if member"sender"step=`String"bad"then "bad"else Base64.encode_exn(pub(n step"sender"))in
     update(R.apply_bond parameters ~chain_id:chain ~epoch:(i step"epoch") ~address:addr ~sender_pubkey_b64:sender ~amount ~nonce payload !registry)
   |"ready"->update(R.mark_ready ~epoch:(i step"epoch") ~address:(address(n step"address")) ~consensus_pubkey_b64:(if member"key"step=`String"bad"then "bad"else Base64.encode_exn(pub(n step"key"))) !registry)
   |"exit"->update(R.request_exit ~epoch:(i step"epoch") ~address:(address(n step"address")) !registry)
   |"withdraw"->payout(R.withdraw parameters ~current_epoch:(i step"epoch") ~active_addresses:(member"active"step|>to_list|>List.map(fun v->address(to_int v))) ~address:(address(n step"address")) !registry)
   |"slash"->let offender=address(n step"offender")in (match R.find offender !registry with None->`Assoc["error",`String"validator bond not found"]|Some candidate->
     let conflict=C_evidence.vote_conflict(vote step(n step"signer")1)(vote step(n step"signer")2)|>Option.get in
     E.verify ~chain_id:(raw step"expected_chain") ~current_epoch:(i step"epoch") ~evidence_epochs:(i step"window") ~bonded_epoch:candidate.bonded_epoch ~address:offender ~pubkey:candidate.pubkey (E.proof_of_message(Some(E.message conflict))|>Result.get_ok)
     |>result(fun evidence->payout(R.apply_slash ~current_epoch:(i step"epoch") ~evidence_epochs:(i step"window") evidence !registry)))
   |"reload"->update(R.of_string(R.to_string !registry))
   |"snapshot"->R.snapshot parameters ~activate_epoch:(i step"epoch") !registry|>result snapshot
   |_->failwith"step"
  in `Assoc["result",out;"state",b64(R.to_string !registry)]))
 |_->failwith"kind"
let ()=let cases=Yojson.Safe.from_channel stdin|>to_list|>List.map(fun input->`Assoc["input",input;"expected",run input])in Yojson.Safe.to_channel stdout(`List cases);print_newline()
