module U=Octra_core.Validator_set_update
module R=Octra_core.Validator_registry
module E=Octra_core.Validator_evidence
open Yojson.Safe.Util
let b64 v=`String(Base64.encode_exn v)
let opt f=function None->`Null|Some v->f v
let number v=`String(Int64.to_string v)
let extra chain binary config catchup shadow=`Assoc["chain",opt b64 chain;"binary",opt b64 binary;"config",opt b64 config;"catchup",opt number catchup;"shadow",opt(fun v->`String(string_of_int v))shadow]
let result f=function Ok v->`Assoc["ok",f v]|Error e->`Assoc["error",`String e]
let run input=
 let op=input|>member"operation"|>to_string in
 let message=match input|>member"message"with `String v->Some(Base64.decode_exn v)|_->None in
 match op with
 |"int64"->(try `String(Int64.to_string(Int64.of_string(Option.get message)))with _->`Null)
 |"int63"->(try `String(string_of_int(int_of_string(Option.get message)))with _->`Null)
 |"update"->U.of_message message|>result(fun(v:U.t)->`Assoc["activate",number v.activate_epoch;"source",opt number v.source_epoch;"weighted",`Bool v.weighted;"fingerprint",`String v.fingerprint;"validators",`List(List.map(fun (e:U.validator_entry)->`List[b64 e.address;b64 e.pubkey_b64;`String(Z.to_string e.weight)])v.validators)])
 |"legacy_ready"->U.ready_ext_of_message message|>result(fun(v:U.ready_ext)->`Assoc["fingerprint",b64 v.ready.fingerprint;"epoch",number v.ready.head_epoch;"root",b64 v.ready.state_root;"extra",extra v.extra.chain_id v.extra.binary_hash v.extra.config_hash v.extra.catchup_head_epoch v.extra.shadow_epochs])
 |"bonded_ready"->R.ready_payload_of_message message|>result(fun(v:R.ready_payload)->`Assoc["key",b64 v.consensus_pubkey_b64;"epoch",number v.head_epoch;"root",b64 v.state_root;"proposal",opt b64 v.head_proposal_id;"extra",extra v.chain_id v.binary_hash v.config_hash v.catchup_head_epoch v.shadow_epochs])
 |"bond"->R.bond_payload_of_message message|>result(fun(v:R.bond_payload)->`Assoc["key",b64 v.consensus_pubkey_b64;"proof",b64 v.proof_b64])
 |"evidence"->E.proof_of_message message|>result(fun(_v:E.proof)->`Null)
 |"admit"->Octra_core.Bft_control_admission.validate_message (Octra_core.Transaction.op_type_of_string(input|>member"op_type"|>to_string)|>Result.get_ok) message|>result(fun()->`Null)
 |_->failwith"unknown op"
let ()=let cases=Yojson.Safe.from_file Sys.argv.(1)|>to_list in print_endline("ORACLE_RESULT="^Yojson.Safe.to_string(`List(List.map(fun input->`Assoc["input",input;"output",run input])cases)))
