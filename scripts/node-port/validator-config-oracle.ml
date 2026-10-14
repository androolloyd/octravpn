open Yojson.Safe.Util
open Octra_consensus
module C=Octra_core
module V=Octra_node_runtime.Validator_config
module A=Octra_node_runtime.Consensus_validator_anchor
let s j k=member k j|>to_string
let i j k=Int64.of_string(s j k)
let raw v=Base64.decode_exn(to_string v)
let b64 s=`String(Base64.encode_exn s)
let opt f=function None->`Null|Some x->f x
let option=function `Null->None|v->Some(raw v)
let list j k=member k j|>to_list
let key id=Mirage_crypto_ec.Ed25519.priv_of_octets(String.make 32(Char.chr id))|>Result.get_ok
let pub id=Mirage_crypto_ec.Ed25519.(pub_to_octets(pub_of_priv(key id)))
let address id=C.Crypto.Address.address_from_pubkey(Base64.encode_exn(pub id))
let entry=function
 |`Int id->address id^":"^Base64.encode_exn(pub id)
 |`String v->Base64.decode_exn v
 |j->let id=member"id"j|>to_int in let addr=match member"address"j with `Null->address id|v->raw v in
      let key=match member"key"j with `Null->Base64.encode_exn(pub id)|v->raw v in addr^":"^key
let entries j k=list j k|>List.map entry
let update=function
 |`Null->None|`String v->Some(Base64.decode_exn v)
 |j->let weighted=member"weighted"j<>`Bool false in
 let validators=list j"ids"|>List.mapi(fun index id->let id=to_int id in
  let weight=match member"weights"j with `List ws->List.nth ws index|_->`String"1"in
  `Assoc(["address",`String(address id);"pubkey",`String(Base64.encode_exn(pub id))]@(if weighted then ["weight",weight]else[])))in
 let fields=["activate_epoch",member"epoch"j;"validators",`List validators]in
 let fields=if weighted then fields@["weighted",`Bool true;"standard",`String"bonded_stake";"source_epoch",member"source"j]else fields in
 Some(Yojson.Safe.to_string(`Assoc fields))
let validator (v:C_types.validator_info)=`List[b64 v.address;b64 v.pubkey]
let set v=b64(C_codec.encode_validator_set v)
let schedule (s:C_driver.scheduled_validator_set_config)=`List[`String(Int64.to_string s.activate_epoch);set s.validator_set;b64 s.fingerprint]
let light (s:C_config.scheduled)=`List[`String(Int64.to_string s.activate_epoch);set s.validator_set]
let transition=function V.No_transition->`Null|Already_active{activate_epoch}->`List[`String"active";`String(Int64.to_string activate_epoch)]|Scheduled{activate_epoch;n;quorum;fingerprint}->`List[`String"scheduled";`String(Int64.to_string activate_epoch);`Int n;`Int quorum;b64 fingerprint]
let dump (c:V.t)=`Assoc[
 "allowed",`List(List.map b64 c.allowed_pubkeys);"errors",`List(List.map b64 c.identity_errors);
 "program",opt b64 c.program_trust_hash;"profile",opt b64 c.runtime_profile_hash;
 "current",`List(List.map validator c.current_validator_list);"next",`List(List.map validator c.next_validator_list);"members",`List(List.map validator c.active_validator_list);
 "stake",set c.stake_vs;"active",set c.active_vs;"scheduled",opt schedule c.scheduled_driver_config;"light",opt light c.light_scheduled_validator_set;"hash",b64 c.consensus_config_hash;"transition",transition c.transition]
let event=function V.Startup_info m->`List[`String"info";b64 m]|Startup_warn m->`List[`String"warn";b64 m]|Startup_refuse ms->`List[`String"refuse";`List(List.map b64 ms)]
let admission cfg input=let address=match member"self"input with `Int id->address id|v->raw v in
 V.node_startup_admission ~getenv:(function "OCTRA_VALIDATOR_ADMISSION_ACTIVATION_EPOCH"->option(member"admission"input)|"OCTRA_ALLOW_UNSAFE_QUORUM"->option(member"unsafe"input)|_->None)
 ~activation_epoch:(fun()->match member"activate"input with `Null->None|v->Some(Int64.of_string(to_string v))) ~address ~voting:(member"voting"input=`Bool true) ~role_label:(raw(member"role"input)) cfg|>List.map event|>fun v->`List v
let outcome cfg input=`Assoc["config",dump cfg;"message",opt b64(V.transition_message ~current_height:(i input"height")cfg);"admission",admission cfg input;"effective",`List(List.map(fun epoch->set(C_driver.validator_set_at ~chain_id:(raw(member"chain"input)) ~current:cfg.stake_vs ~epoch cfg.scheduled_driver_config))[i input"height";Int64.succ(i input"height");63L;64L;127L;128L;1306546L;1306547L])]
let anchor input current next active_raw pending_raw =
 let cfg=(V.build ~chain_id:(raw(member"chain"input)) ~consensus_mode:true ~current_height:(i input"height") ~current_entries:current ~next_entries:next ~chain_pending_entries:[] ~next_activation_epoch:None ~program_trust_hash:None)in
 let cfg=V.bind_persistent_updates ~chain_id:(raw(member"chain"input)) ~consensus_mode:true ~current_height:(i input"height") ~active_raw ~pending_raw cfg in
 let mark=match member"relief"input,cfg with
 |`Assoc _,Ok cfg->let scheduled=Option.get cfg.scheduled_driver_config in
   let height=i input"height"in let proof=List.init 5(fun index->let id=index+1 in
    let r=C_codec.{chain_id=raw(member"chain"input);epoch_id=height;round=64;step=PrecommitStep;request=false;validator=address id;signature=""}in
    {r with signature=Mirage_crypto_ec.Ed25519.sign ~key:(key id)(C_hash.round_sync_sign_bytes r)})in
   let m=match C_relief.decide ~chain_id:(raw(member"chain"input)) ~height ~current:cfg.active_vs ~activate_epoch:scheduled.activate_epoch ~target:scheduled.validator_set ~fingerprint:scheduled.fingerprint ~proof with Apply m->m|_->failwith"fixture relief refused"in
   let j=member"relief"input in Some {m with height=(if member"future"j=`Bool true then Int64.succ height else height);fingerprint=(if member"wrong"j=`Bool true then String.make 64 '0'else m.fingerprint);proof=(if member"bad_signature"j=`Bool true then List.map(fun (r:C_codec.round_sync)->{r with signature=String.make 64 '\000'})m.proof else m.proof)}
 |_->None in
 let source=A.{chain_id=raw(member"chain"input);current_height=(fun()->i input"height");active_raw=(fun()->active_raw);pending_raw=(fun()->pending_raw);
  getenv=(function "OCTRA_VALIDATORS"->Some(String.concat ","current)|"OCTRA_VALIDATORS_NEXT"->Some(String.concat ","next)|"OCTRA_VALIDATORS_ACTIVATE_EPOCH"->(match member"primary"input with `Null->(match member"activate"input with `Null->None|v->Some(to_string v))|v->Some(raw v))|"OCTRA_VALIDATORS_NEXT_EPOCH"->option(member"fallback"input)|_->None);
  relief=(fun _->if member"relief"input=`String"error"then Error"fixture relief unreadable"else Ok mark)}in
 let result=function Ok v->`Assoc["set",set v]|Error e->`Assoc["error",b64 e]in
 let queries=[i input"height";Int64.succ(i input"height");64L;128L;Int64.add(i input"height")32L]in
 let selected=queries|>List.map(fun epoch->`Assoc["stake",result(A.stake_set source ~epoch);"expected",`List(List.map(fun round->result(A.expected_set ?round source ~epoch))[None;Some(-1);Some 63;Some 64;Some 65])])in
 let mark_json=opt(fun(m:C_relief.mark)->`Assoc["height",`String(Int64.to_string m.height);"round",`Int m.round;"activate",`String(Int64.to_string m.activate_epoch);"source",b64 m.source_hash;"target",b64 m.target_hash;"fingerprint",b64 m.fingerprint;"proof",`List(List.map(fun p->b64(C_codec.encode_round_sync p))m.proof)])mark in
 `Assoc["mark",mark_json;"queries",`List selected]
let run input=
 let current=entries input"current"and next=entries input"next"and pending_entries=entries input"chain_pending"in
 let chain_id=raw(member"chain"input)and consensus_mode=member"consensus"input=`Bool true and current_height=i input"height"in
 let activate=match member"activate"input with `Null->None|v->Some(Int64.of_string(to_string v))in
 let base=V.build_full ~chain_id ~consensus_mode ~current_height ~current_entries:current ~next_entries:next ~chain_pending_entries:pending_entries ~next_activation_epoch:activate ~program_trust_hash:(option(member"program"input)) ~runtime_profile_hash:(option(member"profile"input))in
 let active_raw=update(member"active_raw"input)and pending_raw=update(member"pending_raw"input)in
 let bound=V.bind_persistent_updates ~chain_id ~consensus_mode ~current_height ~active_raw ~pending_raw base in
 let warnings=ref[]in
 let loaded=Lwt_main.run(V.load_node_persistent_update {read_pending=(fun()->Lwt.return pending_raw);warn=(fun e->warnings:=e::!warnings)})in
 let loaded=`Assoc["value",opt schedule loaded;"warnings",`List(List.map b64(List.rev !warnings))]in
 `Assoc["material",`Assoc["current",`List(List.map b64 current);"next",`List(List.map b64 next);"pending",`List(List.map b64 pending_entries);"active_raw",opt b64 active_raw;"pending_raw",opt b64 pending_raw];
 "anchor",anchor input current next active_raw pending_raw;"base",outcome base input;"bound",(match bound with Ok c->outcome c input|Error e->`Assoc["error",b64 e]);"loaded",loaded;"pending_entries",`List(List.map b64(V.pending_entries_of_raw pending_raw))]
let ()=let cases=Yojson.Safe.from_channel stdin|>to_list in Yojson.Safe.to_channel stdout(`List(List.map(fun input->`Assoc["input",input;"expected",run input])cases));print_newline()
