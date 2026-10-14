open Yojson.Safe.Util
module C=Octra_consensus
module R=Octra_node_runtime.Consensus_reward_attribution
module E=Octra_core.Epoch_exec
let hex s=String.concat ""(List.init(String.length s)(fun i->Printf.sprintf "%02x"(Char.code s.[i])))
let unhex s=String.init(String.length s/2)(fun i->Char.chr(int_of_string("0x"^String.sub s(i*2)2)))
let h s=`String(hex s)
let raw k j=member k j|>to_string|>unhex
let opt f=function None->`Null|Some x->f x
let attrib (a:R.t)=`Assoc["proposer",h a.proposer_addr;"key",opt h a.proposer_public_key;"validators",`List(List.map(fun(v:E.reward_validator)->`Assoc["address",h v.address;"key",opt h v.public_key;"weight",`String(Z.to_string v.weight)])a.validators)]
let result f=function Ok x->`Assoc["ok",f x]|Error e->`Assoc["error",`String e]
let run j=
 let set=C.C_codec.decode_validator_set(raw"validators"j)in
 let original=C.C_codec.decode_finalize(raw"wire"j)in
 let epoch=member"epoch"j|>to_string|>Int64.of_string in
 let chain=raw"chain"j in
 let original_parent=Some(C.C_parent_commit.decode(raw"parent_wire"j))in
 let parent=match member"parent"j|>to_string with
 |"none"->None
 |"empty"->Option.map(fun(p:C.C_types.parent_commit)->{p with certificate={p.certificate with precommits=[]}})original_parent
 |"unknown"->Option.map(fun(p:C.C_types.parent_commit)->{p with certificate={p.certificate with header={p.certificate.header with creator_addr="unknown"}}})original_parent
 |"unknown_member"->Option.map(fun(p:C.C_types.parent_commit)->{p with certificate={p.certificate with precommits=List.map(fun(v:C.C_types.vote)->{v with validator="unknown"})p.certificate.precommits}})original_parent
 |_ ->original_parent in
 let finalized={original with C.C_types.chain_id=chain;epoch_id=epoch;parent_commit=parent;header={original.header with chain_id=chain;epoch_id=epoch;proto_version=member"version"j|>to_int}}in
 let keys=List.map(fun(v:C.C_types.validator_info)->v.address,Base64.encode_exn v.pubkey)set.validators in
 let full=R.full_set ~proposer_addr:finalized.header.creator_addr ~validator_pubkeys:keys in
 let supplied=match member"supply"j|>to_string with
 |"parent"->(match parent with Some p->(match R.of_parent_commit p with Ok x->x|Error _->full)|None->full)
 |"reverse"->{full with validators=List.rev full.validators}
 |"weight"->{full with validators=List.map(fun(v:E.reward_validator)->{v with weight=Z.of_int 17})full.validators}
 |"bad_key"->{full with proposer_public_key=Some "%%%%"}
 |"short_key"->{full with proposer_public_key=Some "AA=="}
 |"duplicate"->{full with validators=full.validators@full.validators}
 |"empty"->{full with validators=[]}
 |"no_key"->{full with proposer_public_key=None}
 |_ ->full in
 Unix.putenv C.C_protocol.activation_env(member"activation"j|>to_string);
 let source=R.to_source supplied in
 `Assoc["supplied",attrib supplied;
 "source",result(fun s->h(Octra_net.Oce1.encode(fun b->C.C_reward_source.encode_into b s)))source;
 "roundtrip",result attrib(Result.bind source R.of_source);
 "bind",result attrib(R.bind_finality ~validator_set:set finalized supplied);
 "resolve",result attrib(R.resolve_for_epoch ~chain_id:chain ~epoch_id:epoch ~proposer_addr:finalized.header.creator_addr ~validator_pubkeys:keys parent)]
let ()=let cases=Yojson.Safe.from_channel stdin|>to_list|>List.map(fun input->`Assoc["input",input;"expected",run input])in Yojson.Safe.to_channel stdout(`List cases);print_newline()
