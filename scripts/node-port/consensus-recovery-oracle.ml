open Yojson.Safe.Util
open Octra_consensus
module R=Native_relief
module F=C_finality_query
module Q=C_root_query
module W=C_codec
let hex s=String.concat ""(List.init(String.length s)(fun i->Printf.sprintf "%02x"(Char.code s.[i])))
let unhex s=String.init(String.length s/2)(fun i->Char.chr(int_of_string("0x"^String.sub s(i*2)2)))
let str j k=j|>member k|>to_string
let raw j k=unhex(str j k)
let int j k=j|>member k|>to_int
let i64 j k=Int64.of_string(str j k)
let bool j k=j|>member k|>to_bool
let catch f=try f()with Failure e|Invalid_argument e->`Assoc["error",`String e]|e->`Assoc["error",`String(Printexc.to_string e)]
let result f=function Ok v->f v|Error e->`Assoc["error",`String e]
let unit()=`Null
let key id=match Mirage_crypto_ec.Ed25519.priv_of_octets(String.make 32(Char.chr id))with Ok k->k|Error _->failwith"key"
let pub id=Mirage_crypto_ec.Ed25519.(pub_to_octets(pub_of_priv(key id)))
let address id="validator-"^string_of_int id
let validators j k weighted=
 let entries=member k j|>to_list|>List.map(fun m->({C_types.address=address(int m"id");pubkey=pub(int m"key")},Z.of_string(str m"weight")))in
 if weighted then(match C_types.make_weighted_validator_set entries with Ok x->x|Error e->failwith e)else C_types.make_validator_set(List.map fst entries)
let sync j=
 let s:W.round_sync={chain_id=raw j"chain";epoch_id=i64 j"height";round=int j"round";step=C_types.round_step_of_u8(int j"step");request=bool j"request";validator=address(int j"id");signature=String.make 64 '\000'}in
 {s with signature=if bool j"corrupt"then s.signature else Mirage_crypto_ec.Ed25519.sign ~key:(key(int j"id"))(C_hash.round_sync_sign_bytes s)}
let mark(m:R.mark)=`Assoc["height",`String(Int64.to_string m.height);"round",`Int m.round;"activate",`String(Int64.to_string m.activate_epoch);"source",`String(hex m.source_hash);"target",`String(hex m.target_hash);"fingerprint",`String(hex m.fingerprint);"proof",`List(List.map(fun s->`String(hex(W.encode_round_sync s)))m.proof)]
let execute j=catch(fun()->match str j"op"with
|"protocol"->let value=match member"value"j with`Null->None|x->Some(unhex(to_string x))in let get _=value in result(fun n->`Assoc["activation",`String(Int64.to_string n);"id",`String(C_protocol.consensus_id get);"version",`Int(C_protocol.version_at ~activation_epoch:n(i64 j"epoch"))])(C_protocol.activation_epoch_of get)
|"route"->let scope=F.request_scope ~complete_request:(bool j"complete_request")~finality_request:(bool j"finality_request")and proof=F.response_proof ~complete_valid:(bool j"complete")~legacy_valid:(bool j"legacy")~legacy_complete:(bool j"legacy_complete")in
 `String(match F.response_route scope proof with F.Complete_response->"complete"|F.Legacy_range_response->"legacy"|F.Finality_response->"finality"|F.Ignore_legacy_response->"ignore"|F.Reject_response->"reject")
|"query"->let state=if bool j"idle"then F.Idle else F.Sent{epoch=i64 j"prior_epoch";attempts=int j"attempts";sent_at=i64 j"sent_at"}in
 (match F.plan ~now:(i64 j"now")~epoch:(i64 j"epoch")state with F.Wait->`String"wait"|F.Rest->`String"rest"|F.Send F.Idle->assert false|F.Send(F.Sent s)->`Assoc["epoch",`String(Int64.to_string s.epoch);"attempts",`Int s.attempts;"sent_at",`String(Int64.to_string s.sent_at)])
|"roots"->let q=ref Q.empty and leases=Hashtbl.create 16 in
 `List(member"steps"j|>to_list|>List.map(fun step->let epoch=i64 step"epoch"and name=int step"lease"in
 let answer=match str step"op"with
 |"join"->(match Q.join ~epoch !q with Error e->`String e|Ok(next,l)->q:=next;Hashtbl.replace leases name l;`Null)
 |"add"->q:=Q.add ~epoch ~same:String.equal(raw step"value")!q;`Null
 |"leave"->q:=Q.leave(Hashtbl.find leases name)!q;`Null
 |"read"->`List(List.map(fun x->`String(hex x))(Q.read(Hashtbl.find leases name)!q))
 |_->failwith"root op"in `Assoc["answer",answer;"listening",`Bool(Q.listening ~epoch !q)]))
|"relief"->let current=validators j"current"(bool j"weighted")and target=validators j"target"(bool j"target_weighted")in
 let chain_id=raw j"chain"and height=i64 j"height"and activate_epoch=i64 j"activate"and fingerprint=raw j"fingerprint"and proof=member"proof"j|>to_list|>List.map sync in
 let decision=R.decide ~chain_id ~height ~current ~activate_epoch ~target ~fingerprint ~proof in
 let restore=match decision with
 |R.Wait|R.Refuse _->`Null
 |R.Apply m->let m=match str j"mutation"with
 |"height"->{m with height=Int64.succ height}|"activation"->{m with activate_epoch=Int64.succ activate_epoch}|"fingerprint"->{m with fingerprint="bad"}|"source"->{m with source_hash=String.make 32 '\000'}|"target"->{m with target_hash=String.make 32 '\000'}|"round"->{m with round=m.round+1}|"proof"->{m with proof=[]}|"inactive"->{m with height=1L}|_->m in
 result(function None->`Bool false|Some _->`Bool true)(R.restore ~chain_id ~height:(i64 j"restore_height")~current ~activate_epoch ~target ~fingerprint m)in
 `Assoc["set",result unit(R.check_set current target);"plan",result unit(R.check_plan ~height ~current ~activate_epoch ~target ~fingerprint);"proof",result(fun(r,proof)->`Assoc["round",`Int r;"proof",`List(List.map(fun s->`String(hex(W.encode_round_sync s)))proof)])(R.check_proof ~chain_id ~height current proof);"decision",(match decision with R.Wait->`String"wait"|R.Refuse e->`Assoc["refuse",`String e]|R.Apply m->mark m);"restore",restore]
|_->failwith"op")
let ()=Yojson.Safe.from_file Sys.argv.(1)|>to_list|>List.map(fun j->`Assoc["input",j;"expected",execute j])|>fun xs->Yojson.Safe.to_channel stdout(`List xs)
