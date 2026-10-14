open Yojson.Safe.Util
open Octra_consensus
module V=Native_vote
module C=C_codec
module S=Native_sync
let seed=String.make 32 '\001'
let sk=match Mirage_crypto_ec.Ed25519.priv_of_octets seed with Ok k->k|Error _->failwith "key"
let pub=Mirage_crypto_ec.Ed25519.(pub_of_priv sk|>pub_to_octets)
let hex b=String.concat""(List.init(String.length b)(fun i->Printf.sprintf"%02x"(Char.code b.[i])))
let unhex s=String.init(String.length s/2)(fun i->Char.chr(int_of_string("0x"^String.sub s(i*2)2)))
let raw j k=j|>member k|>to_string|>unhex
let str j k=j|>member k|>to_string
let int j k=j|>member k|>to_int
let i64 j k=str j k|>Int64.of_string
let err=function Failure s|Invalid_argument s->s|e->Printexc.to_string e
let catch f=try f()with e->`Assoc["error",`String(err e)]
let result f=function Ok v->f v|Error e->`Assoc["error",`String e]
let opt f=function None->`Null|Some x->f x
let vote v=`String(hex(C.encode_vote v))
let pos(p:V.record_position)=`Assoc["epoch",`String(Int64.to_string p.epoch_id);"round",`Int p.round]
let temp()=let p=Filename.temp_file"octra-journal"""in Sys.remove p;Unix.mkdir p 0o700;p
let write p wire=let f=open_out_bin p in output_string f wire;close_out f
let rec remove p=if Sys.is_directory p then(Sys.readdir p|>Array.iter(fun n->remove(Filename.concat p n));Unix.rmdir p)else Sys.remove p
let sync j =
 let s:C.round_sync={chain_id=raw j "chain";epoch_id=i64 j "epoch";round=int j "round";step=C_types.round_step_of_u8(int j "step");request=(j|>member "request"|>to_bool);validator=raw j "validator";signature=String.make 64 '\000'}in
 {s with signature=if j|>member "corrupt"|>to_bool then String.make 64 '\000'else Mirage_crypto_ec.Ed25519.sign ~key:sk(C_hash.round_sync_sign_bytes s)}
let verify s=C_hash.verify_round_sync ~pubkey_raw:pub s
let execute j=catch(fun()->match str j"op"with
 |"sync_meta"->let s=sync j in `Assoc["key",`String(hex(S.key s));"name",`String(S.name s);"valid",`Bool(S.valid s);"wire",`String(hex(C.encode_round_sync s))]
 |"sync_epoch"->opt(fun n->`String(Int64.to_string n))(S.epoch_of_name(raw j "value"))
 |"sync_trace"->let dir=temp()in Fun.protect ~finally:(fun()->remove dir)(fun()->let store=if str j "mode"="disk"then S.disk ~data_dir:dir else S.memory()in
  `List(member "steps"j|>to_list|>List.map(fun step->catch(fun()->match str step "op"with
   |"keep"->result(fun s->`String(hex(C.encode_round_sync s)))(S.keep store ~verify(sync step))
   |"load"->result(fun xs->`List(List.map(fun s->`String(hex(C.encode_round_sync s)))xs))(S.load store ~chain_id:(raw step "chain")~validator:(raw step "validator")~epoch_id:(i64 step "epoch")~verify)
   |"prune"->result(fun()->`Null)(S.prune store ~through_epoch:(i64 step "epoch"))
   |_->failwith"sync op"))))
 |"meta"->let v=C.decode_vote(raw j"wire")in `Assoc["key",`String(hex(V.key v));"name",`String(V.name v);"position",opt pos(V.record_position(V.name v));"wire",result vote(V.vote_of_wire(raw j"wire"))]
 |"decode"->result vote(V.vote_of_wire(raw j"wire"))
 |"position"->opt pos(V.record_position(raw j"value"))
 |"floor"|"mark"as kind->let p=Filename.temp_file"octra-mark"""in Fun.protect ~finally:(fun()->Sys.remove p)(fun()->write p(raw j"wire");if kind="floor"then result(fun n->`String(Int64.to_string n))(V.read_floor p)else result(fun(e,r)->`Assoc["epoch",`String(Int64.to_string e);"round",`Int r])(V.read_round_mark p))
 |"trace"->let dir=temp()in Fun.protect ~finally:(fun()->remove dir)(fun()->let store=if str j"mode"="disk"then V.disk ~data_dir:dir else V.memory()in
  `List(member"steps"j|>to_list|>List.map(fun step->let round=int step"round"and epoch=i64 step"epoch"in
   let value=catch(fun()->match str step"op"with
   |"floor"->result(fun()->`Null)(V.set_floor store ~through_epoch:epoch)
   |"mark"->result(fun()->`Null)(V.set_round_mark store ~epoch_id:epoch ~round)
   |"keep"->let v=C.decode_vote(raw step"wire")in result vote(V.keep store v)
   |"check"->let v=C.decode_vote(raw step"wire")in result(fun()->`Null)(V.check store v)
   |"find"->let v=C.decode_vote(raw step"wire")in result(opt vote)(V.find_statement store ~chain_id:v.chain_id ~validator:v.validator ~epoch_id:v.epoch_id ~round:v.round ~vote_type:v.vote_type ~proposal_id:v.proposal_id)
   |"prune"->result(fun()->`Null)(V.prune store ~through_epoch:epoch)
   |"corrupt"->let v=C.decode_vote(raw step"wire")in let path=Filename.concat dir"vote_log"in ignore(V.directory path);write(Filename.concat path(V.name v))(raw step"data");`Null
   |_->`Null)in
   `Assoc["result",value;"floor",result(opt(fun n->`String(Int64.to_string n)))(V.floor store);"mark",result(opt(fun(e,r)->`Assoc["epoch",`String(Int64.to_string e);"round",`Int r]))(V.round_mark store);"max",result(opt(fun r->`Int r))(V.max_round store ~chain_id:(raw j"chain")~validator:(raw j"validator")~epoch_id:epoch)])))
 |_->failwith"op")
let ()=Yojson.Safe.from_file Sys.argv.(1)|>to_list|>List.map(fun j->`Assoc["input",j;"expected",execute j])|>fun xs->Yojson.Safe.to_channel stdout(`List xs)
