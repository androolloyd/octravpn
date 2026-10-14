open Yojson.Safe.Util
module M=Octra_net.P2p_tx_gossip
module P=Octra_node_runtime.P2p_tx_plan
let raw v=Base64.decode_exn(to_string v)
let b v=`String(Base64.encode_exn v)
let blob v=`Assoc["size",`Int(String.length v);"sha256",`String Digestif.SHA256.(digest_string v|>to_hex)]
let hashes j=member"hashes"j|>to_list|>List.map raw
let make j=match member"kind"j|>to_string with
 |"inv"->M.Inv(hashes j)|"get"->M.Get(hashes j)
 |_->M.Tx{hash=raw(member"hash"j);tx_json=String.make(member"length"j|>to_int)(Char.chr(member"byte"j|>to_int))}
let catch f=try f()with Failure s|Invalid_argument s->`Assoc["error",b s]
let run j=catch(fun()->
 let wire=M.encode(make j)in
 if member"op"j=`String"encode"then blob wire else
 let wire=match member"cut"j with `Null->wire|n->String.sub wire 0 (min(String.length wire)(to_int n))in
 let wire=match member"offset"j with `Null->wire|n->let out=Bytes.of_string wire in Bytes.set out(to_int n)(Char.chr(member"replacement"j|>to_int));Bytes.to_string out in
 let wire=wire^raw(member"append"j)in
 if member"op"j=`String"decode"then blob(M.encode(M.decode wire))else
 let has h=List.mem h(member"known"j|>to_list|>List.map raw)in
 let cfg={Octra_net.P2p_tx_gossip_guard.default with max_inv_request=member"requests"j|>to_int;max_get_reply=member"replies"j|>to_int}in
 match P.plan ~cfg ~has wire with
 |Request hashes->`Assoc["request",`List(List.map b hashes)]|Serve hashes->`Assoc["serve",`List(List.map b hashes)]|Receive{hash;tx_json}->`Assoc["hash",b hash;"json",blob tx_json]|Legacy->`String"legacy")
let ()=let cases=Yojson.Safe.from_channel stdin|>to_list|>List.map(fun input->`Assoc["input",input;"expected",run input])in Yojson.Safe.to_channel stdout(`List cases);print_newline()
