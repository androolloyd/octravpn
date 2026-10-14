open Yojson.Safe.Util
module G=Octra_net.P2p_tx_gossip_guard
module S=Octra_net.P2p_tx_seen
let raw v=Base64.decode_exn(to_string v)
let b v=`String(Base64.encode_exn v)
let f j k=member k j|>to_string|>float_of_string
let n j k=member k j|>to_int
let bits v=`String(Printf.sprintf "%016Lx"(Int64.bits_of_float v))
let run j=match member"op"j|>to_string with
|"seen"->let seen=ref S.empty in
 `List(member"steps"j|>to_list|>List.map(fun v->let now=f v"now"and key=raw(member"key"v)in
 let result=if member"remember"v|>to_bool then let next,fresh=S.step !seen ~now key in seen:=next;fresh else S.recent !seen ~now key in
 `Assoc["result",`Bool result;"size",`Int(S.size !seen)]))
|_->let g=G.create()in let c=member"config"j in
 let cfg={G.default with window_s=f c"window";max_msgs=n c"messages";max_bytes=n c"bytes";max_payload_bytes=n c"payload"}in
 let results=member"steps"j|>to_list|>List.map(fun v->let now=f v"now"in
 let result=if member"prune"v=`Bool true then(G.prune ~ttl:(f v"ttl") ~max_entries:(n v"maximum")g ~now;`Null)else(match G.admit ~cfg g ~now ~peer:(raw(member"key"v)) ~bytes:(n v"bytes")with Accept->`Null|Drop reason->`String reason)in
 `Assoc["result",result;"size",`Int(G.size g)])in
 let peers=Hashtbl.fold(fun k (v:G.bucket) acc->(k,v)::acc)g.G.peers[]|>List.sort(fun(a,_)(b,_)->String.compare a b)|>List.map(fun(k,v)->`Assoc["key",b k;"start_bits",bits v.G.start;"messages",`Int v.msgs;"bytes",`Int v.bytes;"last_bits",bits v.last_seen])in
 `Assoc["results",`List results;"peers",`List peers]
let ()=let cases=Yojson.Safe.from_channel stdin|>to_list|>List.map(fun input->`Assoc["input",input;"expected",run input])in Yojson.Safe.to_channel stdout(`List cases);print_newline()
