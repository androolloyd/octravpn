(* Qualification uses the unmodified native network modules. *)
open Yojson.Safe.Util
module N=Octra_net
module R=N.P2p_peer_record
module G=N.P2p_peer_guard
module E=N.P2p_endpoint
let bytes v=Base64.decode_exn(to_string v)
let b64 v=`String(Base64.encode_exn v)
let s j k=bytes(member k j)
let n j k=to_int(member k j)
let f j k=to_number(member k j)
let optional j k=match member k j with `Null->None|v->Some(bytes v)
let error exn=match exn with Failure s|Invalid_argument s->s|_->Printexc.to_string exn
let catch run=try run()with e->`Assoc["error",b64(error e)]
let key j=match Mirage_crypto_ec.Ed25519.priv_of_octets(s j "seed")with Ok k->k|Error _->failwith"seed"
let make j=
 let k=key j in let pub=Mirage_crypto_ec.Ed25519.(pub_of_priv k|>pub_to_octets)in
 let pubkey=Option.value(optional j "public_key")~default:pub in
 let r:R.t={chain_id=s j "chain_id";node_id=Option.value(optional j "node_id")~default:(R.node_id_of_pubkey pubkey);node_addr=s j "address";pubkey;binary_hash=s j "binary";config_hash=s j "config";host=s j "host";port=n j "port";features=member"features"j|>to_list|>List.map bytes;ts=member"timestamp"j|>to_string|>Int64.of_string;signature=String.make 64 '\000'}in
 let signature=match optional j "signature"with Some s->s|None->Mirage_crypto_ec.Ed25519.sign ~key:k(R.sign_bytes r)in {r with signature}
let score key (s:G.score_record)=`Assoc["key",b64 key;"bad",`Int s.bad_count;"connections",`Int s.conn_count;"until",`Float s.ban_until;"reason",b64 s.last_reason;"frames",`Int s.invalid_frame_count;"signatures",`Int s.bad_signature_count;"stale",`Int s.stale_root_count]
let endpoint e=b64(E.to_string e)
let run j=catch(fun()->match member"op"j|>to_string with
|"record"->let r=make(member"record"j)in
 `Assoc["wire",b64(R.encode r);"sign_bytes",b64(R.sign_bytes r);"validation",(match R.validate ?binary_hash:(optional j "binary") ~chain_id:(s j "chain") ~config_hash:(s j "config") ~allowed_pubkeys:(member"allowed"j|>to_list|>List.map bytes)r with R.Valid->`Null|R.Invalid reason->b64 reason)]
|"decode"->let r=make(member"record"j)in
 let list=member"list"j|>to_bool in
 let wire=if list then R.encode_list(List.init(n j "count")(fun _->r))else R.encode r in
 let wire=match member"cut"j with `Null->wire|v->String.sub wire 0 (min(String.length wire)(to_int v))in
 let wire=match member"offset"j with `Null->wire|v->let b=Bytes.of_string wire in Bytes.set b(to_int v)(Char.chr(n j "byte"));Bytes.to_string b in
 let wire=wire^s j "append"in
 if list then b64(R.encode_list(R.decode_list wire))else b64(R.encode(R.decode wire))
|"bucket"->b64(R.bucket_of_host(s j "host"))
|"registry"->let registry=N.P2p_peer_registry.create ~ttl_s:(f j "ttl") ~max_per_bucket:(n j "maximum")()in
 let steps=member"steps"j|>to_list|>List.map(fun step->let now=f step "now"in
 let result=match member"kind"step|>to_string with
 |"clear"->N.P2p_peer_registry.clear registry;`Null
 |"add"->(match N.P2p_peer_registry.add ~now registry(make(member"record"step))with Added->`String"new"|Refreshed->`String"refreshed"|Rejected reason->`String reason)
 |_->`Null in
 `Assoc["result",result;"values",`List(List.map(fun r->b64(R.encode r))(N.P2p_peer_registry.values ~now registry))])in `List steps
|"guard"->let guard=G.create()in let cfgj=member"config"j in
 let cfg:G.cfg={bad_window_s=f cfgj"bad_window";max_bad=n cfgj"max_bad";ban_s=f cfgj"ban";conn_window_s=f cfgj"connection_window";max_conn=n cfgj"max_connections"}in
 let steps=member"steps"j|>to_list|>List.map(fun step->let now=f step"now"and key=s step"key"in
 match member"kind"step|>to_string with
 |"admit"->(match G.admit_conn ~cfg guard ~now ~key with Accept->`Null|Drop reason->`String reason)
 |"report"->(match G.report_bad ~cfg guard ~now ~key ~reason:(s step"reason")with Noted count->`Assoc["noted",`Int count]|Banned until->`Assoc["banned",`Float until])
 |"prune"->G.prune ~ttl:(f step"ttl") ~max_entries:(n step"maximum")guard ~now;`Null
 |_->`Bool(G.is_banned guard ~now ~key))in
 `Assoc["results",`List steps;"scores",`List(List.map(fun(s:G.score_record)->score s.key s)(G.snapshot guard))]
|"guard_key"->`Assoc["host",b64(G.host_of_addr(s j"value"));"identity",b64(G.identity_key(s j"value"));"penalty",(match G.handshake_penalty(s j"value")with None->`Null|Some p->`String p)]
|"endpoint"->`Assoc["parsed",(match E.of_string(s j"value")with None->`Null|Some e->endpoint e);"csv",`List(List.map endpoint(E.list_of_csv(s j"value")))]
|"bootstrap"->Unix.putenv"OCTRA_BOOTSTRAP_PEERS"(s j"base");Unix.putenv"OCTRA_BOOTSTRAP_PEERS_EXTRA"(s j"extra");`List(List.map endpoint(E.bootstrap(member"configured"j|>to_list|>List.map bytes)))
|_->failwith"operation")
let ()=let cases=Yojson.Safe.from_channel stdin|>to_list|>List.map(fun input->`Assoc["input",input;"expected",run input])in Yojson.Safe.to_channel stdout(`List cases);print_newline()
