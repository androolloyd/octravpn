(* Real native gossip handler and admission with an observable queue boundary. *)
open Yojson.Safe.Util
module C=Octra_core
module T=C.Transaction
module H=Octra_node_runtime.P2p_tx_handler
module A=Octra_node_runtime.P2p_tx_admit
module M=Octra_net.P2p_tx_gossip
let raw v=Base64.decode_exn(to_string v)
let b v=`String(Base64.encode_exn v)
let optional j k=match member k j with `Null->None|v->Some(raw v)
let f j k=member k j|>to_string|>float_of_string
let n j k=member k j|>to_int
let seed j=String.make 32(Char.chr(n j"seed"))
let pub seed=let key=Mirage_crypto_ec.Ed25519.priv_of_octets seed|>Result.get_ok in Mirage_crypto_ec.Ed25519.(pub_of_priv key|>pub_to_octets)|>Base64.encode_exn
let make j=
 let key=pub(seed j)in
 let from=Option.value(optional j"from")~default:(C.Crypto.Address.address_from_pubkey key)in
 let tx:T.t={from;to_=Option.value(optional j"to")~default:("oct"^String.make 44 '1');amount=member"amount"j|>to_string|>Z.of_string;nonce=n j"nonce";ou=member"ou"j|>to_string|>Z.of_string;timestamp=f j"timestamp";signature="";public_key=Some key;message=optional j"message";encrypted_data=optional j"encrypted";op_type=T.op_type_of_string(member"op"j|>to_string)|>Result.get_ok}in
 let tx=T.sign_with_privkey tx(Base64.encode_exn(seed j))in
 let public_key=match member"public"j|>to_string with "none"->None|"empty"->Some""|"other"->Some(pub(String.make 32 '\099'))|_->tx.public_key in
 let signature=match member"signature"j|>to_string with "zero"->Base64.encode_exn(String.make 64 '\000')|"empty"->""|"newline"->tx.signature^"\n"|_->tx.signature in
 {tx with public_key;signature}
let prepared(tx:T.t)=`Assoc["from",b tx.from;"to",b tx.to_;"amount",`String(Z.to_string tx.amount);"nonce",`Int tx.nonce;"ou",`String(Z.to_string tx.ou);"timestamp_bits",`String(Printf.sprintf"%016Lx"(Int64.bits_of_float tx.timestamp));"signature",b tx.signature;"public_key",(match tx.public_key with None->`Null|Some k->b k);"message",(match tx.message with None->`Null|Some s->b s);"encrypted",(match tx.encrypted_data with None->`Null|Some s->b s);"op",`String(T.op_type_to_string tx.op_type)]
let run j=
 let txs=member"transactions"j|>to_list|>List.map make in let guard=Octra_net.P2p_tx_gossip_guard.create()in let pool=Hashtbl.create 10 in
 List.iter(fun v->let tx=List.nth txs(to_int v)in Hashtbl.replace pool(T.hash tx)tx)(member"known"j|>to_list);
 let traces=member"steps"j|>to_list|>List.map(fun step->
 let index=match member"index"step with `Null->0|v->to_int v in let tx=List.nth txs index in
 let payload=match member"kind"step|>to_string with
 |"raw"->raw(member"raw"step)
 |"large"->String.make(n step"length")'\000'
 |"legacy"->Octra_net.Oce1.encode(fun w->Octra_net.Oce1.put_string w(Yojson.Safe.to_string(T.to_yojson tx)))^raw(member"append"step)
 |"inv"|"get"as kind->let hashes=member"indices"step|>to_list|>List.map(fun v->T.hash(List.nth txs(to_int v)))in M.encode(if kind="inv"then M.Inv hashes else M.Get hashes)
 |_->M.encode(M.Tx{hash=(if member"wrong_hash"step=`Bool true then String.make 64 '0'else T.hash tx);tx_json=Yojson.Safe.to_string(T.to_yojson tx)})in
 let effects=ref[]and attempts=ref[]in let emit kind body=effects:=`List[`String kind;body]::!effects in
 let sender_pk tx=match member"key"step|>to_string with "none"->None|"account"->Some(pub(String.make 32 '\042'))|"wrong"->Some(pub(String.make 32 '\099'))|_->tx.T.public_key in
 let io:H.io={guard;payload;peer_id="peer";has_tx=Hashtbl.mem pool;find_tx=Hashtbl.find_opt pool;sender_pk;
 add_tx=(fun tx->attempts:=b(Yojson.Safe.to_string(T.to_yojson tx))::!attempts;if member"refuse"step=`Bool true then Error"queue refused"else(let hash=T.hash tx in Hashtbl.replace pool hash tx;Ok hash));
 send_payload=(fun p->emit"send"(b p));broadcast_payload=(fun p->emit"broadcast"(b p));report_bad_peer=(fun reason->emit"bad"(`String reason));close_peer=(fun()->emit"close"`Null);now=(fun()->f step"now");max_drift=f j"drift"}in
 H.handle io;
 let verdict=match A.admit ~now:(f step"now") ~max_drift:(f j"drift") ~sender_pk:tx.public_key tx with Accept->"accept"|Invalid_address->"address"|Invalid_payload->"payload"|Timestamp_drift _->"drift"|Invalid_signature->"signature"in
 `Assoc["effects",`List(List.rev !effects);"attempts",`List(List.rev !attempts);"pool",`List(Hashtbl.fold(fun k _ acc->k::acc)pool[]|>List.sort String.compare|>List.map b);"verdict",`String verdict])in
 `Assoc["prepared",`List(List.map prepared txs);"traces",`List traces]
let ()=let cases=Yojson.Safe.from_channel stdin|>to_list|>List.map(fun input->`Assoc["input",input;"expected",run input])in Yojson.Safe.to_channel stdout(`List cases);print_newline()
