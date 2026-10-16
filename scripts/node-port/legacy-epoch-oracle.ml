(* Pristine outgoing payload and incoming diagnostic decision, never state import. *)
open Yojson.Safe.Util
module C=Octra_core
module R=Octra_node_runtime
let b64 s = `String (Base64.encode_exn s)
let key = Mirage_crypto_ec.Ed25519.priv_of_octets (String.make 32 '\011') |> Result.get_ok
let public = Mirage_crypto_ec.Ed25519.(pub_of_priv key |> pub_to_octets) |> Base64.encode_exn
let address = C.Crypto.Address.address_from_pubkey public
let transaction = C.Transaction.{from=address;to_=address;amount=Z.one;nonce=1;ou=Z.of_int 1000;timestamp=10.;signature="";public_key=Some public;message=None;encrypted_data=None;op_type=Standard}
let transaction = C.Transaction.sign_with_privkey transaction (Base64.encode_exn(String.make 32 '\011'))
let encoded_tx = Yojson.Safe.to_string (C.Transaction.to_yojson transaction)
let event observer payload = match R.P2p_epoch_broadcast.observer_event ~observer payload with
 | Error error -> `Assoc ["error",`String error]
 | Ok Silent -> `Assoc ["silent",`Bool true]
 | Ok (Ignored row) -> `Assoc ["epoch",`Int row.epoch;"tx_count",`Int row.tx_count;"root",b64 row.root;"producer",b64 row.producer]
let case input =
 let name=member "name" input |>to_string in
 let epoch=member "epoch" input |>to_int in
 let root=member "root" input|>to_string in
 let producer=member "producer" input|>to_string in
 let count=member "declared" input|>to_int in
 let txs=match member "transactions" input|>to_int with 0->[]|1->[encoded_tx]|_->[encoded_tx;encoded_tx]in
 let txs=if name="bad-tx" then ["{}"]else txs in
 let message=R.Consensus_epoch_apply_broadcast.message ~epoch_id:epoch ~root ~confirmed_count:count ~producer ~txs_serialized:txs in
 let encoded=R.Consensus_epoch_apply_broadcast.payload message in
 let payload=match name with
 |"trailing"->encoded^"trailing"
 |"truncated"->String.sub encoded 0 (String.length encoded-1)
 |"negative-count"->let b=Bytes.of_string encoded in let off=String.length encoded-4 in for i=0 to 3 do Bytes.set b(off+i)'\255'done;Bytes.to_string b
 |_ ->encoded in
 let parsed=try
  let value=R.P2p_epoch_broadcast.parse payload in
  `Assoc ["ok",`Bool true;"epoch",`String(Int64.to_string value.epoch);"root",b64 value.root;"declared",`Int(Int32.to_int value.declared_count);"producer",b64 value.producer;"hashes",`List(List.map(fun tx->`String(C.Transaction.hash tx))value.txs)]
 with error->`Assoc ["ok",`Bool false;"error",`String(Printexc.to_string error)]in
 `Assoc ["input",input;"serialized",`List(List.map b64 txs);"encoded",b64 encoded;"payload",b64 payload;"parsed",parsed;"observer",event true payload;"nonobserver",event false payload]
let ()=Yojson.Safe.from_channel stdin|>to_list|>List.map case|>fun cases->Yojson.Safe.to_channel stdout(`List cases);print_newline()
