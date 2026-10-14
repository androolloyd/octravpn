module Tx=Octra_core.Transaction
module Archive=Native_archive
open Yojson.Safe.Util
let field input key=member key input
let text input key=field input key |> to_string
let bytes input key=text input key |> Base64.decode_exn
let b64 raw=`String(Base64.encode_exn raw)
let optional input key=match field input key with `String raw->Some(Base64.decode_exn raw)|_->None
let unit_result=function Ok()->`Null|Error e->`String e
let hash raw=Digestif.SHA256.digest_string raw |> Digestif.SHA256.to_hex
let json_result f=try f() with Yojson.Json_error reason->`Assoc["serialization_error",`String reason]
let decode_tx input=
 try
  let json=Yojson.Safe.from_string (bytes input "raw") in
  match Tx.of_yojson json with Error reason->`Assoc["decode_error",`String reason]
  | Ok tx->json_result(fun()->`Assoc["json",b64(Yojson.Safe.to_string(Tx.to_yojson tx));"signing",b64(Tx.serialize_for_signing tx);"hash",`String(Tx.hash tx)])
 with Yojson.Json_error _->`Assoc["syntax_error",`Bool true]
let archive input=
 let raw=bytes input "raw" in
 let effective=try
  let json=Yojson.Safe.from_string raw in
  match Tx.of_yojson json with
  | Error _->raw
  | Ok tx->
    let tx=match optional input "seed" with None->tx|Some seed->
      let bytes=match text input "mode" with "exact"->Tx.serialize_for_signing tx|"signed"->Archive.signed_bytes tx|_->Yojson.Safe.to_string(Archive.operation_json tx) in
      let secret=Mirage_crypto_ec.Ed25519.priv_of_octets seed |> Result.get_ok in
      {tx with signature=Base64.encode_exn(Mirage_crypto_ec.Ed25519.sign ~key:secret bytes)} in
    if field input "canonical"=`Bool true then Yojson.Safe.to_string(Tx.to_yojson tx)
    else match optional input "seed",json with
    | Some _,`Assoc fields->Yojson.Safe.to_string(`Assoc(List.map(fun(k,v)->if k="signature" then k,`String tx.signature else k,v)fields))
    | _->raw
 with _->raw in
 let hash=match field input "hash" with `String value->value|_->
   try let tx=Tx.of_yojson(Yojson.Safe.from_string effective)|>Result.get_ok in
    match text input "mode" with "exact"->Tx.hash tx|"signed"->hash(Archive.signed_bytes tx)|_->hash(Yojson.Safe.to_string(Archive.operation_json tx))
   with _->String.make 64 '0' in
 let output=match Archive.decode ~hash ~json:effective with
 | Error reason->if String.starts_with ~prefix:"Yojson" reason then `Assoc["syntax_or_serialization_error",`Bool true] else `Assoc["error",`String reason]
 | Ok value->`Assoc["proof",`String(match Archive.proof value with Exact->"exact"|Signed->"signed"|Signed_operation->"operation");
   "visible",b64(Archive.visible_json value);"proof_bytes",b64(Archive.proof_bytes value);
   "transaction",b64(Yojson.Safe.to_string(Tx.to_yojson(Archive.tx value)));
   "verify",unit_result(Archive.verify ~public_key_of:(fun _->optional input "account_key") value)] in
 `Assoc["raw",b64 effective;"hash",`String hash;"result",output]
let run input=match text input "operation" with
| "decode"->decode_tx input
| "integer"->(try `String(Z.to_string(Z.of_string(bytes input "raw")))with _->`Null)
| "archive"->archive input
| "limits"->let op=Tx.op_type_of_string(text input "op_type")|>Result.get_ok in
 let tx=Tx.{from="";to_="";amount=Z.zero;nonce=0;ou=Z.zero;timestamp=0.;signature="";public_key=None;message=None;op_type=op;encrypted_data=None}in
 let limits=Native_payload.{encrypted_data_len=10;message_len=20;message_zkp_len=30;message_validator_len=40;message_program_len=50} in
 `Assoc["message",`Int(Native_payload.message_limit limits tx);"encrypted",`Int(Native_payload.encrypted_data_limit limits tx)]
| _->failwith "unknown operation"
let ()=let cases=Yojson.Safe.from_file Sys.argv.(1)|>to_list in
 let output=List.map(fun input->`Assoc["input",input;"output",run input])cases in
 print_endline("ORACLE_RESULT="^Yojson.Safe.to_string(`List output))
