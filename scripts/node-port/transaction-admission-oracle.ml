module Core=Octra_core
module Tx=Core.Transaction
module View=Octra_node_runtime.Tx_view
module Package=Native_package
module Envelope=Octra_vm.Program_envelope
open Yojson.Safe.Util
let field v k=member k v
let text v k=field v k|>to_string
let bytes v k=text v k|>Base64.decode_exn
let opt v k=match field v k with `String v->Some(Base64.decode_exn v)|_->None
let b64 v=`String(Base64.encode_exn v)
let n v k=text v k|>int_of_string
let z v k=text v k|>Z.of_string
let bool v k=field v k|>to_bool
let float v k=Int64.float_of_bits(Int64.of_string("0x"^text v k))
let tx_of v=Tx.{from=bytes v"from";to_=bytes v"to";amount=z v"amount";nonce=n v"nonce";ou=z v"ou";timestamp=float v"timestamp_bits";signature=bytes v"signature";public_key=opt v"public_key";message=opt v"message";encrypted_data=opt v"encrypted_data";op_type=Tx.op_type_of_string(text v"op_type")|>Result.get_ok}
let unit_result=function Ok()->`Null|Error e->`String e
let admission=function Ok()->`Null|Error(tag,reason)->`List[`String tag;`String reason]
let run input=match text input"kind"with
|"program"->(match Package.decode_base64(bytes input"raw")with Error e->`Assoc["error",`String(Package.error_message e)]|Ok p->`Assoc["main",b64 p.main;"profile",`Int p.compiler_profile;"sources",`List(List.map(fun(s:Package.source)->`List[b64 s.path;b64 s.body])p.sources);"envelope",b64 p.envelope])
|"envelope"->(match Envelope.decode(bytes input"raw")with Error e->`Assoc["error",`String(Envelope.error_message e)]|Ok p->`Assoc["code",b64 p.code;"cert",b64 p.cert])
|"compute"->let raw=bytes input"raw"in `Assoc["fee",`String(Z.to_string(Core.Compute_bill.fee raw));"request",(match Core.Compute_bill.decode_request raw with Error e->`String e|Ok(fuel,records)->`List[`Int fuel;`List(List.map b64 records)])]
|"transaction"->
 let cfg=field input"context"in
 List.iter(fun(key,field)->Unix.putenv key (Option.value ~default:""(opt cfg field)))["OCTRA_BFT_RELEASE_PROFILE","release";"OCTRA_BFT_CRYPTO_PROFILE","crypto";"OCTRA_BFT_ADMIT_OPS","ops";"OCTRA_STEALTH_MIN_OU","stealth_min"];
 let tx=tx_of(field input"tx")in
 let tx=match opt input"seed"with None->tx|Some seed->Tx.sign_with_privkey tx(Base64.encode_exn seed)in
 let limits=View.{encrypted_data_len=n cfg"encrypted_limit";message_len=n cfg"message_limit";message_zkp_len=n cfg"zkp_limit";message_validator_len=n cfg"validator_limit";message_program_len=n cfg"program_limit"}in
 let now=float cfg"now_bits"and max_timestamp_drift=float cfg"drift_bits"and observer_rpc_mode=bool cfg"observer"and bft_mode=bool cfg"bft"in
 let head=match field cfg"head"with`String v->Some(Int64.of_string v)|_->None in
 let mode=if bool cfg"active"then Core.Rule_graph.Active else Core.Rule_graph.Prior in
 let duty=Option.map(fun head->head,mode)head in
 let confirmed_nonce=n cfg"confirmed"and bft_window=n cfg"window"in
 `Assoc[
 "signature",b64 tx.signature;"semantic",unit_result(View.semantic_check tx);"fee",`String(Z.to_string(Tx.ou_cost tx));
 "staging",unit_result(View.staging_submit_admission ~min_ou:(Tx.stealth_min_ou_of Sys.getenv_opt) ~min_relay_fee:(z cfg"relay_fee")tx);
 "admits",`Bool(Tx.bft_admits_op tx.op_type);"consensus_admits",`Bool(Tx.bft_consensus_admits_op tx.op_type);
 "pre_route",admission(View.pre_route_admission ~duty ~now ~max_timestamp_drift ~observer_rpc_mode ~bft_mode tx);
 "pre_signature",admission(View.submit_pre_signature_admission ~duty ~now ~max_timestamp_drift ~observer_rpc_mode ~bft_mode ~limits ~sender_exists:(bool cfg"sender_exists")tx);
 "payload_size",admission(View.payload_size_admission ~limits tx);"payload",admission(View.payload_admission ~limits tx);
 "address",admission(View.address_route_admission tx);"self",admission(View.self_route_admission tx);
 "signature_admission",admission(View.signature_admission ~account_public_key:(opt cfg"account_key")tx);"sender",admission(View.sender_admission ~sender_exists:(bool cfg"sender_exists")tx);
 "post",admission(View.post_signature_admission ~preverify_has_capacity:(bool cfg"capacity") ~preverify_pending:(n cfg"pending") ~preverify_pending_max:(n cfg"pending_max") ~bft_mode ~confirmed_nonce ~bft_window tx);
 "duty_nonce",unit_result(View.duty_nonce_admission ~head ~confirmed_nonce tx);"duty_retry",`Bool(View.duty_retry ~now ~duty ~bft_mode tx);
 "expired",`Bool(Core.Tx_staging.duty_expired ~head ~mode tx);"call_params",`Bool(View.call_params_ok tx);"encrypted",`Bool(View.encrypted_payload_ok tx)]
|_->failwith"unknown case"
let ()=let inputs=Yojson.Safe.from_file Sys.argv.(1)|>to_list in let cases=List.map(fun input->`Assoc["input",input;"output",run input])inputs in print_endline("ORACLE_RESULT="^Yojson.Safe.to_string(`Assoc["kat",`String(Core.Pvac_registry.expected_kat());"cases",`List cases]))
