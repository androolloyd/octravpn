open Yojson.Safe.Util
module C=Octra_consensus
module N=Octra_node_runtime
module T=Octra_core.Transaction
let hex s=String.concat ""(List.init(String.length s)(fun i->Printf.sprintf "%02x"(Char.code s.[i])))
let unhex s=String.init(String.length s/2)(fun i->Char.chr(int_of_string("0x"^String.sub s(i*2)2)))
let bytes j k=member k j|>to_list|>List.map(fun v->unhex(to_string v))
let output xs=`List(List.map(fun v->`String(hex v))xs)
let run j=
 Unix.putenv"OCTRA_BFT_RELEASE_PROFILE""off";Unix.putenv"OCTRA_BFT_CRYPTO_PROFILE""off";Unix.putenv"OCTRA_STEALTH_MIN_OU""5000";
 let p=C.C_codec.decode_propose(member"proposal"j|>to_string|>unhex)in
 let r:C.C_driver.bundle_response_record={responder_addr="fixture";tx_hashes=bytes j"hashes";txs_json=bytes j"txs";receipts_json=bytes j"receipts"}in
 match N.Consensus_bundle_validation.proposal ~header:p.header ~expected_hashes:(bytes j"expected_hashes") r with
 |Error e->`Assoc["error",`String e]
 |Ok b->`Assoc["hashes",output b.tx_hashes;"txs",output(List.map(fun t->Yojson.Safe.to_string(T.to_yojson t))b.txs);"receipts",output b.receipts_json;"rejections",`Int(List.length b.rejections)]
let ()=let cases=Yojson.Safe.from_channel stdin|>to_list|>List.map(fun input->`Assoc["input",input;"expected",run input])in Yojson.Safe.to_channel stdout(`List cases);print_newline()
