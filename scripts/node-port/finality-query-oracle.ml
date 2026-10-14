open Yojson.Safe.Util
module C=Octra_consensus
let hex s=String.concat ""(List.init(String.length s)(fun i->Printf.sprintf "%02x"(Char.code s.[i])))
let unhex s=String.init(String.length s/2)(fun i->Char.chr(int_of_string("0x"^String.sub s(i*2)2)))
let public n=let key=Mirage_crypto_ec.Ed25519.priv_of_octets(String.make 32(Char.chr n))|>Result.get_ok in Mirage_crypto_ec.Ed25519.(pub_to_octets(pub_of_priv key))
let bytes values=`List(List.map(fun value->`String(hex value))values)
let run j=
 let epoch=member"epoch"j|>to_string|>Int64.of_string in
 let now=member"now"j|>to_string|>Int64.of_string in
 let attempt=member"attempt"j|>to_int in
 let addr=member"address"j|>to_string|>unhex in
 let set=C.C_types.make_validator_set(List.init(member"validators"j|>to_int)(fun i->C.C_types.{address="v"^string_of_int(i+1);pubkey=public(i+1)}))in
 let records=member"records"j|>to_list|>List.map(fun r->C.C_driver.{responder_addr=member"address"r|>to_string;responder_head_epoch=member"head"r|>to_string|>Int64.of_string;state_root=None})in
 let request domain body=Octra_net.Hash_domain.hash domain body|>C.C_hash.mark_complete_catchup_request|>hex in
 `Assoc["peers",bytes(C.C_driver.finality_query_peer_ids set ~epoch_id:epoch records);
 "proof_peers",bytes(C.C_driver.finality_proof_peer_ids set ~epoch_id:epoch records);
 "request",`String(request "octra:finality_query_request"(Printf.sprintf "%s:%Ld:%d:%Ld"addr epoch attempt now));
 "proof_request",`String(request "octra:finality_proof_request"(Printf.sprintf "%s:%Ld:%Ld"addr epoch now))]
let ()=let cases=Yojson.Safe.from_channel stdin|>to_list|>List.map(fun input->`Assoc["input",input;"expected",run input])in Yojson.Safe.to_channel stdout(`List cases);print_newline()
