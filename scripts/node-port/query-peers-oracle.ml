open Yojson.Safe.Util
module D=Octra_consensus.C_driver
let hex s=String.concat ""(List.init(String.length s)(fun i->Printf.sprintf "%02x"(Char.code s.[i])))
let unhex s=String.init(String.length s/2)(fun i->Char.chr(int_of_string("0x"^String.sub s(i*2)2)))
let public n=let key=Mirage_crypto_ec.Ed25519.priv_of_octets(String.make 32(Char.chr n))|>Result.get_ok in Mirage_crypto_ec.Ed25519.(pub_to_octets(pub_of_priv key))
let node n=Octra_net.P2p_handshake.node_id_of_pubkey(public n)
let bytes values=`List(List.map(fun v->`String(hex v))values)
let run j=
 let seed=member"seed"j|>to_string|>unhex in
 let active=List.init(member"validators"j|>to_int)(fun i->node(i+1))in
 let connected=member"connected"j|>to_list|>List.map(function`Int n->node n|`String s->unhex s|_->assert false)in
 let sorted=List.sort_uniq String.compare connected in
 let validators,others=List.partition(fun id->List.mem id active)sorted in
 let rotate values=D.rotate_values(D.bundle_query_offset seed(List.length values))values in
 let ordered=rotate validators@rotate others in
 `Assoc["connected",bytes connected;"ordered",bytes ordered;"offset",`Int(D.bundle_query_offset seed(member"count"j|>to_int));"waves",`List(List.map bytes(D.bundle_query_waves ordered))]
let ()=let cases=Yojson.Safe.from_channel stdin|>to_list|>List.map(fun input->`Assoc["input",input;"expected",run input])in Yojson.Safe.to_channel stdout(`List cases);print_newline()
