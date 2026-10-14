open Yojson.Safe.Util
module C=Octra_core
module T=C.Transaction
module R=C.Preverify_receipt
module W=C.Preverify_worker
let b v=`String(Base64.encode_exn v)
let n j k=member k j|>to_int
let z j k=member k j|>to_string|>Z.of_string
let tx j:T.t={from="a";to_="b";amount=Z.one;nonce=n j"nonce";ou=z j"ou";timestamp=1.;signature="sig";public_key=None;message=None;encrypted_data=Some"payload";op_type=T.op_type_of_string(member"op"j|>to_string)|>Result.get_ok}
let state transition:R.state={pre_state_hash=String.make 64 'a';source_cipher_hash=String.make 64 'b';pvac_key_hash=String.make 64 'c';transition_hash=if transition then Some(String.make 64 'd')else None}
let circle:R.circle_state={snapshot_hash=String.make 64 'a';circle_id="oct"^String.make 44 '1';code_hash=String.make 64 'b';stable_root=String.make 128 'c';public_reads_hash=String.make 64 'd';context_hash=String.make 64 'e';transcript=[]}
let receipt txs j=
 match member"raw"j with
 | `String raw->Base64.decode_exn raw
 | _->
 let tx=List.nth txs(n j"index")in
 let state,circle=match member"kind"j|>to_string with"bound"->Some(state false),None|"transition"->Some(state true),None|"circle"->None,Some circle|_->None,None in
 let lane=C.Resource_lanes.of_op tx.T.op_type in
 let input_hash,output_hash=match state,circle with
 | None,None->W.input_hash tx,W.output_hash tx"ok"
 | Some s,None->W.bound_input_hash tx s,W.bound_output_hash tx s"ok"
 | None,Some c->W.circle_input_hash tx c,W.circle_output_hash tx c"ok"
 | Some _,Some _->assert false in
 let r:R.t={tx_hash=T.hash tx;lane;engine="";input_hash;output_hash;state;circle;ok=true;reason="";cost=C.Resource_lanes.cost tx}in
 let r={r with engine=R.expected_engine r}in
 let fields=R.to_yojson r|>to_assoc in
 let fields=member"remove"j|>to_list|>List.fold_left(fun fields k->List.remove_assoc(to_string k)fields)fields in
 let fields=member"set"j|>to_assoc|>List.fold_left(fun fields(k,v)->(k,v)::List.remove_assoc k fields)fields in
 Yojson.Safe.to_string(`Assoc fields)
let result=function Ok()->`Null|Error e->b e
let run j=
 Unix.putenv"OCTRA_STEALTH_MIN_OU""5000";Unix.putenv"OCTRA_BFT_RELEASE_PROFILE""off";Unix.putenv"OCTRA_BFT_CRYPTO_PROFILE"(if member"crypto"j=`Bool true then"private_v1"else"off");
 let txs=member"transactions"j|>to_list|>List.map tx in
 let raws=member"receipts"j|>to_list|>List.map(receipt txs)in
 let budgets lane=match member"budget"j with
 | `Null->C.Resource_lanes.default_budget lane
 | v->C.Resource_lanes.{max_txs=n v"txs";max_bytes=n v"bytes";max_ou=z v"ou";max_proof=n v"proof"}in
 let activation=member"activation"j in
 let activation=C.Preverify_receipt_policy.activation_epoch_of(fun _->match activation with`Null->None|v->Some(to_string v))in
 `Assoc["raws",`List(List.map b raws);"transactions",`List(List.map(fun tx->b(Yojson.Safe.to_string(T.to_yojson tx)))txs);
 "check",result(C.Preverify_commit.check_strings ~budgets raws txs);"activation",`Int activation;
 "should_check",`Bool(raws<>[]||n j"epoch">=activation)]
let ()=let cases=Yojson.Safe.from_channel stdin|>to_list|>List.map(fun input->`Assoc["input",input;"expected",run input])in Yojson.Safe.to_channel stdout(`List cases);print_newline()
