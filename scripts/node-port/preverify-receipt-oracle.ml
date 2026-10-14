open Yojson.Safe.Util
module C=Octra_core
module R=C.Preverify_receipt
module W=C.Preverify_worker
let b v=`String(Base64.encode_exn v)
let result=function Ok()->`Null|Error e->`String e
let tx j:C.Transaction.t={from="a";to_="b";amount=Z.one;nonce=1;ou=Z.of_string(member"ou"j|>to_string);timestamp=1.;signature="sig";public_key=None;message=None;encrypted_data=Some"payload";op_type=C.Transaction.op_type_of_string(member"op"j|>to_string)|>Result.get_ok}
let run j=
 Unix.putenv"OCTRA_STEALTH_MIN_OU"(member"minimum"j|>to_string);
 let tx=tx j in
 match R.of_string(Base64.decode_exn(member"raw"j|>to_string))with
 | Error e->`Assoc["error",`String e]
 | Ok r->
 let input,output=match r.R.state,r.circle with
 | None,None->W.input_hash tx,W.output_hash tx"ok"
 | Some s,None->W.bound_input_hash tx s,W.bound_output_hash tx s"ok"
 | None,Some c->W.circle_input_hash tx c,W.circle_output_hash tx c"ok"
 | Some _,Some _->assert false in
 let made=match r.state,r.circle with
 | None,None->R.for_tx ~input_hash:input ~output_hash:output ~ok:r.ok ~reason:r.reason tx
 | Some state,None->R.for_tx_bound ~input_hash:input ~output_hash:output ~state ~ok:r.ok ~reason:r.reason tx
 | None,Some circle->R.make_circle ~tx_hash:(C.Transaction.hash tx) ~input_hash:input ~output_hash:output ~circle ~ok:r.ok ~reason:r.reason ~cost:(C.Resource_lanes.cost tx)
 | Some _,Some _->assert false in
 `Assoc["canonical",b(R.canonical r);"hash",`String(R.hash r);"valid",result(R.validate r);"input",`String input;"output",`String output;
 "made",(match made with Ok r->`Assoc["ok",b(R.canonical r)]|Error e->`Assoc["error",`String e])]
let ()=let cases=Yojson.Safe.from_channel stdin|>to_list|>List.map(fun input->`Assoc["input",input;"expected",run input])in Yojson.Safe.to_channel stdout(`List cases);print_newline()
