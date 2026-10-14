open Yojson.Safe.Util
module C=Octra_core
module T=C.Transaction
module R=C.Resource_lanes
let n j k=member k j|>to_int
let z j k=member k j|>to_string|>Z.of_string
let make j:T.t={from="a";to_="b";amount=Z.one;nonce=1;ou=z j"ou";timestamp=1.;signature="sig";public_key=None;message=(match member"message"j with `Null->None|v->Some(to_string v));encrypted_data=Some(String.make(n j"length")'x');op_type=T.op_type_of_string(member"op"j|>to_string)|>Result.get_ok}
let usage(u:R.used)=`Assoc["txs",`Int u.txs;"bytes",`Int u.bytes;"ou",`String(Z.to_string u.ou);"proof",`Int u.proof]
let used j:R.used={txs=n j"txs";bytes=n j"bytes";ou=z j"ou";proof=n j"proof"}
let budget j:R.budget={max_txs=n j"txs";max_bytes=n j"bytes";max_ou=z j"ou";max_proof=n j"proof"}
let result=function Ok()->`Null|Error e->`String e
let run j=
 Unix.putenv"OCTRA_STEALTH_MIN_OU"(member"minimum"j|>to_string);
 let tx=make j in let lane=R.of_op tx.op_type in let d=R.default_budget lane in
 let b=budget(member"budget"j)and u=used(member"used"j)in
 `Assoc["lane",`String(R.to_string lane);"queue",`Int(R.preverify_queue_limit lane);"managed",`Bool(R.preverify_managed lane);
 "budget",`Assoc["txs",`Int d.max_txs;"bytes",`Int d.max_bytes;"ou",`String(Z.to_string d.max_ou);"proof",`Int d.max_proof];
 "cost",usage(R.cost tx);"work",usage(R.work tx);"vm",`Int(R.vm_limit tx.ou);
 "prior",result(R.queue_check ~mode:C.Rule_graph.Prior tx);"active",result(R.queue_check ~mode:C.Rule_graph.Active tx);
 "add",usage(R.add u (R.cost tx));"over",(match R.over b u with None->`Null|Some s->`String s);
 "admit",(match R.admit b u tx with Accept u->`Assoc["ok",usage u]|Reject s->`Assoc["error",`String s])]
let ()=let cases=Yojson.Safe.from_channel stdin|>to_list|>List.map(fun input->`Assoc["input",input;"expected",run input])in Yojson.Safe.to_channel stdout(`List cases);print_newline()
