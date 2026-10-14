(* Native check_bound against a committed Irmin root and current ledger/store. *)
open Yojson.Safe.Util
module C=Octra_core
module S=C.Store_irmin
module L=C.Ledger
module T=C.Transaction
module R=C.Preverify_receipt
module W=C.Preverify_worker
let s j k=member k j|>to_string
let optional j k=match member k j with `String v->Some v|_->None
let b64 v=`String(Base64.encode_exn v)
let sha s=Digestif.SHA256.(digest_string s|>to_hex)
let address="oct4XmjKEd9A96KhoMX94zWJmd28dcPisbWGYWtad1dQ9v5"
let run index j=
 let get=function Ok value->value|Error reason->failwith(Printf.sprintf "case %d: %s" index reason)in
 let store=Lwt_main.run(S.open_store ~fresh:true(Printf.sprintf"/tmp/preverify-state-%d"index))in
 store.S.batch_tree<-Some(S.Store.Tree.empty());
 let entries=ref[]in
 let write path value=entries:= !entries@[`List[`List(List.map(fun s->`String s)path);b64 value]];Lwt_main.run(S.write store path value)in
 if member"sender"j=`Bool true then write["accounts";address;"data"](Yojson.Safe.to_string(L.account_to_yojson L.{empty_account with balance=Z.of_int 100000;encrypted_balance=optional j"cipher"}));
 Option.iter(write["pvac_hashes";address])(optional j"key");
 Lwt_main.run(S.commit_epoch_batch store"preverification fixture");
 let root=Lwt_main.run(S.state_hash store)in
 let ledger=L.create store in
 let tx=T.{from=address;to_=address;amount=Z.zero;nonce=1;ou=Z.of_int 5000;timestamp=1.;signature="fixture";public_key=None;message=None;encrypted_data=optional j"encrypted";op_type=T.op_type_of_string(s j"op")|>get}in
 let bound_root=if member"wrong_root"j=`Bool true then String.make 64 'a'else W.state_hash root in
 let receipt=match s j"binding"with
 |"circle"->let circle=R.{snapshot_hash=bound_root;circle_id=address;code_hash=String.make 64 '0';stable_root=String.make 64 '0';public_reads_hash=String.make 64 '0';context_hash=String.make 64 '0';transcript=[]}in
   R.make_circle ~tx_hash:(T.hash tx) ~input_hash:(W.circle_input_hash tx circle) ~output_hash:(W.circle_output_hash tx circle"ok") ~circle ~ok:true ~reason:"" ~cost:(C.Resource_lanes.cost tx)|>get
 |"unbound"->R.for_tx ~input_hash:(W.input_hash tx) ~output_hash:(W.output_hash tx"ok") ~ok:true ~reason:"" tx|>get
 |_->let cipher=match tx.op_type with CircleBalanceCellPut|CircleRegisterCellPut->(match optional j"encrypted"with Some v->(match Base64.decode v with Ok v->v|_->"")|_->"")|_->Option.value(optional j"cipher")~default:"0"in
   let key=match optional j"key"with None|Some"none"->String.make 64 '0'|Some v->v in
   let state=R.{pre_state_hash=bound_root;source_cipher_hash=(if member"wrong_cipher"j=`Bool true then String.make 64 'a'else sha cipher);pvac_key_hash=(if member"wrong_key"j=`Bool true then String.make 64 'b'else key);transition_hash=Some(String.make 64 'c')}in
   R.for_tx_bound ~input_hash:(W.bound_input_hash tx state) ~output_hash:(W.bound_output_hash tx state"ok") ~state ~ok:true ~reason:"" tx|>get in
 let receipt=if member"wrong_input"j=`Bool true then {receipt with R.input_hash=String.make 64 'e'}else receipt in
 let receipts=if member"missing"j=`Bool true then []else if member"duplicate"j=`Bool true then [receipt;receipt]else [receipt]in
 (* The binding is to HEAD even while uncommitted tree data exists. *)
 Lwt_main.run(S.begin_epoch_batch store);Lwt_main.run(S.set_meta store"speculative""true");
 let result=Lwt_main.run(C.Preverify_commit.check_bound ledger(C.Preverify_commit.create receipts)[tx])in
 let expected=`Assoc["entries",`List !entries;"root",b64 root;"crypto_active",`Bool(T.bft_crypto_active());"transaction",b64(Yojson.Safe.to_string(T.to_yojson tx));"receipts",`List(List.map(fun r->b64(R.canonical r))receipts);"result",(match result with Ok()->`Null|Error e->b64 e)]in
 S.abort_epoch_batch store;Lwt_main.run(S.close store);expected
let ()=let inputs=Yojson.Safe.from_channel stdin|>to_list in Yojson.Safe.to_channel stdout(`List(List.mapi(fun i input->`Assoc["input",input;"expected",run i input])inputs));print_newline()
