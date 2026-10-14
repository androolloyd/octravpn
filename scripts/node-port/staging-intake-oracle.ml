(* Native facade with real account ledger and explicit preverification callbacks. *)
open Yojson.Safe.Util
module C=Octra_core
module T=C.Transaction
module P=C.Tx_staging
module L=C.Ledger
module R=Octra_node_runtime.Node_rest_facade
let raw v=Base64.decode_exn(to_string v)
let b v=`String(Base64.encode_exn v)
let optional j k=match member k j with `Null->None|v->Some(raw v)
let f j k=member k j|>to_string|>float_of_string
let n j k=member k j|>to_int
let seed j=String.make 32(Char.chr(n j"seed"))
let pub seed=let key=Mirage_crypto_ec.Ed25519.priv_of_octets seed|>Result.get_ok in Mirage_crypto_ec.Ed25519.(pub_of_priv key|>pub_to_octets)|>Base64.encode_exn
let make j=
 let key=pub(seed j)in
 let from=Option.value(optional j"from")~default:(C.Crypto.Address.address_from_pubkey key)in
 let tx:T.t={from;to_=Option.value(optional j"to")~default:("oct"^String.make 44 '1');amount=member"amount"j|>to_string|>Z.of_string;nonce=n j"nonce";ou=member"ou"j|>to_string|>Z.of_string;timestamp=f j"timestamp";signature="";public_key=Some key;message=optional j"message";encrypted_data=optional j"encrypted";op_type=T.op_type_of_string(member"op"j|>to_string)|>Result.get_ok}in
 let tx=T.sign_with_privkey tx(Base64.encode_exn(seed j))in
 let public_key=match member"public"j|>to_string with "none"->None|"empty"->Some""|"other"->Some(pub(String.make 32 '\099'))|_->tx.public_key in
 let signature=match member"signature"j|>to_string with "zero"->Base64.encode_exn(String.make 64 '\000')|"empty"->""|"newline"->tx.signature^"\n"|_->tx.signature in
 {tx with public_key;signature}
let prepared(tx:T.t)=`Assoc["from",b tx.from;"to",b tx.to_;"amount",`String(Z.to_string tx.amount);"nonce",`Int tx.nonce;"ou",`String(Z.to_string tx.ou);"timestamp_bits",`String(Printf.sprintf"%016Lx"(Int64.bits_of_float tx.timestamp));"signature",b tx.signature;"public_key",(match tx.public_key with None->`Null|Some k->b k);"message",(match tx.message with None->`Null|Some s->b s);"encrypted",(match tx.encrypted_data with None->`Null|Some s->b s);"op",`String(T.op_type_to_string tx.op_type)]
let hash tx=b(T.hash tx)
let hashes txs=`List(List.map hash txs)
let drop d=`List[b d.P.d_hash;`String(match d.d_reason with Evicted->"evicted"|Expired->"expired");`String d.d_detail]
let mode v=if v=`Bool true then C.Rule_graph.Active else Prior
let point j=match member"duty"j with `Null->None|v->Some(Int64.of_string(member"head"v|>to_string),mode(member"active"v))
let result=function Ok h->`Assoc["ok",b h]|Error(tag,reason)->`Assoc["error",`List[`String tag;`String reason]]
let run store base j=
 P.clear();Hashtbl.clear P.dropped_cache;ignore(P.Preview.send(Check(Some base,"reset")));
 let txs=member"transactions"j|>to_list|>List.map make in
 let ledger=L.create store in
 List.iter(fun a->let public=pub(String.make 32(Char.chr(n a"seed")))in
  let address=C.Crypto.Address.address_from_pubkey public in
  if member"exists"a<>`Bool false then Hashtbl.replace ledger.L.cache address
   {L.empty_account with balance=(member"balance"a|>to_string|>Z.of_string);nonce=n a"nonce";public_key=(match member"key"a|>to_string with "none"->None|"wrong"->Some(pub(String.make 32 '\099'))|_->Some public)}) (member"accounts"j|>to_list);
 let traces=member"steps"j|>to_list|>List.map(fun s->
  P.oracle_time:=f s"now";
  Unix.putenv"OCTRA_STEALTH_MIN_OU"(member"minimum"s|>to_string);
  Unix.putenv"OCTRA_BFT_RELEASE_PROFILE"(member"profile"s|>to_string);
  Unix.putenv"OCTRA_BFT_CRYPTO_ADMIT""";Unix.putenv"OCTRA_BFT_ADMIT_OPS""";
  Unix.putenv"OCTRA_CONSENSUS_MODE"(if member"observer"s=`Bool true then"observer"else if member"bft"s=`Bool true then"bft"else"single");
  Unix.putenv"OCTRA_OBSERVER_RELAY_SUBMITS""0";Unix.putenv"OCTRA_BFT_PENDING_NONCE_WINDOW"(string_of_int(n s"window"));
  let events=ref[]in let emit v=events:=v::!events in
  let head=Some(Int64.add base(Int64.of_string(member"head"s|>to_string)))in
  let runtime:R.runtime={swarm_ref=ref None;duty_head=(fun()->point s);compute_mode=(fun()->mode(member"compute"s));settle_mode=(fun()->mode(member"settle"s));proof_mode=(fun()->mode(member"proof"s));queue_head=(fun()->head);
   preverify_admit=(fun tx->emit(`List[`String"preverify";hash tx]);match member"refuse"s with `Null->Ok()|v->Error(to_string v));
   save_drops=(fun ds->emit(`List[`String"drops";`List(List.map drop ds)]));find_drop=(fun _->None);drops_by_addr=(fun _ ~limit:_ ~offset:_->[])}in
  let tx=List.nth txs(n s"index")in
  let out=match member"route"s|>to_string with
   |"hold"->(match P.Preview.send(Hold{head=Option.get head;epoch=Int64.succ(Option.get head);hash=T.hash tx})with Ok()->`Null|Error e->`String e)
   |"refuse"->(match P.Preview.send(Refuse{head=Option.get head;epoch=Int64.succ(Option.get head);hash=T.hash tx})with Ok()->`Null|Error e->`String e)
   |"clear"->P.clear();`Null
   |"stage"->result(R.add_tx_to_staging ~relay:false ~bft_mode:(member"bft"s=`Bool true) runtime ledger tx|>Result.map_error Octra_node_runtime.Tx_view.staging_error)
   |_->result(R.validate_and_submit_tx runtime ledger tx)in
  let senders=List.map(fun tx->tx.T.from)txs|>List.sort_uniq String.compare in
  `Assoc["result",out;"events",`List(List.rev !events);"all",hashes(P.all());"total",`String(Z.to_string(P.staging_total_ou()));
   "senders",`List(List.map(fun sender->`List[b sender;(match Hashtbl.find_opt P.virtual_balances sender with None->`Null|Some v->`String(Z.to_string v));`Int(P.get_expected_nonce sender)])senders);
   "drops",`List(Hashtbl.fold(fun _ d ds->d::ds)P.dropped_cache[]|>List.sort(fun a b->String.compare a.P.d_hash b.P.d_hash)|>List.map drop)])in
 `Assoc["prepared",`List(List.map prepared txs);"traces",`List traces]
let ()=
 let dir=Filename.temp_file"staging-intake"""in Unix.unlink dir;
 let store=Lwt_main.run(C.Store_irmin.open_store dir)in
 Fun.protect ~finally:(fun()->Lwt_main.run(C.Store_irmin.close store))(fun()->
  let cases=Yojson.Safe.from_channel stdin|>to_list|>List.mapi(fun i input->let base=Int64.of_int((i+1)*10000)in `Assoc["input",input;"base",`String(Int64.to_string base);"expected",run store base input])in
  Yojson.Safe.to_channel stdout(`List cases);print_newline())
