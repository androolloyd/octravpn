open Yojson.Safe.Util
open Octra_consensus
open C_types
module E=C_engine
module C=C_codec
module H=C_hash
let hex raw = String.concat "" (List.init (String.length raw) (fun i->Printf.sprintf "%02x" (Char.code raw.[i])))
let unhex text = String.init (String.length text/2) (fun i->Char.chr(int_of_string("0x"^String.sub text (i*2) 2)))
let h b=`String(hex b)
let int j name default=match member name j with `Null->default|v->to_int v
let bool j name default=match member name j with `Null->default|v->to_bool v
let str j name default=match member name j with `Null->default|v->to_string v
let hash n=String.make 32(Char.chr n)
let addr i="validator-"^string_of_int i
let key i=match Mirage_crypto_ec.Ed25519.priv_of_octets(hash i)with Ok k->k|Error _->failwith "key"
let public i=Mirage_crypto_ec.Ed25519.(pub_of_priv(key i)|>pub_to_octets)
let sign i msg=Mirage_crypto_ec.Ed25519.sign ~key:(key i) msg
let header_wire x=Octra_net.Oce1.encode(fun b->C.encode_epoch_header b x)
let step j=match int j "step" 1 with 1->ProposeStep|2->PrevoteStep|_->PrecommitStep
let error=function Failure s|Invalid_argument s->s|e->Printexc.to_string e
let catch f=try f()with e->`Assoc["error",`String(error e)]
let opt f=function None->`Null|Some x->f x
let set n weighted=let vals=List.init n(fun i->{address=addr(i+1);pubkey=public(i+1)})in
 if weighted then(match make_weighted_validator_set(List.mapi(fun i v->v,Z.of_int(if i=0 then 1000 else 1))vals)with Ok x->x|Error e->failwith e)else make_validator_set vals
let output=function
 | E.SendPropose p->`Assoc["proposal",h(C.encode_propose p)]
 | E.SendVote(v,p)->`Assoc["vote",h(C.encode_vote v);"proposal",opt(fun p->h(C.encode_propose p))p]
 | E.SendFinalize f->`Assoc["send_finalize",h(C.encode_finalize f)]
 | E.RequestProposal{round;proposal_id}->`Assoc["request_round",`Int round;"proposal_id",h proposal_id]
 | E.RequestRoundEvidence round->`Assoc["evidence_round",`Int round]
 | E.ScheduleTimeout{step;round;delay_ms;generation}->`Assoc["step",`Int(round_step_to_u8 step);"round",`Int round;"delay",`Int delay_ms;"generation",`Int generation]
 | E.Finalized{epoch_id;finalize}->`Assoc["epoch_id",`String(Int64.to_string epoch_id);"finalized",h(C.encode_finalize finalize)]
let snapshot t result=
 let outputs=E.drain_outputs t in let s=t.E.state in
 `Assoc["result",result;"height",`String(Int64.to_string s.height);"round",`Int s.round;"step",`Int(round_step_to_u8 s.step);"locked_round",`Int s.locked_round;"locked",opt(fun h->h |> header_wire |> hex |> fun s->`String s)s.locked_value;"valid_round",`Int s.valid_round;"valid",opt(fun h->h |> header_wire |> hex |> fun s->`String s)s.valid_value;"generation",`Int t.generation;"finalized_height",`String(Int64.to_string t.finalized_height);"pending",opt(fun f->h(C.encode_finalize f))t.pending_finalized;"outputs",`List(List.map output outputs);"pristine",`Bool(E.is_pristine t)]
let run config =
 let chain=unhex(str config "chain" "")and epoch=Int64.of_string(str config "epoch" "12")in
 let n=int config "n" 4 and weighted=bool config "weighted" false and me=int config "me" 1 in
 let validators=set n weighted and ready=ref(bool config "ready" true)and skip=ref true in
 let t=E.create ~chain_id:chain ~my_addr:(addr me) ~validator_set:validators ~start_height:epoch ~can_vote:(fun()-> !ready)in
 E.set_round_skip_ready t(fun()-> !skip);
 let verify addr msg signature=match pubkey_of_addr t.vs addr with None->false|Some pubkey_raw->H.verify_ed25519 ~pubkey_raw ~msg ~signature in
 let normalized=ref []in
 let results=config|>member "steps"|>to_list|>List.map(fun input->
  let extras=ref []in let add k v=extras:=(k,v)::!extras in
  let round=int input "round" t.state.round in
  let name=int input "name" 10 in let tx_hashes=[hash name]in
  let default_creator=(leader_of t.vs ~epoch_id:t.state.height ~round:0).address in
  let creator=int input "creator" (int_of_string(String.sub default_creator 10(String.length default_creator-10))) in
  let header:epoch_header={proto_version=4;chain_id=chain;epoch_id=t.state.height;prev_state_root=hash 1;tx_list_hash=E.tx_list_hash_for_header tx_hashes;receipt_root=hash 3;proposed_state_root=hash name;parent_commit_hash=hash 0;creator_addr=addr creator;txid_hi=42L;ts=1000.125}in
  let pid=if bool input "nil" false then hash 0 else H.proposal_id header in
  let make_vote who kind=let v:vote={chain_id=chain;epoch_id=t.state.height;round;vote_type=kind;proposal_id=pid;validator=addr who;signature=String.make 64 '\000'}in
   {v with signature=if bool input "corrupt" false then String.make 64 '\000' else sign who(H.vote_sign_bytes v)}in
  let make_proposal()=let proposer=int input "proposer"(let a=(leader_of t.vs ~epoch_id:t.state.height ~round).address in int_of_string(String.sub a 10(String.length a-10)))in
   let p:propose={chain_id=chain;epoch_id=t.state.height;round;valid_round=(match member "valid_round" input with `Null->None|v->Some(to_int v));header;tx_hashes;parent_commit=None;proposer=addr proposer;signature=String.make 64 '\000'}in
   {p with signature=if bool input "corrupt" false then String.make 64 '\000' else sign proposer(H.propose_sign_bytes p)}in
  let result=catch(fun()->match str input "op" "" with
   |"start"->E.start_round t round;`Null
   |"height"->E.start_height t (Int64.of_string(str input "height" "13"));`Null
   |"realign"->E.realign_round t round;`Null
   |"ready"->ready:=bool input "ready" true;E.on_ready t ~sign_fn:(sign me);`Null
   |"skip_ready"->skip:=bool input "ready" true;`Null
   |"proposal"->let p=make_proposal()in add "wire"(h(C.encode_propose p));if verify p.proposer(H.propose_sign_bytes p)p.signature then E.on_propose t p ~verify_fn:verify ~execute_fn:(fun _->bool input "execute" true) ~sign_fn:(sign me);`Null
   |"local_proposal"->add "header"(h(header_wire header));add "hashes"(`List(List.map h tx_hashes));E.do_propose t header tx_hashes ~sign_fn:(sign me);`Null
   |"vote"->let v=make_vote(int input "who" 2)(if int input "type" 1=1 then Prevote else Precommit)in add "wire"(h(C.encode_vote v));if verify v.validator(H.vote_sign_bytes v)v.signature then E.on_vote t v ~sign_fn:(sign me);`Null
   |"sync"->let who=int input "who" 2 in let s:C.round_sync={chain_id=chain;epoch_id=t.state.height;round;step=ProposeStep;request=false;validator=addr who;signature=String.make 64 '\000'}in let s={s with signature=if bool input "corrupt" false then String.make 64 '\000'else sign who(H.round_sync_sign_bytes s)}in add "wire"(h(C.encode_round_sync s));`Bool(if verify s.validator(H.round_sync_sign_bytes s)s.signature then E.on_round_sync t ~round ~validator:s.validator else false)
   |"timeout"->let step=if member "step" input=`Null then t.state.step else step input in let generation=int input "generation" t.generation in add "step"(`Int(round_step_to_u8 step));add "round"(`Int round);add "generation"(`Int generation);E.on_timeout t ~step ~round ~generation ~sign_fn:(sign me);`Null
   |"restore"->let p=make_proposal()in add "wire"(h(C.encode_propose p));(match E.restore_precommit_lock t p with Ok()->`Null|Error e->`Assoc["error",`String e])
   |"reconfigure"->let vs=set(int input "n" n)(bool input "weighted" weighted)in add "validators"(h(C.encode_validator_set vs));E.reconfigure_validator_set t ~round vs;`Null
   |"finalize"->let f:finalize={chain_id=chain;epoch_id=t.state.height;commit_round=round;header;proposal_id=pid;precommits=List.init(int input "count" n)(fun i->make_vote(i+1)Precommit);parent_commit=None}in add "wire"(h(C.encode_finalize f));(match C_qc.validate_finalize ~chain_id:chain ~validator_set:t.vs ~verify_vote:(fun(v:vote)->verify v.validator(H.vote_sign_bytes v)v.signature)f with C_qc.Invalid e->`Assoc["error",`String e]|C_qc.Valid->`Bool(E.accept_finalize_batch t f))
   |"ack"->`Bool(match t.pending_finalized with None->false|Some f->E.ack_finalized t f)
   |"drain"->`Null
   |_ -> failwith "op")in
  let original=to_assoc input in let norm=`Assoc(!extras@List.filter(fun(k,_)->not(List.mem_assoc k !extras))original)in normalized:=norm::!normalized;snapshot t result)in
 `Assoc["input",`Assoc(("steps",`List(List.rev !normalized))::List.remove_assoc "steps"(to_assoc config));"expected",`List results]
let ()=Octra_log._set_level Octra_log.FATAL;Yojson.Safe.from_file Sys.argv.(1)|>to_list|>List.map run|>fun xs->Yojson.Safe.to_channel stdout(`List xs)
