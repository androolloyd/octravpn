open Yojson.Safe.Util
open Octra_consensus
module A=C_output_actor
module W=C_work_slot
module R=C_relay
module P=C_round_pool
let n j k=member k j |> to_int
let s j k=member k j |> to_string
let b j k=member k j |> to_bool
let f j k=float_of_string(s j k)
let i j k=Int64.of_string(s j k)
let hex s=String.concat "" (List.init(String.length s)(fun i->Printf.sprintf "%02x"(Char.code s.[i])))
let raw j k=let s=s j k in String.init(String.length s/2)(fun i->Char.chr(int_of_string("0x"^String.sub s(i*2)2)))
let time f=`String(Printf.sprintf "%016Lx"(Int64.bits_of_float f))
let item j : int R.item={key=raw j "key"; value=n j "value"; expires=f j "expires"}
let ji (v:int R.item)=`Assoc["key",`String(hex v.key);"value",`Int v.value;"expires",time v.expires]
let outcome j=match s j "outcome" with "sent"->R.Sent|"expired"->R.Expired|"cancelled"->R.Cancelled|_->R.Failed(raw j "reason")
let effect=function R.Send(id,v)->`List[`String"send";`Int id;ji v]|R.Cancel->`String"cancel"|R.Dropped s->`List[`String"dropped";`String(hex s)]
let relay j=
 let state=ref {R.empty with serial=n j "serial"} in
 `List(member "steps" j |> to_list |> List.map(fun j->
  let msg=match s j "op" with
  |"offer"->R.Offer(n j "generation",f j "now",item j)
  |"advance"->R.Advance(n j "generation",f j "now")
  |"open"->R.Open(n j "generation")|"close"->R.Close
  |_->R.Finished((if b j "active" then match (!state).active with Some(id,_)->id|None-> -1 else n j "id"),f j "now",outcome j)in
  let next,effects=R.step !state msg in state:=next;
  `Assoc["generation",`Int next.generation;"serial",`Int next.serial;"active",(match next.active with None->`Null|Some(id,v)->`List[`Int id;ji v]);
    "queue",`List(List.map ji next.queue);"seen",`List(List.map(fun s->`String(hex s))next.seen);"closed",`Bool next.closed;"effects",`List(List.map effect effects)]))
let work j=
 let state=ref W.empty and last=ref(-1)in
 `List(member "steps" j |> to_list |> List.map(fun j->
  let msg=match s j "op" with "submit"->W.Submit(n j "job")|"take"->W.Take|"open"->W.Open|"close"->W.Close
  |_->W.Finish((if b j "active"then !last else n j "id"),n j "reply")in
  let next,effects=W.step !state msg in state:=next;
  let effects=List.map(function W.Run(id,job)->last:=id;`List[`String"run";`Int id;`Int job]
   |W.Complete job->`List[`String"complete";`Int job]|W.Deliver(job,reply)->`List[`String"deliver";`Int job;`Int reply])effects in
  `Assoc["idle",`Bool(W.idle next);"ready",`Bool(W.ready next);"effects",`List effects]))
let actor j=let state=ref A.idle in
 `List(member "steps" j |> to_list |> List.map(fun j->
  let result=match to_string j with
  |"request"->let next,r=A.request !state in state:=next;`String(match r with A.Start->"start"|A.Join->"join")
  |"complete"->let next,r=A.complete !state in state:=next;`String(match r with A.Continue->"continue"|A.Stop->"stop")
  |_->state:=A.fail !state;`Null in `Assoc["result",result;"idle",`Bool(A.is_idle !state)]))
let sync j : C_codec.round_sync={chain_id=raw j "chain";epoch_id=i j "epoch";round=n j "round";step=C_types.round_step_of_u8(n j "step");request=b j "request";validator=raw j "validator";signature=raw j "signature"}
let js(v:C_codec.round_sync)=`Assoc["chain",`String(hex v.chain_id);"epoch",`String(Int64.to_string v.epoch_id);"round",`Int v.round;"step",`Int(C_types.round_step_to_u8 v.step);"request",`Bool v.request;"validator",`String(hex v.validator);"signature",`String(hex v.signature)]
let option f=function None->`Null|Some v->f v
let pool j=
 let entries=member "validators" j |> to_list |> List.mapi(fun index v->({C_types.address=raw v "address";pubkey=String.make 32 (Char.chr(index+1))},Z.of_string(s v "weight")))in
 let validators=if b j "weighted"then match C_types.make_weighted_validator_set entries with Ok v->v|Error e->failwith e else C_types.make_validator_set(List.map fst entries)in
 let pool=P.create()in
 `List(member "steps" j |> to_list |> List.map(fun action->
  Unix.putenv "OCTRA_ROUND_POOL_ORACLE_TIME" (s action "now");
  (match s action "op"with
   |"clear"->P.clear pool
   |"add"->P.add pool(sync(member "sync" action))
   |"local"->P.add_local pool(sync(member "sync" action))
   |"add_at"->P.add_at pool ~current:(n action "current") (sync(member "sync" action))
   |_->());
  `List(member "queries" action |> to_list |> List.map(fun q->
   let epoch_id=i q "epoch"and after_round=n q "after"and through_round=n q "through"in
   `Assoc["reply",option(fun(s,t)->`List[js s;time t])(P.reply pool ~epoch_id ~validator:(raw q "validator"));
    "sent",option js(P.sent_reply pool ~epoch_id ~after_round ~through_round);
    "range",`List(List.map js(P.sent_range pool ~epoch_id ~after_round ~through_round));
    "witness",`List(List.map js(P.witness pool ~chain_id:(raw q "chain") ~epoch_id ~after_round ~through_round ~validator_set:validators))]))))
let settle ()=Lwt_main.run(let rec loop n=if n=0 then Lwt.return_unit else Lwt.bind(Lwt.pause())(fun()->loop(n-1))in loop 20)
let gate j=
 let gate=C_proposal_work_gate.create()and relevant=ref true and checks=ref[]and calls=ref[]in
 let jobs=Hashtbl.create 16 and waits=Hashtbl.create 16 in
 let result p=match Lwt.state p with Lwt.Sleep->`String"pending"|Lwt.Return v->v|Lwt.Fail Lwt.Canceled->`String"cancelled"|Lwt.Fail _->`String"error"in
 let results=member"steps"j|>to_list|>List.map(fun j->
  let id=s j"id"in
  let answer=match s j"op"with
  |"enqueue"->
    let p=C_proposal_work_gate.run gate ~relevant:(fun()->checks:= !checks@[id];!relevant)(fun()->
      calls:= !calls@[id];let p,w=Lwt.task()in Hashtbl.replace jobs id(p,w);Lwt.map(fun n->Some n)p)in
    Hashtbl.replace waits id(Lwt.map(fun n->option(fun n->`Int n)n)p);`Null
  |"cancel"->Option.iter Lwt.cancel(Hashtbl.find_opt waits id);`Null
  |"relevant"->relevant:=b j"value";`Null
  |"resolve"->(match Hashtbl.find_opt jobs id with
     |Some(p,w)when Lwt.is_sleeping p->if b j"error"then Lwt.wakeup_exn w(Failure"worker failed")else Lwt.wakeup w(n j"value");`Bool true
     |_->`Bool false)
  |_->`Null in
  settle();
  let waits=Hashtbl.fold(fun id p acc->(id,result p)::acc)waits[]|>List.sort compare in
  `Assoc["answer",answer;"checks",`List(List.map(fun s->`String s)!checks);"calls",`List(List.map(fun s->`String s)!calls);"waiters",`Assoc waits])in
 Hashtbl.iter(fun _ p->Lwt.cancel p)waits;settle();`List results

let async_relay j=
 let clock=ref 0. and calls=ref[]and pending=ref[]and timers=ref[]and warnings=ref[]in
 let actor=R.create ~now:(fun()-> !clock)
  ~send:(fun value->calls:= !calls@[value];let p,w=Lwt.task()in pending:= !pending@[p,w];p)
  ~wait:(fun seconds->let p,w=Lwt.task()in timers:= !timers@[seconds,p,w];p)
  ~warn:(fun reason->warnings:= !warnings@[hex reason])in
 let state p=match Lwt.state p with Lwt.Sleep->"pending"|Lwt.Return()->"done"|Lwt.Fail Lwt.Canceled->"cancelled"|Lwt.Fail _->"error"in
 let resolve entries index error=match List.nth_opt entries index with
  |Some(p,w)when Lwt.is_sleeping p->if error then Lwt.wakeup_exn w(Failure"peer disconnected")else Lwt.wakeup w();true
  |_->false in
 let results=member"steps"j|>to_list|>List.map(fun step->
  let answer=match s step"op"with
  |"offer"->R.offer actor ~generation:(n step"generation") ~key:(raw step"key") (n step"value");`Null
  |"progress"->R.progress actor ~generation:(n step"generation");`Null
  |"close"->R.close actor;`Null
  |"open"->R.open_ actor ~generation:(n step"generation");`Null
  |"clock"->clock:=f step"now";`Null
  |"resolve"->`Bool(resolve !pending(n step"index")(b step"error"))
  |"expire"->`Bool(resolve(List.map(fun(_,p,w)->p,w)!timers)(n step"index")false)
  |_->`Null in
  settle();
  `Assoc["answer",answer;"calls",`List(List.map(fun n->`Int n)!calls);
   "sends",`List(List.map(fun(p,_)->`String(state p))!pending);
   "timers",`List(List.map(fun(seconds,p,_)->`List[time seconds;`String(state p)])!timers);
   "warnings",`List(List.map(fun s->`String s)!warnings)])in
 R.close actor;settle();`List results

let run j=match s j "kind"with"async_relay"->async_relay j|"gate"->gate j|"actor"->actor j|"work"->work j|"relay"->relay j|_->pool j
let ()=let cases=Yojson.Safe.from_channel stdin |> to_list |> List.map(fun input->`Assoc["input",input;"expected",run input])in Yojson.Safe.to_channel stdout (`List cases);print_newline()
