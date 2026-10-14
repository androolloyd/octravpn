(* Unmodified native reward and emission policies; no peer or live wallet. *)
open Yojson.Safe.Util
module C=Octra_core
module E=C.Epoch_exec
module M=C.Emission_schedule
let z j k=j|>member k|>to_string|>Z.of_string
let b j k=j|>member k|>to_bool
let i j k=j|>member k|>to_int
let bytes v=Base64.decode_exn(to_string v)
let optional j k=match j|>member k with `Null->None|v->Some(bytes v)
let b64 s=`String(Base64.encode_exn s)
let zs z=`String(Z.to_string z)
let schedule j=match j|>member "activation" with `Null->M.Inactive|v->M.Security_curve{activation_epoch=to_int v}
let plan_json (p:E.reward_plan)=`Assoc[
 "base_reward",zs p.base_reward;"fees_burned",zs p.fees_burned;"fees_rewarded",zs p.fees_rewarded;"total_reward",zs p.total_reward;"proposer_total",zs p.proposer_total;"each_validator",zs p.each_validator;"remainder",zs p.remainder;
 "new_emission_remaining",zs p.new_emission_remaining;"new_total_supply",zs p.new_total_supply;"new_supply_retired",zs p.new_supply_retired;"supply_tracking_active",`Bool p.supply_tracking_active]
let plan j=E.build_reward_plan_with_base ~fee_burn_active:(b j "active") ~supply_retired:(z j "retired") ~base_reward:(match j|>member "base" with `Null->E.compute_base_reward ~emission_remaining:(z j "remaining")|v->Z.of_string(to_string v)) ~validator_count:(i j "count") ~emission_remaining:(z j "remaining") ~confirmed_fees:(z j "fees") ~prev_supply:(z j "supply")
let reward j:E.reward_attribution={proposer_addr=bytes(j|>member "proposer");proposer_public_key=None;validators=j|>member "validators"|>to_list|>List.map(fun v->E.{address=bytes(v|>member "address");public_key=None;weight=z v "weight"})}
let credit (c:E.reward_credit)=`Assoc["address",b64 c.address;"proposer",`Bool c.proposer;"validator",`Bool c.validator;"amount",zs c.amount]
let binding j=M.bind ~schedule:(schedule j) ~epoch_id:(i j "epoch") ~remaining:(z j "remaining") ~headroom:(z j "headroom") ~stored_standard:(optional j "standard") ~stored_activation:(optional j "stored_activation") ~stored_initial:(optional j "initial") ~stored_retired:(optional j "stored_retired")
let binding_json (v:M.binding)=`Assoc["initial",zs v.initial;"remaining",zs v.remaining;"retired",zs v.retired;"active",`Bool v.active;"activated",`Bool v.activated;"writes",`List(List.map(fun(k,v)->`List[b64 k;b64 v])v.writes)]
let result f=function Ok v->`Assoc["ok",f v]|Error e->`Assoc["error",`String e]
let run j=match j|>member "op"|>to_string with
 |"plan"->result plan_json(plan j)
 |"credits"->(match plan j with Error e->`Assoc["error",`String e]|Ok p->result(fun xs->`List(List.map credit xs))(E.reward_credits(reward j)p))
 |"binding"->result binding_json(binding j)
 |"reward"->result (function None->`Null|Some v->zs v) (M.reward ~schedule:(schedule j) ~epoch_id:(i j "epoch") {M.initial=z j "initial";remaining=z j "remaining";retired=Z.zero;active=true;activated=false;writes=[]})
 |"cumulative"->zs(M.cumulative(z j "initial")(i j "elapsed"))
 |_->failwith"unknown operation"
let ()=let cases=Yojson.Safe.from_channel stdin|>to_list|>List.map(fun input->`Assoc["input",input;"expected",run input])in Yojson.Safe.to_channel stdout(`List cases);print_newline()
