open Yojson.Safe.Util
module N=Octra_net
module U=N.P2p_upgrade_plan
module S=N.P2p_swarm
let b v=Base64.decode_exn(to_string v)
let enc v=`String(Base64.encode_exn v)
let raw j k=b(member k j)
let i j k=member k j|>to_string|>Int64.of_string
let target j:U.rollback={rollback_epoch=i j"epoch";rollback_binary_hash=raw j"binary";rollback_config_hash=raw j"config"}
let plan j=match j with `Null->None|_->Some U.{activate_epoch=i j"epoch";target_binary_hash=raw j"binary";target_config_hash=raw j"config";rollback=(match member"rollback"j with `Null->None|v->Some(target v))}
let opt j k=match member k j with `Null->None|v->Some(b v)
let catch f=try f()with Failure s|Invalid_argument s->`Assoc["error",enc s]
let direction=function N.P2p_conn.Inbound->`String"inbound"|Outbound->`String"outbound"
let run j=catch(fun()->match member"op"j|>to_string with
|"upgrade"->let p=plan(member"plan"j)and epoch=i j"epoch"and config_hash=raw j"config"and binary_hash=raw j"binary"and require_binary_hash=member"required"j|>to_bool in
 `Assoc["handshake",enc(U.handshake_hash ~epoch ~config_hash ~binary_hash ~require_binary_hash p);"active",`Bool(U.active ~epoch p);"rollback",`Bool(U.rollback_active ~epoch p);"required",`Bool(U.binary_required ~epoch ~require_binary_hash p);"expected",enc(U.expected_binary_hash ~epoch ~binary_hash p);"ready",(match U.ready ~epoch ~config_hash ~binary_hash ~require_binary_hash p with Ready->`Null|Not_ready reason->`String reason);"schedule",(match p with None->`Null|Some p->enc(U.schedule_hash ~base_config_hash:config_hash p))]
|"normalize"->(match U.normalize_hash "test"(raw j"value")with Ok v->enc v|Error e->`Assoc["error",enc e])
|"retry"->(match S.record_dial_plan ~now:(member"now"j|>to_number) ~due:(match member"due"j with `Null->None|v->Some(to_number v)) ~active:(member"active"j|>to_int)with Hold->`Null|Start t->`Float t)
|"capacity"->`Bool(S.peer_capacity ~max_peers:(member"maximum"j|>to_int) ~validator_count:(member"validators"j|>to_int) ~observer_count:(member"observers"j|>to_int)(if member"validator"j|>to_bool then S.Validator else S.Observer))
|"keep"->`Bool(S.keep_profile ~target:(raw j"target") ~current:(raw j"current") ~offered:(opt j"offered"))
|"roles"->let keys=match member"keys"j with `Null->[]|v->to_list v|>List.map b in
 let cfg:S.config={listen_port=9000;chain_id="test";node_id=raw j"local_id";node_addr="node";pubkey_raw=raw j"public";consensus_config_hash=String.make 32 '\001';binary_hash=String.make 32 '\002';require_binary_hash=false;upgrade_plan=None;profile_plan=[];allowed_pubkeys=keys;bootstrap_peers=[];max_peers=10;sign_fn=(fun _->String.make 64 '\000');best_epoch_fn=(fun()->0L);best_root_fn=(fun()->String.make 32 '\000')}in
 let swarm=S.create cfg in
 let updated=match member"update"j with `Null->`Null|v->(match S.set_validator_pubkeys swarm(List.map b(to_list v))with Ok()->`Null|Error e->enc e)in
 `Assoc["validator",`Bool(S.peer_role swarm(raw j"peer_id")=S.Validator);"local",`Bool(S.local_is_validator swarm);"observers",`Bool(S.local_accepts_observers swarm);"direction",direction(S.preferred_direction swarm(raw j"peer_id"));"updated",updated]
|_->failwith"operation")
let ()=let cases=Yojson.Safe.from_channel stdin|>to_list|>List.map(fun input->`Assoc["input",input;"expected",run input])in Yojson.Safe.to_channel stdout(`List cases);print_newline()
