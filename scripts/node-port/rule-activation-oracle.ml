open Yojson.Safe.Util
open Octra_consensus
module R=Octra_core.Rule_graph
module S=Octra_node_runtime.Set_rule
let s j k=member k j|>to_string
let n j k=member k j|>to_int
let i j k=Int64.of_string(s j k)
let raw j k=Base64.decode_exn(s j k)
let b64 s=`String(Base64.encode_exn s)
let opt f=function None->`Null|Some v->f v
let mode=function R.Prior->`Bool false|Active->`Bool true
let result f=function Ok v->f v|Error e->`Assoc["error",`String e]
let plan p=`List[`Int p.R.anchor_epoch;b64 p.anchor_state_root;`Int p.activation_epoch]
let read_plan j=R.{anchor_epoch=n j"anchor";anchor_state_root=raw j"root";activation_epoch=n j"activate"}
let key id=Mirage_crypto_ec.Ed25519.priv_of_octets(String.make 32(Char.chr id))|>Result.get_ok
let pub id=Mirage_crypto_ec.Ed25519.(pub_of_priv(key id)|>pub_to_octets)
let sign id msg=Mirage_crypto_ec.Ed25519.sign ~key:(key id)msg
let addr id="v"^string_of_int id
let parent j=
 let chain_id=raw j"chain"and epoch_id=i j"epoch"and round=n j"round"in
 let validators=List.init(n j"members")(fun k->C_types.{address=addr(k+1);pubkey=pub(k+1)})in
 let validator_set=C_types.make_validator_set validators in
 let header=C_types.{proto_version=C_protocol.version_for_epoch epoch_id;chain_id;epoch_id;prev_state_root=String.make 32 '\001';tx_list_hash=String.make 32 '\002';receipt_root=String.make 32 '\003';proposed_state_root=String.make 32 '\004';parent_commit_hash=String.make 32 '\000';creator_addr=addr 1;txid_hi=7L;ts=1.}in
 let proposal_id=C_hash.proposal_id header in
 let precommits=member"signers"j|>to_list|>List.map(fun id->let id=to_int id in let v=C_types.{chain_id;epoch_id;round;vote_type=Precommit;proposal_id;validator=addr id;signature=""}in {v with signature=(if member"corrupt"j=`Bool true then String.make 64 '\000'else sign id(C_hash.vote_sign_bytes v))})in
 let certificate=C_types.{chain_id;epoch_id;commit_round=round;header;proposal_id;precommits}in
 C_types.{certificate;validator_set}
let activations chain=let graph=R.create ~chain_id:chain ~root_at:(fun _->R.Missing)in [|R.circle_activation graph;R.wasm_compute_activation graph;R.validator_quorum_activation graph;R.epoch_time_activation graph;R.owner_migration_activation graph;R.private_payload_activation graph;R.set_fold_activation graph;R.validator_ready_activation graph;R.ready_ref_activation graph;R.set_live_activation graph;R.set_fold_cap_activation graph;R.set_open_activation graph;R.object_cost_activation graph;R.account_pack_activation graph;R.standard_activation graph;R.set_plan_activation graph;R.math_activation graph;R.exit_activation graph;R.ready_exec_activation_for_chain chain;R.program_source_activation_for_chain chain;R.tx_envelope_activation_for_chain chain;R.fhe_work_activation_for_chain chain;R.wasm_float_activation_for_chain chain;R.batch_activation_for_chain chain;R.proof_activation_for_chain chain;R.vm_bytes_activation_for_chain chain;R.cipher_activation_for_chain chain;R.settle_activation_for_chain chain|]
let modes=[|R.circle;R.wasm_compute;R.validator_quorum;R.epoch_time;R.owner_migration;R.private_payload;R.set_fold;R.validator_ready;R.ready_ref;R.set_live;R.set_fold_cap;R.set_open;R.object_cost;R.account_pack;R.standard;R.set_plan;R.math;R.exit;R.ready_exec;R.program_source;R.tx_envelope;R.fhe_work;R.wasm_float;R.circle_batch;R.proof_exec;R.vm_bytes;R.cipher_migration;R.settle|]
let run input=if s input"kind"="activation" then
 let plan=match member"plan"input with `Null->None|p->Some(read_plan p)in
 let root_at _=match s input"default"with "missing"->R.Missing|"bad"->R.Root"wrong-root"|"unreadable"->R.Unreadable"disk unavailable"|_->R.Root(Option.get plan).anchor_state_root in
 R.activation_mode ~root_at plan ~epoch:(n input"epoch")|>Result.map_error(fun e->Base64.encode_exn(R.fault_message e))|>result mode
 else
 let chain=raw input"chain"and epoch=n input"epoch"in
 let plans=activations chain in
 let root_at epoch=
  let kind=match member(string_of_int epoch)(member"roots"input)with `String s->s|_->s input"default"in
  match kind with
  |"missing"->R.Missing|"bad"->R.Root"wrong-root"|"unreadable"->R.Unreadable"disk unavailable"
  |"good"->(match Array.to_list plans|>List.find_map(function Some p when p.R.anchor_epoch=epoch->Some p.anchor_state_root|_->None)with None->R.Missing|Some p->R.Root p)
  |_->assert false in
 let graph=match member"config"input with `Null->R.create ~chain_id:chain ~root_at|_->R.create_ready ~ready_config_hash:(raw input"config") ~chain_id:chain ~root_at in
 let parent=match member"parent"input with `Null->None|j->Some(parent j)in
 let bound=Result.bind (S.bind graph ~chain_id:(raw input"bind_chain") ~parent ~epoch) (fun f->f(n input"target"))in
 let binding=result(fun (c:Octra_core.Epoch_exec.fold_ctx)->`Assoc[
  "modes",`List(List.map mode [c.mode;c.ready_mode;c.ready_ref_mode;c.live_mode;c.seat_mode;c.open_mode;c.account_mode;c.standard_mode;c.plan_mode;c.exit_mode;c.ready_exec_mode;c.program_mode;c.fhe_work;c.proof_exec;c.vm_bytes;c.wasm_float]);
  "overlap",`Bool c.program_overlap;"math",`Bool c.math;"prune",`Bool(c.cap_mode=Octra_core.Set_fold.Prune);"config",opt b64 c.ready_config_hash;
  "start",`String(Int64.to_string c.start);"profile",`String(Int64.to_string c.profile_start);"members",`List(List.map b64 c.members)])bound in
 `Assoc["plans",`List(Array.to_list plans|>List.map(opt plan));"modes",`List(Array.to_list modes|>List.map(fun f->f graph ~epoch|>Result.map_error(fun e->Base64.encode_exn(R.fault_message e))|>result mode));
 "overlap",(R.program_overlap graph ~epoch|>Result.map_error(fun e->Base64.encode_exn(R.fault_message e))|>result(fun b->`Bool b));
 "profiles",`List(List.map(fun n->`Int n)(R.profile_epochs ~chain_id:chain));"live",`Bool(R.live_chain ~chain_id:chain);"id",b64(R.consensus_id ~chain_id:chain ~epoch);
 "floor",`List(member"probes"input|>to_list|>List.map(fun e->opt b64(R.root_after_floor ~chain_id:chain ~floor_epoch:(n input"floor") ~epoch:(to_int e))));
 "parent",opt(fun p->b64(C_codec.encode_parent_commit p))parent;"bind",binding]
let ()=let cases=Yojson.Safe.from_channel stdin|>to_list in Yojson.Safe.to_channel stdout(`List(List.map(fun input->`Assoc["input",input;"expected",run input])cases));print_newline()
