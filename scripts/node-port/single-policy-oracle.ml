open Yojson.Safe.Util
module R=Octra_node_runtime
module Role=Octra_consensus.C_role
module P=R.Consensus_epoch_apply_proposer
let bytes j k=Base64.decode_exn(member k j|>to_string)
let opt j k=match member k j with `Null->None|v->Some(Base64.decode_exn(to_string v))
let b64 raw=`String(Base64.encode_exn raw)
let gate=function
 |R.Preverify_cache.Ready_gate->`List[`String"ready"]
 |Failed_gate why->`List[`String"failed";b64 why]
 |Timeout_gate why->`List[`String"timeout";b64 why]
 |Defer_gate d->`List[`String"defer";`Int d.next_count;b64 d.status]
 |Unavailable_gate d->`List[`String"unavailable";`Int d.next_count;b64(R.Tx_view.preverify_unavailable_message d.reason)]
let run input=let result=try match member"kind"input|>to_string with
 |"role"->let role=Role.of_mode ~cli_observer:(member"cli"input|>to_bool)(opt input"mode")in `Assoc["label",`String(Role.label role);"consensus",`Bool(Role.consensus_enabled role);"voting",`Bool(Role.voting_enabled role);"observer",`Bool(Role.is_observer role)]
 |"tick"->let plan=R.Consensus_tick_plan.plan ~consensus_mode:false ~epoch_duration:10. ~elapsed:(member"elapsed"input|>to_string|>float_of_string) ~finalized_state:R.Consensus_tick_plan.No_trigger in `List[`Bool(R.Consensus_tick_plan.should_apply plan.action);`Bool plan.log_tick;`Float plan.next_sleep]
 |"proposer"->let validators=member"validators"input|>to_list|>List.map(fun v->Base64.decode_exn(to_string v))in let override=Option.map(fun address->Octra_core.Epochlog.{creator_addr=address;commit_round=7})(opt input"override")in (match P.choose P.{epoch_id=member"epoch"input|>to_int;consensus_mode=false;active_validators=validators;env_fee_recipient=opt input"fee";override_proposer=override;pending_proposer=None;finalized_header_proposer=None;disk_epoch=None}with Error _->`Assoc["error",`String"missing_fallback_validator"]|Ok chosen->`List[b64 chosen.proposer.creator_addr;`String(P.source_label chosen.source);`Int chosen.proposer.commit_round])
 |"validators"->List.iter(fun(key,name)->Unix.putenv name(Option.value(opt input key)~default:""))["current","OCTRA_VALIDATORS";"next","OCTRA_VALIDATORS_NEXT";"activation","OCTRA_VALIDATORS_ACTIVATE_EPOCH"];R.Validators.pubkeys_for_epoch ~wallet_addr:"octWallet" ~wallet_pub:"raw-key" ~epoch:(member"epoch"input|>to_int)|>List.map(fun(a,k)->`List[b64 a;b64 k])|>fun rows->`List rows
 |"cache"|"cache-table"->
 let rows=member"entries"input|>to_list|>List.map(fun row->R.Preverify_submit.{cache_key=bytes row "key";cache_ts=member"time"row|>to_string|>float_of_string;cache_pending=member"pending"row|>to_bool})in
 let entries=if member"kind"input=`String"cache-table"then(let table=Hashtbl.create 100 in List.iter(fun(entry:R.Preverify_submit.cache_entry)->Hashtbl.replace table entry.cache_key entry)rows;Hashtbl.fold(fun _ entry acc->entry::acc)table[])else rows in
 let now=member"now"input|>to_string|>float_of_string and ttl=member"ttl"input|>to_string|>float_of_string and maximum=member"maximum"input|>to_int in
 let prune=R.Preverify_submit.cache_prune_plan ~now ~ttl ~max_entries:maximum entries and cap=R.Preverify_submit.hard_cap_plan ~max_entries:maximum entries in
 `Assoc["order",`List(List.map(fun(entry:R.Preverify_submit.cache_entry)->b64 entry.cache_key)entries);"expired",`List(List.map b64 prune.prune_expired);"overflow",`List(List.map b64 prune.prune_overflow);"hard_drop",`List(List.map b64 cap.hard_cap_drop);"requested",`Int cap.hard_cap_requested_drop]
 |"gate"->let state=match member"state"input|>to_string with "missing"->R.Preverify_cache.Missing|"pending"->Pending|"ready"->Ready|"failed"->Failed(bytes input"reason")|"unavailable"->Unavailable_state(R.Tx_view.Proof_worker_unavailable(bytes input"reason"))|_->assert false in gate(R.Preverify_cache.gate ~state ~defer_count:(member"count"input|>to_int) ~max_defer:(member"maximum"input|>to_int))
 |_->assert false with exn->`Assoc["exception",`String(Printexc.to_string exn)]in `Assoc["input",input;"expected",result]
let ()=let cases=Yojson.Safe.from_channel stdin|>to_list|>List.map run in Yojson.Safe.to_channel stdout(`List cases);print_newline()
