open Yojson.Safe.Util
module C = Octra_consensus
module T = C.C_types
let hex raw = String.concat "" (List.init (String.length raw) (fun i -> Printf.sprintf "%02x" (Char.code raw.[i])))
let unhex text = String.init (String.length text/2) (fun i->Char.chr(int_of_string("0x"^String.sub text (i*2) 2)))
let field name j = member name j
let string name j = field name j |> to_string
let raw name j = string name j |> unhex
let int name j = field name j |> to_int
let i64 name j = string name j |> Int64.of_string
let big name j = string name j |> Z.of_string
let err = function Failure s|Invalid_argument s -> s | exn -> Printexc.to_string exn
let catch f = try f() with exn -> `Assoc["error",`String(err exn)]
let resolve = function Ok v -> v | Error s -> failwith s
let result f = match f() with Ok n -> `String(Int64.to_string n) | Error e -> `Assoc["error",`String e]
let set j =
 let entries=field "entries" j|>to_list|>List.map(fun j -> ({T.address=raw "address" j;pubkey=raw "pubkey" j},big "weight" j)) in
 if field "weighted" j|>to_bool then T.make_weighted_validator_set entries|>resolve else T.make_validator_set(List.map fst entries)
let set_json (s:T.validator_set) = `Assoc[
 "n",`Int s.n;"f",`Int s.f;"quorum",`Int s.quorum;"weighted",`Bool s.weighted;
 "total",`String(Z.to_string s.total_weight);"quorum_weight",`String(Z.to_string s.quorum_weight);
 "entries",`List(List.map(fun (v:T.validator_info)->`Assoc["address",`String(hex v.address);"pubkey",`String(hex v.pubkey);"weight",`String(Z.to_string(Option.get(T.weight_of_addr s v.address)))])s.validators);
 "hash",`String(hex(C.C_config.validator_set_hash s));"wire",`String(hex(C.C_codec.encode_validator_set s))]
let execute j = catch(fun()->match string "op" j with
| "set" -> let s=set j in
 let chain_id=raw "chain_id" j and epoch_id=i64 "epoch_id" j in
 let signers=field "signers" j|>to_list|>List.map(fun x->unhex(to_string x)) in
 let count=int "signer_count" j and weight=big "signed_weight" j in
 let effective=T.validator_set_for_epoch ~chain_id ~epoch_id s in
 `Assoc["set",set_json s;"cap",`String(Z.to_string(T.count_weight_cap s));"effective",set_json effective;
 "leaders",`List(field "rounds" j|>to_list|>List.map(fun round->catch(fun()->`String(hex(T.leader_of effective ~epoch_id ~round:(to_int round)).address))));
 "signed_weight",(match T.signed_weight s signers with None->`Null|Some weight->`String(Z.to_string weight));
 "weight_quorum",`Bool(T.has_weight_quorum s signers);"quorum",`Bool(T.has_quorum s signers);"quorum_at",`Bool(T.has_quorum_at ~chain_id ~epoch_id s signers);
 "reached",`Bool(T.quorum_reached_at ~chain_id ~epoch_id effective ~signer_count:count ~signed_weight:weight);
 "skip_weight",`String(Z.to_string(T.round_skip_weight effective));"skip_reached",`Bool(T.round_skip_reached_at ~chain_id ~epoch_id effective ~signer_count:count ~signed_weight:weight)]
| "decode_set" -> let wire=raw "wire" j in set_json(C.C_codec.decode_validator_set wire)
| "parse_weight" -> (try `String(Z.to_string(Z.of_string(raw "value" j))) with _ -> `Null)
| "policy" -> let chain_id=raw "chain_id" j and epoch_id=i64 "epoch_id" j in
 `Assoc["quorum_active",`Bool(C.C_quorum_policy.active ~chain_id ~epoch_id);"quorum_id",`String(C.C_quorum_policy.consensus_id ~chain_id);
 "rewind_allowed",`Bool(C.C_quorum_policy.rewind_allowed ~chain_id ~from_epoch:epoch_id ~to_epoch:(i64 "to_epoch" j));
 "version",`Int(C.C_protocol.version_at ~activation_epoch:(i64 "activation" j) epoch_id);
 "time_rule",`String(match C.C_epoch_time_policy.rule_for_epoch ~chain_id ~epoch_id with C.Epoch_time.Historical->"historical"|C.Epoch_time.Uniform->"uniform")]
| "time" ->
 let now=Int64.float_of_bits(i64 "now_bits" j) and candidate=Int64.float_of_bits(i64 "candidate_bits" j) in
 let previous=match field "previous" j with `Null->None|value->Some(Int64.of_string(to_string value)) in
 let rule=if string "rule" j="historical" then C.Epoch_time.Historical else C.Epoch_time.Uniform in
 let kind=if string "kind" j="fresh" then C.Epoch_time.Fresh else C.Epoch_time.Reproposal in
 `Assoc["convert",result(fun()->C.Epoch_time.of_seconds candidate);"check",result(fun()->C.Epoch_time.check_proposal ~rule ~kind ~now ~previous ~candidate);
 "delay",`String(Int64.to_string(C.Epoch_time.next_delay_ms ~now ~previous:candidate))]
| _ -> failwith "op")
let () = Yojson.Safe.from_file Sys.argv.(1)|>to_list|>List.map(fun j->`Assoc["input",j;"expected",execute j])|>fun values->Yojson.Safe.to_channel stdout (`List values)
