(* Calls actual pristine exported functions; no source instrumentation. *)
module R=Octra_consensus.Resource_attestations
module A=Octra_consensus.Resource_attestation_admission
module F=Octra_consensus.Resource_attestation_flow
module L=Octra_node_runtime.Consensus_resource_attestation
open Yojson.Safe.Util
let field j k=member k j
let str j=to_string j
let raw s=let n=String.length s in if n mod 2<>0 then failwith "fixture hex" else
  String.init (n/2) (fun i->Char.chr(int_of_string("0x"^String.sub s (i*2) 2)))
let hx s=let b=Buffer.create(String.length s*2) in String.iter(fun c->Buffer.add_string b(Printf.sprintf "%02x"(Char.code c)))s;`String(Buffer.contents b)
let b j k=raw(str(field j k))
let num j=match j with `Int n->Int64.of_int n|`Intlit s|`String s->Int64.of_string s|_->failwith "fixture integer"
let i j k=num(field j k)
let n j k=Int64.to_int(i j k)
let z j k=Z.of_string(str(field j k))
let jz z=`String(Z.to_string z)
let ji n=`String(Int64.to_string n)
let arr f xs=`List(List.map f xs)
let opt f=function None->`Null|Some v->f v
let boxed f=try `Assoc["ok",f()]with Failure s|Invalid_argument s->`Assoc["error",`String s]|Division_by_zero->`Assoc["error",`String "division by zero"]|exn->`Assoc["error",`String(Printexc.to_string exn)]
let fields xs=`Assoc(List.map(fun(k,f)->k,boxed f)xs)
let att j=R.{chain_id=b j "chain_id";epoch_id=i j "epoch_id";node_id=b j "node_id";
  kind=R.attestation_kind_of_u8(n j "kind");commitment=b j "commitment";proof_hash=b j "proof_hash";
  weight=i j "weight";score=b j "score";signature=b j "signature"}
let wire a=hx(R.encode_attestation a)
let ats j=field j "attestations"|>to_list|>List.map att
let storage j=R.{leaf_index=i j "leaf_index";leaf_count=i j "leaf_count";chunk=b j "chunk";
  path=field j "path"|>to_list|>List.map(fun s->R.{side=R.merkle_side_of_u8(n s "side");sibling_hash=b s "sibling_hash"})}
let seed j=F.{chain_id=b j "chain_id";epoch_id=i j "epoch_id";prev_state_root=b j "prev_state_root";prev_qc_randomness=b j "prev_qc_randomness"}
let window j=A.{current_epoch=i j "current_epoch";fraud_window=i j "fraud_window";future_window=i j "future_window"}
let pubkey priv=match Mirage_crypto_ec.Ed25519.priv_of_octets priv with Error _->failwith "fixture key"|Ok key->Mirage_crypto_ec.Ed25519.(pub_to_octets(pub_of_priv key))
let payouts xs=arr(fun p->`List[hx p.R.node_id;ji p.amount])xs
let snapshot s=`Assoc["target_epoch",ji s.F.target_epoch;"source_epoch",ji s.source_epoch;
  "challenge",hx s.challenge;"committee",arr wire s.committee;"root",hx s.committee_root;
  "total",jz s.total_weight;"quorum",jz s.quorum_weight]
let validator_set s=`Assoc["members",arr(fun v->`List[hx v.Octra_consensus.C_types.address;hx v.pubkey])s.Octra_consensus.C_types.validators;
  "n",`Int s.n;"f",`Int s.f;"quorum",`Int s.quorum;"weighted",`Bool s.weighted;"total",jz s.total_weight;"quorum_weight",jz s.quorum_weight]
let gossip j=F.{chain_id=b j "chain_id";seen_epoch=i j "seen_epoch";attestation=att(field j "attestation")}
let reason=function "disabled"->A.Disabled|"capacity"->A.Capacity|"chain_mismatch"->A.ChainMismatch|"epoch_too_old"->A.EpochTooOld|"epoch_too_new"->A.EpochTooNew|"missing_challenge"->A.MissingChallenge|"malformed"->A.Malformed|"bad_score"->A.BadScore|"unknown_node"->A.UnknownNode|"bad_signature"->A.BadSignature|"conflicting_identity"->A.ConflictingIdentity|_->failwith "fixture reason"
let decision j=match str(field j "decision") with "accept"->A.Accept|"reject"->A.Reject(reason(str(field j "reason")))|"quarantine"->A.Quarantine(reason(str(field j "reason")))|_->failwith "fixture decision"
let evidence_json e=`Assoc["node_id",hx e.A.node_id;"epoch_id",ji e.epoch_id;"reason",`String(A.reason_to_string e.reason);"id",hx e.attestation_id;"observed",ji e.observed_epoch;"evidence_id",hx(A.evidence_id e)]
let pool_json pool=`Assoc["accepted",arr wire(A.accepted pool);"rejected",arr evidence_json(A.rejected pool);"quarantined",arr evidence_json(A.quarantined pool);
  "identity",`List(Hashtbl.fold(fun k v acc->`List[hx k;hx v]::acc)pool.A.identity_index [])]
let counts pool=`List[`Int(Hashtbl.length pool.A.accepted);`Int(Hashtbl.length pool.rejected);`Int(Hashtbl.length pool.quarantined)]
let known j calls node= calls:=node::!calls;match field j "public" with `Null->None|v->Some(raw(str v))
let att_value (a:R.attestation)=`Assoc["chain_id",hx a.chain_id;"epoch_id",ji a.epoch_id;"node_id",hx a.node_id;"kind",`Int(R.attestation_kind_to_u8 a.kind);"commitment",hx a.commitment;"proof_hash",hx a.proof_hash;"weight",ji a.weight;"score",hx a.score;"signature",hx a.signature]
let storage_value (e:R.storage_evidence)=`Assoc["leaf_index",ji e.leaf_index;"leaf_count",ji e.leaf_count;"chunk",hx e.chunk;"path",arr(fun s->`Assoc["side",`Int(R.merkle_side_to_u8 s.R.side);"sibling_hash",hx s.sibling_hash])e.path]
let seed_value (e:F.epoch_seed)=`Assoc["chain_id",hx e.chain_id;"epoch_id",ji e.epoch_id;"prev_state_root",hx e.prev_state_root;"prev_qc_randomness",hx e.prev_qc_randomness]
let repeat n=String.make 32(Char.chr n)
let sample chunk=R.{leaf_index=0L;leaf_count=1L;chunk;path=[]}
let fixture_seed=F.{chain_id="resource-fixture";epoch_id=7L;prev_state_root=repeat 18;prev_qc_randomness=repeat 52}
let private_key=String.make 32(Char.chr 7)
let signed ~chain_id ~epoch_id ~node_id ~kind ~commitment ~proof_hash ~weight ~challenge=
 R.unsigned_attestation ~chain_id ~epoch_id ~node_id ~kind ~commitment ~proof_hash ~weight
 |>R.with_score ~challenge|>R.sign_attestation ~priv_raw:private_key
let value_pvac_kat (e:R.pvac_kat_evidence)=`Assoc["key_id",hx e.key_id;"pubkey_hash",hx e.pubkey_hash;"kat_input_hash",hx e.kat_input_hash;"kat_output",hx e.kat_output;"expected_output_hash",hx e.expected_output_hash;"work_units",ji e.work_units]
let value_fhe_receipt (e:R.fhe_receipt_evidence)=`Assoc["verifier_pubkey",hx e.verifier_pubkey;"proof_kind",hx e.proof_kind;"program_id",hx e.program_id;"input_hash",hx e.input_hash;"output_hash",hx e.output_hash;"cost_units",ji e.cost_units;"receipt_signature",hx e.receipt_signature]
let value_circle_asset (e:R.circle_asset_evidence)=`Assoc["circle_id",hx e.circle_id;"resource_path",hx e.resource_path;"asset_root",hx e.asset_root;"byte_count",ji e.byte_count;"storage",storage_value e.storage]
let value_snapshot_availability (e:R.snapshot_availability_evidence)=`Assoc["state_root",hx e.state_root;"range_start",ji e.range_start;"range_end",ji e.range_end;"snapshot_root",hx e.snapshot_root;"byte_count",ji e.byte_count;"storage",storage_value e.storage]
let value_deterministic_trace (e:R.deterministic_trace_evidence)=`Assoc["runtime_id",hx e.runtime_id;"source_hash",hx e.source_hash;"input_hash",hx e.input_hash;"output_hash",hx e.output_hash;"step_limit",ji e.step_limit;"trace_root",hx e.trace_root;"sampled_step",storage_value e.sampled_step]
let value_perturbed_matrix_trace (e:R.perturbed_matrix_trace_evidence)=`Assoc["runtime_id",hx e.runtime_id;"matrix_a_root",hx e.matrix_a_root;"matrix_b_root",hx e.matrix_b_root;"config_hash",hx e.config_hash;"chain_state_hash",hx e.chain_state_hash;"tile_row",ji e.tile_row;"tile_col",ji e.tile_col;"tile_depth",ji e.tile_depth;"tile_trace_root",hx e.tile_trace_root;"sampled_tile",storage_value e.sampled_tile;"field_modulus",ji e.field_modulus;"perturbed_left_values",arr ji e.perturbed_left_values;"perturbed_right_values",arr ji e.perturbed_right_values;"claimed_value",ji e.claimed_value;"opening_nonce",hx e.opening_nonce;"difficulty_bits",`Int e.difficulty_bits;"work_units",ji e.work_units]
let generated event index= signed ~chain_id:(b event "chain_id")~epoch_id:(i event "epoch")
 ~node_id:(b event "prefix"^string_of_int(n event "start"+index))~kind:(R.attestation_kind_of_u8(n event "kind"))
 ~commitment:(b event "commitment")~proof_hash:(repeat 0)~weight:(i event "weight")~challenge:(b event "challenge")
let factory j=
 let challenge=(match field j "challenge_byte"with `Null->F.challenge fixture_seed|v->repeat(to_int v))in let node_id="node-"^str(field j "kind")^"-"^(match field j "plugin"with `Null->"0"|v->string_of_int(to_int v))in
 let make kind commitment proof_hash=signed ~chain_id:fixture_seed.chain_id ~epoch_id:fixture_seed.epoch_id ~node_id ~kind ~commitment ~proof_hash ~weight:1L ~challenge in
 let common op a fields=`Assoc(["op",`String op;"attestation",att_value a;"challenge",hx challenge;"commitment",hx a.R.commitment;"max_weight",ji 10L;"private",hx private_key;"public",hx(pubkey private_key);"seed",seed_value fixture_seed;"raw_attestation",hx(R.encode_attestation a);"raw_gossip",hx(F.encode_gossip F.{chain_id=fixture_seed.chain_id;seen_epoch=fixture_seed.epoch_id;attestation=a})]@fields)in
 match str(field j "kind")with
 | "pow"->let base=R.unsigned_attestation ~chain_id:fixture_seed.chain_id ~epoch_id:fixture_seed.epoch_id ~node_id ~kind:R.PoW ~commitment:"pow-assignment"~proof_hash:(repeat 0)~weight:1L in
   let rec search n=if n>100000 then failwith "fixture pow exhausted"else let nonce=string_of_int n in let a={base with R.proof_hash=R.pow_proof_hash ~nonce}in
     if R.leading_zero_bits(R.pow_attempt_hash ~challenge a ~nonce)>=8 then nonce else search(n+1)in
   let nonce=search 0 in let a=make R.PoW base.commitment(R.pow_proof_hash ~nonce)in
   common "pow"a["nonce",hx nonce;"difficulty",`Int 8;"digest",hx "\000\000\001";"byte",`Int 0]
 | "storage"->let e,commitment,left,right=if field j "leaves"=`Int 2 then(
     let left="left-payload"and right="right-payload"in let lh=R.storage_leaf_hash left and rh=R.storage_leaf_hash right in
     let root=R.storage_parent_hash lh rh in let base=make R.PoStorage root(repeat 0)in
     let index=Option.get(R.storage_challenge_index ~challenge ~leaf_count:2L base)in
     (if index=0L then R.{leaf_index=index;leaf_count=2L;chunk=left;path=[{side=Right;sibling_hash=rh}]}else R.{leaf_index=index;leaf_count=2L;chunk=right;path=[{side=Left;sibling_hash=lh}]}),root,lh,rh
   )else let e=sample "stored-payload"in e,R.storage_leaf_hash e.chunk,repeat 1,repeat 2 in
   let a=make R.PoStorage commitment(R.storage_evidence_hash e)in
   common "storage"a["evidence",storage_value e;"leaf_count",ji e.leaf_count;"left",hx left;"right",hx right;"digest",hx "\128\000\000\000\000\000\000\000"]
 | "hashchain"->let e=R.{input="useful-input";iterations=7;result=Option.get(R.useful_hash_chain_result ~input:"useful-input"~iterations:7)}in
   let a=make R.PoUW(R.useful_hash_chain_task_id ~challenge ~input:e.input ~iterations:e.iterations)(R.useful_hash_chain_evidence_hash e)in
   common "hashchain"a["evidence",`Assoc["input",hx e.input;"iterations",`Int e.iterations;"result",hx e.result];"min_iterations",`Int 1;"max_iterations",`Int 8;"encode_only",`Bool false]
 | "plugin"->
   let finish plugin subject resource_hash work_units proof_hash e extras=
     let a=make R.PoUW(R.useful_plugin_task_id ~challenge ~plugin ~subject ~resource_hash ~work_units)proof_hash in
     common "plugin"a(["plugin",`Int(R.useful_plugin_to_u8 plugin);"subject",hx subject;"resource_hash",hx resource_hash;"work_units",ji work_units;"hash",hx(repeat 0);"evidence",e;"leaf_count",ji 1L;"difficulty",`Int 0]@extras)in
   begin match n j "plugin"with

 | 1->let base=R.{key_id="pvac-key";pubkey_hash=repeat 1;kat_input_hash=repeat 2;kat_output="kat-output";expected_output_hash=repeat 0;work_units=5L}in
   let e={base with R.expected_output_hash=R.pvac_kat_output_hash base}in
   finish R.PvacKat e.key_id(R.pvac_kat_resource_hash e)e.work_units(R.pvac_kat_evidence_hash e)(value_pvac_kat e)["output_hash",hx e.expected_output_hash]
 | 2->let base=R.{verifier_pubkey=pubkey private_key;proof_kind="range";program_id="program";input_hash=repeat 1;output_hash=repeat 2;cost_units=5L;receipt_signature=String.make 64 '\000'}in
   let e={base with R.receipt_signature=R.sign_fhe_receipt_evidence ~priv_raw:private_key base}in
   finish R.FheProofReceipt e.program_id(R.fhe_receipt_resource_hash e)e.cost_units(R.fhe_receipt_evidence_hash e)(value_fhe_receipt e)[]
 | 3->let storage=sample "asset-payload"in let e=R.{circle_id="circle";resource_path="/index.html";asset_root=R.merkle_root_from_evidence storage;byte_count=128L;storage}in
   finish R.CircleAssetAvailability e.circle_id(R.circle_asset_resource_hash e)e.byte_count(R.circle_asset_evidence_hash e)(value_circle_asset e)[]
 | 4->let storage=sample "snapshot-payload"in let e=R.{state_root=repeat 1;range_start=1L;range_end=20L;snapshot_root=R.merkle_root_from_evidence storage;byte_count=128L;storage}in
   finish R.SnapshotAvailability "1:20"(R.snapshot_availability_resource_hash e)e.byte_count(R.snapshot_availability_evidence_hash e)(value_snapshot_availability e)[]
 | 5->let sampled_step=sample "trace-step"in let e=R.{runtime_id="trace-v1";source_hash=repeat 1;input_hash=repeat 2;output_hash=repeat 3;step_limit=8L;trace_root=R.merkle_root_from_evidence sampled_step;sampled_step}in
   finish R.DeterministicComputationTrace e.runtime_id(R.deterministic_trace_resource_hash e)e.step_limit(R.deterministic_trace_evidence_hash e)(value_deterministic_trace e)[]
 | 6->let sampled_tile=sample ""in let base=R.{runtime_id="matrix-v1";matrix_a_root=repeat 1;matrix_b_root=repeat 2;config_hash=repeat 3;chain_state_hash=repeat 4;tile_row=0L;tile_col=1L;tile_depth=2L;tile_trace_root=repeat 0;sampled_tile;field_modulus=17L;perturbed_left_values=[2L;3L];perturbed_right_values=[4L;5L];claimed_value=Option.get(R.field_dot_mod ~modulus:17L [2L;3L][4L;5L]);opening_nonce="";difficulty_bits=0;work_units=5L}in
   let sampled_tile=sample(R.perturbed_matrix_cell_chunk ~challenge base)in let e={base with R.sampled_tile;tile_trace_root=R.merkle_root_from_evidence sampled_tile}in
   finish R.PerturbedMatrixTrace e.runtime_id(R.perturbed_matrix_trace_resource_hash e)e.work_units(R.perturbed_matrix_trace_evidence_hash e)(value_perturbed_matrix_trace e)[]
 | _->failwith "fixture plugin"end
 | _->failwith "fixture factory"

let run j=match str(field j "op") with
| "factory"->factory j
| "constants"->`List[`Int A.max_accepted;`Int A.max_evidence;`Int F.max_chain_id_bytes;`Int F.max_attestation_bytes]
| "enum"->fields["kind",(fun()->let k=R.attestation_kind_of_u8(n j "kind")in `List[`Int(R.attestation_kind_to_u8 k);`String(R.attestation_kind_to_string k)]);
  "side",(fun()->`Int(R.merkle_side_to_u8(R.merkle_side_of_u8(n j "side"))))]
| "attestation"->let a=att(field j "attestation")in let challenge=b j "challenge"in let priv=b j "private"in fields[
  "unsigned",(fun()->wire(R.unsigned_attestation ~chain_id:a.chain_id ~epoch_id:a.epoch_id ~node_id:a.node_id ~kind:a.kind ~commitment:a.commitment ~proof_hash:a.proof_hash ~weight:a.weight));
  "score",(fun()->hx(R.attestation_score ~challenge a));"scored",(fun()->wire(R.with_score ~challenge a));
  "sign_bytes",(fun()->hx(R.attestation_sign_bytes a));"id",(fun()->hx(R.attestation_id a));"sign",(fun()->wire(R.sign_attestation ~priv_raw:priv a));
  "public",(fun()->hx(pubkey priv));"verify",(fun()->`Bool(R.verify_attestation_signature ~pubkey_raw:(b j "public")a));
  "well_formed",(fun()->`Bool(R.is_well_formed a));"encoded",(fun()->wire a);
  "decode",(fun()->wire(R.decode_attestation(b j "raw")));"proof_payload_hash",(fun()->hx(R.proof_payload_hash(b j "raw")))]
| "math"->let values=ats j in let total=z j "total"in let left=z j "left"in let right=z j "right"in fields[
  "sum",(fun()->jz(R.sum_weight values));"quorum",(fun()->jz(R.quorum_weight total));
  "intersection",(fun()->jz(R.qc_intersection_floor ~total_weight:total ~left_weight:left ~right_weight:right));
  "conflicting",(fun()->`Bool(R.conflicting_qc_impossible ~total_weight:total ~byzantine_weight:(z j "byzantine")));
  "proportion",(fun()->jz(R.proportional_amount(z j "budget_z")total(i j "weight")));
  "rewards",(fun()->payouts(R.distribute_resource_rewards ~budget:(i j "budget")values));
  "committee",(fun()->arr wire(R.select_committee ~size:(n j "size")values));
  "take",(fun()->arr wire(R.take(n j "size")values));"root",(fun()->hx(R.attestations_root values));
  "compare",(fun()->arr(fun a->arr(fun c->`Int(compare(R.compare_attestation a c)0))values)values);
  "add_amount",(fun()->let prior=field j "prior"|>to_list|>List.fold_left(fun m row->match to_list row with[k;v]->R.NodeMap.add(raw(str k))(Z.of_string(str v))m|_->failwith "fixture prior")R.NodeMap.empty in
    R.add_amount(b j "node")(z j "amount")prior|>R.NodeMap.bindings|>arr(fun(k,v)->`List[hx k;jz v]))]
| "float"->let f k=Int64.float_of_bits(Int64.of_string("0x"^str(field j k)))in let out f=`String(Printf.sprintf "%016Lx"(Int64.bits_of_float f))in fields[
  "kl",(fun()->out(R.kl_divergence ~p:(f "p")~q:(f "q")));
  "bound",(fun()->out(R.committee_capture_bound ~committee_size:(n j "size")~adversarial_fraction:(f "q")~capture_fraction:(f "p")))]
| "pow"->let a=att(field j "attestation")in let challenge=b j "challenge"in let nonce=b j "nonce"in fields[
  "encoded",(fun()->hx(R.encode_pow_evidence ~nonce));"proof",(fun()->hx(R.pow_proof_hash ~nonce));
  "attempt",(fun()->hx(R.pow_attempt_hash ~challenge a ~nonce));"assigned",(fun()->`Bool(R.assigned ~commitment:(b j "commitment")~max_weight:(i j "max_weight")a));
  "verify",(fun()->`Bool(R.verify_pow_attestation ~challenge ~commitment:(b j "commitment")~max_weight:(i j "max_weight")~difficulty_bits:(n j "difficulty")a ~nonce));
  "leading",(fun()->`Int(R.leading_zero_bits(b j "digest")));"byte_leading",(fun()->`Int(R.byte_leading_zero_bits(n j "byte")))]
| "storage"->let a=att(field j "attestation")in let e=storage(field j "evidence")in let challenge=b j "challenge"in fields[
  "leaf",(fun()->hx(R.storage_leaf_hash e.chunk));"parent",(fun()->hx(R.storage_parent_hash(b j "left")(b j "right")));
  "path",(fun()->`Bool(R.storage_path e));"root",(fun()->hx(R.merkle_root_from_evidence e));
  "encoded",(fun()->hx(R.encode_storage_evidence e));"proof",(fun()->hx(R.storage_evidence_hash e));
  "prefix",(fun()->ji(R.u64_prefix(b j "digest")));"index",(fun()->opt ji(R.storage_challenge_index ~challenge ~leaf_count:(i j "leaf_count")a));
  "verify",(fun()->`Bool(R.verify_storage_attestation ~challenge ~commitment:(b j "commitment")~max_weight:(i j "max_weight")~leaf_count:(i j "leaf_count")a e))]
| "hashchain"->let a=att(field j "attestation")in let e=field j "evidence"in let evidence=R.{input=b e "input";iterations=n e "iterations";result=b e "result"}in let challenge=b j "challenge"in fields[
  "task",(fun()->hx(R.useful_hash_chain_task_id ~challenge ~input:evidence.input ~iterations:evidence.iterations));
  "encoded",(fun()->hx(R.encode_useful_hash_chain_evidence evidence));"proof",(fun()->hx(R.useful_hash_chain_evidence_hash evidence));
  "result",(fun()->if field j "encode_only"=`Bool true then `Null else opt hx(R.useful_hash_chain_result ~input:evidence.input ~iterations:evidence.iterations));
  "verify",(fun()->if field j "encode_only"=`Bool true then `Null else `Bool(R.verify_useful_hash_chain_attestation ~challenge ~commitment:(b j "commitment")~max_weight:(i j "max_weight")~min_iterations:(n j "min_iterations")~max_iterations:(n j "max_iterations")a evidence))]
| "plugin"->let a=att(field j "attestation")in let challenge=b j "challenge"in let e=field j "evidence"in begin match n j "plugin"with
| 1->let (e:R.pvac_kat_evidence)=R.{key_id=(b e "key_id");pubkey_hash=(b e "pubkey_hash");kat_input_hash=(b e "kat_input_hash");kat_output=(b e "kat_output");expected_output_hash=(b e "expected_output_hash");work_units=(i e "work_units")}in fields[
 "plugin",(fun()->`List[`Int(R.useful_plugin_to_u8 R.PvacKat);`String(R.useful_plugin_to_string R.PvacKat)]);
 "task",(fun()->hx(R.useful_plugin_task_id ~challenge ~plugin:R.PvacKat ~subject:(b j "subject")~resource_hash:(b j "resource_hash")~work_units:(i j "work_units")));
 "nonempty",(fun()->`Bool(R.nonempty_hash32(b j "hash")));
 "fits",(fun()->`Bool(R.attestation_weight_fits_resource a(i j "work_units")));
 "encoded",(fun()->hx(R.encode_pvac_kat_evidence e));
 "resource",(fun()->hx(R.pvac_kat_resource_hash e));
 "proof",(fun()->hx(R.pvac_kat_evidence_hash e));
 "verify",(fun()->`Bool(R.verify_pvac_kat_attestation ~challenge ~commitment:(b j "commitment")~max_weight:(i j "max_weight")~output_hash:(b j "output_hash") a e));
 "output",(fun()->hx(R.pvac_kat_output_hash e))]
| 2->let (e:R.fhe_receipt_evidence)=R.{verifier_pubkey=(b e "verifier_pubkey");proof_kind=(b e "proof_kind");program_id=(b e "program_id");input_hash=(b e "input_hash");output_hash=(b e "output_hash");cost_units=(i e "cost_units");receipt_signature=(b e "receipt_signature")}in fields[
 "plugin",(fun()->`List[`Int(R.useful_plugin_to_u8 R.FheProofReceipt);`String(R.useful_plugin_to_string R.FheProofReceipt)]);
 "task",(fun()->hx(R.useful_plugin_task_id ~challenge ~plugin:R.FheProofReceipt ~subject:(b j "subject")~resource_hash:(b j "resource_hash")~work_units:(i j "work_units")));
 "nonempty",(fun()->`Bool(R.nonempty_hash32(b j "hash")));
 "fits",(fun()->`Bool(R.attestation_weight_fits_resource a(i j "work_units")));
 "encoded",(fun()->hx(R.encode_fhe_receipt_evidence e));
 "resource",(fun()->hx(R.fhe_receipt_resource_hash e));
 "proof",(fun()->hx(R.fhe_receipt_evidence_hash e));
 "verify",(fun()->`Bool(R.verify_fhe_receipt_attestation ~challenge ~commitment:(b j "commitment")~max_weight:(i j "max_weight")~verifier_pubkey:(b j "public") a e));
 "sign_bytes",(fun()->hx(R.fhe_receipt_sign_bytes e));
 "signed",(fun()->hx(R.sign_fhe_receipt_evidence ~priv_raw:(b j "private")e))]
| 3->let (e:R.circle_asset_evidence)=R.{circle_id=(b e "circle_id");resource_path=(b e "resource_path");asset_root=(b e "asset_root");byte_count=(i e "byte_count");storage=(storage(field e "storage"))}in fields[
 "plugin",(fun()->`List[`Int(R.useful_plugin_to_u8 R.CircleAssetAvailability);`String(R.useful_plugin_to_string R.CircleAssetAvailability)]);
 "task",(fun()->hx(R.useful_plugin_task_id ~challenge ~plugin:R.CircleAssetAvailability ~subject:(b j "subject")~resource_hash:(b j "resource_hash")~work_units:(i j "work_units")));
 "nonempty",(fun()->`Bool(R.nonempty_hash32(b j "hash")));
 "fits",(fun()->`Bool(R.attestation_weight_fits_resource a(i j "work_units")));
 "encoded",(fun()->hx(R.encode_circle_asset_evidence e));
 "resource",(fun()->hx(R.circle_asset_resource_hash e));
 "proof",(fun()->hx(R.circle_asset_evidence_hash e));
 "verify",(fun()->`Bool(R.verify_circle_asset_attestation ~challenge ~commitment:(b j "commitment")~max_weight:(i j "max_weight")~leaf_count:(i j "leaf_count") a e))]
| 4->let (e:R.snapshot_availability_evidence)=R.{state_root=(b e "state_root");range_start=(i e "range_start");range_end=(i e "range_end");snapshot_root=(b e "snapshot_root");byte_count=(i e "byte_count");storage=(storage(field e "storage"))}in fields[
 "plugin",(fun()->`List[`Int(R.useful_plugin_to_u8 R.SnapshotAvailability);`String(R.useful_plugin_to_string R.SnapshotAvailability)]);
 "task",(fun()->hx(R.useful_plugin_task_id ~challenge ~plugin:R.SnapshotAvailability ~subject:(b j "subject")~resource_hash:(b j "resource_hash")~work_units:(i j "work_units")));
 "nonempty",(fun()->`Bool(R.nonempty_hash32(b j "hash")));
 "fits",(fun()->`Bool(R.attestation_weight_fits_resource a(i j "work_units")));
 "encoded",(fun()->hx(R.encode_snapshot_availability_evidence e));
 "resource",(fun()->hx(R.snapshot_availability_resource_hash e));
 "proof",(fun()->hx(R.snapshot_availability_evidence_hash e));
 "verify",(fun()->`Bool(R.verify_snapshot_availability_attestation ~challenge ~commitment:(b j "commitment")~max_weight:(i j "max_weight")~leaf_count:(i j "leaf_count") a e))]
| 5->let (e:R.deterministic_trace_evidence)=R.{runtime_id=(b e "runtime_id");source_hash=(b e "source_hash");input_hash=(b e "input_hash");output_hash=(b e "output_hash");step_limit=(i e "step_limit");trace_root=(b e "trace_root");sampled_step=(storage(field e "sampled_step"))}in fields[
 "plugin",(fun()->`List[`Int(R.useful_plugin_to_u8 R.DeterministicComputationTrace);`String(R.useful_plugin_to_string R.DeterministicComputationTrace)]);
 "task",(fun()->hx(R.useful_plugin_task_id ~challenge ~plugin:R.DeterministicComputationTrace ~subject:(b j "subject")~resource_hash:(b j "resource_hash")~work_units:(i j "work_units")));
 "nonempty",(fun()->`Bool(R.nonempty_hash32(b j "hash")));
 "fits",(fun()->`Bool(R.attestation_weight_fits_resource a(i j "work_units")));
 "encoded",(fun()->hx(R.encode_deterministic_trace_evidence e));
 "resource",(fun()->hx(R.deterministic_trace_resource_hash e));
 "proof",(fun()->hx(R.deterministic_trace_evidence_hash e));
 "verify",(fun()->`Bool(R.verify_deterministic_trace_attestation ~challenge ~commitment:(b j "commitment")~max_weight:(i j "max_weight")~leaf_count:(i j "leaf_count") a e))]
| 6->let (e:R.perturbed_matrix_trace_evidence)=R.{runtime_id=(b e "runtime_id");matrix_a_root=(b e "matrix_a_root");matrix_b_root=(b e "matrix_b_root");config_hash=(b e "config_hash");chain_state_hash=(b e "chain_state_hash");tile_row=(i e "tile_row");tile_col=(i e "tile_col");tile_depth=(i e "tile_depth");tile_trace_root=(b e "tile_trace_root");sampled_tile=(storage(field e "sampled_tile"));field_modulus=(i e "field_modulus");perturbed_left_values=(field e "perturbed_left_values"|>to_list|>List.map num);perturbed_right_values=(field e "perturbed_right_values"|>to_list|>List.map num);claimed_value=(i e "claimed_value");opening_nonce=(b e "opening_nonce");difficulty_bits=(n e "difficulty_bits");work_units=(i e "work_units")}in fields[
 "plugin",(fun()->`List[`Int(R.useful_plugin_to_u8 R.PerturbedMatrixTrace);`String(R.useful_plugin_to_string R.PerturbedMatrixTrace)]);
 "task",(fun()->hx(R.useful_plugin_task_id ~challenge ~plugin:R.PerturbedMatrixTrace ~subject:(b j "subject")~resource_hash:(b j "resource_hash")~work_units:(i j "work_units")));
 "nonempty",(fun()->`Bool(R.nonempty_hash32(b j "hash")));
 "fits",(fun()->`Bool(R.attestation_weight_fits_resource a(i j "work_units")));
 "encoded",(fun()->hx(R.encode_perturbed_matrix_trace_evidence e));
 "resource",(fun()->hx(R.perturbed_matrix_trace_resource_hash e));
 "proof",(fun()->hx(R.perturbed_matrix_trace_evidence_hash e));
 "verify",(fun()->`Bool(R.verify_perturbed_matrix_trace_attestation ~challenge ~commitment:(b j "commitment")~max_weight:(i j "max_weight")~leaf_count:(i j "leaf_count")~difficulty_bits:(n j "difficulty") a e));
 "noise",(fun()->hx(R.perturbed_matrix_noise_seed ~challenge e));
 "chunk",(fun()->hx(R.perturbed_matrix_cell_chunk ~challenge e));
 "opening",(fun()->hx(R.perturbed_matrix_opening_hash ~challenge e));
 "field",(fun()->opt ji(R.field_dot_mod ~modulus:e.field_modulus e.perturbed_left_values e.perturbed_right_values));
 "valid_values",(fun()->arr(fun v->`Bool(R.field_value_is_valid ~modulus:e.field_modulus v))e.perturbed_left_values);
 "length",(fun()->ji(R.int64_of_list_length e.perturbed_left_values));
 "put_list",(fun()->hx(Octra_net.Oce1.encode(fun w->R.put_u64_list w e.perturbed_left_values)))]
| _->failwith "fixture plugin"end
| "flow"->let values=ats j in let source=seed(field j "seed")in let challenge=b j "challenge"in
  let selected()=F.select_snapshot ~activation_delay:(n j "delay")~committee_size:(n j "size")~target_epoch:(i j "target")~source_seed:source values in fields[
  "challenge",(fun()->hx(F.challenge source));"activated",(fun()->opt ji(F.activated_source_epoch ~activation_delay:(n j "delay")~target_epoch:(i j "target")));
  "eligible",(fun()->arr wire(F.eligible_attestations ~source_epoch:(i j "source")~challenge values));
  "matches",(fun()->arr(fun a->`Bool(F.matches_epoch_challenge ~source_epoch:(i j "source")~challenge a))values);
  "root",(fun()->hx(F.committee_root ~target_epoch:(i j "target")~source_epoch:(i j "source")~challenge values));
  "snapshot",(fun()->opt snapshot(selected()));
  "ready",(fun()->opt(fun s->`Bool(F.ready_for_voting ~minimum_weight:(i j "minimum")s))(selected()));
  "rewards",(fun()->opt(fun s->payouts(F.rewards_for_snapshot ~budget:(i j "budget")s))(selected()));
  "validators",(fun()->let calls=ref[]in let pubkey_of_node node=if node=b j "missing"then None else known j calls node in
    let result=F.validator_set_of_committee ~pubkey_of_node values in `List[opt validator_set result;arr hx(List.rev !calls)])]
| "gossip"->let g=gossip(field j "gossip")in fields[
  "encoded",(fun()->hx(F.encode_gossip g));"decode",(fun()->hx(F.encode_gossip(F.decode_gossip(b j "raw"))))]
| "logging"->let g=gossip(field j "gossip")in let e=L.seen g in fields[
  "seen",(fun()->`List[ji e.seen_epoch;hx e.node;`String e.kind;ji e.weight]);
  "message",(fun()->hx(Printf.sprintf "resource_attestation seen_epoch = %Ld node = %s kind = %s weight = %Ld" e.seen_epoch e.node e.kind e.weight));
  "ready",(fun()->`Bool(match Lwt.state(L.log_seen g)with Lwt.Return ()->true|_->false))]
| "admission"->let pool=A.create_pool()in let outputs=List.map(fun event->boxed(fun()->let w=window(field event "window")in match str(field event "action")with
    | "snapshot"->pool_json pool
    | "prune"->A.prune pool w;counts pool
    | "expired"->`List[`Bool(A.valid_window w);`Bool(A.expired w(i event "epoch"))]
    | "remember"->let a=att(field event "attestation")in A.remember pool ~window:w(decision event)a;counts pool
    | ("ingest_many"|"remember_many") as action->let outcomes=List.init(n event "count")(fun index->
       let value=generated event index in if action="remember_many"then(let d=decision event in A.remember pool ~window:w d value;`String(A.decision_to_string d))
       else let calls=ref[]in let d=A.ingest ~chain_id:(b event "chain_id")~challenge:(b event "challenge")~window:w ~pubkey_of_node:(known event calls)pool value in `String(A.decision_to_string d))in `List[`List outcomes;counts pool]
    | "classify"|"ingest" as action->let a=att(field event "attestation")in let calls=ref[]in let pubkey_of_node=known event calls in
      let result=if action="ingest"then A.ingest ~chain_id:(b event "chain_id")~challenge:(b event "challenge")~window:w ~pubkey_of_node pool a
        else A.classify ~chain_id:(b event "chain_id")~challenge:(b event "challenge")~window:w ~pubkey_of_node pool a in
      `List[`String(A.decision_to_string result);arr hx(List.rev !calls);counts pool;hx(A.identity_key a);
        (if result=A.Reject A.Malformed then `Null else evidence_json(A.evidence ~window:w A.BadScore a))]
    | _->failwith "fixture action"))(field j "events"|>to_list)in `List outputs
| _->failwith "fixture op"
let ()=Yojson.Safe.from_channel stdin|>to_list|>List.map(fun input->`Assoc["input",input;"expected",boxed(fun()->run input)])
  |>fun xs->print_endline(Yojson.Safe.to_string(`List xs))
