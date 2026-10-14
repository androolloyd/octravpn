open Yojson.Safe.Util
module W=Octra_core.Wal
let s j k=member k j|>to_string
let n j k=member k j|>to_int
let hex s=String.concat ""(List.init(String.length s)(fun i->Printf.sprintf "%02x"(Char.code s.[i])))
let unhex s=String.init(String.length s/2)(fun i->Char.chr(int_of_string("0x"^String.sub s(i*2)2)))
let raw j k=unhex(s j k)
let option f=function None->`Null|Some v->f v
let record j:W.pending_commit={epoch_id=n j"epoch";round=n j"round";proposal_id=raw j"pid";proposed_state_root=raw j"root";txid_hi=Int64.of_string(s j"txid");ts=Int64.float_of_bits(Int64.of_string("0x"^s j"time"));validator_addr=raw j"validator";proposal_b64=(match member"proposal"j with`Null->None|v->Some(unhex(to_string v)));vote_b64=(match member"vote"j with`Null->None|v->Some(unhex(to_string v)));tx_hashes=member"hashes"j|>to_list|>List.map(fun v->unhex(to_string v));txs_json=member"txs"j|>to_list|>List.map(fun v->unhex(to_string v));receipts_json=member"receipts"j|>to_list|>List.map(fun v->unhex(to_string v))}
let jr(p:W.pending_commit)=`Assoc["epoch",`Int p.epoch_id;"round",`Int p.round;"pid",`String(hex p.proposal_id);"root",`String(hex p.proposed_state_root);"txid",`String(Int64.to_string p.txid_hi);"time",`String(Printf.sprintf "%016Lx"(Int64.bits_of_float p.ts));"validator",`String(hex p.validator_addr);"proposal",option(fun s->`String(hex s))p.proposal_b64;"vote",option(fun s->`String(hex s))p.vote_b64;"hashes",`List(List.map(fun s->`String(hex s))p.tx_hashes);"txs",`List(List.map(fun s->`String(hex s))p.txs_json);"receipts",`List(List.map(fun s->`String(hex s))p.receipts_json)]
let diagnostic s=
 let starts prefix=String.starts_with ~prefix s in
 if starts"Unix.Unix_error"||starts"Sys_error"then"os"
 else if starts"Yojson__Common.Json_error"||starts"Yojson.Json_error"then"json"
 else if starts"Yojson.Safe.Util.Type_error"||starts"Yojson.Safe.Util.Type_error"||starts"Yojson__Safe.Util.Type_error"then"type"
 else if starts"pending commit position differs from filename:"then"position"
 else if starts"WAL directory is not a directory:"then"directory"
 else s
let catch f=try f()with Failure e->`Assoc["error",`String(diagnostic e)]|W.Read_error(_,reason)->
 let reason=if String.starts_with ~prefix:"Failure(\""reason && String.ends_with ~suffix:"\")"reason then String.sub reason 9(String.length reason-11)else reason in
 `Assoc["error",`String(diagnostic reason)]|e->`Assoc["error",`String(diagnostic(Printexc.to_string e))]
let rec remove path=match(Unix.lstat path).Unix.st_kind with Unix.S_DIR->Array.iter(fun n->remove(Filename.concat path n))(Sys.readdir path);Unix.rmdir path|_->Unix.unlink path
let write path data=let f=open_out_bin path in output_string f data;close_out f
let read path=let f=open_in_bin path in let s=really_input_string f(in_channel_length f)in close_in f;s
let run j=match s j"kind"with
 |"encode"->catch(fun()->let r=record(member"record"j)in let wire=W.pending_commit_to_json r in `Assoc["wire",`String(hex wire);"parsed",jr(W.pending_commit_of_json wire)])
 |"parse"->catch(fun()->jr(W.pending_commit_of_json(raw j"wire")))
 |_->let dir=Filename.temp_file"pending-oracle"""in Unix.unlink dir;Unix.mkdir dir 0o700;
 Fun.protect ~finally:(fun()->remove dir)(fun()->`List(member"steps"j|>to_list|>List.map(fun step->catch(fun()->
  let epoch=n step"epoch"and round=n step"round"in
  match s step"op"with
  |"keep"->W.write_pending_commit dir(record(member"record"step));`Null
  |"read"->`List(List.map jr(W.read_pending_commits dir))
  |"wire"->`String(hex(read(W.pending_commit_path dir epoch round)))
  |"delete"->W.delete_pending_commit dir epoch round;`Null
  |"delete_epoch"->W.delete_pending_commits_for_epoch dir epoch;`Null
  |"corrupt"->W.ensure_dir dir;write(W.pending_commit_path dir epoch round)(raw step"data");`Null
  |"oversize"->W.ensure_dir dir;let f=Unix.openfile(W.pending_commit_path dir epoch round)[Unix.O_WRONLY;Unix.O_CREAT]0o600 in Unix.ftruncate f(W.max_pending_commit_bytes+1);Unix.close f;`Null
  |_->`Null))))
let ()=let cases=Yojson.Safe.from_channel stdin|>to_list|>List.map(fun input->`Assoc["input",input;"expected",run input])in Yojson.Safe.to_channel stdout(`List cases);print_newline()
