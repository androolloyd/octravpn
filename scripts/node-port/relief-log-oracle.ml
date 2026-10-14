open Yojson.Safe.Util
open Octra_consensus
module R=C_relief_log
let s j k=member k j|>to_string
let n j k=member k j|>to_int
let i j k=Int64.of_string(s j k)
let hex s=String.concat ""(List.init(String.length s)(fun i->Printf.sprintf "%02x"(Char.code s.[i])))
let raw j k=let s=s j k in String.init(String.length s/2)(fun i->Char.chr(int_of_string("0x"^String.sub s(i*2)2)))
let mark j:C_relief.mark={height=i j"height";round=n j"round";activate_epoch=i j"activate_epoch";source_hash=raw j"source_hash";target_hash=raw j"target_hash";fingerprint=raw j"fingerprint";proof=member"proof"j|>to_list|>List.map(fun wire->C_codec.decode_round_sync(raw(`Assoc["wire",wire])"wire"))}
let jm(m:C_relief.mark)=`Assoc["height",`String(Int64.to_string m.height);"round",`Int m.round;"activate_epoch",`String(Int64.to_string m.activate_epoch);"source_hash",`String(hex m.source_hash);"target_hash",`String(hex m.target_hash);"fingerprint",`String(hex m.fingerprint);"proof",`List(List.map(fun s->`String(hex(C_codec.encode_round_sync s)))m.proof)]
let starts prefix s=String.starts_with ~prefix s
let diagnostic s=if starts "Unix.Unix_error" s || starts "Sys_error" s then "os" else if starts "Yojson.Json_error" s || starts "Yojson__Common.Json_error" s then "json" else s
let result f=function Ok v->f v|Error e->`Assoc["error",`String(diagnostic e)]
let caught f=try f()with e->`Assoc["error",`String(diagnostic(Printexc.to_string e))]
let write path data=let f=open_out_bin path in output_string f data;close_out f
let read path=let f=open_in_bin path in let s=really_input_string f(in_channel_length f)in close_in f;s
let rec remove path=match(Unix.lstat path).Unix.st_kind with Unix.S_DIR->Array.iter(fun n->remove(Filename.concat path n))(Sys.readdir path);Unix.rmdir path|_->Unix.unlink path
let run j=
 let dir=Filename.temp_file "relief-oracle" ""in Unix.unlink dir;Unix.mkdir dir 0o700;
 Fun.protect ~finally:(fun()->remove dir)(fun()->
  let disk=s j"mode"="disk"and root=Filename.concat dir"relief_log"in
  let store=ref(if disk then R.disk ~data_dir:dir else R.memory())in
  let ensure()=if not(Sys.file_exists root)then Unix.mkdir root 0o700 in
  `List(member"steps"j|>to_list|>List.map(fun step->caught(fun()->
   let name=Printf.sprintf "%020Ld.mark"(i step"height")in
   let record=Filename.concat root name in
   match s step"op"with
   |"keep"->result jm(R.keep !store(mark(member"mark"step)))
   |"latest"->result(function None->`Null|Some m->jm m)(R.latest !store ~through_height:(i step"height"))
   |"prune"->result(fun()->`Null)(R.prune !store ~through_epoch:(i step"height"))
   |"restart"->if disk then store:=R.disk ~data_dir:dir;`Null
   |"read"->`String(hex(read record))
   |"corrupt"->ensure();write record(raw step"data");`Null
   |"file"->ensure();write(Filename.concat root(raw step"name"))(raw step"data");`Null
   |"symlink"->ensure();let backing=Filename.concat dir"backing"in write backing(raw step"data");Unix.symlink backing record;`Null
   |"stage"->ensure();for attempt=0 to n step"count"-1 do write(Printf.sprintf "%s.staged.%d.%d"record(Unix.getpid())attempt)"stale"done;`Null
   |_->failwith"unknown operation"))))
let ()=let cases=Yojson.Safe.from_channel stdin|>to_list|>List.map(fun input->`Assoc["input",input;"expected",run input])in Yojson.Safe.to_channel stdout(`List cases);print_newline()
