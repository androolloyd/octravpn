open Yojson.Safe.Util
module W=Octra_core.Pvac_verify_worker
let names=["OCTRA_PVAC_VERIFY_WORKERS";"OCTRA_PVAC_VERIFY_TIMEOUT_SEC";"OCTRA_PVAC_VERIFY_MAX_RSS_MB"]
let run input=
 let name=member "name" input|>to_string in
 let value=match member "value" input with `String text->Some text|_->None in
 List.iter(fun key->Unix.putenv key(if key=name then Option.value value ~default:"" else ""))names;
 let capacity=W.capacity_of_getenv(fun key->if key=name then value else None) in
 let timeout=W.timeout_seconds() in
 let expected=`Assoc["capacity",`Int capacity;"rss",`Int(W.max_rss_mb());"timeout_bits",`String(Printf.sprintf "%016Lx"(Int64.bits_of_float timeout))]in
 `Assoc["input",input;"expected",expected]
let ()=let cases=Yojson.Safe.from_channel stdin|>to_list|>List.map run in Yojson.Safe.to_channel stdout(`List cases);print_newline()
