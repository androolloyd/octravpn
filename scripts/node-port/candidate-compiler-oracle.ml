(* Bounded compiler and source publication observation, no host execution. *)
open Yojson.Safe.Util
let get input name = member name input
let text input name = get input name |> to_string
let flag input name = get input name |> to_bool
let digest raw = `String Digestif.SHA256.(digest_string raw |> to_hex)
let err reason = `Assoc ["error", `String reason]
let result (value : Oct_compile.compile_result) = match value.error with
  | Some reason -> err reason
  | None -> `Assoc [
      "bytecode", digest value.bytecode; "bytecode_size", `Int (String.length value.bytecode);
      "abi", digest value.abi_json; "verification", digest value.verification_json;
      "certificate", digest value.certificate_json; "instructions", `Int value.instructions;
      "version", `String value.version;
      "facts", (match value.program_facts with None -> `Null | Some facts ->
        digest (Yojson.Safe.to_string (Oct_compile.facts_json facts)))]
let sources input : Program_record.sources = {
  main = "main.aml";
  files = [Program_package.{path="main.aml"; body=text input "source"}];
  compiler = text input "compiler"; loops=flag input "loops";
}
let compile input =
  let source = text input "source" in
  let metered = flag input "metered" in
  if text input "compiler" = "protocol" then result (Oct_compile.compile ~metered source)
  else
    let syntax = if text input "compiler" = "forms" then Oct_gen.Forms else Oct_gen.Source in
    match Aml_source.compile ~metered ~loops:(flag input "loops") ~syntax source with
    | Error reason -> err reason
    | Ok compiled -> result (Oct_compile.source_result ~abi:Oct_compile.Source_abi
        ~syntax ~source_mode:"single" ~source_material:source compiled)
let publish input =
  let sources = sources input in
  let metered = flag input "metered" in
  match Program_record.compile ~metered sources with
  | Error reason -> err reason
  | Ok (code, compiled) ->
    let checked exact stored = match Program_record.verify ~metered sources ~exact ~stored with
      | Error reason -> err reason
      | Ok record -> `Assoc ["record", digest (Program_record.raw record);
          "fee", `String (Z.to_string (Program_record.fee record));
          "valid", (match Program_record.check record with Ok () -> `Bool true | Error reason -> `String reason)] in
    `Assoc ["compiled", result compiled; "code", digest code;
      "exact", checked true code; "semantic", checked false code;
      "damaged", checked false ("bad" ^ code);
      "encoded", digest (Program_record.encode_sources sources);
      "fee", `String (Z.to_string (Program_record.source_fee sources))]
let scope input =
  let ast = Oct_parse.parse (text input "source") in
  `Assoc ["graph", (match Oct_scope.check_consts ast with Ok () -> `Bool true | Error reason -> `String reason);
    "scoped", `Bool (Program_record.source_scope [Program_package.{path="main.aml";body=text input "source"}])]
let run input = try match text input "kind" with
  | "compile" -> compile input | "publish" -> publish input | "scope" -> scope input
  | _ -> invalid_arg "oracle kind"
  with Oct_parse.ParseError (reason,line,column) -> err (Printf.sprintf "line %d column %d: %s" line column reason)
     | Oct_lex.LexError (reason,line,column) -> err (Printf.sprintf "line %d column %d: %s" line column reason)
let () =
  let cases = Yojson.Safe.from_channel stdin |> to_list in
  let result = List.map (fun input -> `Assoc ["input",input;"expected",run input]) cases in
  Yojson.Safe.to_channel stdout (`List result); print_newline ()
