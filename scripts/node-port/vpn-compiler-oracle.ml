(* Unmodified adopted compiler, actual VPN source supplied by the local runner. *)
module V = Octra_vm
open Yojson.Safe.Util
let bytes value = `String (Base64.encode_exn value)
let run input =
  let source = member "source" input |> to_string in
  let loops = member "loops" input |> to_bool in
  let syntax = match member "syntax" input |> to_string with
    | "forms" -> V.Oct_gen.Forms | "source" -> V.Oct_gen.Source
    | _ -> failwith "syntax" in
  let expected = match V.Aml_source.compile ~loops ~syntax source with
    | Error reason -> `Assoc ["error", `String reason]
    | Ok compiled ->
      let result = V.Oct_compile.source_result ~abi:V.Oct_compile.Source_abi
        ~syntax ~source_mode:"single" ~source_material:source compiled in
      `Assoc [
        "bytecode", bytes result.bytecode;
        "abi", bytes result.abi_json;
        "verification", bytes result.verification_json;
        "certificate", bytes result.certificate_json;
        "facts", Option.fold ~none:`Null
          ~some:(fun facts -> bytes (Yojson.Safe.to_string (V.Oct_compile.facts_json facts))) result.program_facts;
        "rpc", bytes (Yojson.Safe.to_string (V.Contract_rpc.compile_result_response result));
      ] in
  `Assoc ["path", member "path" input; "syntax", member "syntax" input;
          "loops", `Bool loops; "expected", expected]
let () = Yojson.Safe.from_channel stdin |> to_list |> List.map run
  |> fun cases -> Yojson.Safe.to_channel stdout (`List cases); print_newline ()
