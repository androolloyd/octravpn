(* FheBalance and proof-worker direct verifier, without modifying native code. *)
module F = Octra_core.Crypto.FheBalance
module D = Octra_core.Pvac_verify_direct
open Yojson.Safe.Util
let raw j name = member name j |> to_string |> Base64.decode_exn
let result f = try match f () with
 | Ok value -> `Assoc["ok", value]
 | Error error -> `Assoc["error", `String(Base64.encode_exn error)]
 with error -> `Assoc["exception", `String(Printexc.to_string error)]
let b64 v = `String(Base64.encode_exn v)
let run input =
 let strict=member "strict" input |> to_bool in
 let cap=member "cap" input |> to_bool in
 let policy=if member "recoverable" input |> to_bool then Octra_core.Private_result_policy.Recoverable else Legacy in
 let math=member "math" input |> to_bool in
 let current=raw input "current" in
 let output=result(fun () -> match member "operation" input |> to_string with
 | "guard" -> Result.map(fun ()->`Null)(F.check_private_input ~cap current)
 | "refresh" -> Result.map(fun ()->`Null)(F.check_refresh_source ~cap current)
 | "proof" -> Result.bind(D.proof_pubkey(raw input "public"))(fun pk ->
   Result.map(fun ()->`Null)(F.verify_encrypt_proof ~math ~strict pk (raw input "delta")
    (Z.of_string(member "amount" input |> to_string)) (raw input "proof")
    (raw input "commitment") (raw input "blinding")))
 | "range" -> Result.bind(D.proof_pubkey(raw input "public"))(fun pk ->
   Ok(`Bool(F.verify_range ~math ~strict pk current (raw input "range"))))
 | operation -> Result.bind(F.load_pubkey_result(raw input "public"))(fun pk ->
   Result.bind(F.decode_cipher ~cap (raw input "delta"))(fun delta ->
     let f=if operation="withdraw" then F.withdraw_with_pubkey else F.deposit_with_pubkey in
     Result.map b64 (f ~cap ~result_policy:policy pk ~current_cipher:(Some current) ~delta_cipher:delta)))) in
 `Assoc["input",input;"expected",output]
let () = Yojson.Safe.from_channel stdin |> to_list |> List.map run |> fun rows ->
 Yojson.Safe.to_channel stdout (`List rows);print_newline ()
