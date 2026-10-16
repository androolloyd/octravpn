module I = Octra_core.Validator_intent
open Yojson.Safe.Util
let key id = Mirage_crypto_ec.Ed25519.priv_of_octets (String.make 32 (Char.chr id)) |> Result.get_ok
let public id = Mirage_crypto_ec.Ed25519.(pub_to_octets (pub_of_priv (key id))) |> Base64.encode_exn
let address id = Octra_core.Crypto.Address.address_from_pubkey (public id)
let outcome f = function Ok value -> f value | Error reason -> `Assoc ["error", `String reason]
let run input =
  let key_id = member "key" input |> to_int in
  let identity = I.{chain_id=member "chain" input |> to_string;
    address=(if member "bad_address" input = `Bool true then address (key_id+1) else address key_id);
    pubkey=(if member "bad_public" input = `Bool true then public key_id ^ "=" else public key_id);
    bonded_epoch=member "epoch" input |> to_string |> Int64.of_string} in
  let private_id = member "private_key" input |> to_int in
  I.create identity ~privkey:(Base64.encode_exn (String.make 32 (Char.chr private_id)))
  |> outcome (fun intent ->
    let encoded = I.encode intent in
    let raw = match member "mutation" input |> to_string with
      | "none" -> encoded
      | "oversized" -> String.make 4097 ' '
      | mutation ->
        let fields = Yojson.Safe.from_string encoded |> to_assoc in
        let fields = match mutation with
          | "standard" -> List.map (fun (k,v)->k,if k="standard" then `String "other" else v) fields
          | "epoch_zero" -> List.map (fun (k,v)->k,if k="bonded_epoch" then `String "00" else v) fields
          | "signature" -> List.map (fun (k,v)->k,if k="signature" then `String (Base64.encode_exn (String.make 64 '\000')) else v) fields
          | "unknown" -> ("extra",`String "")::fields
          | "duplicate" -> ("chain_id",`String "")::List.filter(fun(k,_)->k<>"standard")fields
          | _ -> failwith "mutation" in
        Yojson.Safe.to_string (`Assoc fields) in
    let decoded = I.decode raw |> outcome (fun decoded ->
      let expected = {identity with bonded_epoch=member "expected_epoch" input |> to_string |> Int64.of_string;
        chain_id=(if member "other_chain" input = `Bool true then "another-chain" else identity.chain_id)} in
      `Assoc ["encoded", `String(I.encode decoded); "applies",outcome(fun flag->`Bool flag)(I.applies expected decoded)]) in
    `Assoc ["encoded", `String encoded; "id",`String(I.id intent); "raw",`String raw;"decoded",decoded])
let () = Yojson.Safe.from_channel stdin |> to_list
  |> List.map(fun input->`Assoc["input",input;"expected",run input])
  |> fun rows -> Yojson.Safe.to_channel stdout (`List rows);print_newline ()
