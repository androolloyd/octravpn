(* Pristine native local-registration parameter/auth ordering. The callback
   records authorized arguments only; no store, wallet or public network. *)
open Yojson.Safe.Util
module C = Octra_core
module R = Octra_node_runtime
let key id = Mirage_crypto_ec.Ed25519.priv_of_octets (String.make 32 (Char.chr id)) |> Result.get_ok
let pub id = Mirage_crypto_ec.Ed25519.(pub_of_priv (key id) |> pub_to_octets) |> Base64.encode_exn
let addr id = C.Crypto.Address.address_from_pubkey (pub id)
let sign id message = Mirage_crypto_ec.Ed25519.sign ~key:(key id) message |> Base64.encode_exn
let result = function
 | Ok body -> `Assoc ["result",body]
 | Error error -> `Assoc ["error",`Assoc (["code",`Int error.C.Rpc.code;"message",`String error.message] @ match error.data with None -> [] | Some v -> ["data",v])]
let run input =
 let name = member "name" input |> to_string in
 let bft = member "bft" input |> to_bool in
 let address = addr 11 and public = pub 11 in
 let signature = sign 11 ("register_pubkey:" ^ address) in
 let good = [`String address;`String public;`String signature] in
 let params = match name with
 | "good" | "bft-good" -> `List good
 | "null" | "bft-null" -> `Null
 | "missing-key" -> `List [`String address]
 | "missing-signature" -> `List [`String address;`String public]
 | "bad-address" -> `List [`String "wrong";`String public;`String signature]
 | "short-key" -> `List [`String address;`String "AAAA";`String signature]
 | "short-signature" -> `List [`String address;`String public;`String "AAAA"]
 | "mismatch-short-signature" -> `List [`String address;`String(pub 12);`String "AAAA"]
 | "bad-key-base64" -> `List [`String address;`String "%%%";`String signature]
 | "mismatch-key" -> `List [`String address;`String(pub 12);`String signature]
 | "wrong-domain" -> `List [`String address;`String public;`String(sign 11 ("staging_remove|" ^ address))]
 | "bad-signature" -> `List [`String address;`String public;`String(Base64.encode_exn(String.make 64 '\000'))]
 | "bad-signature-type" -> `List [`String address;`String public;`Int 1]
 | _ -> failwith "unknown fixture" in
 let calls = ref [] in
 let register address public = calls := !calls @ [`List[`String address;`String public]] in
 let outcome = R.Registration_rpc.public_key ~bft_mode:bft ~register params |> Lwt_main.run |> result in
 `Assoc ["input",input;"params",params;"outcome",outcome;"registered",`List !calls]
let () = Yojson.Safe.from_channel stdin |> to_list |> List.map run |> fun cases -> Yojson.Safe.to_channel stdout (`List cases); print_newline ()
