(* SPDX-License-Identifier: BSD-3-Clause *)
(* Copyright (c) 2023-2026 Octra Labs <dev@octra.org> *)
module C = Octra_bootstrap.State_sync_checkpoint
module M = Octra_bootstrap.State_sync_manifest
module T = Octra_consensus.C_types
open Yojson.Safe.Util
let ( let* ) r f = Result.bind r f
let raw j = Base64.decode_exn (to_string j)
let ok f value = Result.map f value
let result = function Ok value -> `Assoc ["ok",value] | Error e -> `Assoc ["error",`String e]
let hash value = `String value
let run j =
 let input = member "raw" j |> raw |> Yojson.Safe.from_string in
 match member "op" j |> to_string with
 | "checkpoint" -> let* b = C.parse_body input in ok hash (C.hash b)
 | "manifest" -> let* b = M.parse_body input in ok hash (M.manifest_hash b)
 | "reference" -> let* b = M.parse_body input in ok (fun () -> `Bool true) (M.validate_reference_body b)
 | "file" -> let* f = M.parse_file input in ok (fun () -> `Bool true) (M.validate_file (member "chunk_size" j |> to_int) f)
 | "draft" -> let* d = M.parse_draft_json input in ok (fun _ -> `Bool true) (M.verify_draft d)
 | "entries" -> let* s = M.validator_set_of_entries (to_list input |> List.map to_string) in Ok (`String (M.set_hash s))
 | "certificate" -> let* c = M.parse_certificate_json input in let* _ = M.verify_draft M.{checkpoint=c.checkpoint;checkpoint_hash=c.checkpoint_hash;manifest=c.manifest;manifest_hash=c.manifest_hash} in
    Ok (`Assoc ["reference",`Bool (M.is_reference c);"fresh",`Bool (M.fresh ~now:(member "now" j |> to_string |> Int64.of_string) c)])
 | "pubkey" -> ok (fun r -> `String (C.raw_to_hex r)) (C.raw_pubkey (to_string input))
 | "signature" -> ok (fun r -> `String (C.raw_to_hex r)) (C.raw_signature (to_string input))
 | "path" -> Ok (`Bool (Option.is_some (M.normalize_path (to_string input))))
 | "reference_file" -> Ok (`Bool (M.reference_file (to_string input)))
 | "same" -> let* left = C.parse_body (member "left" input) in let* right = C.parse_body (member "right" input) in Ok (`Bool (C.same_finalized_state left right))
 | _ -> failwith "operation"
let key seed = match Mirage_crypto_ec.Ed25519.priv_of_octets (String.make 32 (Char.chr seed)) with Ok key -> key | Error _ -> failwith "seed"
let quorum j =
 let keys = List.init 4 (fun i -> key (i+1)) in
 let validators = List.map (fun key -> let pubkey=Mirage_crypto_ec.Ed25519.(pub_of_priv key |> pub_to_octets) in
    T.{address=Octra_core.Crypto.Address.address_from_pubkey (Base64.encode_exn pubkey);pubkey}) keys in
 let entries = List.map2 (fun v w -> v,Z.of_int (to_int w)) validators (member "weights" j |> to_list) in
 let weighted = member "weighted" j = `Bool true in
 let set = if weighted then (match T.make_weighted_validator_set entries with Ok s -> s | Error e -> failwith e) else T.make_validator_set validators in
 let set = T.{set with validators=List.map (fun (v:T.validator_info) -> {v with pubkey=Base64.encode_exn v.pubkey}) set.validators} in
 let body = match C.parse_body (member "raw" j |> raw |> Yojson.Safe.from_string) with Ok b -> C.{b with validator_set_hash=M.set_hash set} | Error e -> failwith e in
 let exporters = member "op" j = `String "exporters" in
 let msg = if exporters then raw (member "message" j) else match C.hash_raw body with Ok m -> m | Error e -> failwith e in
 let indices = member "signers" j |> to_list |> List.map to_int in
 let signatures = List.map (fun i -> let v = List.nth validators i in
   C.{signer=v.address;signature=Base64.encode_exn(Mirage_crypto_ec.Ed25519.sign ~key:(List.nth keys i) msg)}) indices in
 let signatures = if member "ordered" j = `Bool true then List.sort (fun a b -> String.compare a.C.signer b.C.signer) signatures else signatures in
 let signatures = if member "tamper" j = `Bool true then List.map (fun (s:C.signature) -> {s with signature=Base64.encode_exn(String.make 64 '\000')}) signatures else signatures in
 let body = if member "mutate" j = `Bool true then C.{body with state_root=String.make 64 'f'} else body in
 let fields = match j with `Assoc f -> f | _ -> assert false in
 let fields = List.remove_assoc "raw" fields @ ["raw",`String(Base64.encode_exn(Yojson.Safe.to_string(C.body_json body)));
    "validators",`List(List.map2 (fun (v:T.validator_info) w -> `Assoc["address",`String v.address;"pubkey",`String(Base64.encode_exn v.pubkey);"weight",w]) validators (member "weights" j |> to_list));
    "signatures",`List(List.map C.signature_json signatures)] in
 let checked = if exporters then M.verify_exporters ~exporter_set:set ~required:(member "required" j |> to_int)
     ~message:(if member "mutate" j = `Bool true then msg ^ "changed" else msg) signatures
   else C.verify_quorum ~validator_set:set body signatures in
 `Assoc (fields@["expected",result (ok (fun () -> `Bool true) checked)])
let case j =
 if List.mem (member "op" j) [`String "quorum";`String "exporters"] then quorum j else
 let expected = try result (run j) with exn -> `Assoc ["error",`String (Printexc.to_string exn)] in
 match j with `Assoc f -> `Assoc (f@["expected",expected]) | _ -> assert false
let () = Yojson.Safe.from_channel stdin |> to_list |> List.map case |> fun values -> Yojson.Safe.to_channel stdout (`List values);print_newline ()
