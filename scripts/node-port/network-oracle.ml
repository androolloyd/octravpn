open Yojson.Safe.Util
module N = Octra_net
module H = N.P2p_handshake
module F = N.P2p_frame
module B = N.P2p_frame_budget
let hex raw = String.concat "" (List.init (String.length raw) (fun i -> Printf.sprintf "%02x" (Char.code raw.[i])))
let unhex text = String.init (String.length text / 2) (fun i -> Char.chr (int_of_string ("0x" ^ String.sub text (i*2) 2)))
let field name value = value |> member name
let string name value = field name value |> to_string
let raw name value = unhex (string name value)
let int name value = field name value |> to_int
let i64 name value = string name value |> Int64.of_string
let opt name default value = match field name value with `Null -> default | item -> item
let hash raw = Digestif.SHA256.(digest_string raw |> to_hex)
let blob raw = `Assoc ["hex",`String (if String.length raw <= 1024 then hex raw else ""); "length",`Int (String.length raw); "sha256",`String(hash raw)]
let error exn = match exn with Failure s | Invalid_argument s -> s | _ -> Printexc.to_string exn
let catch f = try f () with exn -> `Assoc["error_hex",`String(hex(error exn))]
let validation = function Ok () -> `Null | Error s -> `String (hex s)
let key seed = match Mirage_crypto_ec.Ed25519.priv_of_octets seed with Ok key -> key | Error _ -> failwith "seed"
let public key = Mirage_crypto_ec.Ed25519.(pub_of_priv key |> pub_to_octets)
let sign key msg = Mirage_crypto_ec.Ed25519.sign ~key msg
let make_hello value =
  let key = key (raw "seed" value) in
  let pubkey = opt "public_key" (`String(hex(public key))) value |> to_string |> unhex in
  let h : H.hello = {
    chain_id=raw "chain_id" value; proto_version=int "protocol_version" value;
    node_id=opt "node_id" (`String(hex(H.node_id_of_pubkey pubkey))) value |> to_string |> unhex;
    node_addr=raw "node_address" value; pubkey; consensus_config_hash=raw "config_hash" value;
    listen_port=int "listen_port" value; best_epoch=i64 "best_epoch" value; best_root=raw "best_root" value;
    nonce=raw "nonce" value; signature=String.make 64 '\000';
  } in
  let signature=opt "signature" (`String(hex(sign key (H.hello_sign_bytes h)))) value |> to_string |> unhex in
  { h with signature }
let budget_result = function
  | B.Accept -> `Assoc["accept",`Bool true]
  | B.Drop r -> `Assoc["reason",`String r.reason; "lane",`String(B.lane_name r.lane); "class",`String(B.peer_class_name r.peer_class);
    "frames",`Int r.frames; "bytes",`Int r.bytes; "frame_bytes",`Int r.frame_bytes; "max_frames",`Int r.max_frames; "max_bytes",`Int r.max_bytes; "action",`String(B.rejection_action_name r.action)]
let peer_class = function "validator" -> B.Validator | _ -> B.Observer
let execute value = catch (fun () -> match string "op" value with
| "frame_meta" -> let message=int "message" value in `Assoc["known",`Bool(F.known_msg_type message);"maximum",`Int(F.max_payload_size message);"name",`String(F.msg_type_name message);"lane",`String(B.lane_name(B.lane message))]
| "frame_encode" -> let f:F.frame={msg_type=int "message" value;payload=String.make (int "length" value) (Char.chr(int "byte" value))} in blob(F.encode_frame f)
| "frame_decode" ->
  let wire=raw "wire" value in
  let left,right=Lwt_unix.socketpair Unix.PF_UNIX Unix.SOCK_STREAM 0 in
  let open Lwt.Syntax in
  let reader = Lwt.finalize (fun () -> let* f=F.read_frame ~payload_cap:(int "cap" value) left in Lwt.return(`Assoc["message",`Int f.msg_type;"payload",blob f.payload])) (fun()->Lwt_unix.close left) in
  let writer=Lwt.catch (fun()->let* ()=F.write_all right wire in Lwt_unix.close right) (fun _ -> Lwt.return_unit) in
  Lwt_main.run (let* result=reader in let* ()=writer in Lwt.return result)
| "oce1" -> let c=N.Oce1.make_cursor(raw "wire" value) in
  let result=match string "kind" value with
  | "u8"->`Int(N.Oce1.get_u8 c)|"u16"->`Int(N.Oce1.get_u16 c)|"u32"->`String(Int32.to_string(N.Oce1.get_u32 c))|"u64"->`String(Int64.to_string(N.Oce1.get_u64 c))
  | "bool"->`Bool(N.Oce1.get_bool c)|"bytes"->`String(hex(N.Oce1.get_bytes_bounded ~max:(int "maximum" value) c))
  | "option" -> (match N.Oce1.get_option N.Oce1.get_u8 c with None->`Null|Some n->`Int n)
  | "list" -> `List(List.map (fun n->`Int n) (N.Oce1.get_list_bounded ~max:(int "maximum" value) N.Oce1.get_u8 c))
  | _->failwith "kind" in
  if N.Oce1.remaining c>0 then failwith(Printf.sprintf "OCE1: %d trailing bytes" (N.Oce1.remaining c)); result
| "hash32" -> blob(N.Oce1.encode(fun b->N.Oce1.put_hash32 b (raw "value" value)))
| "hello" -> let h=make_hello (field "hello" value) in
  let allowed=field "allowed" value |> to_list |> List.map(fun j->unhex(to_string j)) in
  `Assoc["encoded",blob(H.encode_hello h);"sign_bytes",`String(hex(H.hello_sign_bytes h));"node_id",`String(hex(H.node_id_of_pubkey h.pubkey));
    "validation",validation(H.validate_hello ~my_chain_id:(raw "chain_id" value) ~my_config_hash:(raw "config_hash" value) ~allowed_pubkeys:allowed h)]
| "decode" -> let bytes=raw "wire" value in
  let result=match string "kind" value with
    | "hello"->H.encode_hello(H.decode_hello bytes)|"ack"->H.encode_hello_ack(H.decode_hello_ack bytes)
    | "finish"->H.encode_hello_finish(H.decode_hello_finish bytes)|"profile"->H.encode_profile(H.decode_profile bytes)|_->failwith "kind" in blob result
| "exchange" ->
  let a=make_hello (field "initiator" value) and b=make_hello (field "responder" value) in
  let ka=key(raw "seed" (field "initiator" value)) and kb=key(raw "seed" (field "responder" value)) in
  let ack=H.make_hello_ack ~hello:b ~challenge_nonce:a.nonce ~sign_fn:(sign kb) in
  let finish=H.make_hello_finish ~initiator:a ~responder:b ~sign_fn:(sign ka) in
  let ack=match string "mutation" value with "ack_nonce"->{ack with challenge_nonce=String.make 32 '\042'}|"ack_signature"->{ack with signature=String.make 64 '\000'}|_->ack in
  let finish=match string "mutation" value with
    |"finish_nonce"->{finish with responder_nonce=String.make 32 '\042'}|"finish_identity"->{finish with responder_node_id=String.make 64 '0'}
    |"finish_chain"->{finish with chain_id="other"}|"finish_config"->{finish with consensus_config_hash=String.make 32 '\042'}|"finish_signature"->{finish with signature=String.make 64 '\000'}|_->finish in
  `Assoc["ack",blob(H.encode_hello_ack ack);"finish",blob(H.encode_hello_finish finish);"ack_sign_bytes",`String(hex(H.hello_ack_sign_bytes ack));"finish_sign_bytes",`String(hex(H.hello_finish_sign_bytes finish));
    "ack_validation",validation(H.validate_hello_ack ~my_hello:a ~allowed_pubkeys:[] ack);"finish_validation",validation(H.validate_hello_finish ~initiator:a ~responder:b finish)]
| "profile" -> let key=key(raw "seed" value) in
  let node_id=raw "node_id" value in
  let p=H.make_profile ~chain_id:(raw "chain_id" value) ~node_id ~epoch:(i64 "epoch" value) ~config_hash:(raw "config_hash" value) ~sign_fn:(sign key) in
  let p={p with signature=opt "signature" (`String(hex p.signature)) value|>to_string|>unhex} in
  `Assoc["encoded",blob(H.encode_profile p);"sign_bytes",`String(hex(H.profile_sign_bytes ~chain_id:(raw "chain_id" value) ~node_id p));"validation",validation(H.validate_profile ~chain_id:(raw "chain_id" value) ~node_id ~pubkey:(public key) p)]
| "ed25519" -> let pub=raw "public" value and msg=raw "message" value and signature=raw "signature" value in
  `Assoc["safe",`Bool(Octra_ed25519.safe pub);"verified",`Bool(Octra_ed25519.verify ~pub ~msg signature)]
| "ed25519_seed" -> let seed=raw "seed" value and msg=raw "message" value in
  let key=key seed in let pub=public key in
  let order=Z.(add (shift_left one 252) (of_string "27742317777372353535851937790883648493")) in
  let of_le bytes=let accumulator=ref Z.zero in for i=String.length bytes-1 downto 0 do accumulator:=Z.(add (shift_left !accumulator 8) (of_int(Char.code bytes.[i]))) done; !accumulator in
  let to_le z=String.init 32(fun i->Z.extract z (i*8) 8|>Z.to_int|>Char.chr) in
  let normal=sign key msg in
  let signature=match string "kind" value with
  | "weak_r" -> let digest=Digestif.SHA512.(digest_string seed|>to_raw_string)|>Bytes.of_string in
    Bytes.set_uint8 digest 0 (Bytes.get_uint8 digest 0 land 248);Bytes.set_uint8 digest 31 ((Bytes.get_uint8 digest 31 land 127) lor 64);
    let secret=of_le(Bytes.sub_string digest 0 32) in let r="\001"^String.make 31 '\000' in
    let h=Digestif.SHA512.(digest_string(r^pub^msg)|>to_raw_string)|>of_le in r^to_le Z.(erem(mul h secret) order)
  | "malleable" -> String.sub normal 0 32 ^ to_le Z.(add (of_le(String.sub normal 32 32)) order)
  | "corrupt" -> let bytes=Bytes.of_string normal in Bytes.set_uint8 bytes 0 (Bytes.get_uint8 bytes 0 lxor 1);Bytes.unsafe_to_string bytes
  | _ -> normal in
  `Assoc["public",`String(hex pub);"signature",`String(hex signature);"safe",`Bool(Octra_ed25519.safe pub);"verified",`Bool(Octra_ed25519.verify ~pub ~msg signature)]
| "budget" -> let b=B.create ~now:(field "now" value|>to_float) ~peer_class:(peer_class(string "class" value)) in
  let results=field "steps" value|>to_list|>List.map(fun step ->
    (match field "class" step with `String name -> B.set_peer_class b (peer_class name)|_->());
    budget_result(B.admit b ~now:(field "now" step|>to_float) ~msg_type:(int "message" step) ~bytes:(int "bytes" step))) in `List results
| _ -> failwith "operation")
let () = let cases=Yojson.Safe.from_file Sys.argv.(1)|>to_list in
  `List(List.map(fun value->`Assoc["input",value;"expected",execute value]) cases)|>Yojson.Safe.to_channel stdout
