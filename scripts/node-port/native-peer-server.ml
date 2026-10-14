(* Live interoperability harness. Native networking modules are unmodified. *)
module N=Octra_net
module S=N.P2p_swarm
module F=N.P2p_frame
let key n=match Mirage_crypto_ec.Ed25519.priv_of_octets(String.make 32(Char.chr n))with Ok k->k|Error _->failwith"seed"
let public k=Mirage_crypto_ec.Ed25519.(pub_of_priv k|>pub_to_octets)
let ()=
 Mirage_crypto_rng_unix.use_default();
 let key=key 77 and client=public(key 42)in
 let pub=public key in
 let cfg:S.config={listen_port=19091;chain_id="native-swarm-interop";node_id=N.P2p_handshake.node_id_of_pubkey pub;node_addr="ocaml-native";pubkey_raw=pub;consensus_config_hash=String.make 32 '\001';binary_hash=String.make 32 '\002';require_binary_hash=false;upgrade_plan=None;profile_plan=[{epoch=5L;config_hash=String.make 32 '\003';profile_hash="profile-five"}];allowed_pubkeys=[pub;client];bootstrap_peers=[];max_peers=4;sign_fn=(fun msg->Mirage_crypto_ec.Ed25519.sign ~key msg);best_epoch_fn=(fun()->0L);best_root_fn=(fun()->String.make 32 '\000')}in
 let swarm=S.create cfg in
 let on_message conn frame=
  if frame.F.msg_type=F.msg_ping then N.P2p_conn.send conn {F.msg_type=F.msg_pong;payload=frame.payload}
  else if frame.msg_type=F.msg_tx_gossip then
   match N.P2p_tx_gossip.decode frame.payload with
   |Inv hashes->N.P2p_conn.send conn {F.msg_type=F.msg_tx_gossip;payload=N.P2p_tx_gossip.encode(Get hashes)}
   |_->Lwt.return_unit
  else Lwt.return_unit in
 let server=S.start swarm ~on_message in
 let ready=let open Lwt.Syntax in let*()=Lwt_unix.sleep 0.1 in print_endline"NATIVE_PEER_READY";flush stdout;Lwt.return_unit in
 Lwt_main.run(Lwt.finalize(fun()->Lwt.pick[server;(let open Lwt.Syntax in let*()=ready in Lwt_unix.sleep 300.)])(fun()->S.stop swarm))
