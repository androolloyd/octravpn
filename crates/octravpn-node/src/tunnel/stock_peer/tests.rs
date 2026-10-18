//! Component transport regressions use real boringtun authentication/replay and
//! real loopback UDP sends. Canonical payment + stock-client/kernel qualification
//! remains the separate native-vpn gate, not a claim made by these fixtures.
use super::*;
use x25519_dalek::{PublicKey, StaticSecret};

fn registration(key: [u8; 32]) -> crate::stock::Registration {
    crate::stock::Registration {
        node_key: key,
        machine_key: "02".repeat(32),
        node_id: 7,
        ipv4: "100.64.0.2".parse().unwrap(),
        created: "1970-01-01T00:00:00+00:00".into(),
        expiry: None,
    }
}
fn identity(peers: &Peers, client: &StaticSecret, server: &StaticSecret) -> Arc<Identity> {
    let registration = registration(PublicKey::from(client).to_bytes());
    peers
        .acquire(&registration, |index| {
            Tunn::new(
                server.clone(),
                PublicKey::from(client),
                None,
                None,
                index,
                None,
            )
        })
        .unwrap()
}
fn wire(result: TunnResult<'_>) -> Vec<u8> {
    let TunnResult::WriteToNetwork(bytes) = result else {
        panic!("network output expected")
    };
    bytes.to_vec()
}
fn raw() -> Vec<u8> {
    let mut raw = vec![0; 28];
    raw[0] = 0x45;
    raw[2..4].copy_from_slice(&28_u16.to_be_bytes());
    raw[8] = 64;
    raw[9] = 1;
    raw[12..16].copy_from_slice(&[100, 64, 0, 2]);
    raw[16..20].copy_from_slice(&[8, 8, 8, 8]);
    raw
}
fn establish(peers: &Peers, peer: &Identity, client: &mut Tunn, source: SocketAddr) {
    let mut work = [0; 4096];
    let init = wire(client.format_handshake_initiation(&mut work, false));
    let (result, token) = peer.receive(&init, source, &mut work);
    let reply = wire(result);
    peer.promote(peers, token.expect("authenticated initiation"), source)
        .unwrap();
    let keepalive = wire(client.decapsulate(None, &reply, &mut work));
    let (result, token) = peer.receive(&keepalive, source, &mut work);
    assert!(matches!(result, TunnResult::Done));
    peer.promote(peers, token.expect("authenticated keepalive"), source)
        .unwrap();
}
fn deliver(peers: &Peers, peer: &Identity, bytes: &[u8], source: SocketAddr) -> Vec<u8> {
    let mut work = [0; 4096];
    let (result, token) = peer.receive(bytes, source, &mut work);
    let TunnResult::WriteToTunnelV4(raw, _) = result else {
        panic!("authenticated IPv4 expected")
    };
    let raw = raw.to_vec();
    peer.promote(peers, token.unwrap(), source).unwrap();
    raw
}

#[tokio::test]
async fn direct_derp_and_nat_roaming_share_noise_replay_and_latest_return_endpoint() {
    let peers = Peers::default();
    let server = StaticSecret::from([71; 32]);
    let client_secret = StaticSecret::from([72; 32]);
    let peer = identity(&peers, &client_secret, &server);
    assert_eq!(peer.index, 1);
    let same = peers
        .acquire(&peer.registration, |_| {
            panic!("same registration must reuse its Tunn")
        })
        .unwrap();
    assert!(Arc::ptr_eq(&peer, &same));
    let mut client = Tunn::new(client_secret, PublicKey::from(&server), None, None, 0, None);
    let direct = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let derp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let nat = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sender.writable().await.unwrap();
    establish(&peers, &peer, &mut client, direct.local_addr().unwrap());
    let mut work = [0; 4096];
    let first = wire(client.encapsulate(&raw(), &mut work));
    let selected = peers
        .receiver(&Tunn::parse_incoming_packet(&first).unwrap(), None)
        .unwrap();
    assert!(
        Arc::ptr_eq(&selected, &peer),
        "transport receiver index selects the existing identity"
    );
    assert_eq!(
        deliver(&peers, &peer, &first, derp.local_addr().unwrap()),
        raw()
    );
    let endpoint = peer.state.lock().endpoint;
    assert_eq!(endpoint, Some(derp.local_addr().unwrap()));
    let (replay, token) = peer.receive(&first, direct.local_addr().unwrap(), &mut work);
    assert!(matches!(replay, TunnResult::Err(_)) && token.is_none());
    assert_eq!(
        peer.state.lock().endpoint,
        endpoint,
        "replay cannot switch back to direct"
    );
    let mut forged = wire(client.encapsulate(&raw(), &mut work));
    *forged.last_mut().unwrap() ^= 1;
    let (invalid, token) = peer.receive(&forged, nat.local_addr().unwrap(), &mut work);
    assert!(matches!(invalid, TunnResult::Err(_)) && token.is_none());
    assert_eq!(peer.state.lock().endpoint, endpoint);
    // A retained return identity follows a valid keepalive; it does not require
    // another outbound application flow to replace a cached kernel return path.
    let keepalive = wire(client.encapsulate(&[], &mut work));
    let (result, token) = peer.receive(&keepalive, nat.local_addr().unwrap(), &mut work);
    assert!(matches!(result, TunnResult::Done));
    peer.promote(&peers, token.unwrap(), nat.local_addr().unwrap())
        .unwrap();
    let (result, unsent) = peer.encapsulate(&raw(), &mut work);
    assert!(!unsent);
    let reply = wire(result);
    peer.send(&peers, &sender, &reply).unwrap();
    let mut received = [0; 4096];
    let count = tokio::time::timeout(std::time::Duration::from_secs(1), nat.recv(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        client.decapsulate(None, &received[..count], &mut work),
        TunnResult::WriteToTunnelV4(..)
    ));
    assert!(direct.try_recv(&mut received).is_err());
    assert!(derp.try_recv(&mut received).is_err());
}

#[test]
fn receiver_indices_are_unique_and_cookie_or_invalid_inputs_never_promote() {
    let peers = Peers::default();
    let server = StaticSecret::from([81; 32]);
    let a = StaticSecret::from([82; 32]);
    let b = StaticSecret::from([83; 32]);
    let first = identity(&peers, &a, &server);
    let second = identity(&peers, &b, &server);
    assert_ne!(first.index, second.index);
    let source = "127.0.0.1:30000".parse().unwrap();
    let mut client = Tunn::new(a, PublicKey::from(&server), None, None, 0, None);
    establish(&peers, &first, &mut client, source);
    let mut work = [0; 4096];
    let mut packet = wire(client.encapsulate(&raw(), &mut work));
    packet[4..8].copy_from_slice(&(second.index << 8).to_le_bytes());
    assert!(Arc::ptr_eq(
        &second,
        &peers
            .receiver(&Tunn::parse_incoming_packet(&packet).unwrap(), None)
            .unwrap()
    ));
    let (result, token) = second.receive(&packet, source, &mut work);
    assert!(matches!(result, TunnResult::Err(_)) && token.is_none());
    assert!(second.state.lock().endpoint.is_none());
    assert!(
        peers
            .receiver(
                &Tunn::parse_incoming_packet(&packet).unwrap(),
                Some(&first.registration.node_key)
            )
            .is_none(),
        "authenticated DERP key cannot select a different registered receiver"
    );
    // An actual valid CookieReply returns Done in boringtun, but authenticates
    // neither a transport packet nor a usable return endpoint.
    let init = wire(
        first
            .state
            .lock()
            .noise
            .format_handshake_initiation(&mut work, true),
    );
    let limiter = boringtun::noise::rate_limiter::RateLimiter::new(
        &PublicKey::from(&StaticSecret::from([82; 32])),
        0,
    );
    let mut scratch = [0; 256];
    let cookie = match limiter.verify_packet(Some(source.ip()), &init, &mut scratch) {
        Err(TunnResult::WriteToNetwork(cookie)) => cookie.to_vec(),
        other => panic!("cookie required, got {other:?}"),
    };
    let (result, token) = first.receive(&cookie, "127.0.0.1:30001".parse().unwrap(), &mut work);
    assert!(matches!(result, TunnResult::Done) && token.is_none());
    assert_eq!(first.state.lock().endpoint, Some(source));
}

#[tokio::test]
async fn registration_replacement_and_idle_retirement_invalidate_retained_return_identity() {
    let peers = Peers::default();
    let server = StaticSecret::from([91; 32]);
    let client = StaticSecret::from([92; 32]);
    let first = identity(&peers, &client, &server);
    let mut changed = first.registration.clone();
    changed.created = "2026-10-17T00:00:00+00:00".into();
    let second = peers
        .acquire(&changed, |index| {
            Tunn::new(
                server.clone(),
                PublicKey::from(&client),
                None,
                None,
                index,
                None,
            )
        })
        .unwrap();
    assert!(!peers.current(&first));
    assert!(peers.current(&second));
    assert_ne!(first.index, second.index);
    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    assert!(first
        .send(&peers, &sender, b"retired must not send")
        .is_err());
    first.state.lock().touched = Instant::now()
        .checked_sub(super::super::PEER_IDLE_TTL)
        .unwrap();
    peers.sweep();
    assert!(
        peers.current(&second),
        "old retained identity cannot evict its replacement"
    );
    second.state.lock().touched = Instant::now()
        .checked_sub(super::super::PEER_IDLE_TTL)
        .unwrap();
    peers.sweep();
    assert!(!peers.current(&second));
    assert!(second
        .send(&peers, &sender, b"expired must not send")
        .is_err());
    let third = identity(&peers, &client, &server);
    assert!(
        third.index > second.index,
        "retired receiver indices are never reused"
    );
    peers.0.lock().allocated = 0x00ff_ffff;
    let other = StaticSecret::from([93; 32]);
    assert!(peers
        .acquire(
            &registration(PublicKey::from(&other).to_bytes()),
            |_| panic!("exhausted index must not build Tunn")
        )
        .is_none());
}

#[test]
fn delayed_authenticated_completion_cannot_replace_newer_endpoint_or_retired_identity() {
    let peers = Peers::default();
    let server = StaticSecret::from([101; 32]);
    let client_key = StaticSecret::from([102; 32]);
    let peer = identity(&peers, &client_key, &server);
    let mut client = Tunn::new(
        client_key.clone(),
        PublicKey::from(&server),
        None,
        None,
        0,
        None,
    );
    let original = "127.0.0.1:31000".parse().unwrap();
    let older = "127.0.0.1:31001".parse().unwrap();
    let newer = "127.0.0.1:31002".parse().unwrap();
    establish(&peers, &peer, &mut client, original);
    let mut work = [0; 4096];
    let a = wire(client.encapsulate(&raw(), &mut work));
    let (result, first) = peer.receive(&a, older, &mut work);
    assert!(matches!(result, TunnResult::WriteToTunnelV4(..)));
    let b = wire(client.encapsulate(&raw(), &mut work));
    let (result, second) = peer.receive(&b, newer, &mut work);
    assert!(matches!(result, TunnResult::WriteToTunnelV4(..)));
    peer.promote(&peers, second.unwrap(), newer).unwrap();
    assert!(peer.promote(&peers, first.unwrap(), older).is_err());
    assert_eq!(peer.state.lock().endpoint, Some(newer));
    let c = wire(client.encapsulate(&raw(), &mut work));
    let (result, token) = peer.receive(&c, older, &mut work);
    assert!(matches!(result, TunnResult::WriteToTunnelV4(..)));
    let mut changed = peer.registration.clone();
    changed.machine_key = "04".repeat(32);
    let replacement = peers
        .acquire(&changed, |index| {
            Tunn::new(
                server,
                PublicKey::from(&client_key),
                None,
                None,
                index,
                None,
            )
        })
        .unwrap();
    assert!(peer.promote(&peers, token.unwrap(), older).is_err());
    assert!(!peers.current(&peer));
    assert!(peers.current(&replacement));
    assert_eq!(peer.state.lock().endpoint, Some(newer));
}

#[test]
fn anonymous_static_without_valid_noise_timestamp_cannot_allocate_identity_or_index() {
    // Public fixtures: fixed test keys111/112; ephemeral initiation generated by
    // pinned boringtun0.7.1. Only encrypted timestamp changes in forged, with
    // public MAC1 recomputed. Regeneration/provenance lives in stock-roaming-fix.
    let genuine = hex::decode("0100000001000000e2d516f250a32920466b0f1bab71d7770bc28d0c791352efaafacae6a43f593a94d8fef0e033360f4d9240f7ddb64c01e1d6e1ee1c935cd084f03df54fc2593f891f78adc2982b7ec336ccbe6be07e9d1b01d47cc6bd081fa585c8edd23c8507653cb8a28f1a570742d9e81d9f78bf3c7e12cc9af84f6cfa3a924bb800000000000000000000000000000000").unwrap();
    let forged = hex::decode("0100000001000000e2d516f250a32920466b0f1bab71d7770bc28d0c791352efaafacae6a43f593a94d8fef0e033360f4d9240f7ddb64c01e1d6e1ee1c935cd084f03df54fc2593f891f78adc2982b7ec336ccbe6be07e9d1a01d47cc6bd081fa585c8edd23c8507653cb8a28f1a570742d9e81d6b8359e6b01153ece5d42fa29377cdd800000000000000000000000000000000").unwrap();
    let server = StaticSecret::from([111; 32]);
    let client_key: [u8; 32] =
        hex::decode("a49eb492bf3c39ee123c3aa7c7a8da3fd51ac9ad058a69a25ee0f72ea1efd176")
            .unwrap()
            .try_into()
            .unwrap();
    let registration = registration(client_key);
    let peers = Peers::default();
    let source: SocketAddr = "127.0.0.1:32000".parse().unwrap();
    let limiter = boringtun::noise::rate_limiter::RateLimiter::new(&PublicKey::from(&server), 100);
    let mut scratch = [0; 256];
    for packet in [&genuine, &forged] {
        let Packet::HandshakeInit(init) = limiter
            .verify_packet(Some(source.ip()), packet, &mut scratch)
            .expect("genuine public MAC1 required")
        else {
            panic!("initiation expected")
        };
        let anonymous = boringtun::noise::handshake::parse_handshake_anon(
            &server,
            &PublicKey::from(&server),
            &init,
        )
        .unwrap();
        assert_eq!(
            anonymous.peer_static_public, client_key,
            "anonymous identity alone is not key possession"
        );
    }
    for _ in 0..8 {
        assert!(peers
            .prepare(&registration, &forged, source, |index| Tunn::new(
                server.clone(),
                PublicKey::from(client_key),
                None,
                None,
                index,
                None
            ))
            .is_none());
        let state = peers.0.lock();
        assert!(state.keys.is_empty() && state.receivers.is_empty());
        assert_eq!(state.allocated, 0);
    }
    let admission = peers
        .prepare(&registration, &genuine, source, |index| {
            Tunn::new(
                server.clone(),
                PublicKey::from(client_key),
                None,
                None,
                index,
                None,
            )
        })
        .expect("genuine full Noise proof");
    assert_eq!(
        peers.0.lock().allocated,
        0,
        "preflight response is never published"
    );
    let identity = peers
        .install(admission, |index| {
            Tunn::new(
                server.clone(),
                PublicKey::from(client_key),
                None,
                None,
                index,
                None,
            )
        })
        .unwrap();
    assert_eq!(identity.index, 1);
    assert!(
        identity.state.lock().endpoint.is_none(),
        "only actual admitted-Tunn authentication may publish endpoint"
    );
    let retry = peers
        .prepare(&registration, &forged, source, |_| {
            panic!("existing identity must not be replaced by unauthenticated retry")
        })
        .unwrap();
    let retained = peers
        .install(retry, |_| panic!("no new allocation on retry"))
        .unwrap();
    assert!(Arc::ptr_eq(&identity, &retained));
    assert_eq!(peers.0.lock().allocated, 1);
    let mut work = [0; 2048];
    let (result, token) = identity.receive(&forged, source, &mut work);
    assert!(matches!(result, TunnResult::Err(_)) && token.is_none());
    assert!(identity.state.lock().endpoint.is_none());
}

#[test]
fn recovery_requires_exact_derp_identity_and_never_replaces_an_active_tunnel() {
    let peers = Peers::default();
    let server = StaticSecret::from([121; 32]);
    let client_key = StaticSecret::from([122; 32]);
    let registration = registration(PublicKey::from(&client_key).to_bytes());
    for source in [None, Some(&[99; 32])] {
        assert!(peers
            .recover(&registration, source, |_| panic!(
                "no trusted DERP identity"
            ))
            .is_none());
    }
    assert_eq!(peers.0.lock().allocated, 0);
    let peer = peers
        .recover(&registration, Some(&registration.node_key), |index| {
            Tunn::new(
                server.clone(),
                PublicKey::from(&client_key),
                None,
                None,
                index,
                None,
            )
        })
        .unwrap();
    for _ in 0..8 {
        let retained = peers
            .recover(&registration, Some(&registration.node_key), |_| {
                panic!("repeated authenticated source must share one Tunn")
            })
            .unwrap();
        assert!(Arc::ptr_eq(&peer, &retained));
    }
    assert_eq!(peers.0.lock().allocated, 1);
    let mut client = Tunn::new(client_key, PublicKey::from(&server), None, None, 0, None);
    let source = "127.0.0.1:33000".parse().unwrap();
    establish(&peers, &peer, &mut client, source);
    let mut work = [0; 4096];
    assert!(matches!(
        peer.recover(
            &peers,
            "127.0.0.1:33001".parse().unwrap(),
            Instant::now(),
            &mut work
        )
        .unwrap(),
        TunnResult::Done
    ));
    assert_eq!(peer.state.lock().endpoint, Some(source));
    assert!(peer.state.lock().recovery.is_none());
}

#[tokio::test]
async fn operator_restart_recovers_existing_client_noise_only_after_authenticated_response() {
    let server = StaticSecret::from([123; 32]);
    let client_key = StaticSecret::from([124; 32]);
    let original = Peers::default();
    let old = identity(&original, &client_key, &server);
    let derp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let source = derp.local_addr().unwrap();
    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sender.writable().await.unwrap();
    let mut client = Tunn::new(
        client_key.clone(),
        PublicKey::from(&server),
        None,
        None,
        0,
        None,
    );
    establish(&original, &old, &mut client, source);
    let mut work = [0; 4096];
    let previous = wire(client.encapsulate(&raw(), &mut work));
    let peers = Peers::default();
    assert!(peers
        .receiver(
            &Tunn::parse_incoming_packet(&previous).unwrap(),
            Some(&old.registration.node_key)
        )
        .is_none());
    let peer = peers
        .recover(
            &old.registration,
            Some(&old.registration.node_key),
            |index| {
                Tunn::new(
                    server.clone(),
                    PublicKey::from(&client_key),
                    None,
                    None,
                    index,
                    None,
                )
            },
        )
        .unwrap();
    let (old_result, token) = peer.receive(&previous, source, &mut work);
    assert!(matches!(old_result, TunnResult::Err(_)) && token.is_none());
    let now = Instant::now();
    let init = wire(peer.recover(&peers, source, now, &mut work).unwrap());
    assert_eq!(&init[..4], &[1, 0, 0, 0]);
    assert!(peer.state.lock().endpoint.is_none());
    assert_eq!(peer.state.lock().authenticated, 0);
    assert!(peer.send(&peers, &sender, &previous).is_err());
    assert!(peer
        .send_control(&peers, &sender, &previous, |_| true)
        .is_err());
    assert!(peer
        .send_control(&peers, &sender, &init, |_| false)
        .is_err());
    assert!(derp.try_recv(&mut work).is_err());
    peer.send_control(&peers, &sender, &init, |candidate| candidate == source)
        .unwrap();
    let mut received = [0; 4096];
    let count = tokio::time::timeout(Duration::from_secs(1), derp.recv(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&received[..count], init);
    // Repeated old-session packets neither replace this in-flight handshake nor
    // authenticate its candidate. Even after the trigger interval, the native
    // handshake stays pending until its own retransmission timer runs.
    for instant in [now, now.checked_add(RECOVERY_INTERVAL).unwrap()] {
        assert!(matches!(
            peer.recover(&peers, source, instant, &mut work).unwrap(),
            TunnResult::Done
        ));
    }
    let response = wire(client.decapsulate(None, &init, &mut work));
    assert_eq!(&response[..4], &[2, 0, 0, 0]);
    let mut forged = response.clone();
    forged[12] ^= 1;
    let (result, token) = peer.receive(&forged, source, &mut work);
    assert!(matches!(result, TunnResult::Err(_)) && token.is_none());
    assert!(peer.state.lock().endpoint.is_none());
    let (result, token) = peer.receive(&response, source, &mut work);
    let keepalive = wire(result);
    peer.promote(
        &peers,
        token.expect("valid response proves static possession"),
        source,
    )
    .unwrap();
    assert!(peer.state.lock().recovery.is_none());
    assert!(matches!(
        client.decapsulate(None, &keepalive, &mut work),
        TunnResult::Done
    ));
    let fresh = wire(client.encapsulate(&raw(), &mut work));
    assert_eq!(deliver(&peers, &peer, &fresh, source), raw());
    let (replayed, token) = peer.receive(&fresh, source, &mut work);
    assert!(matches!(replayed, TunnResult::Err(_)) && token.is_none());
    let (obsolete, token) = peer.receive(&previous, source, &mut work);
    assert!(matches!(obsolete, TunnResult::Err(_)) && token.is_none());
    assert_eq!(peer.state.lock().endpoint, Some(source));
}

#[tokio::test]
async fn lost_recovery_initiation_retries_only_current_derp_candidate_and_retirement_cancels_it() {
    let peers = Peers::default();
    let server = StaticSecret::from([125; 32]);
    let client = StaticSecret::from([126; 32]);
    let registration = registration(PublicKey::from(&client).to_bytes());
    let peer = peers
        .recover(&registration, Some(&registration.node_key), |index| {
            Tunn::new(
                server.clone(),
                PublicKey::from(&client),
                None,
                None,
                index,
                None,
            )
        })
        .unwrap();
    let derp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let source = derp.local_addr().unwrap();
    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sender.writable().await.unwrap();
    let mut work = [0; 4096];
    let initial = wire(
        peer.recover(&peers, source, Instant::now(), &mut work)
            .unwrap(),
    );
    assert_eq!(&initial[..4], &[1, 0, 0, 0]);
    // Drop the first actual Noise initiation. Boringtun uses real monotonic
    // time; this fixture exercises its real five-second retry without altering
    // Noise state, synthetic counters, or the clock.
    tokio::time::sleep(Duration::from_secs(6)).await;
    let retry = wire(peer.state.lock().noise.update_timers(&mut work));
    assert_eq!(&retry[..4], &[1, 0, 0, 0]);
    assert_ne!(
        initial, retry,
        "native retry emits a fresh ephemeral initiation"
    );
    assert!(peer.state.lock().endpoint.is_none());
    assert!(peer
        .send_control(&peers, &sender, &retry, |_| false)
        .is_err());
    assert!(derp.try_recv(&mut work).is_err());
    peer.send_control(&peers, &sender, &retry, |candidate| candidate == source)
        .unwrap();
    let mut received = [0; 4096];
    let count = tokio::time::timeout(Duration::from_secs(1), derp.recv(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&received[..count], retry);
    let mut changed = registration;
    changed.created = "2026-10-17T00:00:01+00:00".into();
    let replacement = peers
        .recover(&changed, Some(&changed.node_key), |index| {
            Tunn::new(server, PublicKey::from(&client), None, None, index, None)
        })
        .unwrap();
    assert!(peers.current(&replacement));
    assert!(peer
        .send_control(&peers, &sender, &retry, |_| true)
        .is_err());
    assert!(peer
        .recover(&peers, source, Instant::now(), &mut work)
        .is_err());
    assert!(derp.try_recv(&mut work).is_err());
}
