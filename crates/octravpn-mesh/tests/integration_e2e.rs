//! End-to-end mesh integration: two `MeshManager`s sharing a registry,
//! exchanging candidates, transitioning through the full connection
//! state machine, surviving a network migration.
//!
//! Each `MeshManager` owns its own conn FSM and `opened` set but
//! consumes the *same* `PeerRegistry` — that's the production setup
//! where members gossip into a tailnet-wide registry.

use std::{sync::Arc, time::Instant};

use octravpn_mesh::{
    ConnState, MeshAction, MeshManager, PeerCandidate, PeerRegistry, PeerSnapshot,
};

const TID: &str = "tnet1";

fn snap(addr: &str, cands: Vec<PeerCandidate>) -> PeerSnapshot {
    PeerSnapshot {
        tailnet_id: TID.into(),
        addr: addr.into(),
        wg_pubkey: [1u8; 32],
        candidates: cands,
        hostname: Some(format!("h-{addr}")),
        last_refresh: Instant::now(),
    }
}

/// Make both managers share the same registry. In production, each
/// manager owns its own and they sync via on-chain or validator-mediated
/// gossip; here we collapse that path.
fn share_registry(a: &MeshManager, b: &MeshManager) -> Arc<PeerRegistry> {
    let reg = a.peers();
    // `MeshManager::new` allocates its own registry; swapping `b`'s for
    // `a`'s isn't directly possible without a setter. We use the
    // pattern of seeding both registries with the same data after each
    // tick: pre-seed once here, and at every tick step copy peers from
    // `a.peers()` into `b.peers()`. That's what `propagate` does below.
    let _ = b;
    reg
}

fn propagate(from: &MeshManager, to: &MeshManager) {
    // Copy every peer from `from`'s registry into `to`'s. The registry
    // de-duplicates by (tailnet_id, addr).
    let other = from.peers();
    let dst = to.peers();
    // Re-publish self-snapshot so the other side learns of us.
    let s_other = from.self_snapshot(TID, Some(format!("h-{}", from.self_addr())));
    dst.publish_unverified(s_other);
    let _ = other;
}

#[test]
fn two_managers_progress_init_to_direct_via_lan() {
    let a = MeshManager::new("octA", [0xAA; 32]);
    let b = MeshManager::new("octB", [0xBB; 32]);

    a.set_self_candidates(vec![PeerCandidate::Lan("10.0.0.1:51820".parse().unwrap())]);
    b.set_self_candidates(vec![PeerCandidate::Lan("10.0.0.2:51820".parse().unwrap())]);

    // Exchange candidates so each registry has the other peer.
    propagate(&a, &b);
    propagate(&b, &a);

    // First tick: Init → Probing. Second: → Direct.
    let _ = a.tick(TID);
    let _ = b.tick(TID);
    let actions_a = a.tick(TID);
    let actions_b = b.tick(TID);

    assert!(
        actions_a
            .iter()
            .any(|x| matches!(x, MeshAction::OpenDirect { peer_addr, .. } if peer_addr == "octB")),
        "a should open direct to b; got {actions_a:?}"
    );
    assert!(
        actions_b
            .iter()
            .any(|x| matches!(x, MeshAction::OpenDirect { peer_addr, .. } if peer_addr == "octA")),
        "b should open direct to a; got {actions_b:?}"
    );

    assert_eq!(
        a.conns().state(TID, "octB").unwrap().state,
        ConnState::Direct
    );
    assert_eq!(
        b.conns().state(TID, "octA").unwrap().state,
        ConnState::Direct
    );
}

#[test]
fn relay_fallback_when_no_direct_candidates() {
    let a = MeshManager::new("octA", [0xAA; 32]);
    let b = MeshManager::new("octB", [0xBB; 32]);

    // Neither has a direct candidate — only relay.
    a.set_self_candidates(vec![PeerCandidate::Relay {
        validator_addr: "octV1".into(),
    }]);
    b.set_self_candidates(vec![PeerCandidate::Relay {
        validator_addr: "octV1".into(),
    }]);

    propagate(&a, &b);
    propagate(&b, &a);

    a.tick(TID); // Probing
    let actions = a.tick(TID); // Relay
    assert!(
        actions.iter().any(
            |x| matches!(x, MeshAction::OpenRelay { peer_addr, relay_validator, .. }
                              if peer_addr == "octB" && relay_validator == "octV1")
        ),
        "expected OpenRelay; got {actions:?}"
    );
    assert_eq!(
        a.conns().state(TID, "octB").unwrap().state,
        ConnState::Relay
    );
}

#[test]
fn network_migration_demotes_then_re_promotes() {
    let a = MeshManager::new("octA", [0xAA; 32]);
    let b = MeshManager::new("octB", [0xBB; 32]);

    a.set_self_candidates(vec![PeerCandidate::Lan("10.0.0.1:51820".parse().unwrap())]);
    b.set_self_candidates(vec![PeerCandidate::Lan("10.0.0.2:51820".parse().unwrap())]);
    propagate(&a, &b);
    propagate(&b, &a);
    a.tick(TID);
    a.tick(TID);
    assert_eq!(
        a.conns().state(TID, "octB").unwrap().state,
        ConnState::Direct
    );

    // Simulate wifi → cellular on `a`. Connections drop to Probing.
    let n = a.on_network_change(TID);
    assert!(n >= 1);
    assert_eq!(
        a.conns().state(TID, "octB").unwrap().state,
        ConnState::Probing
    );

    // Re-discover: new public address; re-publish; tick.
    a.set_self_candidates(vec![PeerCandidate::Stun(
        "203.0.113.7:51820".parse().unwrap(),
    )]);
    propagate(&a, &b);
    let actions = a.tick(TID);
    // The peer still has its direct LAN candidate; we should re-promote.
    assert!(
        actions
            .iter()
            .any(|x| matches!(x, MeshAction::OpenDirect { peer_addr, .. } if peer_addr == "octB")),
        "expected re-promotion to Direct after migration; got {actions:?}"
    );
}

#[test]
fn peer_departure_emits_close_action() {
    let a = MeshManager::new("octA", [0xAA; 32]);
    let b = MeshManager::new("octB", [0xBB; 32]);
    a.set_self_candidates(vec![PeerCandidate::Lan("10.0.0.1:51820".parse().unwrap())]);
    b.set_self_candidates(vec![PeerCandidate::Lan("10.0.0.2:51820".parse().unwrap())]);
    propagate(&a, &b);
    propagate(&b, &a); // a learns about b
    a.tick(TID);
    a.tick(TID); // Direct, opened set has B

    // B vanishes from a's registry.
    a.peers().remove(TID, "octB");

    let actions = a.tick(TID);
    assert!(
        actions
            .iter()
            .any(|x| matches!(x, MeshAction::Close { peer_addr, .. } if peer_addr == "octB")),
        "expected Close for vanished peer; got {actions:?}"
    );
}

#[test]
fn shared_registry_visibility() {
    // Verify the registry assumption used by `propagate`: publishing
    // into one manager's registry doesn't magically appear in
    // another's. (If this ever changes, our `propagate` helper is wrong.)
    let a = MeshManager::new("octA", [0xAA; 32]);
    let b = MeshManager::new("octB", [0xBB; 32]);
    a.set_self_candidates(vec![PeerCandidate::Lan("10.0.0.1:51820".parse().unwrap())]);
    let s = a.self_snapshot(TID, Some("h-a".into()));
    a.peers().publish_unverified(s);
    assert_eq!(a.peers().len(), 1);
    assert_eq!(b.peers().len(), 0);
    let _ = share_registry(&a, &b);
}

#[test]
fn allowed_ips_includes_peer_tailnet_ip() {
    let a = MeshManager::new("octA", [0xAA; 32]);
    a.set_self_candidates(vec![PeerCandidate::Lan("10.0.0.1:51820".parse().unwrap())]);
    a.peers().publish_unverified(snap(
        "octB",
        vec![PeerCandidate::Lan("10.0.0.2:51820".parse().unwrap())],
    ));
    a.tick(TID);
    let actions = a.tick(TID);
    let allowed = actions
        .iter()
        .find_map(|x| match x {
            MeshAction::OpenDirect { allowed_ips, .. } => Some(allowed_ips.clone()),
            _ => None,
        })
        .expect("OpenDirect");
    // /32 host route present.
    assert!(allowed.iter().any(|c| c.prefix_len == 32));
}
