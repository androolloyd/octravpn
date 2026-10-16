use octra_node_protocol::chain_identity::{ChainIdentity, ChainOrigin, StateRoot};
use serde_json::json;
use sha2::{Digest, Sha256};

#[test]
fn legacy_genesis_serialization_and_namespace_remain_exact() {
    let identity = ChainIdentity::genesis("legacy", StateRoot([17; 32]));
    let old = format!(
        "{{\"chain_id\":\"legacy\",\"genesis_root\":[{}]}}",
        ["17"; 32].join(",")
    );
    assert_eq!(serde_json::to_string(&identity).unwrap(), old);
    assert_eq!(
        serde_json::from_str::<ChainIdentity>(&old).unwrap(),
        identity
    );
    assert_eq!(identity.namespace_key(), [17; 32]);
    assert_eq!(identity.genesis_root(), Some(StateRoot([17; 32])));
    assert_eq!(identity.origin.epoch(), 0);
}

#[test]
fn checkpoint_origin_is_explicit_and_domain_separated_from_state() {
    let root = StateRoot([29; 32]);
    let identity = ChainIdentity::checkpoint("public", 1_278_039, root);
    assert!(identity.genesis_root().is_none());
    assert_eq!(identity.origin.state_root(), root);
    let mut preimage = b"octra:checkpoint-origin:v1\0".to_vec();
    preimage.extend_from_slice(&6_u64.to_be_bytes());
    preimage.extend_from_slice(b"public");
    preimage.extend_from_slice(&1_278_039_u64.to_be_bytes());
    preimage.extend_from_slice(&[29; 32]);
    assert_eq!(
        identity.namespace_key().as_slice(),
        Sha256::digest(preimage).as_slice()
    );
    let wire = serde_json::to_value(&identity).unwrap();
    assert_eq!(
        wire,
        json!({"chain_id":"public","origin":{"kind":"checkpoint","epoch":1_278_039,"state_root":"1d".repeat(32)}})
    );
    assert_eq!(
        serde_json::from_value::<ChainIdentity>(wire).unwrap(),
        identity
    );
    for other in [
        ChainIdentity::genesis("public", root),
        ChainIdentity::checkpoint("other", 1_278_039, root),
        ChainIdentity::checkpoint("public", 1_278_040, root),
        ChainIdentity::checkpoint("public", 1_278_039, StateRoot([30; 32])),
    ] {
        assert_ne!(identity.namespace_key(), other.namespace_key());
    }
}

#[test]
fn ambiguous_or_noncanonical_origins_are_rejected() {
    let good = json!({"chain_id":"public","origin":{"kind":"checkpoint","epoch":1_278_039,"state_root":"1d".repeat(32)}});
    let mut both = good.clone();
    both["genesis_root"] = json!(vec![0; 32]);
    assert!(serde_json::from_value::<ChainIdentity>(both).is_err());
    for change in [
        json!("AB".repeat(32)),
        json!("1d".repeat(31)),
        json!(vec![29; 32]),
    ] {
        let mut invalid = good.clone();
        invalid["origin"]["state_root"] = change;
        assert!(serde_json::from_value::<ChainIdentity>(invalid).is_err());
    }
    let mut future = good.clone();
    future["origin"]["epoch"] = json!(1_u64 << 62);
    assert!(serde_json::from_value::<ChainIdentity>(future).is_err());
    let mut empty = good;
    empty["chain_id"] = json!("");
    assert!(serde_json::from_value::<ChainIdentity>(empty).is_err());
    assert!(serde_json::from_value::<ChainIdentity>(json!({"chain_id":"public"})).is_err());
}

#[test]
fn configured_origin_is_stable_across_later_snapshots() {
    let pinned = StateRoot([1; 32]);
    let later = StateRoot([2; 32]);
    let genesis = ChainIdentity::genesis("local", pinned);
    assert_eq!(
        genesis.bind_checkpoint(0, later),
        Err("snapshot differs from configured genesis origin")
    );
    assert!(genesis.bind_checkpoint(0, pinned).is_ok());
    assert!(genesis.bind_checkpoint(1, later).is_ok());
    let identity = ChainIdentity::checkpoint("public", 1_278_039, pinned);
    assert_eq!(
        identity.bind_checkpoint(1_278_038, pinned),
        Err("snapshot precedes configured checkpoint origin")
    );
    assert_eq!(
        identity.bind_checkpoint(1_278_039, later),
        Err("snapshot differs from configured checkpoint origin")
    );
    assert!(identity.bind_checkpoint(1_278_039, pinned).is_ok());
    assert!(identity.bind_checkpoint(1_697_760, later).is_ok());
    assert_eq!(
        identity.origin,
        ChainOrigin::Checkpoint {
            epoch: 1_278_039,
            state_root: pinned
        }
    );
}
