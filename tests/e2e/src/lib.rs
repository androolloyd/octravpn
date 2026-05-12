//! End-to-end tests against the in-process mock chain.
//!
//! Covers the tailnet model:
//!   - register endpoint (gated on Octra-validator)
//!   - create tailnet, add member, configure exit
//!   - open / settle / no-show
//!   - 3-hop onion build/peel round-trip (no chain needed)

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, sync::Arc, time::Duration};

    use curve25519_dalek::{
        constants::RISTRETTO_BASEPOINT_TABLE, ristretto::RistrettoPoint, scalar::Scalar,
        traits::Identity,
    };
    use octravpn_core::{
        address::Address,
        commit,
        earnings::{self, h_generator},
        onion::{build_onion, peel_layer, HopAction, HopBuildInput},
        receipt::{Receipt, SignedReceipt},
        rpc::RpcClient,
        session::SessionId,
        sig::KeyPair,
    };
    use serde_json::json;
    use tokio::time::sleep;
    use x25519_dalek::{PublicKey as X25519Pub, StaticSecret};

    async fn spawn_mock(port: u16, program: &str) -> Arc<()> {
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let prog = program.to_string();
        tokio::spawn(async move {
            octravpn_mock_rpc::serve(addr, prog).await.ok();
        });
        sleep(Duration::from_millis(150)).await;
        Arc::new(())
    }

    fn mock_url(port: u16) -> String {
        format!("http://127.0.0.1:{port}/rpc")
    }

    /// Promote an address to an Octra validator on the mock chain via
    /// the test-helper RPC method.
    async fn become_octra_validator(rpc: &RpcClient, addr: &str) {
        rpc.raw_call("octra_test_grantValidator", json!([addr]))
            .await
            .expect("grant validator");
    }

    #[tokio::test]
    async fn node_status_round_trip() {
        let _g = spawn_mock(18101, "octPROG").await;
        let rpc = RpcClient::new(mock_url(18101));
        let s = rpc.node_status().await.unwrap();
        assert!(s.epoch >= 1);
    }

    #[tokio::test]
    async fn full_lifecycle_endpoint_tailnet_session_claim() {
        let _g = spawn_mock(18102, "octPROG").await;
        let rpc = RpcClient::new(mock_url(18102));

        let val = "octV1Address0000000000000000000000000001";
        let owner = "octOWNER000000000000000000000000000000001";
        let client = "octCLIENT00000000000000000000000000000001";

        // Pre-promote `val` to an Octra protocol validator (mock-only path).
        become_octra_validator(&rpc, val).await;

        // 1. Register endpoint.
        let register_tx = json!({
            "kind": "contract_call",
            "from": val,
            "to": "octPROG",
            "method": "register_endpoint",
            "params": [
                "1.2.3.4:51820",
                "deadbeef".repeat(8),
                "cafe".repeat(16),
                "beef".repeat(16),
                "eu-west",
                100u64,
            ],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        });
        rpc.submit(&register_tx).await.unwrap();

        // 2. Create a tailnet with 2000 OU treasury.
        let create_tx = json!({
            "kind": "contract_call",
            "from": owner,
            "to": "octPROG",
            "method": "create_tailnet",
            "params": ["ac".repeat(32)],
            "value": 2000u64,
            "fee": 10u64,
            "nonce": 0u64,
        });
        let r = rpc.submit(&create_tx).await.unwrap();
        let tx = rpc.transaction(&r.hash).await.unwrap();
        let tid = tx["events"]
            .as_array()
            .cloned()
            .unwrap()
            .into_iter()
            .find(|e| e["name"] == "TailnetCreated")
            .and_then(|e| e["tailnet_id"].as_str().map(String::from))
            .unwrap();

        // 3. Owner adds client as member.
        let add_member_tx = json!({
            "kind": "contract_call",
            "from": owner,
            "to": "octPROG",
            "method": "add_member",
            "params": [tid.clone(), client],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 1u64,
        });
        rpc.submit(&add_member_tx).await.unwrap();

        // 4. Owner configures the validator as a tailnet exit.
        let cfg_exit_tx = json!({
            "kind": "contract_call",
            "from": owner,
            "to": "octPROG",
            "method": "configure_tailnet_exit",
            "params": [tid.clone(), val],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 2u64,
        });
        rpc.submit(&cfg_exit_tx).await.unwrap();

        // 5. Active list shows the endpoint.
        let prog = Address::from_display("octPROG");
        let active = rpc
            .contract_call(
                &prog,
                "list_active_endpoints",
                &[json!(0u64), json!(50u64)],
                None,
            )
            .await
            .unwrap();
        let arr = active.as_array().unwrap();
        assert!(arr.iter().any(|v| v.as_str() == Some(val)));

        // 6. Open session (1 hop, 1000 OU deposit from treasury).
        let open_tx = json!({
            "kind": "contract_call",
            "from": client,
            "to": "octPROG",
            "method": "open_session",
            "params": [
                tid.clone(),
                ["aa".repeat(32)],
                "bb".repeat(32),
                1000u64,
            ],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        });
        let r = rpc.submit(&open_tx).await.unwrap();
        let tx = rpc.transaction(&r.hash).await.unwrap();
        let sid = tx["events"]
            .as_array()
            .cloned()
            .unwrap()
            .into_iter()
            .find(|e| e["name"] == "SessionOpened")
            .and_then(|e| e["session_id"].as_str().map(String::from))
            .unwrap();

        // 7. Settle: bytes_used=2 → pay = 200, refund = 800 back to treasury.
        let bytes_used = 2u64;
        let blind = earnings::fresh_blind();
        let blind_bytes = earnings::scalar_to_bytes(&blind);
        let settle_tx = json!({
            "kind": "contract_call",
            "from": client,
            "to": "octPROG",
            "method": "settle_session",
            "params": [
                sid.clone(),
                7u64,
                bytes_used,
                hex::encode(blind_bytes),
                "11".repeat(32),
                "22".repeat(32),
                [{ "node_addr": val, "blind": "11".repeat(32), "split_bps": 10000u16 }],
            ],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 1u64,
        });
        let r = rpc.submit(&settle_tx).await.unwrap();
        let tx = rpc.transaction(&r.hash).await.unwrap();
        let event = tx["events"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .find(|e| e["name"].as_str() == Some("SessionSettled"))
            .expect("settled event");
        assert_eq!(event["total_paid"].as_u64(), Some(200));
        assert_eq!(event["refund"].as_u64(), Some(800));

        // 8. Tailnet treasury: 2000 - 1000 + 800 = 1800.
        let tnet = rpc
            .contract_call(&prog, "get_tailnet", &[json!(tid)], None)
            .await
            .unwrap();
        assert_eq!(tnet["treasury"].as_u64(), Some(1800));

        // 9. Encrypted earnings: 200*G + blind*H.
        let earn = rpc
            .contract_call(&prog, "get_encrypted_earnings", &[json!(val)], None)
            .await
            .unwrap();
        let earn_hex = earn.as_str().unwrap();
        let scalar_200 = Scalar::from(200u64);
        let expected = &scalar_200 * RISTRETTO_BASEPOINT_TABLE + blind * h_generator();
        assert_eq!(hex::encode(expected.compress().to_bytes()), earn_hex);

        // 10. Claim earnings.
        let claim_tx = json!({
            "kind": "contract_call",
            "from": val,
            "to": "octPROG",
            "method": "claim_earnings",
            "params": [200u64, hex::encode(blind_bytes), "ee".repeat(32)],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 1u64,
        });
        let r = rpc.submit(&claim_tx).await.unwrap();
        let tx = rpc.transaction(&r.hash).await.unwrap();
        let has_claimed = tx["events"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .any(|e| e["name"].as_str() == Some("EarningsClaimed"));
        assert!(has_claimed);

        // 11. Earnings ledger is reset to identity.
        let earn = rpc
            .contract_call(&prog, "get_encrypted_earnings", &[json!(val)], None)
            .await
            .unwrap();
        assert_eq!(
            earn.as_str().unwrap(),
            hex::encode(RistrettoPoint::identity().compress().to_bytes())
        );
    }

    #[tokio::test]
    async fn no_show_refund_returns_to_treasury() {
        let _g = spawn_mock(18104, "octPROG").await;
        let rpc = RpcClient::new(mock_url(18104));
        let owner = "octOWNER0000000000000000000000000000NOSHO";
        let client = "octCLIENT0000000000000000000000000000NOSHO";

        // Create a tailnet with 100 OU treasury and add client.
        let create_tx = json!({
            "kind": "contract_call",
            "from": owner,
            "to": "octPROG",
            "method": "create_tailnet",
            "params": ["bb".repeat(32)],
            "value": 100u64,
            "fee": 10u64,
            "nonce": 0u64,
        });
        let r = rpc.submit(&create_tx).await.unwrap();
        let tx = rpc.transaction(&r.hash).await.unwrap();
        let tid = tx["events"]
            .as_array()
            .cloned()
            .unwrap()
            .into_iter()
            .find(|e| e["name"] == "TailnetCreated")
            .and_then(|e| e["tailnet_id"].as_str().map(String::from))
            .unwrap();

        let add_tx = json!({
            "kind": "contract_call",
            "from": owner,
            "to": "octPROG",
            "method": "add_member",
            "params": [tid.clone(), client],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 1u64,
        });
        rpc.submit(&add_tx).await.unwrap();

        // Client opens a session for 30 OU.
        let open_tx = json!({
            "kind": "contract_call",
            "from": client,
            "to": "octPROG",
            "method": "open_session",
            "params": [tid.clone(), ["00".repeat(32)], "11".repeat(32), 30u64],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        });
        let r = rpc.submit(&open_tx).await.unwrap();
        let tx = rpc.transaction(&r.hash).await.unwrap();
        let sid = tx["events"]
            .as_array()
            .cloned()
            .unwrap()
            .into_iter()
            .find(|e| e["name"] == "SessionOpened")
            .and_then(|e| e["session_id"].as_str().map(String::from))
            .unwrap();

        // No-show claim refunds to treasury.
        let claim_tx = json!({
            "kind": "contract_call",
            "from": client,
            "to": "octPROG",
            "method": "claim_no_show",
            "params": [sid],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 1u64,
        });
        let r = rpc.submit(&claim_tx).await.unwrap();
        let st = rpc.transaction(&r.hash).await.unwrap();
        let has_refunded = st["events"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .any(|e| e["name"].as_str() == Some("SessionRefunded"));
        assert!(has_refunded);

        // Treasury back to 100 (30 came out, 30 went back).
        let prog = Address::from_display("octPROG");
        let tnet = rpc
            .contract_call(&prog, "get_tailnet", &[json!(tid)], None)
            .await
            .unwrap();
        assert_eq!(tnet["treasury"].as_u64(), Some(100));
    }

    #[test]
    fn three_hop_onion_round_trip() {
        use rand::rngs::OsRng;
        let s1 = StaticSecret::random_from_rng(OsRng);
        let s2 = StaticSecret::random_from_rng(OsRng);
        let s3 = StaticSecret::random_from_rng(OsRng);
        let p1 = X25519Pub::from(&s1).to_bytes();
        let p2 = X25519Pub::from(&s2).to_bytes();
        let p3 = X25519Pub::from(&s3).to_bytes();

        let onion = build_onion(
            &[
                HopBuildInput { static_pubkey: p1, endpoint: "n1:51820".into() },
                HopBuildInput { static_pubkey: p2, endpoint: "n2:51820".into() },
                HopBuildInput { static_pubkey: p3, endpoint: "n3:51820".into() },
            ],
            b"final-payload",
        )
        .unwrap();

        let l1 = peel_layer(&s1, &onion).unwrap();
        let HopAction::Forward { endpoint, next_static_pubkey } = l1.action.clone() else {
            panic!("hop1 must forward")
        };
        assert_eq!(endpoint, "n2:51820");
        assert_eq!(next_static_pubkey, p2);

        let l2 = peel_layer(&s2, &l1.inner).unwrap();
        let HopAction::Forward { endpoint, .. } = l2.action.clone() else {
            panic!("hop2 must forward")
        };
        assert_eq!(endpoint, "n3:51820");

        let l3 = peel_layer(&s3, &l2.inner).unwrap();
        assert_eq!(l3.action, HopAction::Egress);
        assert_eq!(l3.inner, b"final-payload");
    }

    #[test]
    fn pedersen_commitment_route_hiding() {
        let v = Address::from_display("octVALIDATOR");
        let b1 = commit::fresh_blind();
        let b2 = commit::fresh_blind();
        let c1 = commit::commit(&v, &b1);
        let c2 = commit::commit(&v, &b2);
        assert_ne!(c1, c2);
        assert!(commit::verify_open(&c1, &commit::Opening { addr: v.clone(), blind: b1 }));
        assert!(commit::verify_open(&c2, &commit::Opening { addr: v, blind: b2 }));
    }

    #[test]
    fn dual_signed_receipt_round_trip() {
        use octravpn_core::session::Blind;
        let client = KeyPair::generate();
        let node = KeyPair::generate();
        let r = Receipt {
            session_id: SessionId::new([1u8; 32]),
            seq: 5,
            bytes_used: 1024,
            blind: Blind::new([9u8; 32]),
        };
        let sr = SignedReceipt::build(r, &client, &node);
        sr.verify().unwrap();
    }
}
