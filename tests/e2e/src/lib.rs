//! End-to-end tests against the in-process mock chain + control plane.
//!
//! Covers:
//!   - register / attest / list active validators
//!   - open session, settle with dual-signed receipt, claim earnings
//!   - no-show refund path
//!   - 3-hop onion build/peel round-trip (wired separately, no chain needed)

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

    #[tokio::test]
    async fn node_status_round_trip() {
        let _g = spawn_mock(18101, "octPROG").await;
        let rpc = RpcClient::new(mock_url(18101));
        let s = rpc.node_status().await.unwrap();
        assert!(s.epoch >= 1);
    }

    #[tokio::test]
    async fn full_lifecycle_register_attest_open_settle_claim() {
        let _g = spawn_mock(18102, "octPROG").await;
        let rpc = RpcClient::new(mock_url(18102));

        // 1. Register a validator (single hop for the simple path).
        let val = "octV1Address0000000000000000000000000001";
        let register_tx = json!({
            "kind": "contract_call",
            "from": val,
            "to": "octPROG",
            "method": "register_validator",
            "params": [
                "1.2.3.4:51820",
                "deadbeef".repeat(8),       // wg_pubkey
                "cafe".repeat(16),          // view_pubkey
                "eu-west",
                100u64,                     // price_per_mb
                "f00d".repeat(32),          // attest_sig
            ],
            "value": 1_000u64,
            "fee": 10u64,
            "nonce": 0u64,
        });
        rpc.submit(&register_tx).await.unwrap();

        // 2. Refresh attestation.
        let attest_tx = json!({
            "kind": "contract_call",
            "from": val,
            "to": "octPROG",
            "method": "refresh_attestation",
            "params": ["abcd".repeat(32)],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 1u64,
        });
        rpc.submit(&attest_tx).await.unwrap();

        // 3. Active list shows the validator.
        let prog = Address::from_display("octPROG");
        let active = rpc
            .contract_call(&prog, "list_active_validators", &[json!(0u64), json!(50u64)], None)
            .await
            .unwrap();
        let arr = active.as_array().unwrap();
        assert!(arr.iter().any(|v| v.as_str() == Some(val)));

        // 4. Open session (1 hop).
        let client = "octCLIENT00000000000000000000000000000001";
        let open_tx = json!({
            "kind": "contract_call",
            "from": client,
            "to": "octPROG",
            "method": "open_session",
            "params": [
                ["aa".repeat(32)],
                "bb".repeat(32),
                "cc".repeat(32),
            ],
            "value": 1_000u64,
            "fee": 10u64,
            "nonce": 0u64,
        });
        let r = rpc.submit(&open_tx).await.unwrap();
        let tx = rpc.transaction(&r.hash).await.unwrap();
        let sid = tx.get("events").and_then(|v| v.as_array()).cloned().unwrap()
            .into_iter().find(|e| e["name"] == "SessionOpened")
            .and_then(|e| e["session_id"].as_str().map(String::from)).unwrap();

        // 5. Settle: bytes_used=2 → pay = 2 * 100 * 10000 / 10000 = 200.
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
                "11".repeat(32),  // client_sig (mock doesn't verify)
                "22".repeat(32),  // node_sig (mock doesn't verify)
                [{ "node_addr": val, "blind": "11".repeat(32), "split_bps": 10000u16 }],
            ],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 1u64,
        });
        let r = rpc.submit(&settle_tx).await.unwrap();
        let tx = rpc.transaction(&r.hash).await.unwrap();
        let names: Vec<_> = tx["events"].as_array().cloned().unwrap_or_default()
            .into_iter().filter_map(|e| e["name"].as_str().map(String::from)).collect();
        assert!(names.contains(&"SessionSettled".to_string()));

        // 6. Read encrypted earnings: must equal 200*G + blind*H.
        let earn = rpc
            .contract_call(&prog, "get_encrypted_earnings", &[json!(val)], None)
            .await
            .unwrap();
        let earn_hex = earn.as_str().unwrap();
        let earn_bytes = hex::decode(earn_hex).unwrap();
        let scalar_200 = Scalar::from(200u64);
        let expected = &scalar_200 * RISTRETTO_BASEPOINT_TABLE + blind * h_generator();
        assert_eq!(hex::encode(expected.compress().to_bytes()), earn_hex);

        // 7. Claim earnings: 200 OCT, opening = (200, blind).
        let claim_tx = json!({
            "kind": "contract_call",
            "from": val,
            "to": "octPROG",
            "method": "claim_earnings",
            "params": [200u64, hex::encode(blind_bytes), "ee".repeat(32)],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 2u64,
        });
        let r = rpc.submit(&claim_tx).await.unwrap();
        let tx = rpc.transaction(&r.hash).await.unwrap();
        let names: Vec<_> = tx["events"].as_array().cloned().unwrap_or_default()
            .into_iter().filter_map(|e| e["name"].as_str().map(String::from)).collect();
        assert!(names.contains(&"EarningsClaimed".to_string()));

        // 8. Earnings ledger is reset to identity.
        let earn = rpc
            .contract_call(&prog, "get_encrypted_earnings", &[json!(val)], None)
            .await
            .unwrap();
        assert_eq!(
            earn.as_str().unwrap(),
            hex::encode(RistrettoPoint::identity().compress().to_bytes())
        );
        let _ = earn_bytes; // keep the let alive
    }

    #[tokio::test]
    async fn three_hop_session_lifecycle() {
        let _g = spawn_mock(18103, "octPROG").await;
        let rpc = RpcClient::new(mock_url(18103));
        let prog = Address::from_display("octPROG");

        // Register 3 validators with distinct prices.
        let addrs = [
            "octHOPaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa01",
            "octHOPbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb02",
            "octHOPccccccccccccccccccccccccccccccccccc03",
        ];
        let prices = [100u64, 150u64, 200u64];
        for (i, addr) in addrs.iter().enumerate() {
            let tx = json!({
                "kind": "contract_call",
                "from": addr,
                "to": "octPROG",
                "method": "register_validator",
                "params": [
                    format!("10.0.0.{}:51820", i + 10),
                    format!("{:02x}", i + 1).repeat(32),
                    format!("{:02x}", i + 1).repeat(32),
                    "global",
                    prices[i],
                    format!("{:02x}", i + 1).repeat(64),
                ],
                "value": 1_000u64,
                "fee": 10u64,
                "nonce": 0u64,
            });
            rpc.submit(&tx).await.unwrap();
        }

        // Open 3-hop session.
        let client = "octCLIENT00000000000000000000000000000099";
        let route_commit = ["aa".repeat(32), "bb".repeat(32), "cc".repeat(32)];
        let open_tx = json!({
            "kind": "contract_call",
            "from": client,
            "to": "octPROG",
            "method": "open_session",
            "params": [
                route_commit,
                "dd".repeat(32),
                "ee".repeat(32),
            ],
            "value": 5_000u64,
            "fee": 10u64,
            "nonce": 0u64,
        });
        let r = rpc.submit(&open_tx).await.unwrap();
        let tx = rpc.transaction(&r.hash).await.unwrap();
        let sid = tx["events"].as_array().cloned().unwrap()
            .into_iter().find(|e| e["name"] == "SessionOpened")
            .and_then(|e| e["session_id"].as_str().map(String::from)).unwrap();

        // Settle: bytes_used=3, even split (3333/3333/3334).
        let blind = earnings::fresh_blind();
        let blind_hex = hex::encode(earnings::scalar_to_bytes(&blind));
        let settle_tx = json!({
            "kind": "contract_call",
            "from": client,
            "to": "octPROG",
            "method": "settle_session",
            "params": [
                sid,
                1u64,
                3u64,
                blind_hex,
                "11".repeat(32),
                "22".repeat(32),
                [
                    { "node_addr": addrs[0], "blind": "11".repeat(32), "split_bps": 3333u16 },
                    { "node_addr": addrs[1], "blind": "22".repeat(32), "split_bps": 3333u16 },
                    { "node_addr": addrs[2], "blind": "33".repeat(32), "split_bps": 3334u16 },
                ],
            ],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 1u64,
        });
        let r = rpc.submit(&settle_tx).await.unwrap();
        let st = rpc.transaction(&r.hash).await.unwrap();
        // total_paid = 3 * (100*3333 + 150*3333 + 200*3334) / 10000 = 174.99 → integer truncation
        // (100*3333 + 150*3333 + 200*3334)/10000 = (333300 + 499950 + 666800)/10000 = 150 (integer floor)
        // * 3 = 450
        let total_paid = st["events"][0]["total_paid"].as_u64().unwrap();
        assert!(total_paid > 0);
        let refund = st["events"][0]["refund"].as_u64().unwrap();
        assert_eq!(refund, 5000u64 - total_paid);
    }

    #[tokio::test]
    async fn no_show_refund_path() {
        let _g = spawn_mock(18104, "octPROG").await;
        let rpc = RpcClient::new(mock_url(18104));

        let client = "octCLIENT0000000000000000000000000000NOSHO";
        let open_tx = json!({
            "kind": "contract_call",
            "from": client,
            "to": "octPROG",
            "method": "open_session",
            "params": [["00".repeat(32)], "11".repeat(32), "22".repeat(32)],
            "value": 30u64,
            "fee": 10u64,
            "nonce": 0u64,
        });
        let r = rpc.submit(&open_tx).await.unwrap();
        let tx = rpc.transaction(&r.hash).await.unwrap();
        let sid = tx["events"].as_array().cloned().unwrap()
            .into_iter().find(|e| e["name"] == "SessionOpened")
            .and_then(|e| e["session_id"].as_str().map(String::from)).unwrap();

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
        let names: Vec<_> = st["events"].as_array().cloned().unwrap_or_default()
            .into_iter().filter_map(|e| e["name"].as_str().map(String::from)).collect();
        assert!(names.contains(&"SessionRefunded".to_string()));
    }

    #[test]
    fn three_hop_onion_round_trip() {
        // Real onion build + 3-hop peel.
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
        let HopAction::Forward { endpoint, next_static_pubkey } = l1.action.clone()
        else { panic!("hop1 must forward") };
        assert_eq!(endpoint, "n2:51820");
        assert_eq!(next_static_pubkey, p2);

        let l2 = peel_layer(&s2, &l1.inner).unwrap();
        let HopAction::Forward { endpoint, .. } = l2.action.clone()
        else { panic!("hop2 must forward") };
        assert_eq!(endpoint, "n3:51820");

        let l3 = peel_layer(&s3, &l2.inner).unwrap();
        assert_eq!(l3.action, HopAction::Egress);
        assert_eq!(l3.inner, b"final-payload");
    }

    #[test]
    fn pedersen_commitment_route_hiding() {
        // Two clients commit to the same validator with different blinds —
        // commitments must differ but both open correctly.
        let v = Address::from_display("octVALIDATOR");
        let b1 = commit::fresh_blind();
        let b2 = commit::fresh_blind();
        let c1 = commit::commit(&v, &b1);
        let c2 = commit::commit(&v, &b2);
        assert_ne!(c1, c2);
        assert!(commit::verify_open(
            &c1,
            &commit::Opening { addr: v.clone(), blind: b1 }
        ));
        assert!(commit::verify_open(
            &c2,
            &commit::Opening { addr: v, blind: b2 }
        ));
    }

    #[test]
    fn dual_signed_receipt_round_trip() {
        let client = KeyPair::generate();
        let node = KeyPair::generate();
        let r = Receipt {
            session_id: SessionId([1u8; 32]),
            seq: 5,
            bytes_used: 1024,
            blind: [9u8; 32],
        };
        let sr = SignedReceipt::build(r, &client, &node);
        sr.verify().unwrap();
    }
}
