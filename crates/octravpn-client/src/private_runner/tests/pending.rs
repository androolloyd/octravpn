use super::*;

#[tokio::test]
async fn offline_pending_checks_held_state_and_never_contacts_unfunded_operator() {
    let (mut plan, key, operator) = crate::payments::private::tests::plan();
    let publisher = Arc::new(Publisher::new(plan.clone(), operator, false));
    let tls = Tls::serve(publisher.clone(), &mut plan).await;
    let root = tempfile::tempdir().unwrap();
    let journal = root.path().join("pending");
    let options = |mode| Options {
        plan: plan.clone(),
        journal: journal.clone(),
        receipt_key: key.clone(),
        interface_name: "octpending0".into(),
        mode,
    };
    let pending = Pending::new(options(OpenMode::Create)).await.unwrap();
    pending.check().await.unwrap();
    assert_eq!(pending.0.connect.request.sequence, 1);
    assert_eq!(publisher.calls.load(Ordering::SeqCst), 0);
    drop(pending);
    let pending = Pending::new(options(OpenMode::Resume)).await.unwrap();
    assert_eq!(pending.0.connect.request.sequence, 2);
    pending.check().await.unwrap();
    std::fs::remove_file(journal.join("state.json")).unwrap();
    assert!(pending.check().await.is_err());
    drop(pending);
    assert!(Pending::new(options(OpenMode::Resume)).await.is_err());
    assert!(Pending::new(options(OpenMode::Create)).await.is_err());
    assert!(!journal.join("state.json").exists());
    assert_eq!(publisher.calls.load(Ordering::SeqCst), 0);
    tls.close().await;
}

#[tokio::test]
async fn pending_hop_preflights_pins_tls_position_and_mtu_before_creating_state() {
    let (mut plan, key, _) = crate::payments::private::tests::plan();
    let cert = rcgen::generate_simple_self_signed(vec!["operator.invalid".into()]).unwrap();
    plan.control_url = "https://operator.invalid:443/".into();
    plan.control_ca_pem = cert.cert.pem();
    plan.control_spki =
        vec![octravpn_core::spki_verifier::SpkiPinVerifier::fingerprint(cert.cert.der()).unwrap()];
    plan.wireguard_endpoint = "8.8.4.4:51820".into();
    let root = tempfile::tempdir().unwrap();
    let options = |mode| Options {
        plan: plan.clone(),
        journal: root.path().join("hop"),
        receipt_key: key.clone(),
        interface_name: "octpending1".into(),
        mode,
    };
    let pins = crate::MultiRoutePins {
        wireguard: "8.8.4.4:51820".parse().unwrap(),
        control: "8.8.4.4:443".parse().unwrap(),
    };
    for change in 0..7 {
        let mut options = options(OpenMode::Create);
        let mut pins = pins;
        let mut position = 1;
        let mut count = 2;
        match change {
            0 => pins.control = "127.0.0.1:443".parse().unwrap(),
            1 => pins.wireguard.set_port(9),
            2 => options.plan.control_spki.clear(),
            3 => options.plan.control_ca_pem = "invalid certificate".into(),
            4 => position = 2,
            5 => count = 1,
            _ => options.interface_name = "tailscale0".into(),
        }
        assert!(
            Pending::for_hop(options, pins, position, count)
                .await
                .is_err(),
            "mutation {change}"
        );
        assert!(!root.path().join("hop").exists());
    }
    let pending = Pending::for_hop(options(OpenMode::Create), pins, 1, 2)
        .await
        .unwrap();
    assert_eq!(pending.0.mtu, 1075);
    assert_eq!(pending.0.connect.request.sequence, 1);
    pending.check().await.unwrap();
    drop(pending);
    let pending = Pending::for_hop(options(OpenMode::Resume), pins, 1, 2)
        .await
        .unwrap();
    assert_eq!(pending.0.connect.request.sequence, 2);
    pending.check().await.unwrap();
}
