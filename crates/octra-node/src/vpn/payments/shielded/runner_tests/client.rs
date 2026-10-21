//! The route phase is exercised inside the real signed-QC purchase fixture.
use super::*;
use crate::vpn::payments::shielded::payer::runner::client::Prepared;

pub(super) async fn prepare(purchase: &Purchase, transport: &Transport) -> Prepared {
    for change in 0..5 {
        let mut bad = transport.clone();
        match change {
            0 => bad.plan.prepaid_bytes[0] += 1,
            1 => bad.plan.binding.plan += 1,
            2 => bad.journal = "relative-client-state".into(),
            3 => bad.interface_name = "bad/name".into(),
            _ => bad.plan.control_spki.clear(),
        }
        assert!(
            purchase.prepare_client(bad).await.is_err(),
            "mutation {change}"
        );
        assert!(!transport.journal.exists());
    }
    // A cancelled preparation may leave incomplete local state, but Create
    // cannot silently adopt it. No quote, payment or transport was admitted.
    std::fs::create_dir(&transport.journal).unwrap();
    assert!(purchase.prepare_client(transport.clone()).await.is_err());
    std::fs::remove_dir(&transport.journal).unwrap();
    let prepared = purchase.prepare_client(transport.clone()).await.unwrap();
    assert!(transport.journal.join("state.json").exists());
    assert!(serde_json::from_slice::<serde_json::Value>(
        &std::fs::read(transport.journal.join("state.json")).unwrap()
    )
    .is_err());
    // Neither a recorded channel nor an offline client sequence proves money.
    let error = prepared.admit().await.err().unwrap();
    assert!(error.to_string().contains("canonical payment step"));
    for change in 0..3 {
        let mut bad = transport.clone();
        match change {
            0 => bad.interface_name = "octchanged".into(),
            1 => bad.journal = transport.journal.with_file_name("new-client-state"),
            _ => bad.plan.wireguard_endpoint = "127.0.0.1:8".into(),
        }
        assert!(
            purchase.prepare_client(bad).await.is_err(),
            "saved mutation {change}"
        );
    }
    purchase.prepare_client(transport.clone()).await.unwrap()
}
