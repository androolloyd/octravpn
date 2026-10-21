//! Same-channel class purchases in the signed-QC native scenario, including
//! partial funding, ambiguous receipt delivery and encrypted cold resume.
use super::*;
use crate::vpn::payments::shielded::payer::runner::client::Prepared;
use octravpn_core::payments::Tariff;

pub(super) fn consent(terms: &Terms, tariff: &Tariff) {
    let encoded = serde_json::to_vec(terms).unwrap();
    let mut old: Value = serde_json::from_slice(&encoded).unwrap();
    assert!(old.get("additional").is_none());
    let legacy: Terms = serde_json::from_value(old.clone()).unwrap();
    assert!(legacy == *terms);
    assert_eq!(serde_json::to_vec(&legacy).unwrap(), encoded);
    old["additional"] = json!([]);
    assert_eq!(
        serde_json::to_vec(&serde_json::from_value::<Terms>(old).unwrap()).unwrap(),
        encoded
    );
    for mutation in 0..6 {
        let mut bad = terms.clone();
        bad.additional.push(Allowance {
            traffic_class: 1,
            bytes: 4096,
            max_cost_ou: tariff.charge(1, 4096).unwrap(),
        });
        match mutation {
            0 => bad.additional[0].traffic_class = bad.traffic_class,
            1 => bad.additional[0].bytes = 0,
            2 => bad.additional[0].max_cost_ou = bad.ceiling_ou,
            3 => bad.additional[0].traffic_class = octravpn_core::payments::MAX_CLASSES as u8,
            4 => bad.additional[0].max_cost_ou = 0,
            _ => bad.additional = vec![bad.additional[0]; octravpn_core::payments::MAX_CLASSES],
        }
        assert!(
            bad.prepaid(tariff).is_err(),
            "bundle consent mutation {mutation}"
        );
    }
}

pub(super) async fn finish(
    fixture: &mut Fixture,
    payer: &Payer,
    purchase: &Purchase,
    transport: &Transport,
    mut prepared: Prepared,
    control: &Control,
    services: Services<'_, Authority>,
) -> Prepared {
    let drive = || Services {
        control,
        ..services
    };
    assert!(matches!(
        prepared.step(drive()).await.unwrap(),
        State::ClassCredited { traffic_class: 0 }
    ));
    let fees = payer
        .reserved_fees(&purchase.terms().relayer_public)
        .await
        .unwrap();
    assert!(!prepared.resume_credit().await.unwrap());
    assert!(prepared.admit().await.is_err());
    let mut bad = transport.clone();
    bad.plan.prepaid_bytes[1] = 0;
    assert!(purchase.prepare_client(bad).await.is_err());
    let mut prepared = purchase.prepare_client(transport.clone()).await.unwrap();
    // An operator-signed quote for a paid class cannot substitute for the
    // independently accepted second class or consume a new relayer fee.
    control.fault.store(4, Ordering::SeqCst);
    assert!(prepared.step(drive()).await.is_err());
    assert_eq!(
        payer
            .reserved_fees(&purchase.terms().relayer_public)
            .await
            .unwrap(),
        fees
    );
    assert!(matches!(
        prepared.step(drive()).await.unwrap(),
        State::Quoted
    ));
    let State::Submitted { hash } = prepared.step(drive()).await.unwrap() else {
        panic!("second class was not staged");
    };
    let reserved = payer
        .reserved_fees(&purchase.terms().relayer_public)
        .await
        .unwrap();
    assert_eq!(reserved, fees + payment_host::FEE);
    drop(prepared);
    let resumed = Purchase::resume(payer.clone(), purchase.id())
        .await
        .unwrap();
    let mut prepared = resumed.prepare_client(transport.clone()).await.unwrap();
    assert!(!prepared.resume_credit().await.unwrap());
    assert!(
        matches!(prepared.step(drive()).await.unwrap(), State::Submitted { hash: same } if same == hash)
    );
    assert_eq!(
        payer
            .reserved_fees(&purchase.terms().relayer_public)
            .await
            .unwrap(),
        reserved
    );
    let transaction = services
        .submission
        .pending
        .transactions()
        .unwrap()
        .into_iter()
        .find(|transaction| hex::encode(transaction.hash().unwrap()) == hash)
        .expect("second class native transaction missing");
    fixture.publish(vec![transaction]).await;
    control.fault.store(3, Ordering::SeqCst);
    assert!(prepared.step(drive()).await.is_err());
    control.fault.store(1, Ordering::SeqCst);
    assert!(prepared.step(drive()).await.is_err());
    drop(prepared);
    let mut prepared = resumed.prepare_client(transport.clone()).await.unwrap();
    assert!(matches!(
        prepared.step(drive()).await.unwrap(),
        State::Credited { .. }
    ));
    let requests = control.calls.lock().unwrap().len();
    assert!(prepared.resume_credit().await.unwrap());
    assert_eq!(control.calls.lock().unwrap().len(), requests);
    assert_eq!(
        payer
            .reserved_fees(&purchase.terms().relayer_public)
            .await
            .unwrap(),
        reserved
    );
    let receipt = resumed.receipt_identity().unwrap().public;
    let calls = control.calls.lock().unwrap();
    let channel = transport.plan.binding.plan;
    let class_quotes: Vec<_> = calls.iter().filter(|(request, _)| {
        matches!(request.request.action, PrivateAction::Quote { channel: got, .. } if got == channel)
    }).collect();
    assert_eq!(class_quotes.len(), 3);
    assert_ne!(class_quotes[0].0.request.id, class_quotes[1].0.request.id);
    assert_eq!(
        class_quotes[1].0.digest().unwrap(),
        class_quotes[2].0.digest().unwrap()
    );
    assert!(class_quotes
        .iter()
        .all(|(request, _)| request.receipt_key == receipt));
    assert_eq!(
        calls
            .iter()
            .filter(|(request, _)| request.receipt_key == receipt
                && matches!(request.request.action, PrivateAction::Open { .. }))
            .count(),
        1
    );
    prepared
}
