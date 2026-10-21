//! Recover original operator credentials and exclusive assignments after a
//! genuine checkpoint import. Current ownership never substitutes for credit.
use super::*;
use crate::vpn::payments::shielded::{
    payer::{
        movement::{Prepared, Window},
        native::{FeePolicy, Operation},
        Payer,
    },
    wallet::Wallet,
};
use octra_private_payments_experimental::pool::transaction::Prover;
use octravpn_core::sealed::Key;
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::path::Path;

async fn customer_image(path: &Path) -> [u8; 32] {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            sqlx::sqlite::SqliteConnectOptions::new()
                .filename(path.join("wallet.sqlite"))
                .read_only(true),
        )
        .await
        .unwrap();
    let rows = sqlx::query(
        "SELECT kind,tag,bucket,value FROM wallet_records WHERE kind<>5 ORDER BY kind,tag",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    let mut hash = Sha256::new();
    for row in rows {
        hash.update(row.get::<i64, _>("kind").to_be_bytes());
        for name in ["tag", "bucket", "value"] {
            let bytes: Vec<u8> = row.get(name);
            hash.update(u64::try_from(bytes.len()).unwrap().to_be_bytes());
            hash.update(bytes);
        }
    }
    pool.close().await;
    hash.finalize().into()
}
fn window(fixture: &Fixture) -> Window {
    Window {
        valid_from_ms: millis(fixture),
        expires_ms: millis(fixture) + 120_000,
        relayer: address(&payment_host::address(12)),
    }
}
async fn commit(
    fixture: &mut Fixture,
    payer: &Payer,
    index: PoolIndex,
    prepared: &Prepared,
    policy: FeePolicy,
) -> PoolIndex {
    let signed = payer
        .sign_native(
            Operation::Movement(prepared.id),
            &index,
            &payment_host::key(12),
            policy,
        )
        .await
        .unwrap();
    let rpc = super::super::rpc_admission::Rpc::open(fixture, fixture.native.clone()).await;
    payer
        .broadcast(&rpc.submission, &signed, &index)
        .await
        .unwrap();
    assert!(payer.confirmed_native(&signed).await.unwrap().is_none());
    let next = index.observe(&prepared.statement().unwrap()).unwrap();
    fixture.publish(rpc.pending.transactions().unwrap()).await;
    rpc.close().await;
    assert!(payer
        .reconcile_native(&signed, &next)
        .await
        .unwrap()
        .is_some());
    next
}
pub(super) async fn run(
    fixture: &mut Fixture,
    journal_root: &Path,
    source: Arc<Pool>,
    config: shielded::Config,
    pk: Arc<ProvingKey<Bn254>>,
    mut index: PoolIndex,
) {
    let a_path = journal_root.join("private-wallet");
    let b_path = journal_root.join("second-operator-wallet");
    let payer_path = journal_root.join("operator-payer");
    let a_image = customer_image(&a_path).await;
    let b_image = customer_image(&b_path).await;
    let a = Wallet::resume(&a_path, Key::from_bytes([83; 32]), source.clone())
        .await
        .unwrap();
    let mut directory = fixture.payments().config;
    directory.offer = 1;
    let b_source = Arc::new(
        Pool::new(
            Arc::new(
                fixture
                    .node
                    .payments(
                        directory,
                        parse_native_address(&payment_host::address(12)).unwrap(),
                    )
                    .unwrap(),
            ),
            config,
        )
        .unwrap(),
    );
    let b = Wallet::resume(&b_path, Key::from_bytes([94; 32]), b_source.clone())
        .await
        .unwrap();
    let payer = Payer::resume(&payer_path, Key::from_bytes([93; 32]), b_source.clone())
        .await
        .unwrap();
    assert!(payer.available_ou(&index).await.is_err());
    assert!(payer
        .attach_income(&a, &PoolIndex::default())
        .await
        .is_err());
    assert_eq!(payer.attach_income(&a, &index).await.unwrap(), 0);
    // The scheduler assigned B income as well. A alone cannot unlock those
    // notes after a cold reopen, even when every credit is canonically retained.
    assert!(payer.available_ou(&index).await.is_err());
    assert_eq!(
        payer
            .reserved_fees(&payment_host::key(11).verifying_key().to_bytes())
            .await
            .unwrap(),
        2 * payment_host::FEE
    );
    assert_eq!(
        payer
            .reserved_fees(&payment_host::key(13).verifying_key().to_bytes())
            .await
            .unwrap(),
        payment_host::FEE
    );

    // The scheduler already assigned B's purchased notes. Only the later 1 OU
    // receipt is new to this book; spent and assigned receipts add no value.
    let b_ids = b.income_ids().await.unwrap();
    assert_eq!(b_ids.len(), 3);
    let mut newly_assigned = Vec::new();
    for id in &b_ids {
        if payer.claim_income(&b, *id, &index).await.unwrap() {
            newly_assigned.push(*id);
        }
        assert!(!payer.claim_income(&b, *id, &index).await.unwrap());
    }
    assert_eq!(newly_assigned.len(), 1);
    assert_eq!(payer.available_ou(&index).await.unwrap(), 87);
    assert_eq!(payer.attach_income(&b, &index).await.unwrap(), 0);
    for wallet in [&a, &b] {
        assert!(wallet.channel(1).await.unwrap().paid_ou > 0);
    }
    let foreign = Payer::create(
        &fixture.directory.path().join("foreign-income-book"),
        Key::from_bytes([201; 32]),
        source.clone(),
    )
    .await
    .unwrap();
    assert_eq!(foreign.attach_income(&a, &index).await.unwrap(), 0);
    assert_eq!(foreign.attach_income(&b, &index).await.unwrap(), 0);
    assert!(foreign
        .claim_income(&b, newly_assigned[0], &index)
        .await
        .unwrap_err()
        .to_string()
        .contains("another payer book"));
    assert_eq!(foreign.available_ou(&index).await.unwrap(), 0);
    drop(foreign);

    let notes = payer.available_notes(&index).await.unwrap();
    let own = notes.iter().find(|n| n.value_ou == 15).unwrap().commitment;
    let earned = notes.iter().find(|n| n.value_ou == 10).unwrap().commitment;
    let prover = Prover::new(pk.clone(), &wire::key(&pk.vk).unwrap()).unwrap();
    let prepared = payer
        .consolidate([202; 32], [own, earned], window(fixture), &index, &prover)
        .await
        .unwrap();
    assert_eq!(payer.available_ou(&index).await.unwrap(), 62);
    let policy = FeePolicy {
        fee_ou: payment_host::FEE,
        lifetime_budget_ou: 3 * payment_host::FEE,
        max_attempts: 3,
    };
    let signed = payer
        .sign_native(
            Operation::Movement(prepared.id),
            &index,
            &payment_host::key(12),
            policy,
        )
        .await
        .unwrap();
    drop(payer);
    drop(a);
    drop(b);
    let payer = Payer::resume(&payer_path, Key::from_bytes([93; 32]), b_source.clone())
        .await
        .unwrap();
    assert!(payer.available_ou(&index).await.is_err());
    let a = Wallet::resume(&a_path, Key::from_bytes([83; 32]), source)
        .await
        .unwrap();
    let b = Wallet::resume(&b_path, Key::from_bytes([94; 32]), b_source.clone())
        .await
        .unwrap();
    assert_eq!(payer.attach_income(&a, &index).await.unwrap(), 0);
    assert!(payer.available_ou(&index).await.is_err());
    assert_eq!(payer.attach_income(&b, &index).await.unwrap(), 0);
    assert_eq!(payer.available_ou(&index).await.unwrap(), 62);
    assert_eq!(
        payer
            .sign_native(
                Operation::Movement(prepared.id),
                &index,
                &payment_host::key(12),
                policy
            )
            .await
            .unwrap()
            .transaction(),
        signed.transaction()
    );
    index = Box::pin(commit(fixture, &payer, index, &prepared, policy)).await;
    assert_eq!(payer.available_ou(&index).await.unwrap(), 87);

    // The smallest exact 10 OU input is now another pre-floor earned note.
    let withdrawal = payer
        .prepare_withdrawal(
            [203; 32],
            10,
            address(&payment_host::address(13)),
            window(fixture),
            &index,
            &prover,
        )
        .await
        .unwrap();
    assert!(withdrawal.output_slot().is_none());
    assert_eq!(payer.available_ou(&index).await.unwrap(), 77);
    assert_eq!(
        payer
            .reserved_fees(&payment_host::key(13).verifying_key().to_bytes())
            .await
            .unwrap(),
        payment_host::FEE
    );
    index = Box::pin(commit(fixture, &payer, index, &withdrawal, policy)).await;
    assert_eq!(payer.available_ou(&index).await.unwrap(), 77);
    assert_eq!(
        payer
            .reserved_fees(&payment_host::key(12).verifying_key().to_bytes())
            .await
            .unwrap(),
        2 * payment_host::FEE
    );
    assert_eq!(customer_image(&a_path).await, a_image);
    assert_eq!(customer_image(&b_path).await, b_image);
    drop(payer);
    drop(a);
    drop(b);
    let payer = Payer::resume(&payer_path, Key::from_bytes([93; 32]), b_source.clone())
        .await
        .unwrap();
    assert!(payer.available_ou(&index).await.is_err());
    let b = Wallet::resume(&b_path, Key::from_bytes([94; 32]), b_source)
        .await
        .unwrap();
    assert_eq!(payer.attach_income(&b, &index).await.unwrap(), 0);
    assert_eq!(payer.available_ou(&index).await.unwrap(), 77);
    assert_eq!(
        payer
            .reserved_fees(&payment_host::key(11).verifying_key().to_bytes())
            .await
            .unwrap(),
        2 * payment_host::FEE
    );
    assert_eq!(
        payer
            .reserved_fees(&payment_host::key(12).verifying_key().to_bytes())
            .await
            .unwrap(),
        2 * payment_host::FEE
    );
}
