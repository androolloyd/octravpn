//! Recover the public index from actual retained native history, including a
//! nested Circle withdrawal whose calldata is opaque to the outer transaction.
use super::*;
use crate::vpn::payments::shielded::index::{Index, Limits as IndexLimits};
use octravpn_core::sealed::Key;

async fn caught_up(index: &Index) {
    for _ in 0..16 {
        if index.sync(128).await.unwrap().complete {
            return;
        }
    }
    panic!("bounded local fixture index failed to catch up");
}
async fn relay(fixture: &mut Fixture, pool: &str) -> String {
    let source = format!(
        r#"program PrivateIndexRelay {{
      fn forward(n: string, s: string, c: uint, w: uint, p: address, a: uint, b: uint,
        q: string, t: string, n0: string, n1: string, o0: string, o1: string,
        e0: string, e1: string, z: string): string {{
        return call("{pool}", "exchange", [n,s,c,w,p,a,b,q,t,n0,n1,o0,o1,e0,e1,z])
      }}
    }}"#
    );
    let payload = crate::vpn::payments::circle_tests::payload(&compiled(&source));
    let parsed = octra_node_protocol::circle_program::Deploy::from_document(
        &octra_node_protocol::native_json::Document::parse(&serde_json::to_vec(&payload).unwrap())
            .unwrap(),
    )
    .unwrap();
    let account = account_store::load(
        &StateBatch::from_snapshot(fixture.node.snapshot().unwrap().state().clone()),
        payment_host::address(11).as_bytes(),
    )
    .unwrap()
    .unwrap();
    let address = String::from_utf8(parsed.id(
        payment_host::address(11).as_bytes(),
        account.nonce.successor(),
    ))
    .unwrap();
    let tx = fixture.transaction(11, &address, OpType::CircleDeploy, payload, 0, vec![]);
    fixture.publish(vec![tx]).await;
    address
}
pub(super) struct Recovery {
    pub index: PoolIndex,
    pub updates: u64,
}

pub(super) async fn run(
    fixture: &mut Fixture,
    source: Arc<Pool>,
    pk: Arc<ProvingKey<Bn254>>,
    mut expected: PoolIndex,
) -> Recovery {
    let path = fixture.directory.path().join("canonical-private-index");
    let key = Key::from_bytes([171; 32]);
    let index = Index::create(&path, key.clone(), source.clone(), IndexLimits::default())
        .await
        .unwrap();
    assert!(index.view().await.is_err());
    assert!(index.sync(0).await.is_err());
    let partial = index.sync(1).await.unwrap();
    assert_eq!(partial.processed, 1);
    assert!(!partial.complete && partial.epoch < partial.target);
    assert!(index.view().await.is_err());
    index.close().await;
    assert!(
        Index::resume(&path, Key::from_bytes([172; 32]), source.clone())
            .await
            .is_err()
    );
    let index = Index::resume(&path, key.clone(), source.clone())
        .await
        .unwrap();
    caught_up(&index).await;
    let first = index.view().await.unwrap();
    assert_eq!(first.index().roots(), expected.roots());
    first.with_current(|_| Ok(())).unwrap();
    fixture.node.suspend("public index fixture lost sync");
    assert!(first.with_current(|_| Ok(())).is_err());
    assert!(index.sync(1).await.is_err());
    assert!(fixture.node.resume().await.unwrap());
    assert!(first.with_current(|_| Ok(())).is_err());
    let view = index.view().await.unwrap();
    fixture.publish(vec![]).await;
    assert!(view.with_current(|_| Ok(())).is_err());
    assert!(index.view().await.is_err());
    assert_eq!(index.sync(1).await.unwrap().processed, 1);
    assert_eq!(
        index.view().await.unwrap().index().roots(),
        expected.roots()
    );

    let spend = SpendKey::random();
    let view = native_stealth::view_secret(&[173; 32]);
    let draft = envelope::Draft::new(
        spend.owner(source.domain()),
        3,
        &native_stealth::view_public(&view),
    )
    .unwrap();
    let deposit_call = Call {
        quote: [0; 32],
        valid_from_ms: millis(fixture),
        expires_ms: millis(fixture) + 120_000,
        payout: address(&payment_host::address(12)),
        deposit_ou: 3,
        withdraw_ou: 0,
        boxes: [draft.ciphertext.clone(), String::new()],
    };
    let context = deposit_call
        .context(
            &source.origin(),
            &address(source.circle()),
            &address(&payment_host::address(12)),
        )
        .unwrap();
    let note = draft.bind(&context);
    let position: u32 = expected.roots().2.try_into().unwrap();
    let (deposit, next) = expected
        .prepare(
            source.domain(),
            &[],
            std::slice::from_ref(&note),
            3,
            0,
            context,
        )
        .unwrap();
    let proof_deposit = proof(&deposit, &pk);
    call_pool(
        fixture,
        source.circle(),
        12,
        "exchange",
        args(&deposit, &deposit_call, &proof_deposit),
        3,
    )
    .await;
    expected = next;
    caught_up(&index).await;
    assert_eq!(
        index.view().await.unwrap().index().roots(),
        expected.roots()
    );
    let relay = relay(fixture, source.circle()).await;
    let call = Call {
        quote: [0; 32],
        valid_from_ms: millis(fixture),
        expires_ms: millis(fixture) + 120_000,
        payout: address(&payment_host::address(13)),
        deposit_ou: 0,
        withdraw_ou: 3,
        boxes: [String::new(), String::new()],
    };
    let context = call
        .context(
            &source.origin(),
            &address(source.circle()),
            &address(&relay),
        )
        .unwrap();
    let (withdraw, next) = expected
        .prepare(
            source.domain(),
            &[Spend {
                note: &note,
                key: &spend,
                index: position,
            }],
            &[],
            0,
            3,
            context,
        )
        .unwrap();
    let proof_withdraw = proof(&withdraw, &pk);
    let receipt = call_pool(
        fixture,
        &relay,
        11,
        "forward",
        args(&withdraw, &call, &proof_withdraw),
        0,
    )
    .await;
    assert!(receipt["events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["contract"] == source.circle()
            && e["event"] == "ShieldedTransition"
            && e["depth"].as_i64().unwrap() > 0));
    expected = next;
    caught_up(&index).await;
    let final_view = index.view().await.unwrap();
    assert_eq!(final_view.index().roots(), expected.roots());
    assert!(final_view
        .index()
        .spent(&pool::encode_field(
            note.nullifier(source.domain(), &spend).unwrap()
        ))
        .unwrap());
    index.close().await;
    let resumed = Index::resume(&path, key.clone(), source.clone())
        .await
        .unwrap();
    assert_eq!(
        resumed.view().await.unwrap().index().roots(),
        expected.roots()
    );
    let updates = resumed.sync(1).await.unwrap().updates;
    resumed.close().await;
    // Losing one encrypted segment must refuse recovery; it cannot silently
    // reset the cursor, skip history or return a partially reconstructed view.
    let db = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(path.join("wallet.sqlite"))
        .create_if_missing(false);
    let edit = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(db)
        .await
        .unwrap();
    sqlx::query("DELETE FROM wallet_records WHERE kind=1 AND tag=(SELECT tag FROM wallet_records WHERE kind=1 LIMIT 1)").execute(&edit).await.unwrap();
    edit.close().await;
    assert!(Index::resume(&path, key, source.clone()).await.is_err());

    let limited_path = fixture.directory.path().join("bounded-private-index");
    let limited = Index::create(
        &limited_path,
        Key::from_bytes([174; 32]),
        source,
        IndexLimits {
            max_notes: 1,
            max_updates: 1,
        },
    )
    .await
    .unwrap();
    assert!(limited.sync(128).await.is_err());
    assert!(limited.view().await.is_err());
    limited.close().await;
    Recovery {
        index: expected,
        updates,
    }
}
