//! Actual compiled AML state feeds the native reader and shared receipt types.
//! Public network and packet-path qualification remain separate.
use super::*;
use octra_exex::StateRoot;
use octra_node_protocol::{circles, transaction::RuleMode};
use octra_node_runtime::{canonical::CanonicalStore, circle_assets::CanonicalAssets};
use octravpn_core::{
    payments::{ServiceReceipt, SignedServiceReceipt, TrafficClass, Usage},
    KeyPair,
};
use serde_json::json;

use super::test_host as host;

fn persist_accounts(chain: &mut host::Chain) {
    for (address, account) in chain.ledger.accounts() {
        account_store::set(&mut chain.state, address, account, RuleMode::Prior).unwrap();
    }
}

fn publish_tariff(chain: &mut host::Chain, circle: &str, tariff: &Tariff) {
    let hash = tariff.hash_hex().unwrap();
    let path = format!("/offers/{hash}/tariff.json");
    let path_key = circles::path_key(path.as_bytes());
    let raw = tariff.canonical_bytes().unwrap();
    let meta = circles::AssetMeta {
        path_key: path_key.as_bytes().to_vec(),
        canonical_path: path.as_bytes().to_vec(),
        content_type: b"application/json".to_vec(),
        encoding: b"identity".to_vec(),
        size_bytes: i64::try_from(raw.len()).unwrap(),
        blob_hash: hash.as_bytes().to_vec(),
        body_mode: circles::ResourceMode::Public,
        plaintext_hash: None,
        key_id: None,
        padding_class: None,
        resource_key: circles::resource_key(circle.as_bytes(), path.as_bytes()).into_bytes(),
        locator_mode: circles::LocatorMode::Path,
        slot_ref: None,
        activate_after_epoch: None,
        expire_after_epoch: None,
        metadata_mode: circles::MetadataMode::Reveal,
    };
    chain
        .state
        .set(
            &[b"circles", circle.as_bytes(), b"browser", b"mode"],
            b"gateway_allowed".to_vec(),
        )
        .unwrap();
    chain
        .state
        .set(
            &[b"circles", circle.as_bytes(), b"resources", b"mode"],
            b"public_resources".to_vec(),
        )
        .unwrap();
    for (field, value) in [
        (b"meta".as_slice(), meta.to_json_bytes()),
        (b"body_b64".as_slice(), STANDARD.encode(raw).into_bytes()),
    ] {
        chain
            .state
            .set(
                &[
                    b"circles",
                    circle.as_bytes(),
                    b"assets",
                    b"by_hash",
                    path_key.as_bytes(),
                    field,
                ],
                value,
            )
            .unwrap();
    }
}

async fn fixture() -> (tempfile::TempDir, host::Chain, Payments, CanonicalStore) {
    let directory = tempfile::tempdir().unwrap();
    let mut chain = host::Chain::new();
    let operator = parse_native_address(&host::address(11)).unwrap();
    let tariff = Tariff::new(
        operator.clone(),
        vec![
            TrafficClass {
                name: "default".into(),
                rate_ou_per_mib: 10,
            },
            TrafficClass {
                name: "premium".into(),
                rate_ou_per_mib: 100,
            },
        ],
        vec![],
    )
    .unwrap();
    let hash = tariff.hash_hex().unwrap();
    chain.funded_plan_for_manifest(&hash);
    persist_accounts(&mut chain);
    let circle = host::address(14);
    publish_tariff(&mut chain, &circle, &tariff);
    chain
        .state
        .set(&[b"meta", b"last_epoch"], b"0".to_vec())
        .unwrap();
    let (_, index) = octra_node_protocol::epoch_index::next_root(
        hex::encode(octra_node_protocol::epoch_index::genesis_root()).as_bytes(),
        0,
        &[],
    )
    .unwrap();
    let root = octra_node_protocol::epoch_index::folded_state_root(
        hex::encode(chain.state.root().unwrap()).as_bytes(),
        hex::encode(index).as_bytes(),
    )
    .unwrap();
    let identity = ChainIdentity::genesis("octranet-reader-component", StateRoot(root));
    let store = CanonicalStore::create(
        &directory.path().join("canonical.db"),
        identity,
        chain.state.snapshot(),
        0,
    )
    .await
    .unwrap();
    let config = Config {
        application: Application::Program,
        program: chain.program.clone(),
        code_hash: hex::encode(Sha256::digest(&host::binaries().0)),
        factory: chain.factory.clone(),
        factory_code_hash: hex::encode(Sha256::digest(&host::binaries().1)),
        domain: host::DOMAIN.into(),
        operator_circle: circle,
        offer: 0,
    };
    // This component fixture deploys before its test genesis root exists. The
    // public constructor correctly refuses its non-network-bound test domain.
    assert!(Payments::new(
        config.clone(),
        store.reader(),
        operator.clone(),
        Arc::new(crate::Shared::new())
    )
    .is_err());
    let reader = Payments {
        deployment: Deployment {
            domain: config.domain.clone(),
            program: parse_native_address(&config.program).unwrap(),
        },
        config,
        history: store.reader(),
        operator,
        shared: Arc::new(crate::Shared::new()),
        circle_authority: None,
        retained: tokio::sync::Mutex::new(RetainedTariff::default()),
    };
    (directory, chain, reader, store)
}

fn receipt(plan: &Plan, sequence: u64, bytes: u64) -> SignedUsage {
    SignedUsage::sign(
        Usage {
            deployment: plan.deployment.clone(),
            payer: plan.payer.clone(),
            generation: plan.generation,
            plan: plan.plan,
            offer: plan.offer,
            manifest_hash: plan.manifest_hash.clone(),
            traffic_class: 1,
            sequence,
            total_bytes: bytes,
        },
        &KeyPair::from_secret_bytes(&[21; 32]),
    )
    .unwrap()
}

#[tokio::test]
async fn operator_service_statement_matches_compiled_aml_and_requires_same_slot() {
    let (_directory, chain, reader, _store) = fixture().await;
    let plan = reader
        .read_state(
            &chain.state.snapshot(),
            0,
            u64::try_from(chain.now).unwrap(),
        )
        .unwrap();
    let usage = Usage {
        deployment: plan.deployment.clone(),
        payer: plan.payer.clone(),
        generation: plan.generation,
        plan: plan.plan,
        offer: plan.offer,
        manifest_hash: plan.manifest_hash.clone(),
        traffic_class: 0,
        sequence: 7,
        total_bytes: 100,
    };
    let statement = ServiceReceipt {
        usage,
        operator: parse_native_address(&host::address(11)).unwrap(),
        operator_generation: 1,
    };
    assert_eq!(
        chain.view("get_service_message", json!([plan.plan, 0, 7, 100])),
        statement.signing_message().unwrap()
    );
    let key = KeyPair::from_secret_bytes(&[11; 32]);
    let first = SignedServiceReceipt::sign(statement.clone(), &key).unwrap();
    let mut second_statement = statement;
    second_statement.usage.total_bytes = 101;
    let second = SignedServiceReceipt::sign(second_statement, &key).unwrap();
    assert_eq!(
        SignedServiceReceipt::slash_params(&first, &second).unwrap(),
        json!([
            plan.plan,
            0,
            7,
            100,
            STANDARD.encode(first.signature.0),
            101,
            STANDARD.encode(second.signature.0)
        ])
    );
}

#[tokio::test]
async fn native_plan_refuses_a_bonded_service_key_unrelated_to_operator_wallet() {
    let (_directory, mut chain, reader, _store) = fixture().await;
    let operator = host::address(11);
    let mut key = internal_key(b"map", b"operator_receipt_key");
    key.push(b'/');
    key.extend_from_slice(operator.len().to_string().as_bytes());
    key.push(b'#');
    key.extend_from_slice(operator.as_bytes());
    chain
        .state
        .set(
            &[b"contracts", chain.program.as_bytes(), b"storage", &key],
            STANDARD
                .encode(host::key(31).verifying_key().as_bytes())
                .into_bytes(),
        )
        .unwrap();
    let error = reader
        .read_state(
            &chain.state.snapshot(),
            0,
            u64::try_from(chain.now).unwrap(),
        )
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("bonded receipt key differs from operator wallet"));
}

#[tokio::test]
async fn compiled_claim_rejects_uint64_charge_intermediate_without_consuming_allowance() {
    let (_directory, mut chain, reader, _store) = fixture().await;
    let plan = reader
        .read_state(
            &chain.state.snapshot(),
            0,
            u64::try_from(chain.now).unwrap(),
        )
        .unwrap();
    let before = chain.number("get_plan_remaining", json!([plan.plan]));
    chain.denied(
        13,
        "claim",
        receipt(&plan, 1, u64::MAX).claim_params().unwrap(),
        0,
        "charge intermediate exceeds uint64",
    );
    assert_eq!(
        chain.number("get_plan_remaining", json!([plan.plan])),
        before
    );
}

#[tokio::test]
async fn compiled_state_tariff_and_payer_signature_agree_on_exact_claim_increment() {
    let (_directory, mut chain, reader, _store) = fixture().await;
    let plan = reader
        .read_state(
            &chain.state.snapshot(),
            0,
            u64::try_from(chain.now).unwrap(),
        )
        .unwrap();
    assert!(plan.eligible && plan.claim_eligible);
    assert_eq!(plan.original_budget_ou, 1000);
    let signed = receipt(&plan, 99, 1);
    assert_eq!(plan.increment_at_snapshot(&signed).unwrap(), 1);
    chain.ok(13, "claim", signed.claim_params().unwrap(), 0);
    persist_accounts(&mut chain);
    let plan = reader
        .read_state(
            &chain.state.snapshot(),
            0,
            u64::try_from(chain.now).unwrap(),
        )
        .unwrap();
    assert_eq!(plan.redeemed_ou, [0, 1]);
    assert!(plan.increment_at_snapshot(&signed).is_err());
    let larger = receipt(&plan, 1, 1_048_576);
    assert_eq!(plan.increment_at_snapshot(&larger).unwrap(), 99);
    chain.ok(13, "claim", larger.claim_params().unwrap(), 0);
    persist_accounts(&mut chain);
    let plan = reader
        .read_state(
            &chain.state.snapshot(),
            0,
            u64::try_from(chain.now).unwrap(),
        )
        .unwrap();
    assert_eq!(plan.redeemed_ou, [0, 100]);
    assert_eq!(plan.remaining_ou, 900);
    assert_eq!(
        chain.number("get_earnings", json!([host::address(11)])),
        100
    );
    assert!(plan
        .increment_at_snapshot(&receipt(&plan, 2, 100 * 1_048_576))
        .is_err());
}

#[tokio::test]
async fn standalone_offer_needs_no_public_payer_and_shares_plan_security_checks() {
    let (_directory, chain, reader, _store) = fixture().await;
    let snapshot = chain.state.snapshot();
    let now = chain.now as u64;
    let offer = reader.read_offer(&snapshot, 0, now).unwrap();
    assert!(offer.liquid && offer.provider_available && offer.purchase_open);
    assert_eq!(
        offer.data.receipt_key,
        Some(KeyPair::from_secret_bytes(&[11; 32]).public)
    );
    assert_eq!(offer.data.operator_generation, 1);
    assert_eq!(
        offer.data.tariff,
        reader.read_state(&snapshot, 0, now).unwrap().tariff
    );
    let mut no_plan = StateBatch::from_snapshot(snapshot.clone());
    no_plan.begin().unwrap();
    no_plan
        .set(
            &[
                b"contracts",
                chain.program.as_bytes(),
                b"storage",
                b"plan_count",
            ],
            b"0".to_vec(),
        )
        .unwrap();
    assert!(reader.read_state(&no_plan.snapshot(), 0, now).is_err());
    assert!(
        reader
            .read_offer(&no_plan.snapshot(), 0, now)
            .unwrap()
            .purchase_open
    );

    for (field, indices, value) in [
        (b"offer_rate".as_slice(), vec!["0", "1"], "1"),
        (b"offer_sealed", vec!["0"], "0"),
        (b"offer_series", vec!["0"], "9"),
        (b"offer_start_ms", vec!["0"], "0"),
        (b"offer_cancelled", vec!["0"], "2"),
        (
            b"operator_receipt_key",
            vec![reader.operator.display()],
            "bad",
        ),
    ] {
        let mut changed = StateBatch::from_snapshot(snapshot.clone());
        changed.begin().unwrap();
        let mut key = internal_key(b"map", field);
        key.push(b'/');
        for index in indices {
            key.extend_from_slice(format!("{}#{index}", index.len()).as_bytes());
        }
        changed
            .set(
                &[b"contracts", chain.program.as_bytes(), b"storage", &key],
                value.as_bytes().to_vec(),
            )
            .unwrap();
        assert!(
            reader.read_offer(&changed.snapshot(), 0, now).is_err(),
            "offer accepted {field:?}"
        );
        assert!(
            reader.read_state(&changed.snapshot(), 0, now).is_err(),
            "plan accepted {field:?}"
        );
    }
    let mut insolvent = StateBatch::from_snapshot(snapshot);
    insolvent.begin().unwrap();
    account_store::set(
        &mut insolvent,
        chain.program.as_bytes(),
        &octra_node_protocol::state::Account::default(),
        RuleMode::Prior,
    )
    .unwrap();
    assert!(
        !reader
            .read_offer(&insolvent.snapshot(), 0, now)
            .unwrap()
            .liquid
    );
    assert!(
        !reader
            .read_state(&insolvent.snapshot(), 0, now)
            .unwrap()
            .eligible
    );
}

#[tokio::test]
async fn native_plan_admission_and_new_purchases_stop_at_compiled_unstake() {
    let (_directory, mut chain, reader, _store) = fixture().await;
    chain.now += 1000;
    chain.ok(11, "request_operator_unstake", json!([]), 0);
    persist_accounts(&mut chain);
    let stopped = u64::try_from(chain.now).unwrap();
    let plan = reader
        .read_state(&chain.state.snapshot(), 0, stopped)
        .unwrap();
    assert!(!plan.eligible && !plan.claim_eligible);
    assert_eq!(plan.claim_deadline_ms, Some(stopped));
    assert!(plan
        .increment_at_snapshot(&receipt(&plan, 1, 1_048_576))
        .is_err());
    assert!(
        !reader
            .read_state(&chain.state.snapshot(), 0, stopped + 86_400_000)
            .unwrap()
            .claim_eligible
    );
    assert!(reader
        .read_state(&chain.state.snapshot(), 0, stopped - 1)
        .is_err());
    chain.now += host::WEEK;
    chain.ok(11, "withdraw_operator_stake", json!([]), 0);
    chain.ok(11, "bond_operator", json!([]), host::STAKE);
    persist_accounts(&mut chain);
    let plan = reader
        .read_state(
            &chain.state.snapshot(),
            0,
            u64::try_from(chain.now).unwrap(),
        )
        .unwrap();
    assert!(!plan.eligible && !plan.claim_eligible);
}

#[tokio::test]
async fn pinned_program_assets_and_genesis_clock_fail_closed() {
    let (_directory, chain, reader, store) = fixture().await;
    let assets = CanonicalAssets::capture(&store).await.unwrap();
    let view = Committed {
        head: store.head().await.unwrap(),
        assets,
    };
    use octra_browser::AssetResolver;
    let manifest = reader
        .read_state(&chain.state.snapshot(), 0, chain.now as u64)
        .unwrap()
        .manifest_hash
        .clone();
    let url = octra_browser::OctUrl::parse(&format!(
        "oct://{}/offers/{manifest}/tariff.json",
        reader.config.operator_circle
    ))
    .unwrap();
    let asset = view.assets.resolve(&url).await.unwrap();
    assert_eq!(hex::encode(Sha256::digest(&asset.bytes)), manifest);
    assert!(reader
        .project(&view, 0)
        .await
        .unwrap_err()
        .to_string()
        .contains("clock missing"));
    let mut changed = StateBatch::from_snapshot(chain.state.snapshot());
    changed.begin().unwrap();
    changed
        .set(
            &[b"contracts", chain.program.as_bytes(), b"bytecode"],
            STANDARD.encode(b"unreviewed").into_bytes(),
        )
        .unwrap();
    assert!(reader
        .read_state(&changed.snapshot(), 0, u64::try_from(chain.now).unwrap())
        .is_err());
    let mut config = reader.config.clone();
    config.code_hash = "0".repeat(64);
    let changed = Payments {
        config,
        history: store.reader(),
        deployment: reader.deployment.clone(),
        operator: reader.operator.clone(),
        shared: reader.shared.clone(),
        circle_authority: None,
        retained: tokio::sync::Mutex::new(RetainedTariff::default()),
    };
    assert!(changed
        .read_state(
            &chain.state.snapshot(),
            0,
            u64::try_from(chain.now).unwrap()
        )
        .is_err());
}

#[test]
fn deployment_domain_binds_chain_label_and_origin() {
    let first = ChainIdentity::genesis("first", StateRoot([7; 32]));
    let second = ChainIdentity::genesis("second", StateRoot([7; 32]));
    let checkpoint = ChainIdentity::checkpoint("first", 0, StateRoot([7; 32]));
    assert_ne!(network_domain(&first), network_domain(&second));
    assert_ne!(network_domain(&first), network_domain(&checkpoint));
}

#[tokio::test]
async fn paid_plan_requires_a_live_revocable_lease() {
    let (_directory, chain, reader, _store) = fixture().await;
    let mut plan = reader
        .read_state(&chain.state.snapshot(), 0, chain.now as u64)
        .unwrap();
    let signed = receipt(&plan, 1, 1);
    // A retained snapshot alone never authorizes paid traffic or claims.
    assert!(!plan.admissible() && !plan.claimable());
    assert!(plan.claim_increment(&signed).is_err());
    let revocation = Revocation::default();
    plan.lease = Some(Lease {
        revocation: revocation.clone(),
        expires: Instant::now() + PLAN_MAX_AGE,
    });
    assert!(plan.admissible() && plan.claimable());
    assert_eq!(plan.claim_increment(&signed).unwrap(), 1);
    revocation.revoke();
    assert!(!plan.admissible() && !plan.claimable());
    assert!(plan.claim_increment(&signed).is_err());
    plan.lease = Some(Lease {
        revocation: Revocation::default(),
        expires: Instant::now(),
    });
    assert!(!plan.admissible() && !plan.claimable());
    assert!(plan.claim_increment(&signed).is_err());
}

#[tokio::test]
async fn resuming_the_same_head_does_not_renew_its_admission_age() {
    let (_directory, _chain, reader, store) = fixture().await;
    let head = store.head().await.unwrap();
    let assets = CanonicalAssets::capture(&store).await.unwrap();
    let serving = || crate::published::Serving {
        committed: Committed {
            head: head.clone(),
            assets: assets.clone(),
        },
        router: axum::Router::new(),
        revocation: Revocation::default(),
        observed_at: Instant::now(),
    };
    let (ticket, _) = reader.shared.suspend("catch-up complete");
    assert!(reader.shared.install(&ticket, serving()));
    let first = reader.shared.current().unwrap();
    let (ticket, _) = reader.shared.suspend("rechecking retained head");
    assert!(first.revocation.is_revoked());
    assert!(reader.shared.install(&ticket, serving()));
    let second = reader.shared.current().unwrap();
    assert_eq!(second.observed_at, first.observed_at);
    assert!(!second.revocation.is_revoked());
    // A resume captured before the newer suspension cannot publish anything.
    reader.shared.suspend("newer catch-up");
    assert!(!reader.shared.install(&ticket, serving()));
    assert!(second.revocation.is_revoked());
}

#[tokio::test]
async fn removed_circle_does_not_erase_authenticated_claim_terms() {
    let (_directory, mut chain, reader, _store) = fixture().await;
    let plan = reader
        .read_state(&chain.state.snapshot(), 0, chain.now as u64)
        .unwrap();
    let tariff = plan.tariff.clone();
    let signed = receipt(&plan, 1, 1_048_576);
    chain
        .state
        .remove(&[b"circles", reader.config.operator_circle.as_bytes()])
        .unwrap();
    assert!(reader
        .read_state(&chain.state.snapshot(), 0, chain.now as u64)
        .is_err());
    let claim = reader
        .read_state_with_tariff(
            &chain.state.snapshot(),
            0,
            chain.now as u64,
            Some(tariff.clone()),
        )
        .unwrap();
    assert!(!claim.eligible && claim.claim_eligible);
    assert_eq!(claim.increment_at_snapshot(&signed).unwrap(), 100);
    chain.ok(13, "claim", signed.claim_params().unwrap(), 0);
    persist_accounts(&mut chain);
    let redeemed = reader
        .read_state_with_tariff(
            &chain.state.snapshot(),
            0,
            chain.now as u64,
            Some(tariff.clone()),
        )
        .unwrap();
    assert_eq!(redeemed.redeemed_ou, [0, 100]);
    assert!(!redeemed.eligible);
    chain.now += 1000;
    chain.ok(12, "request_exit", json!([]), 0);
    persist_accounts(&mut chain);
    let before_deadline = reader
        .read_state_with_tariff(
            &chain.state.snapshot(),
            0,
            chain.now as u64,
            Some(tariff.clone()),
        )
        .unwrap();
    assert!(!before_deadline.eligible && !before_deadline.claim_eligible);
    assert!(
        before_deadline.validate_at_snapshot(&signed).is_ok(),
        "canonical purchase acknowledgements remain valid"
    );
    assert!(before_deadline
        .increment_at_snapshot(&receipt(&before_deadline, 2, 2 * 1_048_576))
        .is_err());
    let at_deadline = reader
        .read_state_with_tariff(
            &chain.state.snapshot(),
            0,
            chain.now as u64 + 86_400_000,
            Some(tariff),
        )
        .unwrap();
    assert!(!at_deadline.eligible && !at_deadline.claim_eligible);
}

#[tokio::test]
async fn retained_tariff_does_not_override_current_manifest_rates_or_code() {
    let (_directory, chain, reader, _store) = fixture().await;
    let original = chain.state.snapshot();
    let tariff = reader
        .read_state(&original, 0, chain.now as u64)
        .unwrap()
        .tariff
        .clone();
    let changed_tariff = Tariff::new(
        reader.operator.clone(),
        vec![TrafficClass {
            name: "default".into(),
            rate_ou_per_mib: 1,
        }],
        vec![],
    )
    .unwrap();
    assert!(reader
        .read_state_with_tariff(&original, 0, chain.now as u64, Some(changed_tariff))
        .is_err());
    let mut changed = StateBatch::from_snapshot(original.clone());
    changed.begin().unwrap();
    let mut key = internal_key(b"map", b"offer_rate");
    key.extend_from_slice(b"/1#01#1");
    changed
        .set(
            &[b"contracts", chain.program.as_bytes(), b"storage", &key],
            b"1".to_vec(),
        )
        .unwrap();
    assert!(reader
        .read_state_with_tariff(
            &changed.snapshot(),
            0,
            chain.now as u64,
            Some(tariff.clone())
        )
        .is_err());
    let mut changed = StateBatch::from_snapshot(original);
    changed.begin().unwrap();
    changed
        .set(
            &[b"contracts", chain.program.as_bytes(), b"bytecode"],
            STANDARD.encode(b"changed").into_bytes(),
        )
        .unwrap();
    assert!(reader
        .read_state_with_tariff(&changed.snapshot(), 0, chain.now as u64, Some(tariff))
        .is_err());
}

struct RefusingArchive;
impl TariffArchive for RefusingArchive {
    fn load_tariff(&self, _: u64) -> Result<Option<Tariff>> {
        Ok(None)
    }
    fn save_tariff(&self, _: u64, _: Tariff) -> Result<()> {
        anyhow::bail!("fixture archive IO failure")
    }
}

#[tokio::test]
async fn archive_failure_prevents_retention_and_immutable_terms_cannot_change() {
    let (_directory, chain, reader, _store) = fixture().await;
    let tariff = reader
        .read_state(&chain.state.snapshot(), 0, chain.now as u64)
        .unwrap()
        .tariff
        .clone();
    reader
        .attach_archive(Arc::new(RefusingArchive))
        .await
        .unwrap();
    assert!(reader.retain_tariff(0, tariff.clone()).await.is_err());
    assert!(reader.retained.lock().await.tariffs.is_empty());
    assert!(reader
        .attach_archive(Arc::new(RefusingArchive))
        .await
        .is_err());
    // A read-only adapter may retain in memory; production attaches its disk
    // archive before grants. Both enforce one immutable configured offer.
    let (_directory, _chain, memory, _store) = fixture().await;
    memory.retain_tariff(0, tariff.clone()).await.unwrap();
    memory.retain_tariff(0, tariff).await.unwrap();
    let other = Tariff::new(
        memory.operator.clone(),
        vec![TrafficClass {
            name: "default".into(),
            rate_ou_per_mib: 7,
        }],
        vec![],
    )
    .unwrap();
    assert!(memory.retain_tariff(0, other).await.is_err());
}

#[tokio::test]
async fn fully_spent_plan_remains_eligible_for_its_canonical_prepaid_bytes() {
    let (directory, mut chain, reader, _store) = fixture().await;
    let plan = reader
        .read_state(
            &chain.state.snapshot(),
            0,
            u64::try_from(chain.now).unwrap(),
        )
        .unwrap();
    let purchase = receipt(&plan, 1, 10 * 1_048_576);
    assert_eq!(plan.increment_at_snapshot(&purchase).unwrap(), 1000);
    chain.ok(13, "claim", purchase.claim_params().unwrap(), 0);
    persist_accounts(&mut chain);
    let plan = reader
        .read_state(
            &chain.state.snapshot(),
            0,
            u64::try_from(chain.now).unwrap(),
        )
        .unwrap();
    assert_eq!(plan.remaining_ou, 0);
    assert_eq!(plan.redeemed_bytes, [0, 10 * 1_048_576]);
    assert!(
        plan.eligible,
        "purchased bytes outlive the monetary remainder"
    );
    assert!(plan.validate_at_snapshot(&purchase).is_ok());
    assert!(plan
        .increment_at_snapshot(&receipt(&plan, 2, 10 * 1_048_576 + 1))
        .is_err());
    let meter = octravpn_node::payment_meter::Meter::open(
        directory.path().join("prepaid"),
        purchase.usage.binding(),
        plan.tariff.clone(),
        plan.original_budget_ou,
        plan.redeemed_bytes.clone(),
    )
    .await
    .unwrap();
    assert_eq!(meter.snapshot().unwrap().committed_totals, [0, 0]);
    meter
        .reserve_class(1, 10 * 1_048_576)
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();
    assert!(meter.reserve_class(1, 1).await.is_err());
    assert!(meter.reserve_class(0, 1).await.is_err());
}

#[tokio::test]
async fn replacement_quote_changes_purchase_window_without_repricing_bought_bytes() {
    let (_directory, mut chain, reader, _store) = fixture().await;
    let old = reader
        .read_state(&chain.state.snapshot(), 0, chain.now as u64)
        .unwrap();
    let purchased = receipt(&old, 1, 1_048_576);
    chain.ok(13, "claim", purchased.claim_params().unwrap(), 0);
    let successor = Tariff::new(
        reader.operator.clone(),
        vec![
            TrafficClass {
                name: "default".into(),
                rate_ou_per_mib: 20,
            },
            TrafficClass {
                name: "premium".into(),
                rate_ou_per_mib: 200,
            },
        ],
        vec![],
    )
    .unwrap();
    publish_tariff(&mut chain, &reader.config.operator_circle, &successor);
    chain.ok(
        11,
        "create_rate_change",
        json!([0, successor.hash_hex().unwrap()]),
        0,
    );
    chain.ok(11, "append_class", json!([1, 20]), 0);
    chain.ok(11, "append_class", json!([1, 200]), 0);
    chain.ok(11, "seal_offer", json!([1]), 0);
    persist_accounts(&mut chain);
    let activation = chain.now + host::DAY;
    let before = reader
        .read_state(&chain.state.snapshot(), 0, (activation - 1) as u64)
        .unwrap();
    assert!(before.eligible && before.claim_eligible);
    assert_eq!(before.offer_end_ms, activation as u64);
    assert_eq!(
        before
            .increment_at_snapshot(&receipt(&before, 2, 2 * 1_048_576))
            .unwrap(),
        100
    );
    chain.denied(12, "open_plan", json!([1, 1000]), 0, "offer quote inactive");
    chain.now = activation;
    let retired = reader
        .read_state(&chain.state.snapshot(), 0, chain.now as u64)
        .unwrap();
    assert!(
        retired.eligible,
        "previously bought bytes remain deliverable"
    );
    assert!(!retired.claim_eligible);
    assert_eq!(
        retired.claim_deadline_ms, None,
        "rate retirement cannot expire delivery status"
    );
    retired.validate_at_snapshot(&purchased).unwrap();
    chain.denied(
        13,
        "claim",
        receipt(&retired, 2, 2 * 1_048_576).claim_params().unwrap(),
        0,
        "offer quote inactive",
    );
    chain.ok(12, "open_plan", json!([1, 1000]), 0);
    persist_accounts(&mut chain);
    let new = reader
        .read_state(&chain.state.snapshot(), 1, chain.now as u64)
        .unwrap();
    assert!(new.eligible && new.claim_eligible);
    assert_eq!(new.offer, 1);
    assert_eq!(new.tariff, successor);
    assert_eq!(
        new.increment_at_snapshot(&receipt(&new, 1, 1_048_576))
            .unwrap(),
        200
    );
    reader.retain_tariff(0, old.tariff.clone()).await.unwrap();
    reader.retain_tariff(1, new.tariff.clone()).await.unwrap();
    assert_eq!(
        reader.retained_tariff(0).await.unwrap(),
        Some(old.tariff.clone())
    );
    assert_eq!(
        reader.retained_tariff(1).await.unwrap(),
        Some(new.tariff.clone())
    );
    // A separate product by the same operator is not a successor in this host.
    chain.ok(11, "create_offer", json!([old.manifest_hash]), 0);
    chain.ok(11, "append_class", json!([2, 10]), 0);
    chain.ok(11, "append_class", json!([2, 100]), 0);
    chain.ok(11, "seal_offer", json!([2]), 0);
    chain.ok(12, "open_plan", json!([2, 1000]), 0);
    assert!(reader
        .read_state(&chain.state.snapshot(), 2, chain.now as u64)
        .is_err());
}

#[tokio::test]
async fn instant_partial_and_full_withdrawal_revoke_old_plans_without_erasing_purchases() {
    let (_directory, mut chain, reader, _store) = fixture().await;
    let plan = reader
        .read_state(&chain.state.snapshot(), 0, chain.now as u64)
        .unwrap();
    let purchased = receipt(&plan, 1, 1_048_576);
    chain.ok(13, "claim", purchased.claim_params().unwrap(), 0);
    chain.ok(12, "withdraw_channel", json!([1]), 0);
    persist_accounts(&mut chain);
    let invalidated = reader
        .read_state(&chain.state.snapshot(), 0, chain.now as u64)
        .unwrap();
    assert!(!invalidated.eligible && !invalidated.claim_eligible);
    assert_eq!(invalidated.redeemed_bytes, [0, 1_048_576]);
    invalidated.validate_at_snapshot(&purchased).unwrap();
    chain.denied(
        13,
        "claim",
        receipt(&invalidated, 2, 2 * 1_048_576)
            .claim_params()
            .unwrap(),
        0,
        "plan generation closed",
    );
    chain.ok(12, "open_plan", json!([0, 1000]), 0);
    let current = reader
        .read_state(&chain.state.snapshot(), 1, chain.now as u64)
        .unwrap();
    assert!(current.eligible && current.claim_eligible);
    assert_eq!(current.generation, plan.generation + 1);
    chain.ok(12, "withdraw_remaining", json!([]), 0);
    persist_accounts(&mut chain);
    let closed = reader
        .read_state(&chain.state.snapshot(), 1, chain.now as u64)
        .unwrap();
    assert!(!closed.eligible && !closed.claim_eligible);
    assert_eq!(closed.claim_deadline_ms, Some(chain.now as u64));
    assert_eq!(
        chain.number("get_channel_balance", json!([host::address(12)])),
        0
    );
    // Re-registration with another key must not replace old plan identity.
    let message = format!(
        "Octranet register v1|{}|{}|{}|3",
        host::DOMAIN,
        chain.program,
        host::address(12)
    );
    chain.ok(
        12,
        "register",
        json!([
            STANDARD.encode(host::key(22).verifying_key().to_bytes()),
            host::sign(22, &message)
        ]),
        0,
    );
    let archived = reader
        .read_state(&chain.state.snapshot(), 0, chain.now as u64)
        .unwrap();
    assert!(!archived.eligible && !archived.claim_eligible);
    archived.validate_at_snapshot(&purchased).unwrap();
    assert_eq!(archived.receipt_key, purchased.receipt_key);
}

#[tokio::test]
async fn operator_earnings_allocate_to_own_prepaid_plan_without_another_deposit() {
    let (_directory, mut chain, reader, _store) = fixture().await;
    let plan = reader
        .read_state(&chain.state.snapshot(), 0, chain.now as u64)
        .unwrap();
    chain.ok(
        13,
        "claim",
        receipt(&plan, 1, 1_048_576).claim_params().unwrap(),
        0,
    );
    let operator = host::address(11);
    let message = format!(
        "Octranet register v1|{}|{}|{}|1",
        host::DOMAIN,
        chain.program,
        operator
    );
    chain.ok(
        11,
        "register",
        json!([
            STANDARD.encode(host::key(11).verifying_key().to_bytes()),
            host::sign(11, &message)
        ]),
        0,
    );
    let locked = chain.number("get_locked_value", json!([]));
    chain.ok(11, "open_plan", json!([0, 50]), 0);
    persist_accounts(&mut chain);
    assert_eq!(chain.number("get_funds", json!([operator])), 50);
    assert_eq!(chain.number("get_earnings", json!([operator])), 50);
    assert_eq!(chain.number("get_channel_balance", json!([operator])), 100);
    assert_eq!(chain.number("get_locked_value", json!([])), locked);
    let own = reader
        .read_state(&chain.state.snapshot(), 1, chain.now as u64)
        .unwrap();
    assert!(own.eligible && own.claim_eligible);
    assert_eq!(own.payer, reader.operator);
    assert_eq!(own.original_budget_ou, 50);
}
