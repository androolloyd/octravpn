//! Actual compiled AML state feeds the native reader and shared receipt types.
//! Public network and packet-path qualification remain separate.
use super::*;
use octra_exex::StateRoot;
use octra_node_protocol::{circles, transaction::RuleMode};
use octra_node_runtime::{canonical::CanonicalStore, circle_assets::CanonicalAssets};
use octravpn_core::{
    payments::{TrafficClass, Usage},
    KeyPair,
};
use serde_json::json;

use super::test_host as host;

fn persist_accounts(chain: &mut host::Chain) {
    for (address, account) in chain.ledger.accounts() {
        account_store::set(&mut chain.state, address, account, RuleMode::Prior).unwrap();
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
async fn native_plan_admission_and_receipt_window_follow_compiled_unstake_state() {
    let (_directory, mut chain, reader, _store) = fixture().await;
    chain.now += 1000;
    chain.ok(11, "request_operator_unstake", json!([]), 0);
    persist_accounts(&mut chain);
    let stopped = u64::try_from(chain.now).unwrap();
    let plan = reader
        .read_state(&chain.state.snapshot(), 0, stopped)
        .unwrap();
    assert!(!plan.eligible && plan.claim_eligible);
    assert_eq!(plan.claim_deadline_ms, Some(stopped + DAY_MS));
    assert!(
        !reader
            .read_state(&chain.state.snapshot(), 0, stopped + DAY_MS)
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
    assert!(!before_deadline.eligible && before_deadline.claim_eligible);
    let at_deadline = reader
        .read_state_with_tariff(
            &chain.state.snapshot(),
            0,
            chain.now as u64 + DAY_MS,
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
    fn load_tariff(&self) -> Result<Option<Tariff>> {
        Ok(None)
    }
    fn save_tariff(&self, _: Tariff) -> Result<()> {
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
    assert!(reader.retain_tariff(tariff.clone()).await.is_err());
    assert!(reader.retained.lock().await.tariff.is_none());
    assert!(reader
        .attach_archive(Arc::new(RefusingArchive))
        .await
        .is_err());
    // A read-only adapter may retain in memory; production attaches its disk
    // archive before grants. Both enforce one immutable configured offer.
    let (_directory, _chain, memory, _store) = fixture().await;
    memory.retain_tariff(tariff.clone()).await.unwrap();
    memory.retain_tariff(tariff).await.unwrap();
    let other = Tariff::new(
        memory.operator.clone(),
        vec![TrafficClass {
            name: "default".into(),
            rate_ou_per_mib: 7,
        }],
        vec![],
    )
    .unwrap();
    assert!(memory.retain_tariff(other).await.is_err());
}
