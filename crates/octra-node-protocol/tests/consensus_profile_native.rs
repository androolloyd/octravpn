//! Differential startup/profile commitments from the unchanged adopted native
//! modules. Epoch-only selectors do not authenticate execution-rule activation.
use octra_node_protocol::{
    consensus::{
        policy,
        profile::{self, Settings},
    },
    rules::{self, Rule},
    transaction::{Nonce, OpType, RuleMode},
    transaction_policy::ReleaseProfile,
};
use serde::{
    de::{self, MapAccess, Visitor},
    Deserialize, Deserializer,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    io::Read,
    path::PathBuf,
};

const NATIVE_PIN: &str = "7f9be4489870645cfcc95439638cde40f5da9f50";
const NATIVE_SOURCES_SHA: &str = "ddefd67b70c877129f1678655715abf6a6a0a1b652c0394be552a4eb8c31e141";
const ORACLE_SHA: &str = "0c6a9bb1a34c3e457008c7d41f0ebd4f2dee587f448d8f71d14178f091f39925";
const INPUTS_SHA: &str = "998eeabecce66b4c3660dc539d9b63333d3b5e7a5894b5ff0c19652ef61c6a23";
const SELECTOR_SCOPE: &str =
    "epoch-only compatibility profile; not authenticated execution-rule activation";
const INPUTS: &[u8] = include_bytes!("fixtures/consensus-profile-inputs.json");

// A typed Option alone permits an omitted field. Native nulls are part of the
// fixture schema, so these fields must be present even on rejected settings.
fn required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

fn environment<'de, D>(deserializer: D) -> Result<BTreeMap<String, String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct Unique;
    impl<'de> Visitor<'de> for Unique {
        type Value = BTreeMap<String, String>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("an environment object with unique OCTRA_ string keys")
        }
        fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut result = BTreeMap::new();
            while let Some((key, value)) = access.next_entry::<String, String>()? {
                if !key.starts_with("OCTRA_") || result.insert(key, value).is_some() {
                    return Err(de::Error::custom("non-OCTRA or duplicate environment key"));
                }
            }
            Ok(result)
        }
    }
    deserializer.deserialize_map(Unique)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inputs {
    schema: String,
    cases: Vec<Input>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    id: String,
    chain_id: String,
    #[serde(deserialize_with = "environment")]
    env: BTreeMap<String, String>,
    operations: Vec<String>,
    expect_valid: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    schema: String,
    native_pin: String,
    native_sources_sha256: String,
    oracle_source_sha256: String,
    case_inputs_sha256: String,
    capture_sha256: String,
    build_provenance_sha256: String,
    native_binary_sha256: String,
    native_capture_status: String,
    case_count: usize,
    cases: Vec<NativeCase>,
    rust_comparator_executed_at_capture: bool,
    whole_node_qualified: bool,
    selector_scope: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeCase {
    schema: String,
    native_pin: String,
    native_sources_sha256: String,
    oracle_source_sha256: String,
    id: String,
    chain_id: String,
    #[serde(deserialize_with = "environment")]
    env: BTreeMap<String, String>,
    valid: bool,
    #[serde(deserialize_with = "required_option")]
    error: Option<String>,
    #[serde(deserialize_with = "required_option")]
    settings: Option<NativeSettings>,
    #[serde(deserialize_with = "required_option")]
    operations: Option<Vec<Operation>>,
    #[serde(deserialize_with = "required_option")]
    activation_graph_hash: Option<String>,
    #[serde(deserialize_with = "required_option")]
    epochs: Option<Vec<Epoch>>,
    selector_scope: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeSettings {
    proposal_txs: i64,
    proposal_bytes: i64,
    proposal_ou: String,
    stealth_defer: i64,
    stealth_slots: i64,
    fhe_slots: i64,
    inline_verify: bool,
    multi_exec: i64,
    minimum_epoch_ms: i64,
    receipt_activation: i64,
    private_result_activation: i64,
    release: String,
    crypto: String,
    crypto_engine: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Operation {
    operation: String,
    admits: bool,
    consensus_admits: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Epoch {
    epoch: i64,
    compat_hash: String,
    standard_hash: String,
    selected_hash: String,
    switch_after: bool,
    standard: String,
    math: String,
    cipher_migration: String,
    private_result: String,
}

fn digest(value: &str) {
    assert!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "invalid SHA256/hash field"
    );
}
fn mode(value: RuleMode) -> &'static str {
    match value {
        RuleMode::Prior => "prior",
        RuleMode::Active => "active",
    }
}
fn epochs(chain: &[u8]) -> Vec<i64> {
    let mut probes = BTreeSet::from([0, 1, Nonce::MAX.get()]);
    for epoch in rules::profile_epochs(chain) {
        if epoch > 0 {
            probes.insert(epoch - 1);
        }
        probes.insert(epoch);
        if epoch < Nonce::MAX.get() {
            probes.insert(epoch + 1);
        }
    }
    probes.into_iter().collect()
}
fn settings(actual: &Settings, expected: &NativeSettings) {
    assert_eq!(actual.proposal_txs, expected.proposal_txs);
    assert_eq!(actual.proposal_bytes, expected.proposal_bytes);
    assert_eq!(actual.proposal_ou.to_string(), expected.proposal_ou);
    assert_eq!(actual.stealth_defer, expected.stealth_defer);
    assert_eq!(actual.stealth_slots, expected.stealth_slots);
    assert_eq!(actual.fhe_slots, expected.fhe_slots);
    assert_eq!(
        matches!(
            actual.get("OCTRA_STEALTH_INLINE_VERIFY"),
            Some(b"1" | b"true")
        ),
        expected.inline_verify
    );
    assert_eq!(actual.multi_exec, expected.multi_exec);
    assert_eq!(policy::next_delay_ms(0.0, 0.0), expected.minimum_epoch_ms);
    assert_eq!(actual.receipt_activation, expected.receipt_activation);
    assert_eq!(
        actual.private_result_activation,
        expected.private_result_activation
    );
    let release = match actual.transactions.release {
        ReleaseProfile::Off => "off",
        ReleaseProfile::DevnetPrivateV1 => "devnet_private_v1",
        ReleaseProfile::DevnetFullV1 => "devnet_full_v1",
    };
    assert_eq!(release, expected.release);
    assert_eq!(
        if actual.transactions.private_v1 {
            "private_v1"
        } else {
            "off"
        },
        expected.crypto
    );
    // Hashing uses the actual native KAT identifier captured by Pvac_registry,
    // not a locally invented crypto-engine constant or a crypto execution claim.
    assert!(!expected.crypto_engine.is_empty() && expected.crypto_engine.len() <= 1024);
}
fn compare(input: &Input, expected: &NativeCase) {
    assert_eq!(expected.schema, "octra_native_consensus_profile_case_v1");
    assert_eq!(expected.native_pin, NATIVE_PIN);
    assert_eq!(expected.native_sources_sha256, NATIVE_SOURCES_SHA);
    assert_eq!(expected.oracle_source_sha256, ORACLE_SHA);
    assert_eq!(expected.selector_scope, SELECTOR_SCOPE);
    assert_eq!(expected.id, input.id);
    assert_eq!(expected.chain_id, input.chain_id);
    assert_eq!(expected.env, input.env);
    assert_eq!(expected.valid, input.expect_valid, "{}", input.id);
    let values = input
        .env
        .iter()
        .map(|(name, value)| (name.clone(), value.as_bytes().to_vec()))
        .collect();
    let result = Settings::from_values(values);
    if !expected.valid {
        let error = result.expect_err(&input.id);
        assert_eq!(Some(error.to_string()), expected.error, "{}", input.id);
        assert!(
            expected.settings.is_none()
                && expected.operations.is_none()
                && expected.activation_graph_hash.is_none()
                && expected.epochs.is_none()
        );
        return;
    }
    assert!(expected.error.is_none(), "{}", input.id);
    let actual = result.expect(&input.id);
    let native = expected.settings.as_ref().expect("valid case settings");
    settings(&actual, native);
    let operations = expected
        .operations
        .as_ref()
        .expect("valid case operation decisions");
    assert_eq!(operations.len(), OpType::ALL.len());
    assert_eq!(
        operations
            .iter()
            .map(|row| row.operation.as_str())
            .collect::<Vec<_>>(),
        input
            .operations
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
    );
    let names = operations
        .iter()
        .map(|row| row.operation.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(names, OpType::ALL.iter().map(|op| op.as_str()).collect());
    for row in operations {
        let op = OpType::parse(row.operation.as_bytes()).expect("native operation name");
        assert_eq!(
            actual.transactions.admits(op),
            row.admits,
            "{} / {}",
            input.id,
            row.operation
        );
        assert_eq!(
            actual.transactions.consensus_admits(op),
            row.consensus_admits,
            "{} / {}",
            input.id,
            row.operation
        );
    }
    let chain = input.chain_id.as_bytes();
    let engine = native.crypto_engine.as_bytes();
    let graph = expected
        .activation_graph_hash
        .as_ref()
        .expect("valid activation graph hash");
    digest(graph);
    assert_eq!(
        hex::encode(profile::activation_graph_hash(chain).unwrap()),
        *graph,
        "{}",
        input.id
    );
    let rows = expected.epochs.as_ref().expect("valid epoch probes");
    assert_eq!(
        rows.iter().map(|row| row.epoch).collect::<Vec<_>>(),
        epochs(chain)
    );
    let boundaries = rules::profile_epochs(chain);
    for row in rows {
        for hash in [&row.compat_hash, &row.standard_hash, &row.selected_hash] {
            digest(hash);
        }
        assert_eq!(
            hex::encode(actual.compatibility_hash(engine).unwrap()),
            row.compat_hash,
            "{} / {} compat",
            input.id,
            row.epoch
        );
        assert_eq!(
            hex::encode(actual.standard_hash(chain, row.epoch, engine).unwrap()),
            row.standard_hash,
            "{} / {} standard",
            input.id,
            row.epoch
        );
        assert_eq!(
            hex::encode(actual.hash(chain, row.epoch, engine).unwrap()),
            row.selected_hash,
            "{} / {} selected",
            input.id,
            row.epoch
        );
        // These predicates use public epoch-only rule/profile APIs. They do not
        // bypass the separate anchored Rules execution authority.
        let switch = row.epoch < Nonce::MAX.get() && boundaries.contains(&(row.epoch + 1));
        assert_eq!(switch, row.switch_after, "{} / {}", input.id, row.epoch);
        assert_eq!(
            mode(rules::at(chain, Rule::Standard, row.epoch)),
            row.standard
        );
        assert_eq!(mode(rules::at(chain, Rule::Math, row.epoch)), row.math);
        assert_eq!(
            mode(rules::at(chain, Rule::CipherMigration, row.epoch)),
            row.cipher_migration
        );
        assert_eq!(
            if row.epoch < actual.private_result_activation {
                "legacy"
            } else {
                "recoverable"
            },
            row.private_result
        );
    }
}

#[test]
fn unchanged_native_settings_profiles_and_hashes() {
    assert_eq!(hex::encode(Sha256::digest(INPUTS)), INPUTS_SHA);
    let inputs: Inputs = serde_json::from_slice(INPUTS).expect("typed native profile inputs");
    assert_eq!(inputs.schema, "octra_native_consensus_profile_inputs_v1");
    let path = std::env::var_os("OCTRA_NATIVE_PROFILE_FIXTURE").map_or_else(
        || {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/consensus-profile-native.json")
        },
        PathBuf::from,
    );
    let metadata = std::fs::metadata(&path).expect("actual native profile fixture is required");
    assert!(metadata.is_file() && metadata.len() <= 16 * 1024 * 1024);
    let mut raw = Vec::new();
    std::fs::File::open(path)
        .expect("open native profile fixture")
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut raw)
        .expect("read native profile fixture");
    assert!(raw.len() <= 16 * 1024 * 1024);
    let fixture: Fixture = serde_json::from_slice(&raw).expect("strict native profile fixture DTO");
    assert_eq!(fixture.schema, "octra_native_consensus_profile_fixture_v1");
    assert_eq!(fixture.native_pin, NATIVE_PIN);
    assert_eq!(fixture.native_sources_sha256, NATIVE_SOURCES_SHA);
    assert_eq!(fixture.oracle_source_sha256, ORACLE_SHA);
    assert_eq!(fixture.case_inputs_sha256, INPUTS_SHA);
    for hash in [
        &fixture.capture_sha256,
        &fixture.build_provenance_sha256,
        &fixture.native_binary_sha256,
    ] {
        digest(hash);
    }
    assert_eq!(fixture.native_capture_status, "PASS_NATIVE_ONLY");
    assert!(!fixture.rust_comparator_executed_at_capture && !fixture.whole_node_qualified);
    assert_eq!(fixture.selector_scope, SELECTOR_SCOPE);
    assert_eq!(fixture.case_count, 96);
    assert_eq!(fixture.cases.len(), fixture.case_count);
    assert_eq!(inputs.cases.len(), fixture.case_count);
    assert_eq!(
        inputs.cases.iter().filter(|case| case.expect_valid).count(),
        57
    );
    assert_eq!(
        inputs
            .cases
            .iter()
            .map(|case| &case.id)
            .collect::<BTreeSet<_>>()
            .len(),
        fixture.case_count
    );
    for (input, expected) in inputs.cases.iter().zip(&fixture.cases) {
        compare(input, expected);
    }
}
