//! Read-only accounting in the isolated four-validator fixture. No wallet
//! leases are bypassed for writing and no secret/witness is exported.
use super::*;
use octravpn_core::{payments::PlanBinding, sealed::Protection};
use sqlx::{sqlite::SqliteConnectOptions, Connection, Row};
use std::{collections::BTreeSet, path::Path};
#[path = "multi_observe/transport.rs"]
mod transport;

fn raw32(value: &Value) -> [u8; 32] {
    serde_json::from_value(value.clone()).expect("invalid isolated accounting field")
}
fn number(value: &Value) -> u64 {
    value.as_u64().expect("invalid isolated accounting number")
}
fn array(value: &Value) -> Vec<u64> {
    serde_json::from_value(value.clone()).expect("invalid isolated accounting counters")
}
fn text(value: &Value) -> &str {
    value.as_str().expect("invalid isolated accounting text")
}
fn key(path: &Path) -> Key {
    let bytes = crate::bootstrap::read_limited(path, 32).unwrap();
    Key::from_bytes(bytes.try_into().expect("fixture master key length differs"))
}
async fn rows(path: &Path, key: &Key, scope: [u8; 32]) -> Vec<(u8, Value)> {
    let mut connection = sqlx::SqliteConnection::connect_with(
        &SqliteConnectOptions::new()
            .filename(path.join("wallet.sqlite"))
            .read_only(true)
            .create_if_missing(false),
    )
    .await
    .unwrap();
    sqlx::query("PRAGMA query_only=ON")
        .execute(&mut connection)
        .await
        .unwrap();
    let mut transaction = connection.begin().await.unwrap();
    let saved = sqlx::query("SELECT kind,tag,value FROM wallet_records LIMIT 4097")
        .fetch_all(&mut *transaction)
        .await
        .unwrap();
    assert!(saved.len() <= 4096, "fixture accounting row bound");
    let database = key.derive(b"wallet database", &scope).unwrap();
    let mut decoded = Vec::new();
    for row in saved {
        let kind = u8::try_from(row.get::<i64, _>("kind")).unwrap();
        let tag: Vec<u8> = row.get("tag");
        assert!(tag.len() == 32);
        let encrypted: Vec<u8> = row.get("value");
        assert!(encrypted.len() <= 131_072 + octravpn_core::sealed::OVERHEAD);
        let mut hash = Sha256::new();
        hash.update(scope);
        hash.update([kind]);
        hash.update(tag);
        let scope: [u8; 32] = hash.finalize().into();
        let protection = Protection::new(database.derive(b"wallet row", &scope).unwrap(), scope);
        let plaintext = protection.open(&encrypted).unwrap();
        decoded.push((kind, serde_json::from_slice(&plaintext).unwrap()));
    }
    transaction.rollback().await.unwrap();
    connection.close().await.unwrap();
    decoded
}
fn spend(key: &Key, context: &[u8]) -> SpendKey {
    for attempt in 0_u32..256 {
        let seed = key
            .derive_bytes(b"spend", &[context, &attempt.to_be_bytes()].concat())
            .unwrap();
        if let Ok(spend) = SpendKey::from_bytes(&seed) {
            return spend;
        }
    }
    panic!("fixture spend derivation exhausted")
}
fn call(value: &Value, deposit: u64, withdraw: u64) -> Call {
    Call {
        quote: raw32(&value["quote"]),
        valid_from_ms: number(&value["valid_from"]),
        expires_ms: number(&value["expires"]),
        payout: address(text(&value["payout"])),
        deposit_ou: deposit,
        withdraw_ou: withdraw,
        boxes: serde_json::from_value(value["boxes"].clone()).unwrap(),
    }
}
struct Canonical {
    outputs: BTreeSet<String>,
    nullifiers: BTreeSet<String>,
}
impl Canonical {
    fn new(input: &Value) -> Self {
        let mut result = Self {
            outputs: BTreeSet::new(),
            nullifiers: BTreeSet::new(),
        };
        for exchange in input["exchanges"].as_array().unwrap() {
            let event = &exchange["transition"];
            assert!(event["event"] == "ShieldedTransition");
            for index in [3, 4] {
                let value = text(&event["values"][index]);
                if value != hex::encode([0; 32]) {
                    assert!(
                        result.nullifiers.insert(value.into()),
                        "canonical nullifier repeated"
                    );
                }
            }
            for index in [5, 6] {
                let value = text(&event["values"][index]);
                if value != hex::encode([0; 32]) {
                    assert!(
                        result.outputs.insert(value.into()),
                        "canonical output repeated"
                    );
                }
            }
        }
        result
    }
}

#[tokio::test]
#[ignore = "explicit read-only isolated multihop accounting only"]
async fn observe_isolated_multihop_private_accounting() {
    assert!(cfg!(target_os = "linux") && Path::new("/.dockerenv").is_file());
    let role = std::env::var("OCTRA_ACCOUNTING_ROLE").unwrap();
    assert!(["A", "B", "C"].contains(&role.as_str()));
    let input: Value = serde_json::from_slice(
        &crate::bootstrap::read_limited(
            Path::new(&format!("/evidence/private-accounting-{role}.json")),
            262_144,
        )
        .unwrap(),
    )
    .unwrap();
    assert!(input["fixture_only"] == true);
    let ready = &input["ready"];
    let origin: [u8; 32] = hex::decode(text(&ready["origin"]))
        .unwrap()
        .try_into()
        .unwrap();
    let pool = address(text(&ready["pool"]["circle"]));
    let domain = Domain::new(&origin, &pool).unwrap();
    let canonical = Canonical::new(&input);
    let mut scope = Sha256::new();
    scope.update(if role == "C" {
        b"Octranet private payer wallet v1\0".as_slice()
    } else {
        b"Octranet private operator wallet v1\0".as_slice()
    });
    scope.update(origin);
    scope.update(pool);
    scope.update(text(&input["pool_code_sha256"]).as_bytes());
    let root = Path::new("/state/native-vpn");
    let (path, master, index) = if role == "C" {
        (root.join("payer"), root.join("payer-master.key"), None)
    } else {
        let index = usize::from(role == "B");
        scope.update(text(&ready["directory"]).as_bytes());
        scope.update(text(&ready["operators"][index]).as_bytes());
        scope.update(number(&ready["offers"][index]["offer"]).to_be_bytes());
        let node = root.join(format!("chain/node-{index}"));
        (
            node.join("private-wallet"),
            node.join("private-master.key"),
            Some(index),
        )
    };
    let scope: [u8; 32] = scope.finalize().into();
    let key = key(&master)
        .derive(
            if index.is_some() {
                b"operator wallet"
            } else {
                b"payer wallet"
            },
            &scope,
        )
        .unwrap();
    let rows = rows(&path, &key, scope).await;
    let meta: Vec<_> = rows.iter().filter(|(kind, _)| *kind == 0).collect();
    assert!(meta.len() == 1 && raw32(&meta[0].1["scope"]) == scope);
    let mut result = if let Some(index) = index {
        operator(
            &rows, &key, &meta[0].1, ready, index, domain, &origin, &pool, &canonical,
        )
    } else {
        payer(&rows, &key, &meta[0].1, domain, &origin, &pool, &canonical)
    };
    if role == "C" {
        result["transport"] = transport::collect(&rows, &key, &meta[0].1, root);
    }
    crate::storage::publish(
        Path::new(&format!("/evidence/private-accounting-{role}-result.json")),
        &serde_json::to_vec(&result).unwrap(),
    )
    .unwrap();
}

#[expect(
    clippy::too_many_arguments,
    reason = "Explicit immutable fixture authority"
)]
fn operator(
    rows: &[(u8, Value)],
    key: &Key,
    meta: &Value,
    ready: &Value,
    index: usize,
    domain: Domain,
    origin: &[u8; 32],
    pool: &[u8; 47],
    canonical: &Canonical,
) -> Value {
    let channels: Vec<_> = rows.iter().filter(|(kind, _)| *kind == 1).collect();
    assert!(
        channels.len() == 1,
        "expected one private channel per fixture operator"
    );
    let channel = &channels[0].1;
    let tariff = octravpn_core::payments::Tariff::from_bytes(
        &serde_json::from_value::<Vec<u8>>(channel["tariff"].clone()).unwrap(),
    )
    .unwrap();
    let binding = PlanBinding {
        deployment: octravpn_core::payments::Deployment {
            domain: hex::encode(domain.digest()),
            program: octravpn_core::parse_native_address(std::str::from_utf8(pool).unwrap())
                .unwrap(),
        },
        payer: octravpn_core::Address::from_pubkey(&raw32(&channel["receipt_key"])),
        generation: 1,
        plan: number(&channel["id"]),
        offer: number(&channel["offer"]),
        manifest_hash: tariff.hash_hex().unwrap(),
    };
    assert!(binding.offer == number(&ready["offers"][index]["offer"]));
    let purchased = array(&channel["totals"]);
    assert!(purchased == array(&ready["caps"][index]));
    let paid = number(&channel["paid_ou"]);
    assert!(paid == tariff.total_charge(&purchased).unwrap());
    assert!(
        paid <= number(&channel["reserved_ou"])
            && number(&channel["reserved_ou"]) <= number(&channel["budget_ou"])
    );
    let mut income = 0_u64;
    let mut credit_totals = vec![0_u64; purchased.len()];
    let wallet = raw32(&meta["wallet_id"]);
    for (_, credit) in rows.iter().filter(|(kind, _)| *kind == 3) {
        assert!(credit["entitled"] == true);
        let proof = &credit["proof"];
        let commitment = raw32(&proof["commitment"]);
        assert!(canonical.outputs.contains(&hex::encode(commitment)));
        let context = [wallet.as_slice(), &number(&credit["slot"]).to_be_bytes()].concat();
        let seed = key.derive_bytes(b"claimant", &context).unwrap();
        let view = native_stealth::view_secret(&seed);
        let spend = spend(key, &context);
        let call = call(proof, 0, 0);
        let relayer = address(text(&proof["relayer"]));
        let context = call.context(origin, pool, &relayer).unwrap();
        let note = pool::envelope::open(
            domain,
            spend.owner(domain),
            &view,
            &call.boxes[0],
            &context,
            pool::decode_field(&commitment).unwrap(),
        )
        .unwrap();
        let signed = SignedInvoice::decode_private(
            &serde_json::from_value::<Vec<u8>>(credit["invoice"].clone()).unwrap(),
        )
        .unwrap();
        let class = usize::from(signed.invoice.traffic_class);
        assert!(
            class < purchased.len() && signed.invoice.receipt_key == raw32(&channel["receipt_key"])
        );
        assert!(
            signed.invoice.offer == binding.offer
                && signed.invoice.amount_ou().unwrap() == note.value()
        );
        assert!(signed.invoice.rate_ou_per_mib == tariff.classes()[class].rate_ou_per_mib);
        credit_totals[class] = credit_totals[class]
            .checked_add(signed.invoice.bytes)
            .unwrap();
        let nullifier = hex::encode(pool::encode_field(note.nullifier(domain, &spend).unwrap()));
        assert!(!canonical.nullifiers.contains(&nullifier));
        income = income.checked_add(note.value()).unwrap();
    }
    assert!(income == paid && credit_totals == purchased);
    let transport = Path::new("/state/native-vpn")
        .join(format!("chain/node-{index}/private-payments-transport"));
    let files = std::fs::read_dir(transport)
        .unwrap()
        .map(|entry| entry.unwrap().path().join("meter.json"))
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    assert!(files.len() == 1, "expected one encrypted private meter");
    let context = serde_json::to_vec(&(
        1_u8,
        &binding,
        &binding.manifest_hash,
        number(&channel["budget_ou"]),
    ))
    .unwrap();
    let scope: [u8; 32] = Sha256::digest(&context).into();
    let meter = key
        .derive(b"wallet meters", &wallet)
        .unwrap()
        .derive(b"payment meter", &scope)
        .unwrap();
    let encrypted =
        crate::bootstrap::read_limited(&files[0], 131_072 + octravpn_core::sealed::OVERHEAD)
            .unwrap();
    let plain = Protection::new(meter, scope).open(&encrypted).unwrap();
    let meter: Value = serde_json::from_slice(&plain).unwrap();
    assert!(meter["version"] == 3);
    let record = &meter["record"];
    assert!(serde_json::from_value::<PlanBinding>(record["binding"].clone()).unwrap() == binding);
    assert!(array(&record["purchased"]) == purchased);
    let used = array(&record["committed"])
        .into_iter()
        .zip(array(&record["pending"]))
        .zip(array(&record["uncertain"]))
        .map(|((a, b), c)| a.checked_add(b).unwrap().checked_add(c).unwrap())
        .collect::<Vec<_>>();
    assert!(used.len() == purchased.len() && used.iter().zip(&purchased).all(|(a, b)| a <= b));
    json!({"purchased":purchased, "paid_ou":paid,"unspent_income_ou":income,"used":used,
        "committed":record["committed"], "pending":record["pending"], "uncertain":record["uncertain"],
        "connection_sequence":number(&record["connect"]["request"]["sequence"]),
        "service_sequence":record["service_sequence"]})
}

fn payer(
    rows: &[(u8, Value)],
    key: &Key,
    meta: &Value,
    domain: Domain,
    origin: &[u8; 32],
    pool: &[u8; 47],
    canonical: &Canonical,
) -> Value {
    let wallet = raw32(&meta["wallet"]);
    let mut available = 0_u64;
    let mut held = 0_u64;
    for (_, coin) in rows.iter().filter(|(kind, _)| *kind == 1) {
        assert!(
            coin.get("income").is_none(),
            "fixture payer did not consent to imported operator income"
        );
        let creation = &coin["creation"];
        let commitment = raw32(&creation["commitment"]);
        assert!(canonical.outputs.contains(&hex::encode(commitment)));
        let context = [wallet.as_slice(), &number(&coin["slot"]).to_be_bytes()].concat();
        let view = key.derive_bytes(b"view", &context).unwrap();
        let spend = spend(key, &context);
        let saved = &creation["call"];
        let call = call(saved, number(&saved["deposit"]), number(&saved["withdraw"]));
        let context = call
            .context(origin, pool, &address(text(&saved["relayer"])))
            .unwrap();
        let note = pool::envelope::open(
            domain,
            spend.owner(domain),
            &view,
            call.boxes
                .get(usize::try_from(number(&creation["output"])).unwrap())
                .unwrap(),
            &context,
            pool::decode_field(&commitment).unwrap(),
        )
        .unwrap();
        let spent = canonical
            .nullifiers
            .contains(&hex::encode(pool::encode_field(
                note.nullifier(domain, &spend).unwrap(),
            )));
        assert!(coin["spent"] == spent);
        if !spent {
            if coin["reserved"].is_null() {
                available = available.checked_add(note.value()).unwrap();
            } else {
                held = held.checked_add(note.value()).unwrap();
            }
        }
    }
    let banks: Vec<_> = rows.iter().filter(|(kind, _)| *kind == 5).collect();
    assert!(banks.len() == 1);
    let bank = &banks[0].1;
    let attempts = rows.iter().filter(|(kind, _)| *kind == 6).count();
    assert!(number(&bank["count"]) == u64::try_from(attempts).unwrap());
    let reserved = number(&bank["reserved_ou"]);
    assert!(
        reserved
            == number(&bank["policy"]["fee_ou"])
                .checked_mul(number(&bank["count"]))
                .unwrap()
    );
    assert!(reserved <= number(&bank["policy"]["lifetime_budget_ou"]));
    json!({"available_ou":available,"held_ou":held,"native_attempts":attempts,"reserved_fees_ou":reserved})
}
