// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native public account and transaction reads from one committed tree.
use super::{account_store, rpc, Arc, Context, Document, Fault, StateBatch, Transaction, Value};
use num_bigint::BigInt;
use octra_node_protocol::{
    native_integer::parse_integer,
    state::{Account, MAX_SUPPLY},
    transaction::{is_valid_address, json_string, native_float, OpType},
};
use octra_node_runtime::staging::{DropReason, DropRecord, QueueState};

mod history;
pub(super) mod rest;

fn unavailable(_: impl std::fmt::Display) -> Fault {
    Fault::new(110, b"service unavailable")
}
fn string(value: impl AsRef<[u8]>) -> Vec<u8> {
    let mut raw = Vec::new();
    json_string(&mut raw, value.as_ref());
    raw
}
#[allow(clippy::needless_pass_by_value)] // Keep the shared serializer API for owned numbers and borrowed values.
fn number(value: impl ToString) -> Vec<u8> {
    value.to_string().into_bytes()
}
fn boolean(value: bool) -> Vec<u8> {
    number(value)
}
fn object(fields: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut raw = vec![b'{'];
    for (index, (name, value)) in fields.iter().enumerate() {
        if index != 0 {
            raw.push(b',');
        }
        json_string(&mut raw, name.as_bytes());
        raw.push(b':');
        raw.extend_from_slice(value);
    }
    raw.push(b'}');
    raw
}
fn array(values: impl IntoIterator<Item = Vec<u8>>) -> Vec<u8> {
    let mut raw = vec![b'['];
    for (index, value) in values.into_iter().enumerate() {
        if index != 0 {
            raw.push(b',');
        }
        raw.extend(value);
    }
    raw.push(b']');
    raw
}
fn balance(value: &BigInt) -> Vec<u8> {
    let unit = BigInt::from(1_000_000);
    let whole = value / &unit;
    let remainder = value % &unit;
    if remainder == BigInt::from(0) {
        whole.to_string().into_bytes()
    } else {
        format!("{whole}.{remainder:06}").into_bytes()
    }
}
fn float(value: f64) -> std::result::Result<Vec<u8>, Fault> {
    native_float(value)
        .map(String::into_bytes)
        .map_err(unavailable)
}
fn counter(value: i64) -> i64 {
    value.wrapping_shl(1) >> 1
}
fn load(
    node: &dyn crate::rpc::context::ReadNode,
    view: &crate::Committed,
    address: &[u8],
) -> std::result::Result<Account, Fault> {
    node.account_for_read(
        address,
        account_store::load(&StateBatch::from_snapshot(view.state().clone()), address)
            .map_err(unavailable)?,
    )
    .map_err(unavailable)?
    .ok_or_else(|| Fault::new(100, b"sender not found"))
}

pub(super) async fn read(
    host: &Arc<Context>,
    method: &[u8],
    doc: &Document,
    params: &Value,
) -> std::result::Result<Vec<u8>, Fault> {
    match method {
        b"octra_validateAddress" => {
            let address = rpc::require_string(doc, params, 0, "address")?;
            let valid = is_valid_address(address);
            let error = if valid {
                b"null".to_vec()
            } else if !address.starts_with(b"oct") {
                string(b"must start with 'oct'")
            } else if address.len() != 47 {
                string(format!("expected length 47, got {}", address.len()))
            } else {
                string(b"invalid base58 characters")
            };
            Ok(object(&[
                ("address", string(address)),
                ("valid", boolean(valid)),
                ("error", error),
            ]))
        }
        b"octra_balance" | b"octra_nonce" | b"octra_publicKey" => {
            let address = rpc::require_address(doc, params, 0, "address")?.to_vec();
            let view = host.node.snapshot().map_err(unavailable)?;
            let pending = host.pending.clone();
            let method = method.to_vec();
            let node = host.node.clone();
            host.executor
                .read(move || {
                    let account = load(node.as_ref(), &view, &address)?;
                    match method.as_slice() {
                        b"octra_balance" => {
                            let nonce = pending
                                .inspect(|pool| pool.pending_nonce(&address, account.nonce))
                                .map_err(unavailable)?;
                            Ok(object(&[
                                ("address", string(&address)),
                                ("balance", string(balance(&account.balance))),
                                ("balance_raw", string(account.balance.to_string())),
                                ("nonce", number(account.nonce.get())),
                                ("pending_nonce", number(nonce.get())),
                                ("has_public_key", boolean(account.public_key.is_some())),
                            ]))
                        }
                        b"octra_nonce" => Ok(object(&[
                            ("address", string(&address)),
                            ("nonce", number(account.nonce.get())),
                        ])),
                        _ => Ok(object(&[
                            ("address", string(&address)),
                            (
                                "public_key",
                                string(account.public_key.as_deref().ok_or_else(|| {
                                    Fault::new(112, b"not found")
                                        .string_data(b"no public key registered")
                                })?),
                            ),
                        ])),
                    }
                })
                .await
        }
        b"octra_supply" => {
            let view = host.node.snapshot().map_err(unavailable)?;
            let policy = host.executor.emission_policy();
            let legacy = if policy.emission_guard {
                policy.legacy_total.clone()
            } else {
                None
            };
            host.executor
                .read(move || supply(&view, legacy.as_deref()))
                .await
        }
        b"octra_totalTransactions" => {
            let head = host.node.head().await.map_err(unavailable)?;
            let confirmed = counter(head.txid_hi.wrapping_add(1));
            let pending = host.pending.clone();
            host.executor
                .read(move || {
                    let staging = pending
                        .inspect(octra_node_runtime::staging::Pool::len)
                        .map_err(unavailable)? as i64;
                    Ok(object(&[
                        ("confirmed", number(confirmed)),
                        ("staging", number(staging)),
                        ("total", number(counter(confirmed.wrapping_add(staging)))),
                    ]))
                })
                .await
        }
        b"octra_transaction" => transaction(host, doc, params).await,
        b"octra_account"
        | b"octra_transactions"
        | b"octra_recentTransactions"
        | b"octra_transactionsByAddress"
        | b"octra_tokenTransfersByAddress"
        | b"octra_rejectedByAddress"
        | b"octra_transactionsByEpoch" => history::read(host, method, doc, params).await,
        _ => Err(Fault::missing(method)),
    }
}

fn supply(view: &crate::Committed, legacy: Option<&[u8]>) -> std::result::Result<Vec<u8>, Fault> {
    let ledger = account_store::ledger(&StateBatch::from_snapshot(view.state().clone()))
        .map_err(unavailable)?;
    let amount = |key: &[u8], optional: bool| match view
        .state()
        .get(&[b"meta", key])
        .or(if key == b"total_supply" { legacy } else { None })
    {
        Some(raw) => parse_integer(raw)
            .filter(|n| n >= &BigInt::from(0))
            .ok_or_else(|| Fault::new(111, b"supply violation")),
        None if optional => Ok(BigInt::from(0)),
        None => Err(Fault::new(110, b"service unavailable")),
    };
    let total = amount(b"total_supply", false)?;
    let maximum = BigInt::from(MAX_SUPPLY);
    if total < *ledger.total_supply() || total > maximum {
        return Err(Fault::new(111, b"supply violation"));
    }
    let hidden = &total - ledger.total_supply();
    let remaining = &maximum - &total;
    let emission = amount(b"emission_remaining", true)?;
    let retired = amount(b"supply_retired", true)?;
    Ok(object(&[
        ("total_supply", string(balance(&total))),
        ("total_supply_raw", string(total.to_string())),
        ("circulating_supply", string(balance(&total))),
        ("circulating_supply_raw", string(total.to_string())),
        ("encrypted_supply", string(balance(&hidden))),
        ("encrypted_supply_raw", string(hidden.to_string())),
        ("max_supply", string(balance(&maximum))),
        ("max_supply_raw", string(maximum.to_string())),
        ("supply_remaining", string(balance(&remaining))),
        ("supply_remaining_raw", string(remaining.to_string())),
        ("emission_remaining", string(balance(&emission))),
        ("emission_remaining_raw", string(emission.to_string())),
        ("retired_supply", string(balance(&retired))),
        ("retired_supply_raw", string(retired.to_string())),
    ]))
}

fn display_from(tx: &Transaction) -> &[u8] {
    if matches!(tx.op_type, OpType::Stealth | OpType::Claim) {
        b"-"
    } else {
        &tx.from
    }
}
fn display_to(tx: &Transaction) -> &[u8] {
    if tx.op_type == OpType::Claim {
        b"-"
    } else {
        &tx.to
    }
}
fn message(tx: &Transaction) -> std::result::Result<Vec<u8>, Fault> {
    let Some(raw) = &tx.message else {
        return Ok(b"null".to_vec());
    };
    if tx.op_type == OpType::CircleProgramUpdate {
        return Ok(b"null".to_vec());
    }
    let decoded = if raw.len() % 2 == 0 && raw.iter().all(u8::is_ascii_hexdigit) {
        hex::decode(raw).map_err(unavailable)?
    } else {
        raw.clone()
    };
    if tx.op_type == OpType::CircleDeploy {
        let Ok(doc) = Document::parse(&decoded) else {
            return Ok(b"null".to_vec());
        };
        let Value::Object(fields) = doc.root() else {
            return Ok(b"null".to_vec());
        };
        let privacy = fields
            .iter()
            .filter(|(key, _)| key == b"privacy_class")
            .map(|(_, id)| doc.get(*id))
            .collect::<Vec<_>>();
        if !matches!(privacy.as_slice(),[Some(Value::String(value))] if value==b"public") {
            return Ok(b"null".to_vec());
        }
    }
    Ok(string(decoded))
}
fn fields(tx: &Transaction) -> std::result::Result<Vec<(&'static str, Vec<u8>)>, Fault> {
    fields_with_message(tx, message(tx)?)
}
fn fields_with_message(
    tx: &Transaction,
    message: Vec<u8>,
) -> std::result::Result<Vec<(&'static str, Vec<u8>)>, Fault> {
    Ok(vec![
        ("from", string(display_from(tx))),
        ("to", string(display_to(tx))),
        ("amount", string(balance(&tx.amount))),
        ("amount_raw", string(tx.amount.to_string())),
        ("nonce", number(tx.nonce.get())),
        ("ou", string(tx.ou.to_string())),
        ("timestamp", float(tx.timestamp)?),
        ("op_type", string(tx.op_type.as_str())),
        ("message", message),
    ])
}
fn queue(state: Option<QueueState>) -> std::result::Result<Vec<(&'static str, Vec<u8>)>, Fault> {
    Ok(match state {
        None => vec![],
        Some(QueueState::Ready { expires_at }) => vec![
            ("stage_status", string(b"ready")),
            ("expires_at", float(expires_at)?),
        ],
        Some(QueueState::WaitNonce {
            expected,
            expires_at,
        }) => vec![
            ("stage_status", string(b"waiting_nonce")),
            ("waiting_for_nonce", number(expected.get())),
            ("expires_at", float(expires_at)?),
        ],
        Some(QueueState::NonceUsed {
            confirmed,
            expires_at,
        }) => vec![
            ("stage_status", string(b"nonce_used")),
            ("confirmed_nonce", number(confirmed.get())),
            ("expires_at", float(expires_at)?),
        ],
    })
}
fn dropped(row: &DropRecord) -> std::result::Result<Vec<u8>, Fault> {
    let from = if matches!(row.operation, OpType::Stealth | OpType::Claim) {
        b"-".as_slice()
    } else {
        &row.from
    };
    let to = if row.operation == OpType::Claim {
        b"-".as_slice()
    } else {
        &row.to
    };
    Ok(object(&[
        ("status", string(b"dropped")),
        ("tx_hash", string(&row.hash)),
        (
            "reason",
            string(match row.reason {
                DropReason::Evicted => b"evicted".as_slice(),
                DropReason::Expired => b"expired",
            }),
        ),
        ("detail", string(&row.detail)),
        ("dropped_at", float(row.timestamp)?),
        ("from", string(from)),
        ("to_", string(to)),
        ("nonce", number(row.nonce.get())),
        ("ou", string(row.ou.to_string())),
        ("op_type", string(row.operation.as_str())),
    ]))
}
async fn transaction(
    host: &Arc<Context>,
    doc: &Document,
    params: &Value,
) -> std::result::Result<Vec<u8>, Fault> {
    let hash = rpc::require_hash(doc, params, 0, "hash")?.to_vec();
    let pending = host.pending.clone();
    let view = host.node.snapshot().map_err(unavailable)?;
    let query = hash.clone();
    let result = host
        .executor
        .read(move || {
            let transaction = pending
                .inspect(|pool| pool.find(&query).cloned())
                .map_err(unavailable)?;
            match transaction {
                None => Ok(None),
                Some(tx) => {
                    let confirmed = account_store::load(
                        &StateBatch::from_snapshot(view.state().clone()),
                        &tx.from,
                    )
                    .map_err(unavailable)?
                    .map(|account| account.nonce);
                    let state = pending
                        .inspect(|pool| confirmed.and_then(|nonce| pool.queue_state(&query, nonce)))
                        .map_err(unavailable)?;
                    let mut values = vec![
                        ("status", string(b"pending")),
                        ("tx_hash", string(&query)),
                        ("epoch", b"null".to_vec()),
                    ];
                    values.extend(queue(state)?);
                    values.extend(fields(&tx)?);
                    Ok(Some(object(&values)))
                }
            }
        })
        .await?;
    if let Some(result) = result {
        return Ok(result);
    }
    let head = host.node.head().await.map_err(unavailable)?;
    if let Some((epoch, record)) = host
        .node
        .reader()
        .transaction(&head, &hash, i64::MAX as usize - 1)
        .await
        .map_err(unavailable)?
    {
        let tx =
            Transaction::from_document(&Document::parse(&record.transaction).map_err(unavailable)?)
                .map_err(unavailable)?;
        let mut values = vec![
            ("status", string(b"confirmed")),
            ("tx_hash", string(&hash)),
            ("epoch", number(epoch.cursor.epoch.0)),
        ];
        values.extend(fields(&tx)?);
        return Ok(object(&values));
    }
    if let Some(row) = history::rejected_hash(host, &head, &hash).await? {
        return Ok(row);
    }
    let pending = host.pending.clone();
    let drop_hash = hash.clone();
    let row = host
        .executor
        .read(move || {
            pending.dropped(&drop_hash).map_err(|_| {
                let mut fault = Fault::new(110, b"service unavailable");
                fault.data = Some(object(&[
                    ("hash", string(&drop_hash)),
                    ("dropped_status", string(b"unavailable")),
                ]));
                fault
            })
        })
        .await?;
    match row {
        Some(row) => dropped(&row),
        None => Err(Fault::new(112, b"not found").string_data(b"transaction not found")),
    }
}
