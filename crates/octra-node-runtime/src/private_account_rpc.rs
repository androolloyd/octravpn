//! Native private-account projections over one authenticated canonical snapshot.
//! Public stealth output rows intentionally omit amount and sender_addr.
use crate::{
    private_crypto as crypto,
    private_key::classify::{self, Cipher, Key, Route},
    private_outputs::{self, Output},
    state_batch::Snapshot,
};
use octra_node_protocol::{
    light_rpc::json::{self, array, boolean, number, object, optional, string},
    native_integer::parse_int64,
    private_account_rpc::{self as wire, Page},
    rpc::{self, Fault},
    state_sync::migration::{Admission, Audit, Entry},
    transaction::RuleMode,
};

pub fn public_cipher(raw: &[u8]) -> Result<Vec<u8>, crypto::Error> {
    if raw.is_empty() || raw == b"0" || !raw.starts_with(b"hfhe_v1|") {
        return Ok(raw.to_vec());
    }
    // Adopted serialize_cipher_public is exactly serialize_cipher. The decoder
    // still enforces the native historical reader's cap=true policy.
    crypto::encode_cipher(&crypto::decode_cipher(raw, false, true)?)
}
pub fn encrypted_cipher(address: &[u8], cipher: &[u8]) -> Result<Vec<u8>, Fault> {
    let cipher = public_cipher(cipher)
        .map_err(|_| Fault::new(-32005, b"encrypted ciphertext unavailable"))?;
    if cipher.len() > rpc::MAX_SINGLE {
        return Err(Fault::response_limit());
    }
    let kind: &[u8] = if cipher.starts_with(b"hfhe_v1|") && cipher.len() > 8 {
        b"pvac_fhe".as_slice()
    } else if cipher != b"0" && !cipher.is_empty() {
        b"legacy_aes_gcm"
    } else {
        b"none"
    };
    Ok(object(&[
        ("address", string(address)),
        ("cipher", string(&cipher)),
        ("cipher_type", string(kind)),
    ]))
}
fn output_json(output: &Output) -> Result<Vec<u8>, Fault> {
    let cipher = match public_cipher(&output.delta_cipher_stored) {
        Ok(cipher) => cipher,
        Err(crypto::Error::Rejected(_)) => {
            return Ok(object(&[
                ("id", number(output.id)),
                ("epoch_id", number(output.epoch_id)),
                ("tx_hash", string(&output.tx_hash)),
                (
                    "error",
                    object(&[
                        ("code", number(-32005)),
                        ("message", string(b"encrypted ciphertext unavailable")),
                    ]),
                ),
            ]))
        }
        Err(crypto::Error::Unavailable(_)) => return Err(Fault::new(110, b"service unavailable")),
    };
    Ok(object(&[
        ("id", number(output.id)),
        ("stealth_tag", string(&output.stealth_tag)),
        ("eph_pub", string(&output.eph_pub)),
        ("enc_amount", string(&output.enc_amount)),
        ("epoch_id", number(output.epoch_id)),
        ("tx_hash", string(&output.tx_hash)),
        ("claimed", number(output.claimed)),
        ("claim_pub", string(&output.claim_pub)),
        ("delta_cipher_stored", string(cipher)),
        ("amount_hash", string(&output.amount_hash)),
        ("amount_commitment", string(&output.amount_commitment)),
    ]))
}
fn output(state: &Snapshot, id: i64) -> Result<Option<Output>, Fault> {
    match state.get(&[b"stealth", id.to_string().as_bytes()]) {
        None => Ok(None),
        Some(raw) => private_outputs::Output::parse(raw, id.wrapping_shl(1) >> 1)
            .map_err(|_| Fault::new(110, b"service unavailable")),
    }
}
pub fn outputs_page(state: &Snapshot, page: Page) -> Result<Vec<u8>, Fault> {
    let latest = match state.get(&[b"index", b"stealth_counter"]) {
        None => 0,
        Some(raw) => parse_int64(raw).ok_or_else(|| Fault::new(110, b"service unavailable"))?,
    };
    let mut cursor = page.before_id.unwrap_or(latest).max(0).min(latest);
    let limit = page.limit.clamp(1, 256);
    let scan_limit = (limit * 8).clamp(256, 2048);
    let mut outputs = Vec::new();
    let mut scanned = 0;
    let mut remaining = rpc::MAX_SINGLE;
    let more = loop {
        if cursor <= 0 {
            break false;
        }
        if outputs.len() >= limit || scanned >= scan_limit {
            break true;
        }
        cursor -= 1;
        scanned += 1;
        let Some(row) = output(state, cursor)? else {
            continue;
        };
        if row.epoch_id < page.from_epoch {
            break false;
        }
        let projected = output_json(&row)?;
        remaining = remaining
            .checked_sub(projected.len().saturating_add(1))
            .ok_or_else(Fault::response_limit)?;
        outputs.push(projected);
    };
    outputs.reverse();
    Ok(wire::page_response(
        page,
        outputs,
        more.then_some(cursor),
        more,
        scanned,
    ))
}
pub fn outputs_by_id(state: &Snapshot, ids: &[i64]) -> Result<Vec<u8>, Fault> {
    let mut outputs = Vec::new();
    let mut remaining = rpc::MAX_SINGLE;
    for id in ids {
        if let Some(row) = output(state, *id)? {
            let projected = output_json(&row)?;
            remaining = remaining
                .checked_sub(projected.len().saturating_add(1))
                .ok_or_else(Fault::response_limit)?;
            outputs.push(projected);
        }
    }
    Ok(wire::ids_response(ids.len(), outputs))
}

#[derive(Clone, Copy)]
pub struct MigrationRules {
    pub epoch: i64,
    pub owner: RuleMode,
    pub cipher: RuleMode,
    pub proof: RuleMode,
    pub math: bool,
}
/// A classification produced only by the bounded native migration actor.
pub struct Classified(pub(crate) classify::Status);
enum Replay<'a> {
    NotRequired,
    Unavailable,
    NotActive,
    NotFound,
    CipherMismatch,
    Ready(&'a Entry),
}
impl Replay<'_> {
    fn status(&self) -> &'static [u8] {
        match self {
            Self::NotRequired => b"not_required",
            Self::Unavailable => b"unavailable",
            Self::NotActive => b"not_active",
            Self::NotFound => b"not_found",
            Self::CipherMismatch => b"cipher_mismatch",
            Self::Ready(_) => b"ready",
        }
    }
    fn json(&self) -> Vec<u8> {
        if matches!(self, Self::NotRequired) {
            return json::null();
        }
        if let Self::Ready(entry) = self {
            let audit = match entry.audit {
                Audit::PublicClean => b"public_clean".as_slice(),
                Audit::HiddenWitness => b"hidden_witness",
                Audit::Poisoned => b"poisoned",
            };
            return object(&[
                ("admission_status", string(b"ready")),
                ("total", number(entry.total)),
                ("scanned", number(entry.total)),
                ("complete", boolean(true)),
                ("audit_class", string(audit)),
                ("can_public_migrate", boolean(entry.can_public_migrate)),
                (
                    "public_net",
                    entry
                        .public_net
                        .as_ref()
                        .map_or_else(json::null, |value| string(value.to_string())),
                ),
                ("commitment_net", optional(entry.commitment_net.as_deref())),
                ("blockers", array(entry.blockers.iter().map(string))),
                ("reason", string(&entry.reason)),
            ]);
        }
        let reason = match self {
            Self::Unavailable => b"migration records unavailable".as_slice(),
            Self::NotActive => b"migration records not active",
            Self::NotFound => b"migration record not found",
            Self::CipherMismatch => b"migration record ciphertext mismatch",
            _ => unreachable!(),
        };
        object(&[
            ("total", number(0)),
            ("scanned", number(0)),
            ("complete", boolean(false)),
            ("admission_status", string(self.status())),
            ("audit_class", string(b"unavailable")),
            ("can_public_migrate", boolean(false)),
            ("public_net", json::null()),
            ("commitment_net", json::null()),
            ("blockers", array([string(reason)])),
            ("reason", string(reason)),
        ])
    }
}
pub fn migration_status(
    address: &[u8],
    cipher: &[u8],
    classified: Classified,
    rules: MigrationRules,
    admission: Option<&Admission>,
) -> Result<Vec<u8>, Fault> {
    let status = classified.0;
    let history =
        status.history(rules.cipher == RuleMode::Active && rules.proof == RuleMode::Active);
    let replay = if history {
        match admission {
            None => Replay::Unavailable,
            Some(admission) => match admission.find(rules.epoch, address, cipher) {
                Ok(entry) => Replay::Ready(entry),
                Err(error) => match error.as_bytes() {
                    b"migration entitlement is not active" => Replay::NotActive,
                    b"migration entitlement not found" => Replay::NotFound,
                    b"migration entitlement source ciphertext mismatch" => Replay::CipherMismatch,
                    _ => return Err(Fault::new(-32005, b"pvac migration status unavailable")),
                },
            },
        }
    } else {
        Replay::NotRequired
    };
    let owner = rules.owner == RuleMode::Active
        && status.cipher == Cipher::Proven
        && status.key == Key::Historical
        && matches!(&replay,Replay::Ready(entry) if entry.audit!=Audit::Poisoned&&entry.commitment_net.is_some());
    let cipher_proof = rules.cipher == RuleMode::Active
        && rules.proof == RuleMode::Active
        && status.cipher == Cipher::Proven
        && status.key == Key::Historical;
    let (cipher_class, format) = match status.cipher {
        Cipher::Empty => (b"empty".as_slice(), b"empty".as_slice()),
        Cipher::Proven => (b"v3".as_slice(), b"proven".as_slice()),
        Cipher::Legacy => (b"legacy_hfhe".as_slice(), b"historical".as_slice()),
        Cipher::Foreign => (b"foreign".as_slice(), b"foreign".as_slice()),
        Cipher::Malformed => (b"malformed".as_slice(), b"malformed".as_slice()),
    };
    let key_class = match status.key {
        Key::Current => b"current".as_slice(),
        Key::Historical => b"historical",
        Key::Missing => b"missing",
        Key::Malformed => b"malformed",
    };
    let route = match status.route {
        Route::Direct => b"direct_key_switch".as_slice(),
        Route::Bound => b"bound_migration",
        Route::History => b"history_migration",
        Route::Blocked => b"blocked",
    };
    let root = || optional(admission.map(Admission::root));
    let activation = || admission.map_or_else(json::null, |value| number(value.activation_epoch()));
    let snapshot = || admission.map_or_else(json::null, |value| number(value.snapshot_epoch()));
    let state_root = || optional(admission.map(Admission::state_root));
    Ok(object(&[
        ("address", string(address)),
        (
            "proof_math",
            string(if rules.math {
                b"wide".as_slice()
            } else {
                b"prior"
            }),
        ),
        ("cipher_format", string(format)),
        ("history_recovery", boolean(history)),
        ("cipher_class", string(cipher_class)),
        ("key_class", string(key_class)),
        ("target_key_class", string(b"current")),
        ("migration_route", string(route)),
        ("can_key_switch", boolean(status.route == Route::Direct)),
        ("can_v3_migrate", boolean(status.route == Route::Bound)),
        ("can_owner_proof_migrate", boolean(owner)),
        ("can_cipher_proof_migrate", boolean(cipher_proof)),
        (
            "cipher_proof_rule",
            string(if rules.cipher == RuleMode::Active {
                b"active".as_slice()
            } else {
                b"prior"
            }),
        ),
        (
            "owner_migration_authority",
            string(if owner {
                b"finalized_history_commitment".as_slice()
            } else {
                b"unavailable"
            }),
        ),
        (
            "owner_proof_rule",
            string(if rules.owner == RuleMode::Active {
                b"active".as_slice()
            } else {
                b"prior"
            }),
        ),
        (
            "needs_legacy_public_replay",
            boolean(status.route == Route::History),
        ),
        ("reason", string(status.reason)),
        (
            "migration_record",
            object(&[
                ("root", root()),
                ("activation_epoch", activation()),
                ("snapshot_epoch", snapshot()),
                ("state_root", state_root()),
                ("count", number(admission.map_or(0, Admission::len))),
                ("status", string(replay.status())),
            ]),
        ),
        ("entitlement_root", root()),
        ("entitlement_activation_epoch", activation()),
        ("entitlement_snapshot_epoch", snapshot()),
        ("entitlement_state_root", state_root()),
        ("legacy_public_replay", replay.json()),
    ]))
}
