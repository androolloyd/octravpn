//! Native validator-duty proof shape and admission expiry. This layer decodes
//! proofs; consensus authentication still uses the validator set and finality.
use crate::{
    consensus::{
        codec::Wire,
        types::{ParentCommit, Vote},
    },
    control_payload::BondedReady,
    native_json::{Document, Value},
    transaction::{decode_base64, Error, OpType, RuleMode, Transaction},
};
use base64::{engine::general_purpose::STANDARD, Engine};
#[derive(Clone, Debug)]
pub struct Proof {
    pub vote: Vote,
    pub commit: ParentCommit,
}
fn decode(label: &str, limit: usize, value: &[u8]) -> Result<Vec<u8>, Error> {
    if value.len() > limit {
        return Err(Error(format!("{label} exceeds size limit")));
    }
    let raw = decode_base64(value).map_err(|_| Error(format!("{label} is not base64")))?;
    if STANDARD.encode(&raw).as_bytes() != value {
        return Err(Error(format!("{label} base64 is not exact")));
    }
    Ok(raw)
}
pub fn proof_of_message(message: Option<&[u8]>) -> Result<Option<Proof>, Error> {
    let raw = message.ok_or_else(|| Error("validator duty message is missing".into()))?;
    let doc = Document::parse(raw)
        .map_err(|_| Error("validator duty message encoding is invalid".into()))?;
    let Value::Object(fields) = doc.root() else {
        return Err(Error("validator duty message has wrong type".into()));
    };
    let mut names = std::collections::BTreeSet::new();
    for (name, _) in fields {
        if !names.insert(name) {
            return Err(Error(format!(
                "validator duty field is duplicated: {}",
                String::from_utf8_lossy(name)
            )));
        }
    }
    match (
        doc.field(doc.root(), b"duty_vote"),
        doc.field(doc.root(), b"duty_commit"),
    ) {
        (None, None) => Ok(None),
        (Some(Value::String(vote)), Some(Value::String(commit))) => {
            let vote = decode("validator duty vote", 4096, vote)?;
            let commit = decode("validator duty commit", 1_000_000, commit)?;
            let vote = Vote::decode(&vote)
                .map_err(|_| Error("validator duty proof encoding is invalid".into()))?;
            let commit = ParentCommit::decode(&commit)
                .map_err(|_| Error("validator duty proof encoding is invalid".into()))?;
            Ok(Some(Proof { vote, commit }))
        }
        (Some(_), Some(_)) => Err(Error("validator duty proof fields have wrong type".into())),
        _ => Err(Error("validator duty proof is incomplete".into())),
    }
}
pub fn ready_expired(head: i64, reference: i64) -> bool {
    reference < 0 || head < 0 || reference <= head && head.wrapping_sub(reference) > 2
}
pub fn expired(tx: &Transaction, head: Option<i64>, mode: RuleMode) -> bool {
    let Some(head) = head.filter(|_| tx.op_type == OpType::ValidatorReady) else {
        return false;
    };
    match BondedReady::parse(tx.message.as_deref()) {
        Ok(ready) => match mode {
            RuleMode::Prior => ready.head_epoch < head,
            RuleMode::Active => {
                ready.head_proposal_id.is_none()
                    || ready_expired(head, ready.head_epoch)
                    || match proof_of_message(tx.message.as_deref()) {
                        Err(_) => true,
                        Ok(None) => false,
                        Ok(Some(proof)) => {
                            proof.vote.epoch_id < 0
                                || proof.vote.epoch_id <= head
                                    && head.wrapping_sub(proof.vote.epoch_id) >= 16
                        }
                    }
            }
        },
        Err(_) => mode == RuleMode::Active,
    }
}
