//! Native duty eligibility and the durable local exit-intent switch.
use crate::{validator_control::Control, validator_duty::post::Eligibility};
use octra_node_protocol::{
    control_payload::BondedReady,
    duty,
    transaction::{RuleMode, Transaction},
    validator::{admission::Candidate, intent::Identity},
};
pub struct Enrollment<'a> {
    pub chain_id: &'a [u8],
    pub head_epoch: i64,
    pub candidate: Option<&'a Candidate>,
}
pub fn eligible(
    mode: RuleMode,
    head: i64,
    bonded_epoch: i64,
    snapshot: Result<Enrollment<'_>, &str>,
    tx: &Transaction,
) -> Eligibility {
    if head < 0 {
        Eligibility::Paused
    } else if duty::expired(tx, Some(head), mode) {
        Eligibility::Expired
    } else {
        match BondedReady::parse(tx.message.as_deref()) {
            Err(_) => Eligibility::Expired,
            Ok(ready) if ready.head_epoch > head => Eligibility::Paused,
            Ok(_) => match snapshot {
                Ok(snapshot) if snapshot.head_epoch == head => match snapshot.candidate {
                    Some(candidate)
                        if candidate.bonded_epoch == bonded_epoch
                            && candidate.exit_epoch.is_none() =>
                    {
                        Eligibility::Eligible
                    }
                    _ => Eligibility::Expired,
                },
                _ => Eligibility::Eligible,
            },
        }
    }
}
pub fn bonded(
    control: &Control,
    address: &[u8],
    pubkey: &[u8],
    snapshot: Result<Enrollment<'_>, String>,
) -> Result<bool, String> {
    let snapshot = snapshot?;
    match snapshot.candidate {
        None => Ok(false),
        Some(candidate) if candidate.exit_epoch.is_some() => Ok(false),
        Some(candidate) => control
            .status(&Identity {
                chain_id: snapshot.chain_id.to_vec(),
                address: address.to_vec(),
                pubkey: pubkey.to_vec(),
                bonded_epoch: candidate.bonded_epoch,
            })
            .map(|value| value.is_none())
            .map_err(|e| e.to_string()),
    }
}
