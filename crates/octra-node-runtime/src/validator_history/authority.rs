//! Finality authority from retained canonical metadata and native relief proofs.
use super::{CanonicalValidators, Environment};
use crate::{
    canonical::{Head, Reader, ReliefSource},
    finality::{EpochRules, ReceiptRules, ValidatorHistory},
};
use num_bigint::BigInt;
use octra_node_protocol::{
    consensus::journal::JournalOwner,
    preverify_commit,
    transaction_policy::{self, Profile},
    validator::config::anchor,
};

/// Captured startup values; replay never re-reads the process environment.
#[derive(Clone)]
pub struct ReceiptPolicy {
    activation: i64,
    crypto_active: bool,
    stealth_minimum: BigInt,
}
impl ReceiptPolicy {
    pub fn new(
        activation: Option<&[u8]>,
        profile: &Profile,
        stealth_minimum: Option<&[u8]>,
    ) -> Self {
        Self {
            activation: preverify_commit::activation(activation),
            crypto_active: profile.private_v1,
            stealth_minimum: transaction_policy::stealth_min_ou(stealth_minimum),
        }
    }
    fn at(&self, epoch: i64) -> ReceiptRules {
        ReceiptRules {
            required: epoch >= self.activation,
            crypto_active: self.crypto_active,
            stealth_minimum: self.stealth_minimum.clone(),
        }
    }
}

pub struct Authority {
    membership: CanonicalValidators,
    receipts: ReceiptPolicy,
    journal: JournalOwner,
}
impl Authority {
    pub fn new(
        reader: Reader,
        environment: Environment,
        receipts: ReceiptPolicy,
        journal: JournalOwner,
    ) -> Self {
        Self {
            membership: CanonicalValidators::new(reader, environment),
            receipts,
            journal,
        }
    }
}
#[async_trait::async_trait]
impl ValidatorHistory for Authority {
    async fn resolve(
        &self,
        parent: &Head,
        epoch: u64,
        evidence: ReliefSource,
    ) -> Result<EpochRules, String> {
        if parent.cursor.epoch.0.checked_add(1) != Some(epoch) {
            return Err("authority epoch is not consecutive".into());
        }
        let epoch = i64::try_from(epoch).map_err(|e| e.to_string())?;
        let config = self
            .membership
            .config(parent)
            .await
            .map_err(|e| e.to_string())?;
        let chain = self.membership.reader.chain().chain_id.as_bytes();
        let diagnostic = |e: Vec<u8>| super::diagnostic(e).to_string();
        // Native selection/cap failures precede any journal read.
        let current =
            anchor::expected_set(chain, &config, epoch, None, &|_| Ok(None)).map_err(diagnostic)?;
        let needed = config
            .scheduled
            .as_ref()
            .is_some_and(|p| epoch < p.activate_epoch);
        let relief = if needed {
            match evidence {
                ReliefSource::Committed(mark) => mark,
                ReliefSource::Journal => {
                    let journal = self.journal.clone();
                    tokio::task::spawn_blocking(move || journal.latest_relief(epoch))
                        .await
                        .map_err(|e| e.to_string())?
                        .map_err(|e| e.to_string())?
                }
            }
        } else {
            None
        };
        let validators = if relief.is_some() {
            // Finalized history uses epoch selection. Pending-lock recovery
            // separately calls CanonicalValidators::expected_set with a round.
            anchor::expected_set(chain, &config, epoch, None, &|_| Ok(relief.clone()))
                .map_err(diagnostic)?
        } else {
            current
        };
        Ok(EpochRules {
            validators,
            receipts: self.receipts.at(epoch),
            relief,
        })
    }
}
