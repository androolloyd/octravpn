//! Proposal framing bound to canonical history. This does not attest execution
//! or authorize a vote: local proofs, receipts and both replay passes follow it.
use super::{invalid, EpochRules, Error, Publisher, Result, ValidatorHistory};
use crate::{canonical::Head, execution_rules::Bound};
use octra_node_protocol::{
    consensus::{driver_policy, hash, parent, policy, qc, ParentCommit, Proposal},
    rules::Graph,
};
mod build;
pub use build::BuildContext;

/// Trusted startup inputs. A genesis timestamp must come from the chain's
/// genesis data; local database commit dates are never consensus timestamps.
#[derive(Clone, Copy)]
pub struct Policy {
    pub protocol: policy::Protocol,
    pub genesis_time: Option<f64>,
}

/// Only Publisher can create this context. In particular its Bound has no
/// finalized authority, so it cannot enter the certified private replay path.
pub struct Authenticated {
    parent: Head,
    proposal: Proposal,
    rules: Bound,
    authority: EpochRules,
}
impl Authenticated {
    pub fn parent(&self) -> &Head {
        &self.parent
    }
    pub fn proposal(&self) -> &Proposal {
        &self.proposal
    }
    pub fn rules(&self) -> &Bound {
        &self.rules
    }
    pub fn authority(&self) -> &EpochRules {
        &self.authority
    }
}

impl<A: ValidatorHistory> Publisher<A> {
    /// Authenticate an immutable candidate at the current canonical parent.
    /// Callers must recheck freshness before voting after asynchronous execution.
    pub async fn authenticate_proposal(
        &self,
        base: &Head,
        proposal: &Proposal,
        graph: &Graph,
        policy: Policy,
        now: f64,
    ) -> Result<Authenticated> {
        self.proposal_parent_current(base).await?;
        let epoch =
            u64::try_from(proposal.epoch_id).map_err(|_| invalid("proposal epoch is invalid"))?;
        if base.cursor.epoch.0.checked_add(1) != Some(epoch) || proposal.epoch_id >= 1_i64 << 62 {
            return Err(invalid("proposal is not consecutive"));
        }
        let chain = self.store.chain();
        if graph.chain_id() != chain.chain_id.as_bytes() {
            return Err(invalid("execution graph differs from canonical chain"));
        }
        let authority = self.rules(base, epoch).await?;
        if let Some(reason) = driver_policy::validate_proposal_frame(
            chain.chain_id.as_bytes(),
            &authority.validators,
            policy.protocol,
            proposal,
        )
        .map_err(invalid)?
        {
            return Err(invalid(format!("proposal frame: {}", reason.label())));
        }
        let expected = self.proposal_parent(base, policy).await?;
        check_parent(expected.as_ref(), proposal.parent_commit.as_ref())?;
        let previous = expected
            .as_ref()
            .map(|p| p.certificate.header.ts)
            .or(policy.genesis_time)
            .ok_or_else(|| Error::Unavailable("previous_epoch_time_unavailable".into()))?;
        let previous = policy::time_of_seconds(previous).map_err(invalid)?;
        policy::check_proposal_time(
            policy::time_rule(chain.chain_id.as_bytes(), proposal.epoch_id),
            if proposal.valid_round.is_some() {
                policy::ProposalKind::Reproposal
            } else {
                policy::ProposalKind::Fresh
            },
            now,
            Some(previous),
            proposal.header.ts,
        )
        .map_err(invalid)?;
        if proposal.header.prev_state_root != base.cursor.state_root.0 {
            return Err(invalid("proposal previous root mismatch"));
        }
        let legacy = authority
            .validators
            .validators
            .iter()
            .map(|v| v.address.clone())
            .collect::<Vec<_>>();
        let rules = Bound::canonical_header(
            graph,
            base,
            &proposal.header,
            proposal.parent_commit.clone(),
            &legacy,
            self,
        )
        .await
        .map_err(|e| Error::Authority(e.to_string()))?;
        self.proposal_parent_current(base).await?;
        Ok(Authenticated {
            parent: base.clone(),
            proposal: proposal.clone(),
            rules,
            authority,
        })
    }

    async fn proposal_parent(&self, base: &Head, policy: Policy) -> Result<Option<ParentCommit>> {
        if base.cursor.epoch.0 == 0 {
            let epoch = i64::try_from(base.cursor.epoch.0 + 1).map_err(invalid)?;
            if epoch >= policy.protocol.activation_epoch() {
                return Err(invalid("parent finality entry is missing"));
            }
            Ok(None)
        } else {
            // record() reauthenticates the retained QC against its own local
            // activation history, not against the candidate's advertised set.
            let record = self.record(base.cursor.sequence).await?;
            let proof = record
                .finality
                .ok_or_else(|| invalid("parent commit journal is missing"))?;
            Ok(Some(ParentCommit {
                certificate: proof.finalize.certificate(),
                validator_set: proof.validator_set,
            }))
        }
    }

    async fn proposal_parent_current(&self, base: &Head) -> Result<()> {
        if self.store.head().await? != *base {
            return Err(Error::Unavailable(
                "proposal parent is no longer current".into(),
            ));
        }
        Ok(())
    }
}

fn check_parent(expected: Option<&ParentCommit>, incoming: Option<&ParentCommit>) -> Result<()> {
    match (expected, incoming) {
        (None, None) => Ok(()),
        (None, Some(_)) => Err(invalid("unexpected parent commit")),
        (Some(_), None) => Err(invalid("parent commit is missing")),
        (Some(expected), Some(incoming)) => {
            let certificate = &expected.certificate;
            qc::validate_parent(
                &qc::ExpectedParent {
                    chain_id: certificate.chain_id.clone(),
                    epoch_id: certificate.epoch_id,
                    proposal_id: certificate.proposal_id.clone(),
                    state_root: certificate.header.proposed_state_root.clone(),
                    validator_set_hash: hash::validator_set_hash(&expected.validator_set)
                        .map_err(invalid)?
                        .to_vec(),
                },
                incoming,
            )
            .map_err(|e| invalid(format!("invalid parent commit: {e}")))?;
            if !parent::same_block(incoming, expected) {
                return Err(invalid("parent commit does not match local finality"));
            }
            Ok(())
        }
    }
}
