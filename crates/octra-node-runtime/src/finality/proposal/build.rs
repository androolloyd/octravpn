//! Bind local proposal construction to the same canonical history as verification.
use super::{
    invalid, policy, Bound, EpochRules, Error, Graph, ParentCommit, Policy, Publisher, Result,
    ValidatorHistory,
};
use crate::canonical::Head;
use octra_node_protocol::consensus::{
    engine::tx_list_hash_for_header, hash, EpochHeader, LEGACY_VERSION, NIL,
};

/// Captured before speculative execution. The header has empty commitments;
/// execution must replace them before the driver signs anything. This context
/// grants neither finality authority nor permission to vote.
pub struct BuildContext {
    parent: Head,
    header: EpochHeader,
    parent_commit: Option<ParentCommit>,
    rules: Bound,
    authority: EpochRules,
}
impl BuildContext {
    pub fn parent(&self) -> &Head {
        &self.parent
    }
    pub fn header(&self) -> &EpochHeader {
        &self.header
    }
    pub fn parent_commit(&self) -> Option<&ParentCommit> {
        self.parent_commit.as_ref()
    }
    pub fn rules(&self) -> &Bound {
        &self.rules
    }
    pub fn authority(&self) -> &EpochRules {
        &self.authority
    }
}

impl<A: ValidatorHistory> Publisher<A> {
    pub async fn proposal_build_context(
        &self,
        base: &Head,
        graph: &Graph,
        policy: Policy,
        creator: &[u8],
        now: f64,
    ) -> Result<BuildContext> {
        self.proposal_parent_current(base).await?;
        let epoch = base
            .cursor
            .epoch
            .0
            .checked_add(1)
            .filter(|e| *e < 1_u64 << 62)
            .ok_or_else(|| invalid("proposal epoch is invalid"))?;
        let chain = self.store.chain();
        if graph.chain_id() != chain.chain_id.as_bytes() {
            return Err(invalid("execution graph differs from canonical chain"));
        }
        let authority = self.rules(base, epoch).await?;
        if authority.validators.public_key(creator).is_none() {
            return Err(invalid("proposal creator is not an active validator"));
        }
        let parent_commit = self.proposal_parent(base, policy).await?;
        let previous = parent_commit
            .as_ref()
            .map(|p| p.certificate.header.ts)
            .or(policy.genesis_time)
            .ok_or_else(|| Error::Unavailable("previous_epoch_time_unavailable".into()))?;
        // The native builder waits for this interval even under historical rules.
        if policy::next_delay_ms(now, previous) > 0 {
            return Err(Error::Unavailable(
                "proposal epoch time interval has not elapsed".into(),
            ));
        }
        policy::check_proposal_time(
            policy::time_rule(chain.chain_id.as_bytes(), epoch as i64),
            policy::ProposalKind::Fresh,
            now,
            Some(policy::time_of_seconds(previous).map_err(invalid)?),
            now,
        )
        .map_err(invalid)?;
        let version = policy.protocol.version_at(epoch as i64);
        if version == LEGACY_VERSION && parent_commit.is_some() {
            return Err(invalid("legacy proposal has parent commit"));
        }
        let header = EpochHeader {
            proto_version: version,
            chain_id: chain.chain_id.as_bytes().to_vec(),
            epoch_id: epoch as i64,
            prev_state_root: base.cursor.state_root.0.to_vec(),
            tx_list_hash: tx_list_hash_for_header(&[]).to_vec(),
            receipt_root: hash::receipt_root(&[]).map_err(invalid)?.to_vec(),
            proposed_state_root: NIL.to_vec(),
            parent_commit_hash: hash::parent_commit_hash_opt(parent_commit.as_ref())
                .map_err(invalid)?
                .to_vec(),
            creator_addr: creator.to_vec(),
            txid_hi: base.txid_hi,
            ts: now,
        };
        let legacy = authority
            .validators
            .validators
            .iter()
            .map(|v| v.address.clone())
            .collect::<Vec<_>>();
        let rules =
            Bound::canonical_header(graph, base, &header, parent_commit.clone(), &legacy, self)
                .await
                .map_err(|e| Error::Authority(e.to_string()))?;
        self.proposal_parent_current(base).await?;
        Ok(BuildContext {
            parent: base.clone(),
            header,
            parent_commit,
            rules,
            authority,
        })
    }
}
