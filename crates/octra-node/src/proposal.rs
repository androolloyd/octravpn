//! Snapshot and authentication for speculative execution. A Candidate is not a
//! verified execution result; only local receipt and state replay may admit it.
use crate::{Host, Node};
use octra_node_protocol::{consensus::Proposal, rules::Graph};
use octra_node_runtime::{
    finality::{
        self,
        proposal::{Authenticated, BuildContext, Policy},
    },
    state_batch::Snapshot,
};

pub struct Candidate {
    context: Authenticated,
    state: Snapshot,
    revocation: octravpn_node::admission::Revocation,
}
impl Candidate {
    pub fn context(&self) -> &Authenticated {
        &self.context
    }
    pub fn state(&self) -> &Snapshot {
        &self.state
    }
}

pub struct Draft {
    context: BuildContext,
    state: Snapshot,
    revocation: octravpn_node::admission::Revocation,
}
impl Draft {
    pub(crate) fn live(&self) -> bool {
        !self.revocation.is_revoked()
    }
    pub fn context(&self) -> &BuildContext {
        &self.context
    }
    pub fn state(&self) -> &Snapshot {
        &self.state
    }
}

impl<A: Host> Node<A> {
    /// Capture a local build at the serving parent. The driver still owns
    /// leader/round selection, signing, durable precommit and finality.
    pub async fn proposal_draft(
        &self,
        graph: &Graph,
        policy: Policy,
        creator: &[u8],
        now: f64,
    ) -> Result<Draft, finality::Error> {
        let serving = self
            .shared
            .current()
            .map_err(|e| finality::Error::Unavailable(e.to_string()))?;
        let context = self
            .publisher
            .proposal_build_context(serving.committed.head(), graph, policy, creator, now)
            .await?;
        if serving.revocation.is_revoked() {
            return Err(finality::Error::Unavailable(
                "proposal snapshot was revoked".into(),
            ));
        }
        Ok(Draft {
            context,
            state: serving.committed.state().clone(),
            revocation: serving.revocation.clone(),
        })
    }

    pub fn draft_current(&self, draft: &Draft) -> bool {
        !draft.revocation.is_revoked()
            && self
                .snapshot()
                .is_ok_and(|v| v.head() == draft.context.parent())
    }

    /// Capture the same serving parent and state, then authenticate the proposal
    /// against canonical history. Suspended or advancing nodes cannot furnish
    /// a candidate. Policy and graph come from trusted startup configuration.
    pub async fn proposal_candidate(
        &self,
        proposal: &Proposal,
        graph: &Graph,
        policy: Policy,
        now: f64,
    ) -> Result<Candidate, finality::Error> {
        let serving = self
            .shared
            .current()
            .map_err(|e| finality::Error::Unavailable(e.to_string()))?;
        let context = self
            .publisher
            .authenticate_proposal(serving.committed.head(), proposal, graph, policy, now)
            .await?;
        if serving.revocation.is_revoked() {
            return Err(finality::Error::Unavailable(
                "proposal snapshot was revoked".into(),
            ));
        }
        Ok(Candidate {
            context,
            state: serving.committed.state().clone(),
            revocation: serving.revocation.clone(),
        })
    }

    /// Use after asynchronous verification and again before durable precommit.
    /// Authentication alone never establishes an execution verdict.
    pub fn proposal_current(&self, candidate: &Candidate) -> bool {
        !candidate.revocation.is_revoked()
            && self
                .snapshot()
                .is_ok_and(|v| v.head() == candidate.context.parent())
    }
}
