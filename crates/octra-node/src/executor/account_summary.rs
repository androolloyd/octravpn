use super::Native;
use octra_node_runtime::{account_summary::Summary, state_batch::Snapshot};
use std::sync::Arc;

impl Native {
    pub(crate) fn account_summary(&self, state: &Snapshot) -> anyhow::Result<Arc<Summary>> {
        self.account_summary.get(state).map_err(Into::into)
    }
}
