use super::{Error, Host, Validator, ValidatorSet};
use octra_node_runtime::consensus_driver::ReliefPlan;

impl<A: Host> Validator<A> {
    pub(super) async fn canonical_relief_plan(
        &self,
        number: i64,
        current: &ValidatorSet,
    ) -> Result<Option<ReliefPlan>, Error> {
        let epoch = self.epoch()?;
        if epoch.number != number || &epoch.rules.validators != current {
            return Err("relief source differs from canonical validator view".into());
        }
        if epoch.rules.relief.is_some() {
            return Ok(None);
        }
        let canonical = self.peers.config(&epoch.head).await?;
        let Some(schedule) = canonical.scheduled.filter(|p| number < p.activate_epoch) else {
            return Ok(None);
        };
        if self.epoch()?.head != epoch.head {
            return Err("relief canonical parent advanced".into());
        }
        Ok(Some(ReliefPlan {
            target: schedule.validators.for_epoch(
                self.node.store.chain().chain_id.as_bytes(),
                schedule.activate_epoch,
            )?,
            activate_epoch: schedule.activate_epoch,
            fingerprint: schedule.fingerprint.into_bytes(),
        }))
    }
}
