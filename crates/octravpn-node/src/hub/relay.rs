use anyhow::{bail, Result};

use crate::relay_settlement::RelayClaimSubmission;

use super::Hub;

impl Hub {
    /// Submit a v4 `relay_claim` from the daemon-owned receipt vault.
    /// The path is default-off; callers must opt in via
    /// `[control.relay].enabled = true`.
    #[allow(dead_code)] // manual CLI hook is wired first; daemon loop is a follow-up.
    pub(crate) async fn relay_claim_session(
        &self,
        session_id: u64,
    ) -> Result<RelayClaimSubmission> {
        if !self.cfg.control.relay.enabled {
            bail!("v4 relay settlement disabled; set [control.relay].enabled = true");
        }
        crate::relay_settlement::submit_relay_claim_from_vault(
            &self.chain_v3,
            self.receipt_vault.as_ref(),
            session_id,
        )
        .await
    }
}
