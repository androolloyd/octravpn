use anyhow::{bail, Result};
use octravpn_core::receipt_vault::{LifecycleState, ReceiptVaultResult};
use octravpn_core::session::SessionId;

use crate::relay_settlement::RelayClaimSubmission;

use super::Hub;

/// Outcome of one `relay_confirm_and_drain` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DrainOutcome {
    /// On-chain `RELAY_CLAIMED` — the vault entry is now terminal `Claimed`.
    Claimed,
    /// On-chain `RELAY_REFUNDED` — the vault entry is now terminal `Refunded`.
    Refunded,
    /// Not terminal yet (`RELAY_ARMED`/other) — leave in the vault, retry later.
    Pending,
}

impl Hub {
    /// Submit a v4 `relay_claim` from the daemon-owned receipt vault. This is the
    /// SOLE relay-claim submitter: it routes through `self.chain_v3` (the boot-
    /// built shared `ChainTxQueue`, so I4 nonce-single-owner holds) and the
    /// daemon-owned vault (single writer). Default-off; opt in via
    /// `[control.relay].enabled = true`.
    pub(crate) async fn relay_claim_session(
        &self,
        session_id: u64,
    ) -> Result<RelayClaimSubmission> {
        if !self.cfg.control.relay.enabled {
            bail!("v4 relay settlement disabled; set [control.relay].enabled = true");
        }
        let margin = self.cfg.control.relay.resolved_margin_epochs();
        crate::relay_settlement::submit_relay_claim_from_vault(
            &self.chain_v3,
            self.receipt_vault.as_ref(),
            session_id,
            margin,
        )
        .await
    }

    /// Confirm a vaulted claim from chain truth and drain it to a terminal vault
    /// state so `compact()` can GC it. Terminal transitions are a **pure function
    /// of an EXACT positive on-chain status match** — `RELAY_CLAIMED` -> Claimed,
    /// `RELAY_REFUNDED` -> Refunded — never a negation and never an
    /// epoch-vs-deadline inference. `get_session_status_strict` turns a
    /// hostile/failed RPC body into an `Err`, so a bad read leaves the entry
    /// untouched to retry next tick rather than wrongly draining it (which, past
    /// `compact()`, would irreversibly lose the receipt + preimage).
    pub(crate) async fn relay_confirm_and_drain(&self, session_id: u64) -> Result<DrainOutcome> {
        let id = SessionId::from_u64(session_id);
        let status = self.chain_v3.get_session_status_strict(session_id).await?;
        match status {
            crate::chain_v3::SESSION_RELAY_CLAIMED => {
                // Reuse the recorded ClaimSubmitted{tx} so a re-drain is
                // lifecycle-equivalent (no IllegalTransition on retry); empty
                // when some foreign party claimed and we never recorded a tx.
                let tx = match self.receipt_vault.state(&id) {
                    Some(LifecycleState::ClaimSubmitted { tx }) => tx,
                    _ => String::new(),
                };
                self.drain_mark(&id, self.receipt_vault.mark_claimed(&id, tx));
                Ok(DrainOutcome::Claimed)
            }
            crate::chain_v3::SESSION_RELAY_REFUNDED => {
                let r = self
                    .receipt_vault
                    .mark_refunded(&id, "<foreign-refund>".to_string());
                self.drain_mark(&id, r);
                Ok(DrainOutcome::Refunded)
            }
            _ => Ok(DrainOutcome::Pending),
        }
    }

    /// Best-effort terminal mark: a mark that failed only because the entry is
    /// ALREADY terminal (a raced/duplicate drain) is success; anything else is
    /// logged and left for a later tick. A confirmed on-chain terminal status
    /// must never wedge the claimer loop.
    fn drain_mark(&self, id: &SessionId, r: ReceiptVaultResult<()>) {
        if let Err(e) = r {
            let already_terminal = matches!(
                self.receipt_vault.state(id),
                Some(
                    LifecycleState::Claimed { .. }
                        | LifecycleState::Refunded { .. }
                        | LifecycleState::Expired
                )
            );
            if !already_terminal {
                tracing::warn!(
                    session = %id.to_hex(),
                    error = %e,
                    "relay drain terminal mark failed; leaving entry for a later tick",
                );
            }
        }
    }
}
