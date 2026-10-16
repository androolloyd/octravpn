//! Canonical-snapshot binding around the settlement application's state reader.
use std::{sync::Arc, time::Duration};

use anyhow::Result;
use async_trait::async_trait;
use octravpn_core::{control::AnnounceSessionRequest, receipt::ReceiptContext, session::SessionId};
use octravpn_node::admission::{FundedSession, RelayLifecycle, SessionAuthority, SessionPermit};
use tokio::sync::watch;

use crate::{Committed, Host, Node, Shared};
mod keys;
mod pinned;
pub(crate) mod settlement;
pub(crate) mod storage;
pub use keys::Keys;
pub use pinned::{Application, Config, Layout, Pinned};

/// A trusted adapter for one pinned settlement application. No RPC, peer-fed
/// discovery index, or uncommitted state is available through this capability.
/// Implementations must verify code, operator, opening transaction and escrow
/// against `view`, returning None when the session is ineligible.
#[async_trait]
pub trait Settlement: Send + Sync {
    async fn session(
        &self,
        view: &Committed,
        request: &AnnounceSessionRequest,
        domain: &ReceiptContext,
    ) -> Result<Option<FundedSession>>;

    async fn lifecycle(
        &self,
        view: &Committed,
        session: &SessionId,
        domain: &ReceiptContext,
    ) -> Result<RelayLifecycle>;
}

pub struct CanonicalAuthority {
    shared: Arc<Shared>,
    settlement: Arc<dyn Settlement>,
}

impl<A: Host> Node<A> {
    pub fn vpn_authority(&self, settlement: Arc<dyn Settlement>) -> Arc<CanonicalAuthority> {
        self.published().vpn_authority(settlement)
    }
}
impl crate::published::Handle {
    pub(crate) fn vpn_authority(&self, settlement: Arc<dyn Settlement>) -> Arc<CanonicalAuthority> {
        Arc::new(CanonicalAuthority {
            shared: self.shared.clone(),
            settlement,
        })
    }
}

#[async_trait]
impl SessionAuthority for CanonicalAuthority {
    fn updates(&self) -> Option<watch::Receiver<()>> {
        Some(self.shared.1.subscribe())
    }
    async fn authorize(
        &self,
        request: &AnnounceSessionRequest,
        domain: &ReceiptContext,
    ) -> Result<Option<SessionPermit>> {
        let view = self.shared.current()?;
        let session = self
            .settlement
            .session(&view.committed, request, domain)
            .await?;
        anyhow::ensure!(
            !view.revocation.is_revoked(),
            "canonical session snapshot changed"
        );
        let Some(session) = session else {
            return Ok(None);
        };
        // The adapter cannot select another network or extend session life by
        // supplying an older epoch. Both signatures and WG identity are checked
        // by FundedSession against this generation's revocation capability.
        if &session.domain != domain
            || session.current_epoch != view.committed.head().cursor.epoch.0
        {
            return Ok(None);
        }
        let permit = session.authorize(request, view.revocation.clone(), Duration::from_secs(120));
        anyhow::ensure!(
            !view.revocation.is_revoked(),
            "canonical session snapshot changed"
        );
        Ok(permit)
    }

    async fn lifecycle(
        &self,
        session: &SessionId,
        domain: &ReceiptContext,
    ) -> Result<RelayLifecycle> {
        let view = self.shared.current()?;
        let lifecycle = self
            .settlement
            .lifecycle(&view.committed, session, domain)
            .await?;
        anyhow::ensure!(
            !view.revocation.is_revoked(),
            "canonical session snapshot changed"
        );
        Ok(lifecycle)
    }
}
