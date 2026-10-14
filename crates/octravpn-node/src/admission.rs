//! Local-host authorization for the embedded VPN. Implementations must read one
//! authenticated committed snapshot. Discovery records and auxiliary receipts
//! do not establish escrow, ownership or finality.
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use octravpn_core::{
    address::Address,
    control::{announce_opener_binding_payload, announce_signing_payload, AnnounceSessionRequest},
    receipt::ReceiptContext,
    session::SessionId,
    sig::verify,
};
use sha2::{Digest, Sha256};

/// The host supplies this capability; it is never deserialized from a peer.
#[async_trait]
pub trait SessionAuthority: Send + Sync {
    /// Return no permit while syncing, behind the canonical head, unfunded,
    /// expired, closed, or unable to authenticate this request. A new snapshot
    /// must revoke obsolete permits before becoming available to admission.
    async fn authorize(
        &self,
        request: &AnnounceSessionRequest,
        domain: &ReceiptContext,
    ) -> anyhow::Result<Option<SessionPermit>>;

    /// Read the receipt lifecycle from the same pinned application. Failure
    /// closes receipt acceptance; it must never fall back to an RPC view.
    async fn lifecycle(
        &self,
        session: &SessionId,
        domain: &ReceiptContext,
    ) -> anyhow::Result<RelayLifecycle>;
}

/// A session read from the serving operator's pinned settlement application at
/// one committed root. The host validates application code and funding rules.
#[derive(Clone)]
pub struct FundedSession {
    pub domain: ReceiptContext,
    pub session_id: SessionId,
    pub opener: Address,
    pub client_pubkey: octravpn_core::sig::PublicKey,
    pub client_wg_pubkey: [u8; 32],
    pub open_tx_hash: String,
    pub current_epoch: u64,
    pub expires_epoch: u64,
    pub escrow_ou: u64,
    pub open: bool,
}

/// Host-controlled revocation shared with each packet check. Revocation cannot
/// be undone by replaying an old request or by renewing the wall-clock lease.
#[derive(Clone, Default)]
pub struct Revocation(Arc<AtomicBool>);

impl Revocation {
    pub fn revoke(&self) {
        self.0.store(true, Ordering::Release);
    }
    pub fn is_revoked(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

#[derive(Clone)]
pub struct SessionPermit {
    revocation: Revocation,
    service_stop: Option<Revocation>,
    expires_at: Instant,
    binding: [u8; 32],
    domain: ReceiptContext,
}

impl FundedSession {
    /// Verify both key holders and bind the permit to this exact application,
    /// opening transaction and WireGuard identity. The current epoch and escrow
    /// must come from the same committed snapshot as the session state.
    pub fn authorize(
        &self,
        request: &AnnounceSessionRequest,
        revocation: Revocation,
        lifetime: Duration,
    ) -> Option<SessionPermit> {
        if !self.open
            || self.escrow_ou == 0
            || self.current_epoch >= self.expires_epoch
            || self.client_pubkey != request.client_pubkey
            || self.client_wg_pubkey != request.client_wg_pubkey
            || self.session_id != request.session_id
            || self.open_tx_hash != request.open_tx_hash
            || Address::from_pubkey(&request.opener_pubkey.0) != self.opener
            || revocation.is_revoked()
            || lifetime.is_zero()
            || request.client_wg_pubkey == [0; 32]
            || verify(
                &request.client_pubkey,
                &announce_signing_payload(
                    &request.session_id,
                    &request.client_pubkey,
                    &request.client_wg_pubkey,
                    &request.open_tx_hash,
                ),
                &request.client_sig,
            )
            .is_err()
            || verify(
                &request.opener_pubkey,
                &announce_opener_binding_payload(
                    &request.session_id,
                    &request.client_pubkey,
                    &request.client_wg_pubkey,
                    &request.open_tx_hash,
                ),
                &request.opener_sig,
            )
            .is_err()
        {
            return None;
        }
        Some(SessionPermit {
            revocation,
            service_stop: None,
            expires_at: Instant::now().checked_add(lifetime.min(crate::tunnel::ADMISSION_LEASE))?,
            binding: binding(request),
            domain: self.domain.clone(),
        })
    }
}

fn binding(request: &AnnounceSessionRequest) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(announce_signing_payload(
        &request.session_id,
        &request.client_pubkey,
        &request.client_wg_pubkey,
        &request.open_tx_hash,
    ));
    digest.update(request.opener_pubkey.0);
    digest.finalize().into()
}

impl SessionPermit {
    pub(crate) fn with_service_stop(mut self, stop: Revocation) -> Self {
        self.service_stop = Some(stop);
        self
    }

    pub(crate) fn matches(
        &self,
        request: &AnnounceSessionRequest,
        domain: &ReceiptContext,
    ) -> bool {
        self.domain == *domain && self.binding == binding(request) && self.live()
    }
    pub fn live(&self) -> bool {
        !self.revocation.is_revoked()
            && self
                .service_stop
                .as_ref()
                .map_or(true, |stop| !stop.is_revoked())
            && Instant::now() < self.expires_at
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayArmedState {
    pub deadline: u64,
    pub settlement_hash: String,
}

/// On-chain relay lifecycle of a session, as the receipt POST handler needs to
/// see it: `Open` still accepts receipts, `Armed` pins the vault entry, and
/// `Terminal` (SETTLED/REFUNDED/RELAY_CLAIMED/RELAY_REFUNDED) rejects further
/// receipts — the session is closed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelayLifecycle {
    Open,
    Armed(RelayArmedState),
    Terminal(u64),
}
