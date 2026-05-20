//! `MockChain` — the abstraction over the v2 main-net program.
//!
//! The Circle's proxy interactions with main-net AML go through this
//! trait. Unit tests use [`MemoryChain`] (a simple Rust struct);
//! integration tests will wire this against the real
//! `octra-mock-rpc` once that mock dispatches the v2 entrypoints
//! (`authorize_proxy`, `open_session` with the v2 args, etc.).

use std::collections::HashMap;

use async_trait::async_trait;
use parking_lot::Mutex;
use thiserror::Error;

use crate::acl::ExitClass;

/// What main-net knows about a session — the v2 AML's `Session`
/// record fields the CircleSim cares about.
#[derive(Clone, Debug)]
pub struct SessionOnChain {
    pub session_id: u64,
    pub tailnet_id: u64,
    pub opener: String,
    pub proxy: String,
    pub class: ExitClass,
    pub price_per_mb: u64,
    pub deposit: u64,
    pub status: SessionStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionStatus {
    Open,
    Settled,
    Refunded,
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ChainError {
    #[error("session {0} not found on chain")]
    SessionNotFound(u64),
    #[error("rpc error: {0}")]
    Rpc(String),
    #[error("authorization denied: {0}")]
    Unauthorized(String),
}

/// The Circle's view of main-net. Methods are async because real
/// chain calls go through JSON-RPC.
#[async_trait]
pub trait MockChain: Send + Sync {
    async fn get_session(&self, sid: u64) -> Result<SessionOnChain, ChainError>;
    async fn submit_settle_claim(&self, sid: u64, bytes_used: u64) -> Result<(), ChainError>;
}

/// Trivial in-memory implementation for unit tests.
#[derive(Debug, Default)]
pub struct MemoryChain {
    sessions: Mutex<HashMap<u64, SessionOnChain>>,
    claims: Mutex<Vec<(u64, u64)>>,
    /// If `Some`, future `submit_settle_claim` calls will return this
    /// error — for testing error paths.
    fail_with: Mutex<Option<ChainError>>,
}

impl MemoryChain {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn upsert_session(&self, s: SessionOnChain) {
        self.sessions.lock().insert(s.session_id, s);
    }

    pub fn claims(&self) -> Vec<(u64, u64)> {
        self.claims.lock().clone()
    }

    pub fn fail_next_submit(&self, err: ChainError) {
        *self.fail_with.lock() = Some(err);
    }
}

#[async_trait]
impl MockChain for MemoryChain {
    async fn get_session(&self, sid: u64) -> Result<SessionOnChain, ChainError> {
        self.sessions
            .lock()
            .get(&sid)
            .cloned()
            .ok_or(ChainError::SessionNotFound(sid))
    }

    async fn submit_settle_claim(&self, sid: u64, bytes_used: u64) -> Result<(), ChainError> {
        if let Some(err) = self.fail_with.lock().take() {
            return Err(err);
        }
        self.sessions
            .lock()
            .get(&sid)
            .ok_or(ChainError::SessionNotFound(sid))?;
        self.claims.lock().push((sid, bytes_used));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_session(id: u64) -> SessionOnChain {
        SessionOnChain {
            session_id: id,
            tailnet_id: 1,
            opener: "octCLI".into(),
            proxy: "octPROXY".into(),
            class: ExitClass::Shared,
            price_per_mb: 100,
            deposit: 1000,
            status: SessionStatus::Open,
        }
    }

    #[tokio::test]
    async fn memory_chain_records_claims() {
        let chain = MemoryChain::new();
        chain.upsert_session(mk_session(7));
        chain.submit_settle_claim(7, 42).await.unwrap();
        assert_eq!(chain.claims(), vec![(7, 42)]);
    }

    #[tokio::test]
    async fn memory_chain_fails_on_missing_session() {
        let chain = MemoryChain::new();
        let err = chain.submit_settle_claim(99, 1).await.unwrap_err();
        assert!(matches!(err, ChainError::SessionNotFound(99)));
    }

    #[tokio::test]
    async fn memory_chain_honors_injected_failure() {
        let chain = MemoryChain::new();
        chain.upsert_session(mk_session(1));
        chain.fail_next_submit(ChainError::Rpc("flake".into()));
        let err = chain.submit_settle_claim(1, 5).await.unwrap_err();
        assert!(matches!(err, ChainError::Rpc(_)));
        // Subsequent call succeeds (one-shot failure).
        chain.submit_settle_claim(1, 5).await.unwrap();
        assert_eq!(chain.claims(), vec![(1, 5)]);
    }
}
