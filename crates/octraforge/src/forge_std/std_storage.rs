//! Fluent state-mutation API analogous to Foundry's `StdStorage`.
//!
//! Foundry's `StdStorage` lets tests do
//! `stdstore.target(addr).sig("balanceOf(address)").with_key(user).checked_write(amount);`
//! at the storage-slot level. Our equivalent is typed: we expose the
//! typed maps the mock chain holds (endpoints, tailnets, sessions,
//! earnings, balances) and let tests write to them directly through a
//! builder.

use octravpn_mock_rpc::{EndpointRow, SessionRow, TailnetRow};

use crate::ForgeCtx;

/// Mutation builder for chain state — chain calls to set up complex
/// test scenarios without going through `register_endpoint` /
/// `open_session` etc.
pub struct StoreBuilder<'a> {
    ctx: &'a mut ForgeCtx,
}

impl<'a> StoreBuilder<'a> {
    pub fn new(ctx: &'a mut ForgeCtx) -> Self {
        Self { ctx }
    }

    /// Mark `addr` as an Octra protocol validator. Required for
    /// `register_endpoint` to succeed.
    pub fn octra_validator(self, addr: impl Into<String>) -> Self {
        let mut s = self.ctx.app.state.write();
        s.octra_validators.insert(addr.into());
        drop(s);
        self
    }

    /// Insert (or replace) an endpoint row.
    pub fn endpoint(self, addr: impl Into<String>, row: EndpointRow) -> Self {
        let mut s = self.ctx.app.state.write();
        s.endpoints.insert(addr.into(), row);
        drop(s);
        self
    }

    /// Insert (or replace) a tailnet row.
    pub fn tailnet(self, id: u64, row: TailnetRow) -> Self {
        let mut s = self.ctx.app.state.write();
        s.tailnets.insert(id, row);
        drop(s);
        self
    }

    /// Insert (or replace) a session row.
    pub fn session(self, sid: u64, row: SessionRow) -> Self {
        let mut s = self.ctx.app.state.write();
        s.sessions.insert(sid, row);
        drop(s);
        self
    }

    /// Set an arbitrary balance.
    pub fn balance(self, addr: impl Into<String>, amount: u64) -> Self {
        let mut s = self.ctx.app.state.write();
        s.balances.insert(addr.into(), amount);
        drop(s);
        self
    }

    /// Reset the chain to a fresh state.
    pub fn reset(self) -> Self {
        let mut s = self.ctx.app.state.write();
        *s = octravpn_mock_rpc::ChainState {
            epoch: 1,
            ..Default::default()
        };
        drop(s);
        self
    }
}

impl ForgeCtx {
    /// Open a fluent store builder.
    pub fn store(&mut self) -> StoreBuilder<'_> {
        StoreBuilder::new(self)
    }
}
