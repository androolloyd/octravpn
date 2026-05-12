//! Shared admin-UI state: the RPC client, program address, and an
//! optional signing wallet.

use std::sync::Arc;

use octravpn_core::{
    address::Address,
    rpc::RpcClient,
    sig::KeyPair,
};

pub struct AdminState {
    pub rpc: RpcClient,
    pub program_addr: Address,
    /// Optional wallet for write operations. `None` makes the UI
    /// read-only (handy for demos and audit dashboards).
    pub wallet: Option<KeyPair>,
    /// Optional URL of a node's control plane to proxy SSE events from.
    pub node_url: Option<String>,
}

impl AdminState {
    pub fn new(
        rpc_url: impl Into<String>,
        program_addr: impl Into<String>,
        wallet: Option<KeyPair>,
        node_url: Option<String>,
    ) -> Arc<Self> {
        Arc::new(Self {
            rpc: RpcClient::new(rpc_url),
            program_addr: Address::from_display(program_addr.into()),
            wallet,
            node_url,
        })
    }

    pub fn caller_addr(&self) -> Option<String> {
        self.wallet
            .as_ref()
            .map(|kp| Address::from_pubkey(&kp.public.0).display().to_string())
    }
}
