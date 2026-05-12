//! Lightweight fork support.
//!
//! Foundry's `vm.createFork(rpc)` snapshots remote chain state at a
//! given block. We expose two flavours:
//!
//!   - **Snapshot fork**: take a `ChainState` clone tagged by URL/label
//!     and switch into it. (For tests that want multiple parallel
//!     "what-if" worlds.)
//!   - **Remote-seed fork**: future enhancement — actually call
//!     `node_status`, `list_active_validators`, etc. against a real
//!     RPC and seed our `ChainState` with the result. Not wired
//!     because most tests run fully synthetic; the API is in place so
//!     a real-network harness can implement it.

use octravpn_mock_rpc::ChainState;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForkId(pub usize);

/// Per-fork stored chain state + label.
#[derive(Clone)]
pub struct ForkEntry {
    pub label: String,
    pub state: ChainState,
}

impl std::fmt::Debug for ForkEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForkEntry")
            .field("label", &self.label)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Default)]
pub struct ForkTable {
    pub forks: Vec<ForkEntry>,
    pub active: Option<ForkId>,
}

impl ForkTable {
    pub fn create(&mut self, label: impl Into<String>, state: ChainState) -> ForkId {
        self.forks.push(ForkEntry {
            label: label.into(),
            state,
        });
        ForkId(self.forks.len() - 1)
    }

    pub fn get(&self, id: ForkId) -> Option<&ForkEntry> {
        self.forks.get(id.0)
    }

    pub fn select(&mut self, id: ForkId) -> bool {
        if id.0 < self.forks.len() {
            self.active = Some(id);
            true
        } else {
            false
        }
    }
}
