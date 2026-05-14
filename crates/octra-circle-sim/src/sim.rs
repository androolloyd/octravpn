//! `CircleSim` — the public face of the simulated Circle.

use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::acl::{AccessContract, AclRule, ExitClass};
use crate::chain::{MockChain, SessionStatus};
use crate::meter::ByteMeter;

/// Static config for a Circle. The proxy address is the on-chain
/// identity main-net sees; the WG pubkey is what clients connect to.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircleConfig {
    pub proxy_addr: String,
    pub wg_pubkey_hex: String,
    pub region: String,
    /// Tailnet IDs this Circle is authorized to serve. The Circle
    /// declines `open_session` for tailnets not in this set.
    pub tailnet_ids: Vec<u64>,
}

/// What the client sends to ask for a session. Mirrors what the
/// (future) HTTP control plane will accept.
#[derive(Clone, Debug)]
pub struct OpenSessionRequest {
    pub tailnet_id: u64,
    pub member: String,
    pub class: ExitClass,
    pub max_pay: u64,
}

/// Session record the Circle keeps locally for an active session.
#[derive(Clone, Debug)]
pub struct SessionRecord {
    pub session_id: u64,
    pub tailnet_id: u64,
    pub member: String,
    pub class: ExitClass,
    pub price_per_mb: u64,
    pub meter: ByteMeter,
    /// `true` once `settle_claim` has been submitted to chain.
    pub claimed: bool,
}

#[derive(Default)]
struct State {
    /// Per-tailnet access contract. The Circle's owner installs these
    /// when configuring the Circle for that tailnet.
    acl_per_tailnet: BTreeMap<u64, AccessContract>,
    /// Active + closed sessions (keyed by chain session_id).
    sessions: BTreeMap<u64, SessionRecord>,
}

/// The Circle. Holds config + state + a chain handle. All methods
/// are `&self` (interior mutability via `parking_lot::RwLock`) so
/// downstream callers can hold `Arc<CircleSim<_>>` across tasks.
pub struct CircleSim<C: MockChain> {
    cfg: CircleConfig,
    state: RwLock<State>,
    chain: Arc<C>,
}

impl<C: MockChain> CircleSim<C> {
    pub fn new(cfg: CircleConfig, chain: Arc<C>) -> Self {
        Self {
            cfg,
            state: RwLock::new(State::default()),
            chain,
        }
    }

    pub fn config(&self) -> &CircleConfig {
        &self.cfg
    }

    /// Install / replace the access contract for one tailnet. Idempotent.
    pub fn set_access_contract(&self, tailnet_id: u64, ac: AccessContract) {
        self.state.write().acl_per_tailnet.insert(tailnet_id, ac);
    }

    /// Convenience: add one ACL rule to the tailnet's contract, creating
    /// the contract if it doesn't yet exist.
    pub fn add_rule(&self, tailnet_id: u64, rule: AclRule) {
        let mut s = self.state.write();
        s.acl_per_tailnet
            .entry(tailnet_id)
            .or_default()
            .add_rule(rule);
    }

    /// Convenience: tag a tailnet member.
    pub fn set_member_tags<I>(&self, tailnet_id: u64, member: &str, tags: I)
    where
        I: IntoIterator<Item = crate::acl::MemberTag>,
    {
        let mut s = self.state.write();
        s.acl_per_tailnet
            .entry(tailnet_id)
            .or_default()
            .set_member_tags(member, tags);
    }

    /// Quote a price for the requested session. Returns
    /// `Err` if the Circle doesn't serve the tailnet or the member's
    /// ACL doesn't allow the class.
    pub fn quote(&self, req: &OpenSessionRequest) -> Result<u64> {
        let tid = req.tailnet_id;
        if !self.cfg.tailnet_ids.contains(&tid) {
            return Err(anyhow!("circle does not serve tailnet {tid}"));
        }
        let s = self.state.read();
        let ac = s
            .acl_per_tailnet
            .get(&tid)
            .ok_or_else(|| anyhow!("no access contract for tailnet {tid}"))?;
        let rule = ac
            .quote(&req.member, req.class)
            .ok_or_else(|| anyhow!("acl: no rule for member/class"))?;
        Ok(rule.price_per_mb)
    }

    /// Accept the chain-side `open_session` event for `session_id`.
    /// Builds the local session record + opens a fresh byte meter.
    /// Should be called after the client's `open_session` tx confirms
    /// on chain.
    pub async fn accept_session(&self, session_id: u64) -> Result<()> {
        let s = self
            .chain
            .get_session(session_id)
            .await
            .context("fetch session from chain")?;
        if s.proxy != self.cfg.proxy_addr {
            let want = &self.cfg.proxy_addr;
            let got = &s.proxy;
            return Err(anyhow!(
                "session {session_id} routes to proxy {got}, not this circle ({want})"
            ));
        }
        if !self.cfg.tailnet_ids.contains(&s.tailnet_id) {
            let tid = s.tailnet_id;
            return Err(anyhow!(
                "session {session_id} is on tailnet {tid}, which this circle does not serve"
            ));
        }
        let record = SessionRecord {
            session_id: s.session_id,
            tailnet_id: s.tailnet_id,
            member: s.opener,
            class: s.class,
            price_per_mb: s.price_per_mb,
            meter: ByteMeter::new(),
            claimed: false,
        };
        self.state.write().sessions.insert(session_id, record);
        Ok(())
    }

    /// Record bandwidth on an open session. Called from the
    /// WireGuard pipeline (one packet, one batch — caller's choice).
    pub fn record_bytes(&self, session_id: u64, n: u64) -> Result<()> {
        let mut s = self.state.write();
        let rec = s
            .sessions
            .get_mut(&session_id)
            .ok_or_else(|| anyhow!("no local session {session_id}"))?;
        if rec.claimed {
            return Err(anyhow!("session {session_id} already settled"));
        }
        rec.meter.record(n);
        Ok(())
    }

    /// Look up the current encrypted byte counter (wire format) for
    /// an active session. Used by the (future) HTTP control plane so
    /// the client can verify the running total mid-session.
    pub fn bytes_ciphertext(&self, session_id: u64) -> Result<String> {
        let s = self.state.read();
        let rec = s
            .sessions
            .get(&session_id)
            .ok_or_else(|| anyhow!("no local session {session_id}"))?;
        Ok(rec.meter.ciphertext().to_string())
    }

    /// Submit `settle_claim` for the session. Idempotent: a second
    /// call with the same `bytes_used` is a no-op (matches AML
    /// behavior). After this returns Ok, the client confirms.
    pub async fn settle_claim(&self, session_id: u64) -> Result<u64> {
        let bytes_used = {
            let s = self.state.read();
            let rec = s
                .sessions
                .get(&session_id)
                .ok_or_else(|| anyhow!("no local session {session_id}"))?;
            rec.meter.bytes_used()
        };
        self.chain
            .submit_settle_claim(session_id, bytes_used)
            .await
            .context("submit settle_claim")?;
        self.state
            .write()
            .sessions
            .get_mut(&session_id)
            .ok_or_else(|| anyhow!("no local session {session_id}"))?
            .claimed = true;
        Ok(bytes_used)
    }

    /// Drop the local session record once main-net says it's
    /// settled / refunded. Caller invokes this after observing the
    /// terminal event.
    pub fn finalize(&self, session_id: u64, _final_status: SessionStatus) {
        self.state.write().sessions.remove(&session_id);
    }

    /// Snapshot of currently-active session ids — useful for the
    /// HTTP control plane / observability.
    pub fn active_sessions(&self) -> Vec<u64> {
        self.state.read().sessions.keys().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::acl::{AccessContract, MemberTag};
    use crate::chain::{MemoryChain, SessionOnChain};

    fn cfg() -> CircleConfig {
        CircleConfig {
            proxy_addr: "octPROXY".into(),
            wg_pubkey_hex: "de".repeat(32),
            region: "eu-west".into(),
            tailnet_ids: vec![1],
        }
    }

    fn install_default_acl(c: &CircleSim<MemoryChain>) {
        let mut ac = AccessContract::new();
        ac.set_member_tags("octCLI", std::iter::once(MemberTag::new("user")));
        ac.add_rule(AclRule {
            require_tags: BTreeSet::new(),
            class: ExitClass::Shared,
            price_per_mb: 100,
        });
        ac.add_rule(AclRule {
            require_tags: BTreeSet::new(),
            class: ExitClass::Internal,
            price_per_mb: 0,
        });
        c.set_access_contract(1, ac);
    }

    #[tokio::test]
    async fn full_lifecycle() {
        let chain = Arc::new(MemoryChain::new());
        let circle = CircleSim::new(cfg(), chain.clone());
        install_default_acl(&circle);

        // Client opens a session on chain.
        chain.upsert_session(SessionOnChain {
            session_id: 1,
            tailnet_id: 1,
            opener: "octCLI".into(),
            proxy: "octPROXY".into(),
            class: ExitClass::Shared,
            price_per_mb: 100,
            deposit: 1000,
            status: SessionStatus::Open,
        });

        // Circle picks up the session.
        circle.accept_session(1).await.unwrap();
        assert_eq!(circle.active_sessions(), vec![1]);

        // Traffic flows.
        circle.record_bytes(1, 500).unwrap();
        circle.record_bytes(1, 600).unwrap();

        // Circle submits settle_claim.
        let bytes_used = circle.settle_claim(1).await.unwrap();
        assert_eq!(bytes_used, 1100);
        assert_eq!(chain.claims(), vec![(1, 1100)]);

        // Main-net flips to settled; Circle finalizes.
        circle.finalize(1, SessionStatus::Settled);
        assert!(circle.active_sessions().is_empty());
    }

    #[tokio::test]
    async fn quote_rejects_unknown_tailnet() {
        let chain = Arc::new(MemoryChain::new());
        let circle = CircleSim::new(cfg(), chain);
        let req = OpenSessionRequest {
            tailnet_id: 99,
            member: "octCLI".into(),
            class: ExitClass::Shared,
            max_pay: 1000,
        };
        let err = circle.quote(&req).unwrap_err();
        assert!(err.to_string().contains("does not serve tailnet"));
    }

    #[tokio::test]
    async fn quote_rejects_member_without_acl_match() {
        let chain = Arc::new(MemoryChain::new());
        let circle = CircleSim::new(cfg(), chain);
        let mut ac = AccessContract::new();
        ac.set_member_tags("octCLI", std::iter::once(MemberTag::new("user")));
        // Only an internal rule.
        ac.add_rule(AclRule {
            require_tags: BTreeSet::new(),
            class: ExitClass::Internal,
            price_per_mb: 0,
        });
        circle.set_access_contract(1, ac);
        let req = OpenSessionRequest {
            tailnet_id: 1,
            member: "octCLI".into(),
            class: ExitClass::Shared,
            max_pay: 1000,
        };
        assert!(circle.quote(&req).is_err());
    }

    #[tokio::test]
    async fn quote_returns_cheapest_matching_price() {
        let chain = Arc::new(MemoryChain::new());
        let circle = CircleSim::new(cfg(), chain);
        let mut ac = AccessContract::new();
        ac.set_member_tags("octCLI", std::iter::once(MemberTag::new("user")));
        ac.add_rule(AclRule {
            require_tags: BTreeSet::new(),
            class: ExitClass::Shared,
            price_per_mb: 100,
        });
        ac.add_rule(AclRule {
            require_tags: std::iter::once(MemberTag::new("user")).collect(),
            class: ExitClass::Shared,
            price_per_mb: 60,
        });
        circle.set_access_contract(1, ac);
        let q = circle
            .quote(&OpenSessionRequest {
                tailnet_id: 1,
                member: "octCLI".into(),
                class: ExitClass::Shared,
                max_pay: 1000,
            })
            .unwrap();
        assert_eq!(q, 60);
    }

    #[tokio::test]
    async fn accept_session_rejects_wrong_proxy() {
        let chain = Arc::new(MemoryChain::new());
        let circle = CircleSim::new(cfg(), chain.clone());
        chain.upsert_session(SessionOnChain {
            session_id: 2,
            tailnet_id: 1,
            opener: "octCLI".into(),
            proxy: "octOTHER".into(),
            class: ExitClass::Shared,
            price_per_mb: 100,
            deposit: 1000,
            status: SessionStatus::Open,
        });
        let err = circle.accept_session(2).await.unwrap_err();
        assert!(err.to_string().contains("not this circle"));
    }

    #[tokio::test]
    async fn record_bytes_blocks_after_claim() {
        let chain = Arc::new(MemoryChain::new());
        let circle = CircleSim::new(cfg(), chain.clone());
        install_default_acl(&circle);
        chain.upsert_session(SessionOnChain {
            session_id: 3,
            tailnet_id: 1,
            opener: "octCLI".into(),
            proxy: "octPROXY".into(),
            class: ExitClass::Shared,
            price_per_mb: 100,
            deposit: 1000,
            status: SessionStatus::Open,
        });
        circle.accept_session(3).await.unwrap();
        circle.record_bytes(3, 10).unwrap();
        circle.settle_claim(3).await.unwrap();
        let err = circle.record_bytes(3, 1).unwrap_err();
        assert!(err.to_string().contains("already settled"));
    }
}
