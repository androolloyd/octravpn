//! Native Circle RPC clock and anchored view rules. Browser provenance keeps
//! the captured epoch; evaluation uses the next epoch against that same tree.
use crate::{
    circle::WasmRules, circle_assets::CanonicalAssets, execution::Error, finality::history::History,
};
use octra_node_protocol::{
    native_integer::parse_int64,
    rules::{Graph, RootRead, Rule},
    transaction::RuleMode,
};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

/// A host-owned monotonic view deadline. Sharing it across nested calls never
/// resets the deadline or grants mutation authority.
#[derive(Clone)]
pub struct Clock {
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
}
impl Clock {
    pub fn new(seconds: Duration) -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            deadline: Instant::now() + seconds,
        }
    }
    pub fn running(&self) -> bool {
        !self.cancelled.load(Ordering::Acquire) && Instant::now() < self.deadline
    }
    pub fn expired(&self) -> bool {
        Instant::now() >= self.deadline
    }
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
    /// Shared with the owned crypto helper, so request cancellation stops work
    /// even when the synchronous VM is waiting for its child process.
    pub fn cancellation(&self) -> Arc<AtomicBool> {
        self.cancelled.clone()
    }
    pub fn stop(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
}

#[derive(Clone, Copy)]
pub enum ReadKind {
    Program,
    View,
    Policy,
}

pub fn epoch(raw: Option<&[u8]>, kind: ReadKind) -> Result<i64, Error> {
    let captured = raw
        .and_then(parse_int64)
        .filter(|n| *n >= 0)
        .ok_or_else(|| Error("store epoch missing".into()))?;
    if captured >= (1_i64 << 62) - 1 {
        let name = match kind {
            ReadKind::Program => "program",
            ReadKind::View => "view",
            ReadKind::Policy => "policy",
        };
        return Err(Error(format!("circle {name} epoch exceeds limit")));
    }
    Ok(captured + 1)
}

const ORDER: [Rule; 6] = [
    Rule::Standard,
    Rule::Math,
    Rule::ObjectCost,
    Rule::FheWork,
    Rule::ProofExecution,
    Rule::WasmFloat,
];

/// Contract_rpc.view_profile, including faults in fields unused by WASM.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    pub epoch: i64,
    pub point_ops: bool,
    pub math: bool,
    pub object_cost: bool,
    pub int_work: bool,
    pub fhe_work: RuleMode,
    pub proof_exec: RuleMode,
    pub wasm_float: RuleMode,
}
impl Profile {
    pub fn prior(epoch: i64) -> Self {
        Self {
            epoch,
            point_ops: false,
            math: false,
            object_cost: false,
            int_work: false,
            fhe_work: RuleMode::Prior,
            proof_exec: RuleMode::Prior,
            wasm_float: RuleMode::Prior,
        }
    }
    pub fn resolve(
        graph: &Graph,
        epoch: i64,
        root_at: &impl Fn(i64) -> RootRead,
    ) -> Result<Self, octra_node_protocol::rules::Fault> {
        let mode = |rule| graph.mode(rule, epoch, root_at);
        let standard = mode(Rule::Standard)?;
        let math = mode(Rule::Math)?;
        let object_cost = mode(Rule::ObjectCost)?;
        let fhe_work = mode(Rule::FheWork)?;
        let proof_exec = mode(Rule::ProofExecution)?;
        let wasm_float = mode(Rule::WasmFloat)?;
        Ok(Self {
            epoch,
            point_ops: standard == RuleMode::Active,
            math: math == RuleMode::Active,
            object_cost: object_cost == RuleMode::Active,
            int_work: standard == RuleMode::Active,
            fhe_work,
            proof_exec,
            wasm_float,
        })
    }
    pub fn wasm(&self) -> WasmRules {
        WasmRules {
            math: self.math,
            proof_exec: self.proof_exec == RuleMode::Active,
            wasm_float: self.wasm_float == RuleMode::Active,
        }
    }
}

/// The node supplies its authenticated history. Anchor reads are bounded by
/// the captured snapshot, even if publication advances while this awaits I/O.
pub async fn canonical(assets: &CanonicalAssets, history: &dyn History) -> Result<Profile, Error> {
    let graph = Graph::new(assets.identity().chain_id.as_bytes().to_vec(), None);
    canonical_with_graph(assets, &graph, history).await
}

/// The host passes the same captured graph used by transaction execution.
/// Private fixture activation is checked against authenticated genesis contents;
/// every active native rule still revalidates its independent retained anchor.
pub async fn canonical_with_graph(
    assets: &CanonicalAssets,
    graph: &Graph,
    history: &dyn History,
) -> Result<Profile, Error> {
    let epoch = epoch(
        assets.snapshot().get(&[b"meta", b"last_epoch"]),
        ReadKind::View,
    )?;
    assets
        .check_view_graph(graph)
        .await
        .map_err(|error| Error(error.to_string()))?;
    anchored(graph, epoch, assets.identity().epoch, history).await
}

/// Resolve against the node's authenticated rule anchors. The caller must
/// independently authenticate the captured epoch and private genesis opt-in;
/// this profile carries no canonical snapshot or mutation authority.
pub async fn anchored(
    graph: &Graph,
    epoch: i64,
    captured: u64,
    history: &dyn History,
) -> Result<Profile, Error> {
    let mut roots = BTreeMap::new();
    for rule in ORDER {
        if let Some(plan) = graph
            .activation(rule)
            .filter(|p| epoch >= p.activation_epoch)
        {
            if let std::collections::btree_map::Entry::Vacant(entry) =
                roots.entry(plan.anchor_epoch)
            {
                let root = if u64::try_from(plan.anchor_epoch).is_ok_and(|e| e <= captured) {
                    match history.root(plan.anchor_epoch).await {
                        Ok(Some(bytes)) => RootRead::Root(hex::encode(bytes).into_bytes()),
                        Ok(None) => RootRead::Missing,
                        Err(error) => RootRead::Unreadable(error.to_string().into_bytes()),
                    }
                } else {
                    RootRead::Missing
                };
                entry.insert(root);
            }
        }
        // Stop at the first native fault instead of querying lower-priority roots.
        graph
            .mode(rule, epoch, &|e| {
                roots.get(&e).cloned().unwrap_or(RootRead::Missing)
            })
            .map_err(|e| Error(e.to_string()))?;
    }
    Profile::resolve(graph, epoch, &|e| {
        roots.get(&e).cloned().unwrap_or(RootRead::Missing)
    })
    .map_err(|e| Error(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{canonical::Head, consensus_bundle::RawBundle, finality, finality_queries::Range};
    use std::sync::Mutex;

    struct Roots {
        graph: Graph,
        fault: Option<(i64, &'static str)>,
        reads: Mutex<Vec<i64>>,
    }
    #[async_trait::async_trait]
    impl History for Roots {
        async fn head(&self) -> Result<Head, finality::Error> {
            unreachable!()
        }
        async fn range(&self, _: i64, _: i64) -> Result<Range, finality::Error> {
            unreachable!()
        }
        async fn bundle(&self, _: &[u8; 32]) -> Result<Option<RawBundle>, finality::Error> {
            unreachable!()
        }
        async fn root(&self, epoch: i64) -> Result<Option<Vec<u8>>, finality::Error> {
            self.reads.lock().unwrap().push(epoch);
            match self.fault.filter(|(e, _)| *e == epoch).map(|(_, s)| s) {
                Some("missing") => Ok(None),
                Some("wrong") => Ok(Some(vec![0; 32])),
                Some(_) => Err(finality::Error::Unavailable("disk unavailable".into())),
                None => Ok(Some(
                    hex::decode(
                        ORDER
                            .iter()
                            .filter_map(|r| self.graph.activation(*r))
                            .find(|p| p.anchor_epoch == epoch)
                            .unwrap()
                            .anchor_state_root,
                    )
                    .unwrap(),
                )),
            }
        }
    }
    #[tokio::test]
    async fn anchored_views_use_verified_raw_roots_once_and_preserve_fault_order() {
        let graph = Graph::new(
            octra_node_protocol::consensus::policy::DEVNET.to_vec(),
            None,
        );
        let mut history = Roots {
            graph: graph.clone(),
            fault: None,
            reads: Mutex::new(vec![]),
        };
        let profile = anchored(&graph, 1_663_000, 1_662_999, &history)
            .await
            .unwrap();
        assert!(profile.math && profile.object_cost && profile.point_ops);
        assert_eq!(profile.proof_exec, RuleMode::Active);
        assert_eq!(
            *history.reads.lock().unwrap(),
            [1_380_960, 1_504_440, 1_353_962]
        );
        for fault in ["missing", "wrong", "unreadable"] {
            history.fault = Some((1_504_440, fault));
            history.reads.lock().unwrap().clear();
            let error = anchored(&graph, 1_663_000, 1_662_999, &history)
                .await
                .unwrap_err();
            assert!(error.to_string().contains("1504440"), "{error}");
            assert_eq!(
                *history.reads.lock().unwrap(),
                [1_380_960, 1_504_440],
                "later rules must not override an earlier fault"
            );
        }
        history.reads.lock().unwrap().clear();
        assert!(anchored(&graph, 1_663_000, 0, &history).await.is_err());
        assert!(
            history.reads.lock().unwrap().is_empty(),
            "future roots are unavailable to a retained snapshot"
        );
    }
}
