//! Current-head peer evidence controls serving admission, never ledger rollback.
//! Only `EpochRoots` supplies production responses: its receive boundary checks
//! signatures and membership and its query leases deduplicate each responder.
#[cfg(test)]
mod network_tests;

use super::Service;
use crate::{Host, RootQuarantineTicket};
use anyhow::{Context, Result};
use num_bigint::Sign;
use octra_node_protocol::consensus::{catchup, health as policy, ValidatorSet};
use octra_node_runtime::{
    canonical::Head,
    epoch_roots::{self, Response, WaitFor},
};
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Status {
    Attested { consensus: bool },
    Conflicting { root: [u8; 32], consensus: bool },
    Unknown,
    Stale,
}

pub(super) struct Sample {
    pub head: Head,
    pub ticket: RootQuarantineTicket,
    /// The native fault-tolerant target includes every authenticated reply,
    /// independently of whether that peer supplied a current-head root.
    pub peer_target: i64,
    pub target: Option<u64>,
    pub required: i64,
    pub matching: i64,
    pub responses: i64,
    pub status: Status,
}

struct Members {
    active: ValidatorSet,
    stake: ValidatorSet,
}

pub(super) async fn query<A: Host>(service: &Service<A>) -> Result<Sample> {
    query_source(service).await
}

#[async_trait::async_trait]
trait Source: Send + Sync {
    fn chain(&self) -> &[u8];
    fn config(&self) -> policy::Config {
        policy::Config::default()
    }
    fn ticket(&self) -> RootQuarantineTicket;
    async fn head(&self) -> Result<Head>;
    async fn authority(&self, head: &Head, epoch: i64) -> Result<Members>;
    async fn roots(&self, epoch: i64, wait_for: WaitFor) -> Result<Vec<Response>>;
}

#[async_trait::async_trait]
impl<A: Host> Source for Service<A> {
    fn chain(&self) -> &[u8] {
        self.node.store.chain().chain_id.as_bytes()
    }
    fn ticket(&self) -> RootQuarantineTicket {
        self.node.root_quarantine_ticket()
    }
    fn config(&self) -> policy::Config {
        self.health.clone()
    }
    async fn head(&self) -> Result<Head> {
        self.node.head().await
    }
    async fn authority(&self, head: &Head, epoch: i64) -> Result<Members> {
        let stake = self.membership.stake_set(head, epoch).await?;
        let relief = self.node.store.reader().relief_after(head).await?;
        let rules = self
            .node
            .host
            .resolve(head, u64::try_from(epoch)?, relief)
            .await
            .map_err(anyhow::Error::msg)?;
        Ok(Members {
            active: rules.validators,
            stake,
        })
    }
    async fn roots(&self, epoch: i64, wait_for: WaitFor) -> Result<Vec<Response>> {
        Ok(self.roots.query(epoch, 5., wait_for, false).await?)
    }
}

async fn query_source(source: &impl Source) -> Result<Sample> {
    // The native health probe retries one moving-head sample. A second change
    // reports no usable evidence; the owning node separately guards gate writes.
    let mut retries = 1;
    loop {
        let ticket = source.ticket();
        let head = source.head().await?;
        let epoch = i64::try_from(head.cursor.epoch.0)?;
        let next = epoch.checked_add(1).context("health epoch overflow")?;
        let authority = source.authority(&head, next).await?;
        let mut sample = Sample {
            head,
            ticket,
            peer_target: epoch,
            target: None,
            required: policy::required_attesters(
                authority.active.f,
                authority.active.n,
                source.config().state_attest_min_peers,
            ),
            matching: 0,
            responses: 0,
            status: Status::Stale,
        };
        if source.head().await? != sample.head {
            if retries > 0 {
                retries -= 1;
                continue;
            }
            return Ok(sample);
        }
        // Native health waits for consensus evidence, then applies its separate
        // distinct-peer admission threshold to the replies actually received.
        let responses = source.roots(epoch, WaitFor::ConsensusQuorum).await;
        if source.head().await? != sample.head {
            if retries > 0 {
                retries -= 1;
                continue;
            }
            return Ok(sample);
        }
        let classified = classify_members(
            source.chain(),
            &sample.head,
            &authority,
            sample.required,
            &responses?,
        )?;
        sample.status = classified.status;
        sample.peer_target = classified.peer_target;
        sample.target = (classified.peer_target > epoch)
            .then(|| u64::try_from(classified.peer_target))
            .transpose()?;
        sample.matching = classified.matching;
        sample.responses = classified.responses;
        return Ok(sample);
    }
}

struct Classified {
    status: Status,
    peer_target: i64,
    matching: i64,
    responses: i64,
}

fn classify_members(
    chain: &[u8],
    head: &Head,
    authority: &Members,
    required: i64,
    responses: &[Response],
) -> Result<Classified> {
    let epoch = i64::try_from(head.cursor.epoch.0)?;
    let mut seen = BTreeSet::new();
    let mut records = Vec::new();
    for response in responses {
        // Reject malformed roots before deduplication so an internal malformed
        // duplicate cannot hide that responder's valid record. Rootless replies
        // still carry authenticated head hints, as in native peer_target_epoch.
        if response
            .state_root
            .as_ref()
            .is_some_and(|root| root.len() != 32)
        {
            continue;
        }
        if authority
            .active
            .public_key(&response.responder_addr)
            .is_none_or(|key| key.len() != 32)
            || authority
                .stake
                .weight(&response.responder_addr)
                .is_none_or(|weight| weight.sign() != Sign::Plus)
            || !seen.insert(response.responder_addr.clone())
        {
            continue;
        }
        records.push(response.clone());
    }
    let heads = records
        .iter()
        .map(|response| catchup::PeerHead {
            responder_addr: response.responder_addr.clone(),
            responder_head_epoch: response.responder_head_epoch,
        })
        .collect::<Vec<_>>();
    let responses = records.len() as i64;
    let peer_target = if responses >= required {
        catchup::pick_target_epoch(&heads, authority.active.f, epoch)?
    } else {
        epoch
    };
    let matching = records
        .iter()
        .filter(|r| r.state_root.as_deref() == Some(head.cursor.state_root.0.as_slice()))
        .count() as i64;
    let quorum = policy::peer_root_quorum(
        required,
        &head.cursor.state_root.0,
        records.iter().map(|r| r.state_root.as_deref()),
    );
    let selected = match quorum {
        policy::RootQuorum::Matching(majority) | policy::RootQuorum::Mismatching(majority) => {
            Some(majority.root)
        }
        _ if required == 0 => Some(head.cursor.state_root.0.to_vec()),
        _ => None,
    };
    let status = if let Some(root) = selected {
        let group = records
            .into_iter()
            .filter(|r| r.state_root.as_deref() == Some(root.as_slice()))
            .collect::<Vec<_>>();
        let consensus = epoch_roots::reached(
            chain,
            epoch,
            &authority.stake,
            WaitFor::ConsensusQuorum,
            &group,
        )?;
        let root: [u8; 32] = root.try_into().expect("validated root length");
        if root == head.cursor.state_root.0 {
            Status::Attested { consensus }
        } else {
            Status::Conflicting { root, consensus }
        }
    } else {
        Status::Unknown
    };
    Ok(Classified {
        status,
        peer_target,
        matching,
        responses,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::published::Shared;
    use octra_exex::{Cursor, EpochId, Sequence, StateRoot};
    use octra_node_protocol::consensus::{policy, Validator};
    use std::{
        collections::VecDeque,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Mutex,
        },
    };

    const CHAIN: &[u8] = b"health-classifier-fixture";
    const LOCAL: [u8; 32] = [7; 32];
    const OTHER: [u8; 32] = [8; 32];

    // These fixtures exercise classification/freshness only. Production input
    // authenticity belongs to EpochRoots::handle, not this synthetic Source.
    fn head(epoch: u64) -> Head {
        Head {
            cursor: Cursor {
                sequence: Sequence(epoch),
                epoch: EpochId(epoch),
                state_root: StateRoot(LOCAL),
            },
            ledger_root: "0".repeat(64),
            irmin_commit: "0".repeat(128),
            parent_commit: None,
            index_root: "0".repeat(64),
            index_hash: None,
            txid_hi: -1,
            date: 0,
            message: vec![],
        }
    }
    fn validator(seed: u8) -> Validator {
        Validator {
            address: format!("validator-{seed}").into_bytes(),
            pubkey: ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .to_bytes()
                .to_vec(),
        }
    }
    fn validators(count: u8) -> ValidatorSet {
        ValidatorSet::unweighted((1..=count).map(validator).collect())
    }
    fn reply(seed: u8, root: [u8; 32], epoch: i64) -> Response {
        Response {
            responder_addr: validator(seed).address,
            responder_head_epoch: epoch,
            state_root: Some(root.to_vec()),
        }
    }
    fn status(authority: &ValidatorSet, responses: &[Response]) -> Status {
        classify(CHAIN, &head(10), authority, responses).unwrap().0
    }
    fn classify(
        chain: &[u8],
        head: &Head,
        authority: &ValidatorSet,
        responses: &[Response],
    ) -> Result<(Status, Option<u64>)> {
        let members = Members {
            active: authority.clone(),
            stake: authority.clone(),
        };
        let required = super::policy::required_attesters(authority.f, authority.n, 0);
        let value = classify_members(chain, head, &members, required, responses)?;
        let epoch = i64::try_from(head.cursor.epoch.0)?;
        let target = (value.peer_target > epoch)
            .then(|| u64::try_from(value.peer_target))
            .transpose()?;
        Ok((value.status, target))
    }

    #[test]
    fn native_count_admission_and_weak_conflict_are_preserved() {
        let authority = validators(4);
        assert_eq!(status(&authority, &[]), Status::Unknown);
        assert_eq!(status(&authority, &[reply(1, LOCAL, 10)]), Status::Unknown);
        let local = [reply(1, LOCAL, 10), reply(2, LOCAL, 10)];
        assert_eq!(
            status(&authority, &local),
            Status::Attested { consensus: false }
        );
        let conflict = [reply(1, OTHER, 10), reply(2, OTHER, 10)];
        assert_eq!(
            status(&authority, &conflict),
            Status::Conflicting {
                root: OTHER,
                consensus: false
            }
        );
    }

    #[test]
    fn proven_conflict_is_not_filtered_away_by_a_local_reply() {
        let authority = validators(4);
        let responses = [
            reply(1, LOCAL, 10),
            reply(2, OTHER, 10),
            reply(3, OTHER, 10),
            reply(4, OTHER, 10),
        ];
        assert_eq!(
            status(&authority, &responses),
            Status::Conflicting {
                root: OTHER,
                consensus: true
            }
        );
    }

    #[test]
    fn root_choice_counts_distinct_signers_independently_of_byte_order() {
        let authority = validators(7);
        let mut responses = (1..=3)
            .map(|seed| reply(seed, LOCAL, 10))
            .collect::<Vec<_>>();
        responses.extend((4..=7).map(|seed| reply(seed, OTHER, 10)));
        assert_eq!(
            status(&authority, &responses),
            Status::Conflicting {
                root: OTHER,
                consensus: false
            }
        );
        responses.reverse();
        assert_eq!(
            status(&authority, &responses),
            Status::Conflicting {
                root: OTHER,
                consensus: false
            }
        );
        for response in &mut responses {
            if response.state_root.as_deref() == Some(OTHER.as_slice()) {
                response.state_root = Some(vec![6; 32]);
            }
        }
        assert_eq!(
            status(&authority, &responses),
            Status::Conflicting {
                root: [6; 32],
                consensus: false
            }
        );
    }

    #[test]
    fn duplicate_unknown_and_malformed_roots_cannot_supply_agreement() {
        let authority = validators(4);
        let one = reply(1, LOCAL, 10);
        let mut responses = vec![one; 100];
        responses.extend((5..=10).map(|seed| reply(seed, LOCAL, 10)));
        for root in [Some(vec![7; 31]), Some(vec![7; 33])] {
            responses.push(Response {
                state_root: root,
                ..reply(2, LOCAL, 10)
            });
        }
        responses.push(Response {
            state_root: None,
            ..reply(3, LOCAL, 10)
        });
        assert_eq!(status(&authority, &responses), Status::Unknown);
        responses.push(reply(2, LOCAL, 10));
        assert_eq!(
            status(&authority, &responses),
            Status::Attested { consensus: false }
        );
        // An impossible duplicate from a synthetic internal caller cannot be
        // counted again for another root; the real query already enforces this.
        responses.extend([reply(1, OTHER, 10), reply(2, OTHER, 10)]);
        assert_eq!(
            status(&authority, &responses),
            Status::Attested { consensus: false }
        );
    }

    #[test]
    fn count_admission_is_separate_from_historical_weighted_consensus() {
        let authority = ValidatorSet::weighted(vec![
            (validator(1), 100.into()),
            (validator(2), 1.into()),
            (validator(3), 1.into()),
            (validator(4), 1.into()),
        ])
        .unwrap();
        let before = policy::QUORUM_ACTIVATION - 1;
        let after = policy::QUORUM_ACTIVATION;
        assert_eq!(
            classify(
                policy::DEVNET,
                &head(before as u64),
                &authority,
                &[reply(1, LOCAL, before)]
            )
            .unwrap()
            .0,
            Status::Unknown
        );
        assert_eq!(
            classify(
                policy::DEVNET,
                &head(after as u64),
                &authority,
                &[reply(1, LOCAL, after)]
            )
            .unwrap()
            .0,
            Status::Unknown
        );
        let responses = [
            reply(1, LOCAL, after),
            reply(2, OTHER, after),
            reply(3, OTHER, after),
            reply(4, OTHER, after),
        ];
        assert_eq!(
            classify(policy::DEVNET, &head(before as u64), &authority, &responses)
                .unwrap()
                .0,
            Status::Conflicting {
                root: OTHER,
                consensus: false
            }
        );
        assert_eq!(
            classify(
                policy::DEVNET,
                &head(before as u64),
                &authority,
                &[reply(2, LOCAL, before), reply(3, LOCAL, before)]
            )
            .unwrap()
            .0,
            Status::Attested { consensus: false }
        );
        assert_eq!(
            classify(policy::DEVNET, &head(after as u64), &authority, &responses)
                .unwrap()
                .0,
            Status::Conflicting {
                root: OTHER,
                consensus: true
            }
        );
    }

    #[test]
    fn configured_attester_count_cannot_be_replaced_by_weighted_finality() {
        let authority = ValidatorSet::weighted(vec![
            (validator(1), 100.into()),
            (validator(2), 1.into()),
            (validator(3), 1.into()),
            (validator(4), 1.into()),
        ])
        .unwrap();
        let members = Members {
            active: authority.clone(),
            stake: authority,
        };
        let epoch = policy::QUORUM_ACTIVATION - 1;
        let local = head(epoch as u64);
        let two = [reply(1, LOCAL, epoch), reply(2, LOCAL, epoch)];
        assert_eq!(
            classify_members(policy::DEVNET, &local, &members, 3, &two)
                .unwrap()
                .status,
            Status::Unknown
        );
        let three = [
            reply(1, LOCAL, epoch),
            reply(2, LOCAL, epoch),
            reply(3, LOCAL, epoch),
        ];
        assert_eq!(
            classify_members(policy::DEVNET, &local, &members, 3, &three)
                .unwrap()
                .status,
            Status::Attested { consensus: true }
        );
    }

    #[test]
    fn selected_active_set_supplies_count_policy_and_stake_supplies_proof() {
        let active = validators(4);
        let members = Members {
            active,
            stake: validators(7),
        };
        let records = [
            reply(1, LOCAL, 10),
            reply(2, LOCAL, 10),
            reply(7, OTHER, 999),
        ];
        let required = super::policy::required_attesters(members.active.f, members.active.n, 0);
        assert_eq!(required, 2);
        let classified = classify_members(CHAIN, &head(10), &members, required, &records).unwrap();
        assert_eq!(classified.responses, 2);
        assert_eq!(classified.peer_target, 10);
        assert_eq!(classified.status, Status::Attested { consensus: false });
    }

    #[test]
    fn all_authenticated_heads_supply_the_native_fault_tolerant_target() {
        let authority = validators(4);
        let responses = [
            reply(1, LOCAL, 12),
            reply(2, LOCAL, 11),
            reply(3, OTHER, 999),
        ];
        assert_eq!(
            classify(CHAIN, &head(10), &authority, &responses)
                .unwrap()
                .1,
            Some(12)
        );
        let responses = [
            reply(1, LOCAL, 999),
            reply(2, LOCAL, 10),
            reply(3, OTHER, 10),
        ];
        assert_eq!(
            classify(CHAIN, &head(10), &authority, &responses)
                .unwrap()
                .1,
            None
        );
    }

    struct Step {
        next: Option<Head>,
        conflict: bool,
        responses: Vec<Response>,
    }
    struct Fixture {
        shared: Shared,
        head: Mutex<Head>,
        steps: Mutex<VecDeque<Step>>,
        queries: AtomicUsize,
        authority_epochs: Mutex<Vec<i64>>,
    }
    impl Fixture {
        fn new(steps: Vec<Step>) -> Self {
            Self {
                shared: Shared::new(),
                head: Mutex::new(head(10)),
                steps: Mutex::new(steps.into()),
                queries: AtomicUsize::new(0),
                authority_epochs: Mutex::new(vec![]),
            }
        }
    }
    #[async_trait::async_trait]
    impl Source for Fixture {
        fn chain(&self) -> &[u8] {
            CHAIN
        }
        fn ticket(&self) -> RootQuarantineTicket {
            self.shared.root_quarantine_ticket()
        }
        async fn head(&self) -> Result<Head> {
            Ok(self.head.lock().unwrap().clone())
        }
        async fn authority(&self, head: &Head, epoch: i64) -> Result<Members> {
            assert_eq!(epoch, head.cursor.epoch.0 as i64 + 1);
            self.authority_epochs.lock().unwrap().push(epoch);
            Ok(Members {
                active: validators(4),
                stake: validators(4),
            })
        }
        async fn roots(&self, epoch: i64, wait_for: WaitFor) -> Result<Vec<Response>> {
            assert!(matches!(wait_for, WaitFor::ConsensusQuorum));
            assert_eq!(epoch, self.head.lock().unwrap().cursor.epoch.0 as i64);
            self.queries.fetch_add(1, Ordering::Relaxed);
            let step = self
                .steps
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected retry");
            if let Some(next) = step.next {
                *self.head.lock().unwrap() = next;
            }
            if step.conflict {
                self.shared
                    .quarantine_root(&self.head.lock().unwrap(), "newer same-head conflict");
            }
            Ok(step.responses)
        }
    }
    fn step(next: Option<Head>, epoch: i64) -> Step {
        Step {
            next,
            conflict: false,
            responses: (1..=3).map(|seed| reply(seed, LOCAL, epoch)).collect(),
        }
    }

    #[tokio::test]
    async fn moving_head_retries_once_with_new_canonical_authority_capture() {
        let fixture = Fixture::new(vec![step(Some(head(11)), 10), step(None, 11)]);
        let sample = query_source(&fixture).await.unwrap();
        assert_eq!(sample.head, head(11));
        assert_eq!(sample.status, Status::Attested { consensus: true });
        assert_eq!(*fixture.authority_epochs.lock().unwrap(), vec![11, 12]);
        assert_eq!(fixture.queries.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn second_head_movement_reports_stale_without_forward_or_root_proof() {
        let fixture = Fixture::new(vec![step(Some(head(11)), 10), step(Some(head(12)), 11)]);
        let sample = query_source(&fixture).await.unwrap();
        assert_eq!(sample.head, head(11));
        assert_eq!(sample.status, Status::Stale);
        assert_eq!(sample.target, None);
        assert_eq!(fixture.queries.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn same_epoch_metadata_change_also_invalidates_the_sample() {
        let mut changed = head(10);
        changed.message = b"different exact head".to_vec();
        let fixture = Fixture::new(vec![step(Some(changed.clone()), 10), step(None, 10)]);
        let sample = query_source(&fixture).await.unwrap();
        assert_eq!(sample.head, changed);
        assert_eq!(sample.status, Status::Attested { consensus: true });
        assert_eq!(fixture.queries.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn newer_same_head_conflict_invalidates_the_prequery_ticket() {
        let mut response = step(None, 10);
        response.conflict = true;
        let fixture = Fixture::new(vec![response]);
        let sample = query_source(&fixture).await.unwrap();
        assert_eq!(sample.status, Status::Attested { consensus: true });
        assert!(fixture.shared.root_quarantined());
        assert!(!fixture.shared.clear_root_quarantine(&sample.ticket));
        assert!(fixture.shared.root_quarantined());
    }
}
