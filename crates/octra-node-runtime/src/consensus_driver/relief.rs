//! Same-height relief uses only a canonical schedule and signed round witnesses.
use super::{Driver, Error, Host, Publication};
use octra_node_protocol::consensus::{
    policy,
    relief::{self, Decision, Plan},
};

impl<H: Host, C: Publication> Driver<H, C> {
    pub(super) async fn maybe_activate_relief(&mut self) -> Result<(), Error> {
        let height = self.engine.state().height;
        if !relief::active(&self.chain, height)
            || self.engine.state().round < relief::MIN_ROUND && !self.engine.round_wait()
            || self.engine.pending_finalized().is_some()
        {
            return Ok(());
        }
        let current = self.engine.validators().clone();
        let Some(schedule) = self.host.relief_plan(height, &current).await? else {
            self.engine.set_relief_limit(None);
            return Ok(());
        };
        let chain = self.chain.clone();
        let plan = Plan {
            chain_id: &chain,
            height,
            current: &current,
            activate_epoch: schedule.activate_epoch,
            target: &schedule.target,
            fingerprint: &schedule.fingerprint,
        };
        self.engine.set_relief_limit(plan.clock_limit());
        if self.engine.state().round < relief::MIN_ROUND {
            return Ok(());
        }
        let proof = self.round_pool.witness(
            &self.chain,
            height,
            relief::MIN_ROUND - 1,
            self.engine.state().round,
            &current,
        );
        let mark = match plan.decide(&proof)? {
            Decision::Wait => return Ok(()),
            Decision::Refuse(reason) => {
                self.host
                    .warning(&format!("validator_set_relief refused: {reason}"));
                return Ok(());
            }
            Decision::Apply(mark) => mark,
        };
        // Source proofs must survive removal of a proposer or prevote signer.
        if let Err(reason) = self.keep_recovery() {
            self.votes.hold_journal(reason.clone());
            return Err(reason);
        }
        let saved = self.journal.keep_relief(mark)?;
        let Some(target) = plan.restore_with_authors(&saved)? else {
            return Ok(());
        };
        let policy = self.engine.quorum_policy();
        let votes = if policy.select(height) == policy::Rule::Stake {
            self.journal
                .load_proofs(policy, &self.chain, height, &target)?
        } else {
            Vec::new()
        };
        let round = votes
            .iter()
            .map(|v| v.round)
            .chain([self.engine.state().round, saved.round])
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or("relief round overflow")?;
        self.host.install_relief(height, &target).await?;
        self.work.abort_all();
        self.active_work = None;
        self.checking = false;
        self.build_retry = None;
        self.pace = None;
        self.pending_votes.clear();
        self.future_votes.clear();
        self.pending_checks.clear();
        self.verified.clear();
        self.replies.clear();
        self.round_replies.clear();
        self.round_peers.clear();
        self.fetches.clear();
        self.past_round = None;
        self.sync_retry = None;
        self.round_pool.clear();
        self.engine.reconfigure_validator_set(round, target)?;
        self.engine.restore_proofs(&votes)?;
        self.engine.set_relief_limit(None);
        self.host.warning(&format!(
            "validator_set_relief height = {height} round = {round} activate_epoch = {}",
            schedule.activate_epoch
        ));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus_driver::{ProposalPlan, ReliefPlan, Verdict};
    use crate::consensus_votes::{Precommit, Readiness};
    use ed25519_dalek::{Signer, SigningKey};
    use octra_node_protocol::{
        consensus::{
            engine::{Engine, TimeoutConfig},
            evidence::VoteConflict,
            hash,
            journal::JournalOwner,
            policy::{Protocol, DEVNET, ROUND_ACTIVATION},
            Bytes, Finalize, ParentCommit, Proposal, RoundStep, RoundSync, Validator, ValidatorSet,
        },
        network::{
            endpoint::Endpoint,
            session::Timeouts,
            swarm::{Config, Swarm},
        },
    };
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    const HEIGHT: i64 = ROUND_ACTIVATION;
    fn set(n: u8) -> ValidatorSet {
        ValidatorSet::weighted(
            (1..=n)
                .map(|id| {
                    (
                        Validator {
                            address: vec![id],
                            pubkey: SigningKey::from_bytes(&[id; 32])
                                .verifying_key()
                                .to_bytes()
                                .to_vec(),
                        },
                        1.into(),
                    )
                })
                .collect(),
        )
        .unwrap()
    }
    #[derive(Clone)]
    struct Authority {
        journal: JournalOwner,
        installed: Arc<AtomicBool>,
    }
    #[async_trait::async_trait]
    impl Host for Authority {
        fn sign(&self, b: &[u8]) -> Result<Bytes, Error> {
            Ok(SigningKey::from_bytes(&[1; 32]).sign(b).to_bytes().to_vec())
        }
        fn readiness(&self) -> Readiness {
            Readiness {
                role_can_vote: true,
                can_vote: true,
                finality_proof_needed: false,
            }
        }
        fn verify_parent(&self, _: i64, _: Option<&ParentCommit>) -> Result<(), Error> {
            Ok(())
        }
        async fn build(&self, _: i64) -> Result<Option<ProposalPlan>, Error> {
            Ok(None)
        }
        async fn verify(&self, _: &Proposal) -> Result<Verdict, Error> {
            Ok(Verdict::Wait)
        }
        async fn before_precommit(&self, _: Precommit) -> bool {
            false
        }
        async fn activate(&self, _: i64) -> Result<ValidatorSet, Error> {
            Ok(set(6))
        }
        async fn validators(&self, _: i64) -> Result<ValidatorSet, Error> {
            Ok(set(6))
        }
        async fn evidence(&self, _: VoteConflict) -> Result<(), Error> {
            Ok(())
        }
        fn warning(&self, _: &str) {}
        async fn relief_plan(&self, _: i64, _: &ValidatorSet) -> Result<Option<ReliefPlan>, Error> {
            Ok(
                (!self.installed.load(Ordering::SeqCst)).then(|| ReliefPlan {
                    activate_epoch: HEIGHT + 2,
                    target: set(5),
                    fingerprint: vec![b'a'; 64],
                }),
            )
        }
        async fn install_relief(&self, epoch: i64, target: &ValidatorSet) -> Result<(), Error> {
            let mark = self
                .journal
                .latest_relief(epoch)?
                .ok_or("relief must be durable before installation")?;
            assert_eq!(mark.height, HEIGHT);
            assert!(target.is_author(DEVNET, HEIGHT, &[6]));
            self.installed.store(true, Ordering::SeqCst);
            Ok(())
        }
    }
    #[async_trait::async_trait]
    impl Publication for Authority {
        fn head_epoch(&self) -> i64 {
            HEIGHT - 1
        }
        async fn finalized(&self, _: &ValidatorSet, _: &Finalize) -> Result<(), Error> {
            Err("fixture does not publish".into())
        }
        fn stopped(&self) {}
    }
    #[tokio::test]
    async fn dynamic_relief_requires_signed_witnesses_and_durable_mark() {
        let dir = tempfile::tempdir().unwrap();
        let journal = JournalOwner::open(dir.path()).unwrap();
        journal.set_floor(HEIGHT - 1).unwrap();
        let authority = Authority {
            journal: journal.clone(),
            installed: Arc::new(AtomicBool::new(false)),
        };
        let swarm = Swarm::new(
            Config {
                chain_id: DEVNET.to_vec(),
                node_address: vec![1],
                config_hash: vec![1; 32],
                binary_hash: vec![2; 32],
                require_binary_hash: false,
                upgrade: None,
                profiles: vec![],
                allowed_public_keys: vec![],
                bootstrap: vec![],
                maximum_validators: 6,
                advertised: Endpoint {
                    host: b"127.0.0.1".to_vec(),
                    port: 20800,
                },
                timeouts: Timeouts::default(),
                head: Arc::new(|| (HEIGHT - 1, [0; 32])),
            },
            SigningKey::from_bytes(&[1; 32]),
        )
        .unwrap();
        let mut engine = Engine::new(
            DEVNET.to_vec(),
            vec![1],
            set(6),
            HEIGHT,
            Protocol::default(),
            TimeoutConfig::default(),
        )
        .unwrap();
        engine.start_round(64);
        let (_, mut driver) = Driver::new(
            engine,
            journal.clone(),
            swarm,
            authority.clone(),
            authority.clone(),
            Ok(vec![]),
        )
        .unwrap();
        driver.maybe_activate_relief().await.unwrap();
        assert!(!authority.installed.load(Ordering::SeqCst));
        for corrupt in [true, false] {
            driver.round_pool.clear();
            for id in 1..=3 {
                let mut sync = RoundSync {
                    chain_id: DEVNET.to_vec(),
                    epoch_id: HEIGHT,
                    round: 64,
                    step: RoundStep::Prevote,
                    request: false,
                    validator: vec![id],
                    signature: vec![],
                };
                sync.signature = SigningKey::from_bytes(&[id; 32])
                    .sign(&hash::round_sync_sign_bytes(&sync).unwrap())
                    .to_bytes()
                    .to_vec();
                if corrupt {
                    sync.signature[0] ^= 1;
                }
                driver.round_pool.add(sync, 0.0);
            }
            driver.maybe_activate_relief().await.unwrap();
            assert_eq!(authority.installed.load(Ordering::SeqCst), !corrupt);
        }
        assert_eq!(driver.engine.validators().n, 5);
        assert_eq!(driver.engine.state().round, 65);
        let mark = journal.latest_relief(HEIGHT).unwrap().unwrap();
        assert_eq!(mark.round, 64);
        assert!(!driver.engine.validators().is_validator(&[6]));
        driver.maybe_activate_relief().await.unwrap();
        assert_eq!(driver.engine.state().round, 65);
    }
}
