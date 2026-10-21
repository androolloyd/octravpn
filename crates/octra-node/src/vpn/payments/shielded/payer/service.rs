//! Supervised finite jobs. Startup discovers only existing encrypted consent;
//! neither a timer nor a control reply can create a purchase or deposit.
use super::super::{wallet::Wallet, Pool};
use super::{funding, native::FeePolicy, runner, Payer};
use crate::{
    rpc::Submission,
    vpn::payments::shielded::index::{Handle, Index},
    Host,
};
use anyhow::{ensure, Context, Result};
use ed25519_dalek::SigningKey;
use octra_private_payments_experimental::pool::transaction::Prover;
use octravpn_core::payments::{PrivateExchange, PrivateTarget};
use std::{sync::Arc, time::Duration};
use tokio::sync::watch;

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct Status {
    pub remaining: usize,
    pub completed: usize,
    /// Errors pause a finite job without terminating the consensus node.
    pub blocked: usize,
    /// Consented purchases held until their operator's carrier is ready.
    pub paused: usize,
}
struct Operator {
    payer: Payer,
    control: Arc<dyn PrivateExchange>,
    purchases: Vec<(runner::Purchase, bool)>,
    enabled: bool,
}
pub struct Service<A: Host> {
    payer: Payer,
    index: Handle,
    submission: Arc<Submission<A>>,
    relayer: Arc<SigningKey>,
    prover: Prover,
    funding: Vec<(funding::Funding, bool)>,
    operators: Vec<Operator>,
    income: Vec<Wallet>,
    fees: Option<FeePolicy>,
    status: watch::Sender<Status>,
}
impl<A: Host> Service<A> {
    pub async fn resume(
        payer: Payer,
        index: Index,
        submission: Arc<Submission<A>>,
        relayer: Arc<SigningKey>,
        prover: Prover,
        control: Arc<dyn PrivateExchange>,
    ) -> Result<Self> {
        let index = Handle::ready(Arc::new(index), payer.1.clone())?;
        Self::resume_handle(payer, index, submission, relayer, prover, control).await
    }
    pub(super) async fn resume_handle(
        payer: Payer,
        index: Handle,
        submission: Arc<Submission<A>>,
        relayer: Arc<SigningKey>,
        prover: Prover,
        control: Arc<dyn PrivateExchange>,
    ) -> Result<Self> {
        ensure!(
            index.belongs_to(&payer.1)
                && Arc::ptr_eq(&payer.1.directory.shared, &submission.node.shared),
            "private payer services belong to another canonical node or pool"
        );
        let funding = funding::Funding::discover(payer.clone()).await?;
        let purchases = runner::Purchase::discover(payer.clone()).await?;
        let public = relayer.verifying_key().to_bytes();
        let mut policy = None;
        for (key, fees) in funding
            .iter()
            .map(|f| (f.terms().relayer_public, f.terms().fees))
            .chain(
                purchases
                    .iter()
                    .map(|p| (p.terms().relayer_public, p.terms().fees)),
            )
        {
            accept_policy(public, &mut policy, key, fees)?;
        }
        let (status, _) = watch::channel(Status {
            remaining: funding.len() + purchases.len(),
            ..Status::default()
        });
        Ok(Self {
            payer: payer.clone(),
            index,
            submission,
            relayer,
            prover,
            funding: funding.into_iter().map(|job| (job, false)).collect(),
            operators: vec![Operator {
                payer,
                control,
                purchases: purchases.into_iter().map(|job| (job, false)).collect(),
                enabled: true,
            }],
            income: Vec::new(),
            fees: policy,
            status,
        })
    }
    pub fn status(&self) -> watch::Receiver<Status> {
        self.status.subscribe()
    }

    /// Add an operator view of the same custody book. Its jobs start paused:
    /// the route owner enables them only after their paid carrier is live.
    /// Different pools need separate books and explicit relayer authorities.
    pub async fn add_operator(
        &mut self,
        source: Arc<Pool>,
        control: Arc<dyn PrivateExchange>,
    ) -> Result<()> {
        ensure!(
            self.operators.len() < 64,
            "private operator capacity exhausted"
        );
        let payer = self.payer.for_operator(source)?;
        ensure!(
            self.operators.iter().all(|operator| {
                operator.payer.1.directory.operator != payer.1.directory.operator
                    || operator.payer.1.directory.config.program != payer.1.directory.config.program
            }),
            "private operator target already registered"
        );
        let purchases = runner::Purchase::discover(payer.clone()).await?;
        let mut policy = self.fees;
        for job in &purchases {
            accept_policy(
                self.relayer.verifying_key().to_bytes(),
                &mut policy,
                job.terms().relayer_public,
                job.terms().fees,
            )?;
        }
        let paused = purchases.len();
        self.operators.push(Operator {
            payer,
            control,
            purchases: purchases.into_iter().map(|job| (job, false)).collect(),
            enabled: false,
        });
        self.fees = policy;
        self.status.send_modify(|state| {
            state.remaining += paused;
            state.paused += paused;
        });
        Ok(())
    }

    /// Host routing authority only. This neither creates consent nor changes
    /// a saved job, tariff, fee allowance or canonical purchase requirement.
    pub fn set_operator_enabled(&mut self, target: &PrivateTarget, enabled: bool) -> Result<()> {
        let operator = self
            .operators
            .iter_mut()
            .find(|operator| runner::matches_source(target, &operator.payer.1))
            .ok_or_else(|| anyhow::anyhow!("private operator target is not registered"))?;
        if operator.enabled != enabled {
            let unfinished = operator.purchases.iter().filter(|(_, done)| !done).count();
            operator.enabled = enabled;
            self.status.send_modify(|state| {
                if enabled {
                    state.paused = state.paused.saturating_sub(unfinished);
                } else {
                    state.paused += unfinished;
                }
            });
        }
        Ok(())
    }

    /// Explicitly attach an unlocked operator wallet. Canonical earnings retain
    /// their exclusive one-book assignment; attachment creates no spending job.
    pub fn with_income(mut self, wallet: Wallet) -> Result<Self> {
        ensure!(
            self.payer.1.same_custody(wallet.income_pool()),
            "private income has another custody source or node"
        );
        if !self
            .income
            .iter()
            .any(|saved| saved.income_id() == wallet.income_id())
        {
            ensure!(
                self.income.len() < 64,
                "private income provider capacity exhausted"
            );
            self.income.push(wallet);
        }
        Ok(self)
    }

    pub async fn view(&self) -> Result<super::super::index::View> {
        self.index
            .opened()
            .context("private index awaits fresh chain admission")?
            .view()
            .await
    }

    async fn import_income(&self, index: &Index) -> Result<()> {
        if !self.income.is_empty() && index.sync(128).await?.complete {
            let view = index.view().await?;
            for wallet in &self.income {
                self.payer.attach_income(wallet, view.index()).await?;
            }
            view.with_current(|_| Ok(()))?;
        }
        Ok(())
    }

    /// One bounded pass, useful for embedded hosts with their own scheduler.
    /// Recovered jobs always reauthenticate canonical confirmation first.
    pub async fn step(&mut self) -> Status {
        let Ok(index) = self.index.get().await else {
            let funding = self.funding.iter().filter(|(_, done)| !done).count();
            let mut remaining = funding;
            let mut paused = 0;
            let mut total = self.funding.len();
            for operator in &self.operators {
                let pending = operator.purchases.iter().filter(|(_, done)| !done).count();
                remaining += pending;
                total += operator.purchases.len();
                if !operator.enabled {
                    paused += pending;
                }
            }
            return self.publish(Status {
                remaining,
                completed: total - remaining,
                blocked: remaining.saturating_sub(paused).max(1),
                paused,
            });
        };
        let mut state = Status::default();
        for (job, done) in &mut self.funding {
            if !*done {
                let result = Box::pin(job.step(funding::Services {
                    index: &index,
                    submission: &self.submission,
                    relayer: &self.relayer,
                    prover: &self.prover,
                }))
                .await;
                match result {
                    Ok(funding::State::Funded { .. }) => *done = true,
                    Err(_) => state.blocked += 1,
                    _ => {}
                }
            }
            if *done {
                state.completed += 1;
            } else {
                state.remaining += 1;
            }
        }
        if self.import_income(&index).await.is_err() {
            state.blocked += 1;
        }
        for operator in &mut self.operators {
            for (job, done) in &mut operator.purchases {
                if !*done && !operator.enabled {
                    state.remaining += 1;
                    state.paused += 1;
                    continue;
                }
                if !*done {
                    let result = Box::pin(job.step(runner::Services {
                        index: &index,
                        submission: &self.submission,
                        relayer: &self.relayer,
                        prover: &self.prover,
                        control: &*operator.control,
                    }))
                    .await;
                    match result {
                        Ok(runner::State::Credited { .. }) => *done = true,
                        Err(_) => state.blocked += 1,
                        _ => {}
                    }
                }
                if *done {
                    state.completed += 1;
                } else {
                    state.remaining += 1;
                }
            }
        }
        self.publish(state)
    }
    fn publish(&self, state: Status) -> Status {
        if *self.status.borrow() != state {
            tracing::debug!(
                completed = state.completed,
                remaining = state.remaining,
                blocked = state.blocked,
                paused = state.paused,
                "private payer progress"
            );
        }
        self.status.send_replace(state);
        state
    }
    pub async fn run(mut self, mut stop: watch::Receiver<bool>) -> Result<()> {
        let mut heads = self.payer.1.directory.shared.1.subscribe();
        let mut poll = tokio::time::interval(Duration::from_secs(1));
        poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            if *stop.borrow() {
                break;
            }
            tokio::select! {
                biased;
                _ = stop.changed() => break,
                changed = heads.changed() => { changed?; },
                _ = poll.tick() => {},
            }
            tokio::select! {
                biased;
                _ = stop.changed() => break,
                _ = Box::pin(self.step()) => {},
            }
        }
        // Release all wallet clones before closing the index. No detached
        // request task survives this service's shutdown.
        self.funding.clear();
        self.operators.clear();
        self.income.clear();
        self.index.close().await;
        Ok(())
    }
}

fn accept_policy(
    public: [u8; 32],
    policy: &mut Option<FeePolicy>,
    key: [u8; 32],
    fees: FeePolicy,
) -> Result<()> {
    fees.validate()?;
    ensure!(key == public, "private service job uses another relayer");
    ensure!(
        policy.is_none_or(|accepted| accepted == fees),
        "private service fee policies differ"
    );
    *policy = Some(fees);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_groups_cannot_change_relayer_or_increase_shared_fee_consent() {
        let fees = FeePolicy {
            fee_ou: 1000,
            lifetime_budget_ou: 4000,
            max_attempts: 4,
        };
        let mut policy = None;
        accept_policy([1; 32], &mut policy, [1; 32], fees).unwrap();
        assert!(accept_policy([1; 32], &mut policy, [2; 32], fees).is_err());
        for changed in [
            FeePolicy {
                lifetime_budget_ou: 5000,
                ..fees
            },
            FeePolicy {
                max_attempts: 5,
                ..fees
            },
            FeePolicy {
                fee_ou: 2000,
                ..fees
            },
        ] {
            assert!(accept_policy([1; 32], &mut policy, [1; 32], changed).is_err());
            assert!(policy == Some(fees));
        }
        accept_policy([1; 32], &mut policy, [1; 32], fees).unwrap();
    }
}
