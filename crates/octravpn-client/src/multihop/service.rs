//! Shared route lifecycle: blockers, ordered admission and owned hop tasks.
use super::{journal, Pins};
use crate::{paid_routes::CompositeRouteGuard, Interface};
use anyhow::{ensure, Context, Result};
use std::{sync::Arc, time::Duration};
use tokio::sync::watch;
#[cfg(test)]
mod tests;

#[async_trait::async_trait]
pub(super) trait Prepared: Send {
    type Live: Connection;
    async fn open(self) -> Result<Self::Live>;
}
#[async_trait::async_trait]
pub(super) trait Connection: Send + 'static {
    type Summary: Send + 'static;
    fn interface(&self) -> &Interface;
    async fn run(self, stop: watch::Receiver<bool>) -> Result<Self::Summary>;
}
macro_rules! connection {
    ($prepared:ty, $client:ty, $summary:ty) => {
        #[async_trait::async_trait]
        impl Prepared for $prepared {
            type Live = $client;
            async fn open(self) -> Result<Self::Live> {
                <$prepared>::open(self).await
            }
        }
        #[async_trait::async_trait]
        impl Connection for $client {
            type Summary = $summary;
            fn interface(&self) -> &Interface {
                <$client>::interface(self)
            }
            async fn run(self, mut stop: watch::Receiver<bool>) -> Result<Self::Summary> {
                <$client>::run(self, async move {
                    stop.wait_for(|v| *v).await?;
                    Ok(())
                })
                .await
            }
        }
    };
}
connection!(
    crate::payment_runner::Prepared,
    crate::PaymentClient,
    crate::PaymentSummary
);
connection!(
    crate::private_runner::Local,
    crate::PrivatePaymentClient,
    crate::PrivatePaymentSummary
);

pub(super) struct Route<S: Send + 'static> {
    workers: tokio::task::JoinSet<(usize, Result<S>)>,
    stop: watch::Sender<bool>,
    routes: CompositeRouteGuard,
    journal: Arc<dyn super::funded::Journal>,
    pub(super) chain: Option<Box<dyn super::funded::Chain>>,
    interfaces: Vec<Interface>,
}
impl<S: Send + 'static> Route<S> {
    pub(super) async fn open<P>(
        prepared: Vec<P>,
        pins: &[Pins],
        routes: CompositeRouteGuard,
        journal: journal::Lease,
    ) -> Result<Self>
    where
        P: Prepared,
        P::Live: Connection<Summary = S>,
    {
        let mut client = Self::new(routes, Arc::new(journal));
        for (index, prepared) in prepared.into_iter().enumerate() {
            client.next(pins[index])?;
            client.admit(prepared.open()).await?;
        }
        client.finish().await?;
        Ok(client)
    }

    pub(super) fn new(
        routes: CompositeRouteGuard,
        journal: Arc<dyn super::funded::Journal>,
    ) -> Self {
        let (stop, _) = watch::channel(false);
        Self {
            workers: tokio::task::JoinSet::new(),
            stop,
            routes,
            journal,
            chain: None,
            interfaces: Vec::new(),
        }
    }
    async fn guard(&self) -> Result<()> {
        self.journal.check().await?;
        if let Some(chain) = &self.chain {
            chain.check()?;
        }
        Ok(())
    }
    pub(super) fn next(&mut self, pin: Pins) -> Result<()> {
        if let Some(previous) = self.interfaces.last() {
            self.routes.next(previous, pin.wireguard, pin.control)?;
        }
        Ok(())
    }
    pub(super) async fn admit<C: Connection<Summary = S>>(
        &mut self,
        opened: impl std::future::Future<Output = Result<C>>,
    ) -> Result<()> {
        self.guard().await?;
        let connection = guarded_open(
            opened,
            &mut self.workers,
            self.journal.as_ref(),
            self.chain.as_deref(),
        )
        .await?;
        let index = self.interfaces.len();
        self.interfaces.push(connection.interface().clone());
        let stop = self.stop.subscribe();
        self.workers
            .spawn(async move { (index, connection.run(stop).await) });
        Ok(())
    }
    pub(super) fn routes_chain(&mut self, entry: &crate::Interface) -> Result<()> {
        self.routes.chain(entry)
    }
    pub(super) async fn finish(&mut self) -> Result<()> {
        self.guard().await?;
        if let Some(failed) = self.workers.try_join_next() {
            return Err(worker_failure(Some(failed)));
        }
        self.routes
            .finish(self.interfaces.last().context("route exit missing")?)
    }

    pub(super) fn interfaces(&self) -> &[crate::Interface] {
        &self.interfaces
    }

    /// Only a successful explicit shutdown releases host routes. Errors and
    /// future cancellation leave the kernel blockers for deliberate recovery.
    pub(super) async fn run(
        mut self,
        shutdown: impl std::future::Future<Output = Result<()>>,
    ) -> Result<Vec<S>> {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tokio::pin!(shutdown);
        let outcome = loop {
            tokio::select! {
                biased;
                signal = &mut shutdown => break signal,
                failure = self.workers.join_next() => break Err(worker_failure(failure)),
                _ = interval.tick() => { if let Err(error) = self.guard().await { break Err(error); } },
            }
        };
        let outcome = match outcome {
            Ok(()) => match self.chain.as_mut() {
                Some(chain) => chain.pause().await,
                None => Ok(()),
            },
            Err(error) => Err(error),
        };
        self.stop.send_replace(true);
        let mut summaries = Vec::new();
        let mut failure = None;
        while let Some(result) = self.workers.join_next().await {
            match result {
                Ok((index, Ok(summary))) => summaries.push((index, summary)),
                Ok((_, Err(error))) => {
                    failure.get_or_insert(error);
                }
                Err(error) => {
                    failure.get_or_insert(error.into());
                }
            }
        }
        outcome?;
        if let Some(error) = failure {
            return Err(error);
        }
        ensure!(
            summaries.len() == self.interfaces.len(),
            "a route hop stopped before shutdown"
        );
        self.routes.disconnect()?;
        if let Some(mut chain) = self.chain {
            self.journal.released().await?;
            chain.release().await?;
        }
        summaries.sort_by_key(|(index, _)| *index);
        Ok(summaries.into_iter().map(|(_, summary)| summary).collect())
    }
}

/// Keep polling the opener while a journal check awaits resources it may hold.
/// Awaiting that check inside a timer branch can deadlock the same task on a
/// single-connection custody book. Both futures stay owned and cancellation
/// drops them together; an unhealthy guard or existing hop still wins.
async fn guarded_open<C, S: Send + 'static>(
    opened: impl std::future::Future<Output = Result<C>>,
    workers: &mut tokio::task::JoinSet<(usize, Result<S>)>,
    journal: &dyn super::funded::Journal,
    chain: Option<&dyn super::funded::Chain>,
) -> Result<C> {
    let connection = tokio::select! {
        biased;
        failed = workers.join_next(), if !workers.is_empty() => Err(worker_failure(failed)),
        error = guard_failure(journal, chain) => Err(error),
        result = opened => result,
    }?;
    // The opener may finish while a check is queued on its book. Authenticate
    // again after it releases that transaction, before handing off traffic.
    journal.check().await?;
    if let Some(chain) = chain {
        chain.check()?;
    }
    Ok(connection)
}

async fn guard_failure(
    journal: &dyn super::funded::Journal,
    chain: Option<&dyn super::funded::Chain>,
) -> anyhow::Error {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        if let Err(error) = journal.check().await {
            return error;
        }
        if let Some(chain) = chain {
            if let Err(error) = chain.check() {
                return error;
            }
        }
    }
}

fn worker_failure<S>(
    result: Option<Result<(usize, Result<S>), tokio::task::JoinError>>,
) -> anyhow::Error {
    match result {
        Some(Ok((index, Err(error)))) => {
            error.context(format!("paid route hop {index} failed; blockers retained"))
        }
        Some(Ok((index, Ok(_)))) => {
            anyhow::anyhow!("paid route hop {index} stopped unexpectedly; blockers retained")
        }
        Some(Err(error)) => error.into(),
        None => anyhow::anyhow!("paid route workers missing; blockers retained"),
    }
}
