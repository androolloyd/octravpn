use super::{Accounting, Plan, PrivateControl};
use anyhow::{ensure, Context, Result};
use octravpn_core::payments::{SignedConnect, SignedShieldedStatus};
use std::time::Duration;

pub(super) struct Observation {
    pub(super) signed: SignedShieldedStatus,
    pub(super) freshness: crate::payment_runner::Freshness,
}

pub(super) fn purchased(signed: &SignedShieldedStatus, plan: &Plan) -> bool {
    signed.status.purchased_totals.len() == plan.prepaid_bytes.len()
        && signed
            .status
            .purchased_totals
            .iter()
            .zip(&plan.prepaid_bytes)
            .all(|(a, b)| a >= b)
}
pub(super) async fn poll(
    control: &PrivateControl,
    connect: &SignedConnect,
    plan: &Plan,
    journal: &Accounting,
) -> Result<Observation> {
    let signed = control.connect(connect).await?;
    ensure!(
        signed.status.operator_generation == plan.operator_generation
            && signed.status.tariff == plan.tariff
            && signed.status.quote_ceiling_ou == plan.quote_ceiling_ou,
        "private status differs from accepted plan"
    );
    let retained = signed.clone();
    let freshness = crate::payment_runner::Freshness::new(signed.status.canonical_ms);
    journal
        .with(move |j| j.observe_private_status(&retained))
        .await?;
    freshness.ensure_live()?;
    Ok(Observation { signed, freshness })
}

/// Admission retries the original signed connection, without opening a TUN,
/// buying capacity or allocating another journal connection sequence.
pub(super) async fn initial(
    control: &PrivateControl,
    connect: &SignedConnect,
    plan: &Plan,
    journal: &Accounting,
) -> Result<Observation> {
    tokio::time::timeout(crate::payment_runner::STATUS_MAX_AGE, async {
        loop {
            match poll(control, connect, plan, journal).await {
                Ok(observation) => return Ok(observation),
                Err(error) if PrivateControl::retryable(&error) => {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                Err(error) => return Err(error),
            }
        }
    })
    .await
    .context("private admission deadline exceeded")?
}

pub(super) async fn run(
    control: PrivateControl,
    connect: SignedConnect,
    plan: Plan,
    journal: Accounting,
    initial: Observation,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let Observation {
        signed: initial,
        mut freshness,
    } = initial;
    freshness.ensure_live()?;
    let mut timer = tokio::time::interval(Duration::from_secs(1));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            _ = stop.wait_for(|v| *v) => return Ok(()),
            () = tokio::time::sleep_until(freshness.deadline) => anyhow::bail!("private canonical clock stopped advancing"),
            _ = timer.tick() => (),
        }
        let signed = tokio::select! {
            biased;
            _ = stop.wait_for(|v| *v) => return Ok(()),
            () = tokio::time::sleep_until(freshness.deadline) => anyhow::bail!("private canonical clock stopped advancing"),
            result = poll(&control, &connect, &plan, &journal) => match result {
                Ok(observation) => observation,
                // Keep the original deadline. Only a newer authenticated
                // canonical clock below may renew it; errors grant nothing.
                Err(error) if PrivateControl::retryable(&error) => continue,
                Err(error) => return Err(error),
            },
        };
        ensure!(
            signed.signed.status.server_wireguard_key == initial.status.server_wireguard_key,
            "private WireGuard identity changed during connection"
        );
        freshness.observe(signed.signed.status.canonical_ms)?;
        ensure!(
            purchased(&signed.signed, &plan),
            "private prepaid capacity regressed"
        );
    }
}
