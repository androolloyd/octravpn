//! One controller pauses packets while canonical admission and a new handshake
//! recover the existing session. Neither key identity nor counters are reset.
use anyhow::{ensure, Context, Result};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use tokio::sync::watch;

pub(crate) struct Control {
    phase: Arc<AtomicU64>,
    requested: watch::Sender<u64>,
    authenticated: watch::Receiver<u64>,
    fault: watch::Receiver<u64>,
    resumed: u64,
}
pub(super) struct Driver {
    phase: Arc<AtomicU64>,
    requested: watch::Receiver<u64>,
    authenticated: watch::Sender<u64>,
    fault: watch::Sender<u64>,
}
pub(super) fn channel() -> (Control, Driver) {
    let phase = Arc::new(AtomicU64::new(0));
    let (request_tx, request_rx) = watch::channel(0);
    let (auth_tx, auth_rx) = watch::channel(0);
    let (fault_tx, fault_rx) = watch::channel(0);
    (
        Control {
            phase: phase.clone(),
            requested: request_tx,
            authenticated: auth_rx,
            fault: fault_rx,
            resumed: 0,
        },
        Driver {
            phase,
            requested: request_rx,
            authenticated: auth_tx,
            fault: fault_tx,
        },
    )
}
// A single atomic transition binds authentication to one generation. A fault
// invalidates even a paused handshake, and an old Tunn cannot authenticate it
// again merely because time_since_last_handshake remains populated.
const PENDING: u64 = 1;
const AUTHENTICATED: u64 = 2;
const READY: u64 = 3;
fn encoded(generation: u64, phase: u64) -> u64 {
    (generation << 2) | phase
}
fn invalidate(phase: &AtomicU64) -> u64 {
    phase.fetch_and(!3, Ordering::AcqRel)
}
impl Control {
    pub(crate) fn pause(&self) {
        invalidate(&self.phase);
    }
    pub(crate) async fn fault(&mut self) -> Result<()> {
        self.fault
            .changed()
            .await
            .context("WireGuard recovery driver stopped")?;
        self.fault.borrow_and_update();
        Ok(())
    }
    pub(crate) async fn handshake(&mut self) -> Result<u64> {
        self.pause();
        let generation = self
            .requested
            .borrow()
            .checked_add(1)
            .filter(|value| *value <= u64::MAX >> 2)
            .context("WireGuard recovery generation exhausted")?;
        self.phase
            .store(encoded(generation, PENDING), Ordering::Release);
        self.requested
            .send(generation)
            .context("WireGuard recovery driver stopped")?;
        tokio::time::timeout(
            std::time::Duration::from_secs(15),
            self.authenticated.wait_for(|value| *value == generation),
        )
        .await
        .context("recovery WireGuard handshake timed out")?
        .context("WireGuard recovery driver stopped")?;
        Ok(generation)
    }
    pub(crate) fn resume(&mut self, generation: u64) -> Result<()> {
        ensure!(
            generation > self.resumed
                && *self.requested.borrow() == generation
                && *self.authenticated.borrow() == generation,
            "recovery handshake generation differs"
        );
        self.phase
            .compare_exchange(
                encoded(generation, AUTHENTICATED),
                encoded(generation, READY),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| anyhow::anyhow!("recovery transport failed after authentication"))?;
        self.resumed = generation;
        Ok(())
    }
}
impl Driver {
    pub(super) fn ready(&self) -> bool {
        self.phase.load(Ordering::Acquire) & 3 == READY
    }
    pub(super) fn initial_authenticated(&self) {
        self.phase.store(READY, Ordering::Release);
    }
    pub(super) fn unavailable(&self) {
        if invalidate(&self.phase) & 3 == READY {
            self.fault
                .send_modify(|value| *value = value.saturating_add(1));
        }
    }
    pub(super) async fn requested(&mut self) -> Result<u64> {
        self.requested
            .changed()
            .await
            .context("WireGuard recovery controller stopped")?;
        Ok(*self.requested.borrow_and_update())
    }
    pub(super) fn authenticated(&self, generation: u64) {
        if self
            .phase
            .compare_exchange(
                encoded(generation, PENDING),
                encoded(generation, AUTHENTICATED),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            self.authenticated.send_replace(generation);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn reconnect_gate_requires_each_fresh_authenticated_generation() {
        let (mut control, mut driver) = channel();
        assert!(!driver.ready());
        driver.initial_authenticated();
        assert!(driver.ready());
        driver.unavailable();
        assert!(!driver.ready());
        control.fault().await.unwrap();
        assert!(control.resume(0).is_err());
        let handshake = tokio::spawn(async move {
            let generation = control.handshake().await.unwrap();
            (control, generation)
        });
        let generation = driver.requested().await.unwrap();
        assert!(!driver.ready());
        driver.authenticated(generation);
        let (mut control, generation) = handshake.await.unwrap();
        assert!(!driver.ready());
        control.resume(generation).unwrap();
        assert!(driver.ready());
        control.pause();
        let old = generation;
        assert!(control.resume(old).is_err());
        let handshake = tokio::spawn(async move {
            let generation = control.handshake().await.unwrap();
            (control, generation)
        });
        let generation = driver.requested().await.unwrap();
        driver.authenticated(generation);
        let (mut control, new) = handshake.await.unwrap();
        assert!(control.resume(old).is_err());
        assert!(!driver.ready());
        control.resume(new).unwrap();
        assert!(driver.ready());
    }

    #[tokio::test]
    async fn reconnect_fault_during_canonical_recheck_invalidates_authenticated_generation() {
        let (mut control, mut driver) = channel();
        driver.initial_authenticated();
        control.pause();
        let handshake = tokio::spawn(async move {
            let generation = control.handshake().await.unwrap();
            (control, generation)
        });
        let generation = driver.requested().await.unwrap();
        driver.authenticated(generation);
        let (mut control, generation) = handshake.await.unwrap();
        // The controller is now awaiting the independent canonical recheck.
        driver.unavailable();
        // A still-populated Boringtun handshake timestamp cannot re-arm it.
        driver.authenticated(generation);
        assert!(control.resume(generation).is_err());
        assert!(!driver.ready());
        let handshake = tokio::spawn(async move {
            let generation = control.handshake().await.unwrap();
            (control, generation)
        });
        let next = driver.requested().await.unwrap();
        driver.authenticated(generation);
        assert!(!driver.ready());
        driver.authenticated(next);
        let (mut control, next) = handshake.await.unwrap();
        control.resume(next).unwrap();
        assert!(driver.ready());
    }
}
