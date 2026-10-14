//! Cooperative consensus output draining and serialized proposal work.
//! The host still checks generation and proposal bindings when delivering work.
use octra_node_protocol::consensus::driver_work::OutputActor;
use std::{future::Future, sync::Mutex};

/// Native C_proposal_work_gate: check relevance after acquiring the work lock.
/// Cancellation before acquisition never runs the callback; cancellation or a
/// panic inside work releases the gate. CPU backends retain their own permits.
#[derive(Default)]
pub struct ProposalGate(tokio::sync::Mutex<()>);
impl ProposalGate {
    pub async fn run<T, R: Future<Output = Option<T>>>(
        &self,
        relevant: impl FnOnce() -> bool,
        work: impl FnOnce() -> R,
    ) -> Option<T> {
        let _guard = self.0.lock().await;
        if relevant() {
            work().await
        } else {
            None
        }
    }
}

/// Coalesces overlapping output-drain requests. Joiners return immediately;
/// their request causes another yielding turn of the active drain.
#[derive(Default)]
pub struct OutputPump(Mutex<OutputActor>);
impl OutputPump {
    pub fn idle(&self) -> bool {
        self.0.lock().expect("output actor lock").idle()
    }
    /// True means this caller drained outputs; false means it joined a drain.
    /// Error, panic and cancellation reset the actor so a later request can run.
    pub async fn run<F, R, E>(&self, mut step: F) -> Result<bool, E>
    where
        F: FnMut() -> R,
        R: Future<Output = Result<(), E>>,
    {
        if !self.0.lock().expect("output actor lock").request() {
            return Ok(false);
        }
        let mut guard = Drain {
            pump: self,
            active: true,
        };
        loop {
            step().await?;
            let again = {
                let mut actor = self.0.lock().expect("output actor lock");
                let again = actor.complete();
                // Complete and disarm together: a newly started drain must not
                // be reset by this completed caller's Drop implementation.
                if !again {
                    guard.active = false;
                }
                again
            };
            if !again {
                return Ok(true);
            }
            tokio::task::yield_now().await;
        }
    }
}
struct Drain<'a> {
    pump: &'a OutputPump,
    active: bool,
}
impl Drop for Drain<'_> {
    fn drop(&mut self) {
        if self.active {
            self.pump.0.lock().expect("output actor lock").fail();
        }
    }
}
