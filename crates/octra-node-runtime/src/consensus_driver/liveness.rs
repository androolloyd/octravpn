//! Adopted health fallback; round recovery stays inside the owning actor.
use super::{Driver, Error, Host, Publication};
use octra_node_protocol::consensus::liveness as policy;

#[derive(Clone, Copy, Debug)]
pub struct LivenessContext {
    pub expected: i64,
    /// Native health uses wall time; proposal grace remains monotonic.
    pub now: f64,
    pub stall_sec: f64,
    pub observer: bool,
    pub voting: bool,
    pub catchup_active: bool,
    pub quarantine_active: bool,
    pub state_attested: bool,
    pub pending_finalized: bool,
}

#[allow(clippy::cast_precision_loss)] // Native float_of_int on a bounded setting.
pub fn configured_stall_sec(raw: Option<&[u8]>) -> f64 {
    // Native startup limits: max non-proposal timeout (120s) plus 30s.
    raw.and_then(octra_node_protocol::native_integer::parse_int63)
        .filter(|value| (150..=3600).contains(value))
        .unwrap_or(150) as f64
}

impl<H: Host, C: Publication> Driver<H, C> {
    #[allow(clippy::cast_precision_loss)] // Native float_of_int on step timeout ms.
    pub(super) async fn poll_health(&mut self) -> Result<(), Error> {
        if !self.initialized {
            return Ok(());
        }
        let Some(context) = self.host.liveness() else {
            return Ok(());
        };
        let state = self.engine.state();
        let result = policy::record(
            &self.liveness,
            &policy::Sample {
                height: state.height,
                round: state.round,
                step: policy::step_label(state.step),
                expected: context.expected,
                now: context.now,
                source: b"health_poll",
                stall_sec: context.stall_sec,
                step_timeout_sec: Some(self.engine.step_timeout_ms() as f64 / 1000.),
                observer: context.observer,
                voting: context.voting,
                catchup_active: context.catchup_active,
                quarantine_active: context.quarantine_active,
                state_attested: context.state_attested,
                pending_finalized: context.pending_finalized
                    || self.engine.pending_finalized().is_some(),
                proposal_active: self.work_grace(),
            },
        );
        self.liveness = result.state;
        let Some(reset) = result.reset else {
            return Ok(());
        };
        // No await separates the native policy sample from this mutation. A
        // queued health poll cannot apply a decision from an older generation.
        let increment = |round: i64| (round.wrapping_add(1) << 1) >> 1;
        let round = increment(self.engine.state().round).max(increment(reset.round));
        self.clear_round_work(reset.expected, round);
        self.engine.realign_round(round)?;
        self.host.warning(&format!(
            "liveness realign height = {} round = {} step = {} source = health_poll stall_sec = {:.0} step_timeout_sec = {:.0} state_age = {:.0} height_age = {:.0} resets = {}",
            reset.height, reset.round, String::from_utf8_lossy(&reset.step),
            reset.stall_sec, reset.step_timeout_sec.unwrap_or(0.), reset.state_age,
            reset.height_age, reset.resets,
        ));
        self.relay.progress(self.engine.generation());
        self.drain().await?;
        self.round_sync(self.engine.state().round, self.engine.state().step, true)
            .await?;
        Ok(())
    }

    fn clear_round_work(&mut self, height: i64, round: i64) {
        self.work.abort_all();
        self.active_work = None;
        self.checking = false;
        self.build_retry = None;
        self.pace = None;
        self.pending_votes.clear();
        self.past_round = None;
        self.sync_retry = None;
        self.replies.clear();
        self.epoch_started = self.now();
        self.pending_checks
            .retain(|&(epoch, candidate), _| epoch == height && candidate >= round);
        self.verified
            .retain(|&(epoch, candidate), _| epoch == height && candidate >= round);
        // Timers and fetches carry their old generation and fail their normal
        // freshness checks. Locks, POLCs, durable votes and signing floors stay.
    }
}
