//! Analytics tap — best-effort side-channel from `AuditLog::write`
//! into the in-process [`octravpn_analytics`] indexer (task #231).
//! Send is best-effort; the on-disk JSONL envelope is untouched. The
//! channel is unbounded — the indexer is in-process and consumes
//! synchronously. See `audit/README.md` for the lifetime + non-blocking
//! contract.

use tokio::sync::mpsc;

use super::log::AuditRecord;
use super::AuditLog;

impl AuditLog {
    /// Install a live analytics tap. The returned `AuditLog` is the
    /// same handle (cheap `Arc<Mutex>` clone) — calling this twice
    /// replaces the previous tap.
    #[must_use]
    pub(crate) fn with_analytics_tap(
        mut self,
        tap: mpsc::UnboundedSender<octravpn_analytics::AnalyticsEvent>,
    ) -> Self {
        self.analytics_tap = Some(tap);
        self
    }

    /// Fan out one record to the analytics tap (best-effort).
    pub(super) fn tap_publish(&self, rec: &AuditRecord) {
        let Some(tap) = self.analytics_tap.as_ref() else {
            return;
        };
        let Ok(json) = serde_json::to_string(rec) else {
            return;
        };
        let Some(ev) = octravpn_analytics::AnalyticsEvent::from_audit_record_json(&json) else {
            return;
        };
        // Best-effort: if the indexer task has died, drop the event.
        let _ = tap.send(ev);
    }
}
