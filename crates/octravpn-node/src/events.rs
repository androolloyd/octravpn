//! Process-local event bus for fan-out of control-plane events to SSE
//! subscribers and (in future) other observers (audit, telemetry).
//!
//! Design choice: `tokio::sync::broadcast`. Each subscriber gets every
//! event published *after* it subscribed. The channel has a fixed
//! capacity; if a subscriber falls behind, it receives `Lagged(n)` on
//! its next `recv`, and the publisher is **never** blocked. This is
//! exactly the right tradeoff for SSE — a stalled HTTP client should
//! never wedge the control plane.
//!
//! Events carry a unix timestamp, a short `kind` discriminator, and an
//! opaque JSON payload. Keeping the payload as `serde_json::Value`
//! avoids a typed enum that the caller would have to import; the SSE
//! consumer is happy to receive whatever shape we encode.

use serde::Serialize;
use tokio::sync::broadcast;

/// One published event. `Clone` is required because the broadcast
/// channel hands each subscriber its own copy.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Event {
    /// Unix seconds at publish time.
    pub ts_unix: u64,
    /// Short discriminator (e.g. `session_announced`, `receipt_signed`).
    pub kind: String,
    /// Event-specific JSON payload. Schema is loosely defined per
    /// `kind`; consumers are expected to switch on `kind` first.
    pub payload: serde_json::Value,
}

/// Process-local fan-out hub. Cheap to clone (shares a single
/// `broadcast::Sender` under the hood; cloning happens when the
/// `ControlState` is itself cloned for each request handler).
#[derive(Clone)]
pub(crate) struct EventBus {
    tx: broadcast::Sender<Event>,
}

impl EventBus {
    /// Construct a bus with room for `capacity` in-flight events per
    /// subscriber. 256 is a sane default for SSE — bursty enough to
    /// absorb a flurry of announces without lag, small enough to keep
    /// memory bounded.
    pub(crate) fn new(capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity);
        Self { tx }
    }

    /// Publish an event. Never blocks. If there are no subscribers the
    /// event is dropped silently (this is the broadcast contract). If
    /// a subscriber's buffer is full, that subscriber will see `Lagged`
    /// — it is not our problem here.
    pub(crate) fn publish(&self, ev: Event) {
        // `send` only fails when there are zero subscribers; treat as
        // a no-op since "nobody listening" is the common case (no SSE
        // clients connected).
        let _ = self.tx.send(ev);
    }

    /// Number of live subscribers. Callers building an expensive `Event`
    /// payload on a hot path can skip the allocation when this is 0 —
    /// `publish` would drop it anyway (the "nobody listening" common
    /// case). A cheap atomic load on the underlying broadcast channel.
    pub(crate) fn receiver_count(&self) -> usize {
        self.tx.receiver_count()
    }

    /// Subscribe to receive every event published *after* this call.
    /// Events published before subscribing are not replayed — that's
    /// the broadcast contract.
    pub(crate) fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.tx.subscribe()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new(256)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A subscriber sees events published while it is subscribed, and
    /// misses events published before it subscribed (broadcast
    /// semantics).
    #[tokio::test]
    async fn bus_delivers_events_to_subscribers() {
        let bus = EventBus::new(8);

        // Pre-subscribe publish: no listener, dropped on the floor.
        bus.publish(Event {
            ts_unix: 1,
            kind: "before".into(),
            payload: serde_json::json!({"missed": true}),
        });

        let mut rx = bus.subscribe();

        // Post-subscribe publish: must be delivered.
        bus.publish(Event {
            ts_unix: 2,
            kind: "after".into(),
            payload: serde_json::json!({"seen": true}),
        });

        let got = tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv())
            .await
            .expect("timed out waiting for event")
            .expect("recv error");
        assert_eq!(got.kind, "after");
        assert_eq!(got.ts_unix, 2);

        // The "before" event must NOT arrive; the channel should be
        // empty (try_recv yields Empty, not a value).
        match rx.try_recv() {
            Err(tokio::sync::broadcast::error::TryRecvError::Empty) => {}
            other => panic!("expected Empty after draining; got {other:?}"),
        }
    }

    /// Publishing past a slow subscriber's capacity must not panic.
    /// The slow subscriber will observe `Lagged`, but the bus stays
    /// healthy and a fresh subscriber still receives subsequent
    /// events. This is the contract that makes the bus safe to use
    /// from request handlers: a stuck SSE client never blocks the
    /// control plane.
    #[tokio::test]
    async fn bus_drops_slow_subscribers() {
        let bus = EventBus::new(4);
        let mut slow = bus.subscribe();

        // Publish 16 events without ever calling `recv` on `slow`.
        // The broadcast channel will overflow; the slow subscriber's
        // first `recv` should return `Lagged`, not a panic.
        for i in 0..16u64 {
            bus.publish(Event {
                ts_unix: i,
                kind: "spam".into(),
                payload: serde_json::json!({"i": i}),
            });
        }

        // Slow subscriber sees Lagged on its next recv (the channel
        // has dropped the oldest events to make room).
        match slow.recv().await {
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                assert!(n > 0, "Lagged count should be positive, got {n}");
            }
            Ok(_) => {
                // Some buffered events may still be returnable before
                // Lagged surfaces. That's also acceptable — we only
                // assert "no panic" here.
            }
            Err(e) => panic!("unexpected error from slow subscriber: {e:?}"),
        }

        // A fresh subscriber can still receive after the overflow.
        let mut fresh = bus.subscribe();
        bus.publish(Event {
            ts_unix: 99,
            kind: "after_overflow".into(),
            payload: serde_json::Value::Null,
        });
        let got = tokio::time::timeout(std::time::Duration::from_millis(200), fresh.recv())
            .await
            .expect("timed out")
            .expect("recv error");
        assert_eq!(got.kind, "after_overflow");
    }
}
