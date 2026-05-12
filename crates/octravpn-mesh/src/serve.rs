//! Serve / funnel registry.
//!
//! `serve` exposes a local TCP service (e.g. `localhost:8080`) to other
//! tailnet members at `<hostname>.<tailnet>.octra:<port><external_path>`.
//! `funnel` is the same idea, but published outside the tailnet through a
//! paid validator exit node so a non-member visitor can reach
//! `https://<hostname>.<tailnet>.octra.public.example/<external_path>`.
//!
//! This module is concerned only with the bookkeeping: a thread-safe
//! registry of "I want to advertise this local port" entries. The actual
//! TCP packet-forwarding and the protocol-level advertisement are the
//! data-plane's responsibility and live elsewhere.
//!
//! Entries are keyed on `local_port`. Re-adding an entry for an
//! already-registered port replaces the previous entry — the user's
//! latest declaration wins, the way `tailscale serve` behaves.

use parking_lot::RwLock;

/// A single serve/funnel advertisement.
///
/// `local_proto` is `"tcp"` for the foreseeable future; we keep the field
/// so the registry stays forward-compatible with UDP/QUIC advertisements
/// without a schema migration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServeEntry {
    pub local_port: u16,
    pub local_proto: &'static str,
    pub external_path: String,
    pub funnel: bool,
}

impl ServeEntry {
    /// Convenience constructor for TCP entries — by far the common case.
    pub fn tcp(local_port: u16, external_path: impl Into<String>, funnel: bool) -> Self {
        Self {
            local_port,
            local_proto: "tcp",
            external_path: external_path.into(),
            funnel,
        }
    }
}

/// Thread-safe registry of serve/funnel entries.
///
/// Entries are keyed by `local_port`: each local TCP port can be in at
/// most one entry. `add` is upsert semantics; `remove` is idempotent.
#[derive(Default)]
pub struct ServeRegistry {
    inner: RwLock<Vec<ServeEntry>>,
}

impl ServeRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace the entry for `entry.local_port`.
    pub fn add(&self, entry: ServeEntry) {
        let mut g = self.inner.write();
        g.retain(|e| e.local_port != entry.local_port);
        g.push(entry);
    }

    /// Remove the entry advertising `local_port`. No-op if no such entry.
    pub fn remove(&self, local_port: u16) {
        let mut g = self.inner.write();
        g.retain(|e| e.local_port != local_port);
    }

    /// Snapshot of the registry, sorted by `local_port` for determinism.
    pub fn list(&self) -> Vec<ServeEntry> {
        let mut out = self.inner.read().clone();
        out.sort_by_key(|e| e.local_port);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_then_list_round_trip() {
        let r = ServeRegistry::new();
        r.add(ServeEntry::tcp(8080, "/v1", false));
        let l = r.list();
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].local_port, 8080);
        assert_eq!(l[0].local_proto, "tcp");
        assert_eq!(l[0].external_path, "/v1");
        assert!(!l[0].funnel);
    }

    #[test]
    fn add_replaces_entry_with_same_port() {
        let r = ServeRegistry::new();
        r.add(ServeEntry::tcp(8080, "/v1", false));
        r.add(ServeEntry::tcp(8080, "/v2", true));
        let l = r.list();
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].external_path, "/v2");
        assert!(l[0].funnel);
    }

    #[test]
    fn remove_drops_only_the_matching_port() {
        let r = ServeRegistry::new();
        r.add(ServeEntry::tcp(8080, "/a", false));
        r.add(ServeEntry::tcp(9090, "/b", true));
        r.remove(8080);
        let l = r.list();
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].local_port, 9090);
    }

    #[test]
    fn remove_unknown_port_is_noop() {
        let r = ServeRegistry::new();
        r.add(ServeEntry::tcp(8080, "/a", false));
        r.remove(7777);
        assert_eq!(r.list().len(), 1);
    }

    #[test]
    fn list_is_sorted_by_port_for_determinism() {
        let r = ServeRegistry::new();
        r.add(ServeEntry::tcp(9000, "/c", false));
        r.add(ServeEntry::tcp(8080, "/a", false));
        r.add(ServeEntry::tcp(8443, "/b", true));
        let ports: Vec<u16> = r.list().iter().map(|e| e.local_port).collect();
        assert_eq!(ports, vec![8080, 8443, 9000]);
    }
}
