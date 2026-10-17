//! Local connection outcomes. Labels are fixed; no remote payload or error text
//! is retained. The enum product bounds storage independently of peer churn.
use super::{Direction, Error};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Transport,
    Handshake,
    Admission,
    Session,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Accepted,
    Refused,
    Dns,
    Timeout,
    ProxyRejected,
    ProxyDenied,
    ProxyNetworkUnreachable,
    ProxyHostUnreachable,
    ProxyRefused,
    ProxyTtl,
    ProxyProtocol,
    Io,
    Config,
    Chain,
    Signature,
    Identity,
    UnknownKey,
    Challenge,
    Frame,
    Protocol,
    Stopped,
    SelfConnection,
    Banned,
    Duplicate,
    Observer,
    Capacity,
    ConnectionBudget,
    PendingLimit,
    Cancelled,
    LocalClose,
    RemoteClose,
    ReadTimeout,
    WriteTimeout,
    Reset,
    FrameBudget,
    Other,
}

pub(super) fn proxy_reply(reply: u8) -> Outcome {
    match reply {
        2 => Outcome::ProxyDenied,
        3 => Outcome::ProxyNetworkUnreachable,
        4 => Outcome::ProxyHostUnreachable,
        5 => Outcome::ProxyRefused,
        6 => Outcome::ProxyTtl,
        7 | 8 => Outcome::ProxyProtocol,
        _ => Outcome::ProxyRejected,
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Count {
    pub direction: &'static str,
    pub phase: Phase,
    pub outcome: Outcome,
    pub count: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct Connections {
    pub generation: u64,
    pub running: bool,
    pub proxy: bool,
    pub dialing: usize,
    pub record_dialing: usize,
    pub outcomes: Vec<Count>,
}

#[derive(Default)]
pub(super) struct Counters(BTreeMap<(bool, Phase, Outcome), u64>);
impl Counters {
    pub(super) fn record(&mut self, direction: Direction, phase: Phase, outcome: Outcome) {
        let count = self
            .0
            .entry((direction == Direction::Outbound, phase, outcome))
            .or_default();
        *count = count.saturating_add(1);
    }
    pub(super) fn snapshot(&self) -> Vec<Count> {
        self.0
            .iter()
            .map(|((outbound, phase, outcome), count)| Count {
                direction: if *outbound { "outbound" } else { "inbound" },
                phase: *phase,
                outcome: *outcome,
                count: *count,
            })
            .collect()
    }
}

fn io(raw: &[u8]) -> Option<Outcome> {
    // These are local OS diagnostics, inspected only within a fixed prefix.
    let lower = raw.to_ascii_lowercase();
    if lower.starts_with(b"connection refused") {
        Some(Outcome::Refused)
    } else if lower.starts_with(b"connection reset") || lower.starts_with(b"broken pipe") {
        Some(Outcome::Reset)
    } else if lower.starts_with(b"failed to lookup address")
        || lower.starts_with(b"name or service not known")
        || lower.starts_with(b"temporary failure in name resolution")
    {
        Some(Outcome::Dns)
    } else if lower.starts_with(b"connection timed out")
        || lower.starts_with(b"operation timed out")
    {
        Some(Outcome::Timeout)
    } else if lower.starts_with(b"bad file descriptor")
        || lower.starts_with(b"socket is not connected")
        || lower.starts_with(b"network is unreachable")
        || lower.starts_with(b"host is unreachable")
    {
        Some(Outcome::Io)
    } else {
        None
    }
}

pub(super) fn failure(phase: Phase, error: &Error) -> Outcome {
    let raw = error.as_bytes();
    let raw = &raw[..raw.len().min(512)];
    match phase {
        Phase::Transport => match raw {
            b"P2P transport connect timeout" => Outcome::Timeout,
            b"SOCKS5 proxy refused no-auth transport" | b"SOCKS5 CONNECT refused" => {
                Outcome::ProxyRejected
            }
            b"invalid SOCKS5 address type" | b"invalid SOCKS5 peer endpoint" => {
                Outcome::ProxyProtocol
            }
            _ => io(raw).unwrap_or(Outcome::Io),
        },
        Phase::Handshake => {
            // Match the outer validation reason first: the chain mismatch's
            // suffix contains arbitrary peer text and cannot select a label.
            if raw.starts_with(b"chain_id mismatch:") || raw == b"HELLO_FINISH chain mismatch" {
                return Outcome::Chain;
            }
            if raw.starts_with(b"consensus_config_hash mismatch:")
                || raw == b"HELLO_FINISH config mismatch"
            {
                return Outcome::Config;
            }
            if raw.starts_with(b"p2p proto mismatch:") {
                return Outcome::Protocol;
            }
            if raw.starts_with(b"invalid Ed25519 signature on ") {
                return Outcome::Signature;
            }
            if raw == b"node_id does not match pubkey" || raw == b"HELLO_FINISH identity mismatch" {
                return Outcome::Identity;
            }
            if raw.starts_with(b"unknown validator pubkey (") {
                return Outcome::UnknownKey;
            }
            if matches!(
                raw,
                b"HELLO_ACK challenge mismatch" | b"HELLO_FINISH challenge mismatch"
            ) {
                return Outcome::Challenge;
            }
            if raw == b"handshake timeout" {
                return Outcome::Timeout;
            }
            let inner = raw
                .strip_prefix(b"handshake failed: Failure(\"")
                .and_then(|inner| inner.strip_suffix(b"\")"))
                .unwrap_or(raw);
            if inner == b"connection_closed" {
                return Outcome::RemoteClose;
            }
            if inner.starts_with(b"OCE1:")
                || inner.starts_with(b"p2p hello:")
                || inner.starts_with(b"p2p finish:")
                || inner.starts_with(b"frame_")
                || inner.starts_with(b"expected HELLO")
                || inner == b"empty_frame"
                || inner == b"invalid listen port"
            {
                return Outcome::Frame;
            }
            io(inner).unwrap_or(Outcome::Other)
        }
        Phase::Session => match raw {
            b"connection_closed" => Outcome::RemoteClose,
            b"read timeout" => Outcome::ReadTimeout,
            b"write timeout" => Outcome::WriteTimeout,
            b"frame_byte_budget" | b"frame_count_budget" => Outcome::FrameBudget,
            _ if raw.starts_with(b"frame_") || raw == b"empty_frame" => Outcome::Frame,
            _ if raw.starts_with(b"OCE1: need ")
                || raw.starts_with(b"OCE1: bytes len ")
                || raw.starts_with(b"OCE1: list count ")
                || raw.starts_with(b"OCE1: trailing ") =>
            {
                Outcome::Frame
            }
            _ => io(raw).unwrap_or(Outcome::Other),
        },
        Phase::Admission => Outcome::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_bounded_and_peer_text_cannot_spoof_another_reason() {
        let hostile = Error::from(
            "chain_id mismatch: handshake timeout connection_closed invalid Ed25519 signature vs local",
        );
        assert_eq!(failure(Phase::Handshake, &hostile), Outcome::Chain);
        let mut counters = Counters::default();
        counters.record(Direction::Outbound, Phase::Handshake, Outcome::Chain);
        let encoded = serde_json::to_string(&counters.snapshot()).unwrap();
        assert!(!encoded.contains("mismatch"));
        assert!(!encoded.contains("signature"));
        assert!(encoded.contains("\"outcome\":\"chain\""));
    }

    #[test]
    fn counters_saturate() {
        let mut counters = Counters::default();
        counters
            .0
            .insert((true, Phase::Transport, Outcome::Refused), u64::MAX);
        counters.record(Direction::Outbound, Phase::Transport, Outcome::Refused);
        assert_eq!(counters.snapshot()[0].count, u64::MAX);
    }

    #[test]
    fn wrapped_handshake_io_is_distinct_from_malformed_framing() {
        for (raw, expected) in [
            (
                "handshake failed: Failure(\"Connection reset by peer (os error 54)\")",
                Outcome::Reset,
            ),
            (
                "handshake failed: Failure(\"Broken pipe (os error 32)\")",
                Outcome::Reset,
            ),
            (
                "handshake failed: Failure(\"OCE1: need 4 bytes, have 0\")",
                Outcome::Frame,
            ),
            (
                "handshake failed: Failure(\"unknown error\")",
                Outcome::Other,
            ),
        ] {
            assert_eq!(failure(Phase::Handshake, &Error::from(raw)), expected);
        }
        assert_eq!(
            failure(Phase::Session, &Error::from("OCE1: need 4 bytes, have 0")),
            Outcome::Frame
        );
        assert_eq!(
            failure(Phase::Session, &Error::from("OCE1: allocation unavailable")),
            Outcome::Other
        );
    }
}
