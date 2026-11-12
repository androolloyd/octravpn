//! One bounded reply per explicitly requested peer before its deadline.
use super::Bytes;
use std::collections::BTreeSet;
#[derive(Clone, Debug)]
pub struct ReplyWindow {
    pub deadline: i64,
    pub requested: BTreeSet<Bytes>,
    pub consumed: BTreeSet<Bytes>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Read,
    Expired,
    Repeated,
    UnexpectedPeer,
}
impl ReplyWindow {
    pub fn new(deadline: i64, peers: impl IntoIterator<Item = Bytes>) -> Self {
        Self {
            deadline,
            requested: peers.into_iter().collect(),
            consumed: BTreeSet::new(),
        }
    }
    pub fn extend(&mut self, peers: impl IntoIterator<Item = Bytes>) {
        self.requested.extend(peers);
    }
    pub fn take(&mut self, now: i64, peer: &[u8]) -> Decision {
        if now >= self.deadline {
            Decision::Expired
        } else if !self.requested.contains(peer) {
            Decision::UnexpectedPeer
        } else if !self.consumed.insert(peer.to_vec()) {
            Decision::Repeated
        } else {
            Decision::Read
        }
    }
}
