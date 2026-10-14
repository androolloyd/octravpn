// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native per-peer, per-lane fixed-window frame admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerClass {
    Validator,
    Observer,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lane {
    Control,
    Consensus,
    Artifact,
    Tx,
    Data,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Close,
    Discard,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limit {
    pub max_frames: i64,
    pub max_bytes: i64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rejection {
    pub reason: &'static str,
    pub lane: Lane,
    pub peer_class: PeerClass,
    pub frames: i64,
    pub bytes: i64,
    pub frame_bytes: i64,
    pub max_frames: i64,
    pub max_bytes: i64,
    pub action: Action,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Drop(Rejection),
}
pub const fn lane(message: u8) -> Lane {
    match message {
        0x20 => Lane::Tx,
        0x30..=0x35 | 0x3d..=0x3f => Lane::Consensus,
        0x21 | 0x36..=0x3b | 0x40 => Lane::Artifact,
        0x11 | 0x3c | 0x41 => Lane::Data,
        _ => Lane::Control,
    }
}
pub const fn limit(class: PeerClass, lane: Lane) -> Limit {
    let (max_frames, max_bytes) = match (class, lane) {
        (_, Lane::Control) => (2048, 16 * 1024 * 1024),
        (PeerClass::Validator, Lane::Consensus) => (2048, 128 * 1024 * 1024),
        (PeerClass::Observer, Lane::Consensus) => (256, 16 * 1024 * 1024),
        (PeerClass::Validator, Lane::Artifact) => (512, 512 * 1024 * 1024),
        (PeerClass::Observer, Lane::Artifact) | (_, Lane::Data) => (512, 128 * 1024 * 1024),
        (_, Lane::Tx) => (4096, 64 * 1024 * 1024),
    };
    Limit {
        max_frames,
        max_bytes,
    }
}
#[derive(Clone, Copy, Debug)]
struct Bucket {
    start: f64,
    frames: i64,
    bytes: i64,
}
impl Bucket {
    const fn new(now: f64) -> Self {
        Self {
            start: now,
            frames: 0,
            bytes: 0,
        }
    }
}
#[derive(Debug)]
pub struct Budget {
    class: PeerClass,
    buckets: [Bucket; 5],
}
impl Budget {
    pub const fn new(now: f64, class: PeerClass) -> Self {
        Self {
            class,
            buckets: [Bucket::new(now); 5],
        }
    }
    pub const fn peer_class(&self) -> PeerClass {
        self.class
    }
    pub fn set_peer_class(&mut self, class: PeerClass) {
        self.class = class;
    }
    pub fn admit(&mut self, now: f64, message: u8, bytes: i64) -> Verdict {
        let lane = lane(message);
        let limit = limit(self.class, lane);
        let index = match lane {
            Lane::Control => 0,
            Lane::Consensus => 1,
            Lane::Artifact => 2,
            Lane::Tx => 3,
            Lane::Data => 4,
        };
        let bucket = &mut self.buckets[index];
        if now - bucket.start >= 60.0 {
            *bucket = Bucket::new(now);
        }
        let reason = if bytes < 0 || bytes > limit.max_bytes {
            Some("frame_byte_budget")
        } else if bucket.frames >= limit.max_frames {
            Some("frame_count_budget")
        } else if bucket.bytes > limit.max_bytes - bytes {
            Some("frame_byte_budget")
        } else {
            None
        };
        if let Some(reason) = reason {
            Verdict::Drop(Rejection {
                reason,
                lane,
                peer_class: self.class,
                frames: bucket.frames,
                bytes: bucket.bytes,
                frame_bytes: bytes,
                max_frames: limit.max_frames,
                max_bytes: limit.max_bytes,
                action: if self.class == PeerClass::Validator && lane == Lane::Artifact {
                    Action::Discard
                } else {
                    Action::Close
                },
            })
        } else {
            bucket.frames += 1;
            bucket.bytes += bytes;
            Verdict::Accept
        }
    }
}
