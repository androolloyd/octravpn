// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native output coalescing, generation-bound proposal relay and worker slots.
//! Effects are host actions; state transitions never spawn or detach work.
use super::Bytes;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OutputActor {
    #[default]
    Idle,
    Running,
    Requested,
}
impl OutputActor {
    /// True starts the output drain; false joins the already running drain.
    pub fn request(&mut self) -> bool {
        let start = *self == Self::Idle;
        *self = if start {
            Self::Running
        } else {
            Self::Requested
        };
        start
    }
    /// True requires another yielding turn, false ends this drain.
    pub fn complete(&mut self) -> bool {
        let again = *self == Self::Requested;
        *self = if again { Self::Running } else { Self::Idle };
        again
    }
    pub fn fail(&mut self) {
        *self = Self::Idle;
    }
    pub fn idle(&self) -> bool {
        *self == Self::Idle
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Phase<J, R> {
    Idle,
    Running(i64, J),
    Ready(J, R),
    Closed,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkSlot<J, R> {
    next: i64,
    phase: Phase<J, R>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkMessage<J, R> {
    Submit(J),
    Finish(i64, R),
    Take,
    Close,
    Open,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkEffect<J, R> {
    Run(i64, J),
    Complete(J),
    Deliver(J, R),
}
impl<J, R> Default for WorkSlot<J, R> {
    fn default() -> Self {
        Self {
            next: 0,
            phase: Phase::Idle,
        }
    }
}
impl<J: Clone, R> WorkSlot<J, R> {
    pub fn idle(&self) -> bool {
        matches!(self.phase, Phase::Idle)
    }
    pub fn ready(&self) -> bool {
        matches!(self.phase, Phase::Ready(..))
    }
    pub fn step(&mut self, message: WorkMessage<J, R>) -> Option<WorkEffect<J, R>> {
        match message {
            WorkMessage::Close => self.phase = Phase::Closed,
            WorkMessage::Open if matches!(self.phase, Phase::Closed) => self.phase = Phase::Idle,
            WorkMessage::Submit(job) if self.idle() && self.next < (1i64 << 62) - 1 => {
                let id = self.next;
                self.next += 1;
                self.phase = Phase::Running(id, job.clone());
                return Some(WorkEffect::Run(id, job));
            }
            WorkMessage::Finish(id, reply) => {
                if matches!(&self.phase, Phase::Running(current, _) if *current == id) {
                    let Phase::Running(_, job) = std::mem::replace(&mut self.phase, Phase::Idle)
                    else {
                        unreachable!()
                    };
                    self.phase = Phase::Ready(job.clone(), reply);
                    return Some(WorkEffect::Complete(job));
                }
            }
            WorkMessage::Take if self.ready() => {
                let Phase::Ready(job, reply) = std::mem::replace(&mut self.phase, Phase::Idle)
                else {
                    unreachable!()
                };
                return Some(WorkEffect::Deliver(job, reply));
            }
            _ => (),
        }
        None
    }
}

pub const RELAY_CAPACITY: usize = 4;
pub const RELAY_LIFETIME: f64 = 2.;
#[derive(Clone, Debug, PartialEq)]
pub struct RelayItem<T> {
    pub key: Bytes,
    pub value: T,
    pub expires: f64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelayOutcome {
    Sent,
    Expired,
    Failed(Bytes),
    Cancelled,
}
#[derive(Clone, Debug, PartialEq)]
pub enum RelayMessage<T> {
    Offer {
        generation: i64,
        now: f64,
        item: RelayItem<T>,
    },
    Finished {
        serial: i64,
        now: f64,
        outcome: RelayOutcome,
    },
    Advance {
        generation: i64,
        now: f64,
    },
    Close,
    Open(i64),
}
#[derive(Clone, Debug, PartialEq)]
pub enum RelayEffect<T> {
    Send(i64, RelayItem<T>),
    Cancel,
    Dropped(Bytes),
}
#[derive(Clone, Debug, PartialEq)]
pub struct Relay<T> {
    pub generation: i64,
    pub serial: i64,
    pub active: Option<(i64, RelayItem<T>)>,
    pub queue: Vec<RelayItem<T>>,
    pub seen: Vec<Bytes>,
    pub closed: bool,
}
impl<T> Default for Relay<T> {
    fn default() -> Self {
        Self {
            generation: 0,
            serial: 0,
            active: None,
            queue: vec![],
            seen: vec![],
            closed: false,
        }
    }
}
impl<T: Clone> Relay<T> {
    fn expire(&mut self, now: f64, effects: &mut Vec<RelayEffect<T>>) {
        self.queue.retain(|item| {
            if item.expires <= now {
                effects.push(RelayEffect::Dropped(b"expired".to_vec()));
                false
            } else {
                true
            }
        });
    }
    fn start(&mut self, now: f64, effects: &mut Vec<RelayEffect<T>>) {
        self.expire(now, effects);
        if self.active.is_none() && !self.queue.is_empty() && !self.closed {
            let item = self.queue.remove(0);
            self.serial = self.serial.wrapping_add(1).wrapping_shl(1) >> 1;
            self.active = Some((self.serial, item.clone()));
            effects.push(RelayEffect::Send(self.serial, item));
        }
    }
    fn known(&self, key: &[u8]) -> bool {
        self.seen.iter().any(|v| v == key)
            || self.queue.iter().any(|v| v.key == key)
            || self.active.as_ref().is_some_and(|(_, v)| v.key == key)
    }
    fn advance(&mut self, generation: i64, effects: &mut Vec<RelayEffect<T>>) {
        if generation > self.generation {
            self.generation = generation;
            if self.active.take().is_some() {
                effects.push(RelayEffect::Cancel);
            }
            self.queue.clear();
            self.seen.clear();
        }
    }
    pub fn step(&mut self, message: RelayMessage<T>) -> Vec<RelayEffect<T>> {
        let mut effects = vec![];
        match message {
            RelayMessage::Close => {
                self.closed = true;
                self.active = None;
                self.queue.clear();
                self.seen.clear();
                effects.push(RelayEffect::Cancel);
            }
            RelayMessage::Open(generation) => {
                self.generation = generation;
                self.closed = false;
                self.active = None;
                self.queue.clear();
                self.seen.clear();
                effects.push(RelayEffect::Cancel);
            }
            RelayMessage::Advance { generation, now } => {
                self.advance(generation, &mut effects);
                self.start(now, &mut effects);
            }
            RelayMessage::Finished {
                serial,
                now,
                outcome,
            } => {
                if self
                    .active
                    .as_ref()
                    .is_some_and(|(current, _)| *current == serial)
                {
                    let (_, item) = self.active.take().expect("active serial checked");
                    match outcome {
                        RelayOutcome::Sent => {
                            self.seen.insert(0, item.key);
                            self.seen.truncate(64);
                        }
                        RelayOutcome::Expired => {
                            effects.push(RelayEffect::Dropped(b"expired".to_vec()));
                        }
                        RelayOutcome::Failed(reason) => effects.push(RelayEffect::Dropped(reason)),
                        RelayOutcome::Cancelled => (),
                    }
                    self.start(now, &mut effects);
                }
            }
            RelayMessage::Offer {
                generation,
                now,
                item,
            } => {
                if !self.closed && generation >= self.generation {
                    self.advance(generation, &mut effects);
                    self.expire(now, &mut effects);
                    if !self.known(&item.key) {
                        if item.expires <= now {
                            effects.push(RelayEffect::Dropped(b"expired".to_vec()));
                        } else if self.queue.len() >= RELAY_CAPACITY {
                            effects.push(RelayEffect::Dropped(b"full".to_vec()));
                        } else {
                            self.queue.push(item);
                            self.start(now, &mut effects);
                        }
                    }
                }
            }
        }
        effects
    }
}
