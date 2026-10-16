//! Native epoch-local preview refusal state. Queue ownership serializes mutation;
//! a host using a shared pool must refuse a busy preview lock rather than wait.
use std::collections::BTreeSet;

#[derive(Clone, Debug)]
pub enum Message {
    Check(Option<i64>, Vec<u8>),
    Ready(Option<i64>, Vec<u8>),
    Refuse {
        head: i64,
        epoch: i64,
        hash: Vec<u8>,
    },
    Hold {
        head: i64,
        epoch: i64,
        hash: Vec<u8>,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub(super) head: i64,
    hashes: BTreeSet<Vec<u8>>,
    full: bool,
}
impl Default for State {
    fn default() -> Self {
        Self {
            head: -1,
            hashes: BTreeSet::new(),
            full: false,
        }
    }
}
impl State {
    pub(super) fn valid(&self, limit: usize) -> bool {
        self.head >= -1
            && self.hashes.len() <= limit
            && self.hashes.iter().all(|h| {
                h.len() == 64
                    && h.iter()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
            })
    }
    fn advance(&mut self, head: Option<i64>) {
        if let Some(head) = head.filter(|head| *head > self.head) {
            *self = Self {
                head,
                ..Self::default()
            };
        }
    }
    pub fn step(&mut self, limit: usize, message: &Message) -> Result<(), &'static str> {
        match message {
            Message::Check(head, hash) | Message::Ready(head, hash) => {
                self.advance(*head);
                if self.hashes.contains(hash) {
                    Err("preview refused in this epoch")
                } else if self.full && matches!(message, Message::Check(..)) {
                    Err("staging full until epoch commit")
                } else {
                    Ok(())
                }
            }
            Message::Refuse { head, epoch, hash } | Message::Hold { head, epoch, hash } => {
                if *head < 0 || *head == i64::MAX || *head < self.head || *epoch != head + 1 {
                    return Err("preview epoch changed");
                }
                self.advance(Some(*head));
                if matches!(message, Message::Refuse { .. }) && !self.hashes.contains(hash) {
                    if self.hashes.len() >= limit {
                        self.full = true;
                    } else {
                        self.hashes.insert(hash.clone());
                    }
                }
                Ok(())
            }
        }
    }
}
