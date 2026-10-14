//! Native transaction gossip receiver. The host owns canonical account reads
//! and queue admission; public-key authentication alone never admits a transaction.
use crate::admission::{self, Error};
use crate::staging::{intake, Pool};
use octra_node_protocol::{
    native_json::Document,
    network::{
        gossip_guard::{self, Guard},
        transaction_gossip::{self, Message, Plan},
    },
    oce1::Reader,
    state::Ledger,
    transaction::{self, RuleMode, Transaction},
    transaction_payload::{self, Limits},
};

#[derive(Clone, Copy, Debug)]
pub struct Rules {
    pub max_drift: f64,
    pub duty: Option<(i64, RuleMode)>,
    pub bft: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    InvalidAddress,
    InvalidPayload,
    TimestampDrift,
    InvalidSignature,
}
pub fn admit(tx: &Transaction, now: f64, rules: Rules) -> Result<Verdict, Error> {
    if admission::address_route(tx).is_err() {
        return Ok(Verdict::InvalidAddress);
    }
    if admission::payload_size(tx, Limits::default()).is_err() {
        return Ok(Verdict::InvalidPayload);
    }
    if !(tx.timestamp.is_finite() && now.is_finite())
        || ((tx.timestamp - now).abs() > rules.max_drift
            && !admission::duty_retry_at(tx, now, rules.duty, rules.bft))
    {
        return Ok(Verdict::TimestampDrift);
    }
    if admission::signature(tx, tx.public_key.as_deref()).is_err() {
        return Ok(Verdict::InvalidSignature);
    }
    match admission::payload(tx, Limits::default()) {
        Ok(()) => Ok(Verdict::Accept),
        Err(Error::Rejected(_)) => Ok(Verdict::InvalidPayload),
        Err(e) => Err(e),
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    Send(Vec<u8>),
    Broadcast(Vec<u8>),
    ReportBad(&'static str),
    Close,
}
/// Apply gossip effects to the authenticated connection that produced them.
/// A disconnected or backpressured peer does not undo accepted queue admission.
pub async fn deliver(
    swarm: &octra_node_protocol::network::swarm::Swarm,
    peer: &octra_node_protocol::network::session::Peer,
    effect: Effect,
) -> Result<(), octra_node_protocol::network::Error> {
    use octra_node_protocol::network::{frame::Frame, swarm::SEND_DEADLINE};
    match effect {
        Effect::Send(payload) => {
            peer.enqueue(
                Frame {
                    message: 0x20,
                    payload,
                },
                SEND_DEADLINE,
            )
            .await;
        }
        Effect::Broadcast(payload) => {
            swarm
                .broadcast(
                    Frame {
                        message: 0x20,
                        payload,
                    },
                    Some(&peer.hello().node_id),
                    false,
                )
                .await?;
        }
        Effect::ReportBad(reason) => swarm.report_peer(peer, reason.as_bytes()),
        Effect::Close => peer.close(),
    }
    Ok(())
}
pub trait Host {
    fn now(&self) -> f64;
    fn has(&self, hash: &[u8]) -> bool;
    fn find(&self, hash: &[u8]) -> Option<Transaction>;
    fn sender_key(&self, transaction: &Transaction) -> Option<Vec<u8>>;
    /// Must atomically enforce the host's complete staging policy against its
    /// authenticated state and pending queue, including fees and nonce rules.
    fn add(&mut self, transaction: Transaction) -> Result<Vec<u8>, String>;
    /// Enqueue an effect in order; queue acceptance does not imply delivery.
    fn emit(&mut self, effect: Effect);
}
#[derive(Default)]
pub struct Ingress {
    pub guard: Guard,
}
/// A borrowed view under the host's queue/head lock. Proposal-bundle lookup is
/// separate because native gossip serves both staged and shared transactions.
pub struct Staging<'a> {
    pub pool: &'a mut Pool,
    pub ledger: &'a Ledger,
    pub rules: &'a intake::Rules,
    pub host: &'a mut dyn intake::Host,
    pub shared: &'a dyn Fn(&[u8]) -> Option<Transaction>,
    pub clock: &'a dyn Fn() -> f64,
    pub effects: &'a mut dyn FnMut(Effect),
}
impl Host for Staging<'_> {
    fn now(&self) -> f64 {
        (self.clock)()
    }
    fn has(&self, hash: &[u8]) -> bool {
        self.pool.find(hash).is_some() || (self.shared)(hash).is_some()
    }
    fn find(&self, hash: &[u8]) -> Option<Transaction> {
        self.pool
            .find(hash)
            .cloned()
            .or_else(|| (self.shared)(hash))
    }
    fn sender_key(&self, tx: &Transaction) -> Option<Vec<u8>> {
        self.ledger
            .account(&tx.from)
            .and_then(|a| a.public_key.clone())
            .or_else(|| tx.public_key.clone())
    }
    fn add(&mut self, tx: Transaction) -> Result<Vec<u8>, String> {
        intake::stage(
            self.pool,
            &tx,
            self.ledger,
            self.rules,
            self.host,
            self.clock,
        )
    }
    fn emit(&mut self, effect: Effect) {
        (self.effects)(effect);
    }
}
fn unavailable(error: impl std::fmt::Display) -> Error {
    Error::Unavailable(error.to_string())
}
fn hash(tx: &Transaction) -> Result<Vec<u8>, Error> {
    tx.hash()
        .map(|h| hex::encode(h).into_bytes())
        .map_err(unavailable)
}
fn decode(json: &[u8]) -> Option<Transaction> {
    let document = Document::parse(json).ok()?;
    let tx = Transaction::from_document(&document).ok()?;
    transaction_payload::admit(Limits::default(), &tx).ok()?;
    Some(tx)
}
impl Ingress {
    pub fn stage(
        &mut self,
        peer: &[u8],
        payload: &[u8],
        max_drift: f64,
        context: &mut Staging<'_>,
    ) -> Result<(), Error> {
        self.receive(
            peer,
            payload,
            Rules {
                max_drift,
                duty: context.rules.duty,
                bft: context.rules.bft,
            },
            context,
        )
    }
    pub fn receive(
        &mut self,
        peer: &[u8],
        payload: &[u8],
        rules: Rules,
        host: &mut impl Host,
    ) -> Result<(), Error> {
        if let Err(reason) = self.guard.admit(
            gossip_guard::Config::default(),
            host.now(),
            peer,
            payload.len() as i64,
        ) {
            host.emit(Effect::ReportBad(reason));
            host.emit(Effect::Close);
            return Ok(());
        }
        match transaction_gossip::plan(payload, |hash| host.has(hash), 256, 64) {
            Plan::Request(hashes) => {
                let now = host.now();
                let hashes = hashes
                    .into_iter()
                    .filter(|h| !self.guard.seen.recent(now, h))
                    .collect::<Vec<_>>();
                if !hashes.is_empty() {
                    host.emit(Effect::Send(
                        Message::Get(hashes).encode().map_err(unavailable)?,
                    ));
                }
            }
            Plan::Serve(hashes) => {
                for h in hashes {
                    if let Some(tx) = host.find(&h) {
                        host.emit(Effect::Send(
                            Message::Transaction {
                                hash: h,
                                json: tx.to_json_bytes().map_err(unavailable)?,
                            }
                            .encode()
                            .map_err(unavailable)?,
                        ));
                    }
                }
            }
            Plan::Receive {
                hash: advertised,
                json,
            } => {
                if let Some(tx) = decode(&json) {
                    if hash(&tx)? == advertised {
                        self.handle(&tx, rules, host)?;
                    }
                }
            }
            Plan::Legacy => {
                // Native legacy messages read the first OCE1 string and permit trailing bytes.
                if let Ok(json) = Reader::new(payload).get_bytes() {
                    if let Some(tx) = decode(json) {
                        self.handle(&tx, rules, host)?;
                    }
                }
            }
        }
        Ok(())
    }
    fn handle(
        &mut self,
        tx: &Transaction,
        rules: Rules,
        host: &mut impl Host,
    ) -> Result<(), Error> {
        let received = hash(tx)?;
        let now = host.now();
        if host.has(&received) || self.guard.seen.recent(now, &received) {
            return Ok(());
        }
        let Ok(normalized) = transaction::normalize_envelope(tx, host.sender_key(tx).as_deref())
        else {
            self.guard.seen.remember(now, &received);
            return Ok(());
        };
        let normalized_hash = hash(&normalized)?;
        if received != normalized_hash {
            self.guard.seen.remember(now, &received);
        }
        if host.has(&normalized_hash) {
            return Ok(());
        }
        let now = host.now();
        if !self.guard.seen.remember(now, &normalized_hash) {
            return Ok(());
        }
        if admit(&normalized, now, rules)? == Verdict::Accept {
            if let Ok(accepted) = host.add(normalized) {
                host.emit(Effect::Broadcast(
                    Message::Inventory(vec![accepted])
                        .encode()
                        .map_err(unavailable)?,
                ));
            }
        }
        Ok(())
    }
}
