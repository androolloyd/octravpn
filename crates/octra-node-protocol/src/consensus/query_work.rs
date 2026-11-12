//! Native per-peer, network and validator-lane admission for bounded query replies.
use super::Bytes;
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};
pub const REPLY_LIMIT: usize = 8 * 1024 * 1024;
pub const LANE_LIMIT: usize = 4 * REPLY_LIMIT;
const UNIT: i64 = 1_000_000_000;
const WAIT_SPAN: i64 = 16_000_000_000;
#[derive(Clone, Copy, Debug)]
struct Bucket {
    at: i64,
    credit: i64,
}
impl Bucket {
    fn new(now: i64, units: i64) -> Self {
        Self {
            at: now,
            credit: units * UNIT,
        }
    }
    fn refill(self, now: i64, capacity: i64, rate: i64) -> Self {
        let cap = capacity * UNIT;
        let elapsed = now.saturating_sub(self.at).max(0);
        Self {
            at: now.max(self.at),
            credit: (self.credit + elapsed.min(cap) * rate).min(cap),
        }
    }
    fn refund(&mut self, capacity: i64, amount: i64) {
        self.credit = (self.credit + amount).min(capacity * UNIT);
    }
}
#[derive(Clone, Debug)]
struct Peer {
    bucket: Bucket,
    seen: i64,
    validator: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Building,
    Writing(usize),
}
#[derive(Clone, Debug)]
struct Job {
    id: u64,
    peer: Bytes,
    network: Bytes,
    validator: bool,
    cost: i64,
    phase: Phase,
}
impl Job {
    fn bytes(&self) -> usize {
        match self.phase {
            Phase::Building => REPLY_LIMIT,
            Phase::Writing(bytes) => bytes,
        }
    }
}
#[derive(Clone, Debug)]
struct Waiting {
    who: Bytes,
    group: Bytes,
    until: i64,
    lane: bool,
    cost: i64,
}
#[derive(Clone, Debug)]
pub struct QueryWork {
    public: Bucket,
    validators: Bucket,
    peers: BTreeMap<Bytes, Peer>,
    networks: BTreeMap<Bytes, Peer>,
    active: Vec<Job>,
    waiting: Vec<Waiting>,
    next: u64,
}
pub fn network(address: SocketAddr) -> Bytes {
    let ip = match address.ip() {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
        IpAddr::V4(ip) => IpAddr::V4(ip),
    };
    match ip {
        IpAddr::V4(ip) => {
            let mut bytes = ip.octets();
            bytes[3] = 0;
            Ipv4Addr::from(bytes).to_string().into_bytes()
        }
        IpAddr::V6(ip) => {
            let mut bytes = ip.octets();
            bytes[8..].fill(0);
            Ipv6Addr::from(bytes).to_string().into_bytes()
        }
    }
}
impl QueryWork {
    pub fn new(now: i64) -> Self {
        Self {
            public: Bucket::new(now, 16),
            validators: Bucket::new(now, 64),
            peers: BTreeMap::new(),
            networks: BTreeMap::new(),
            active: Vec::new(),
            waiting: Vec::new(),
            next: 0,
        }
    }
    pub fn finish(&mut self, id: u64) {
        self.active.retain(|job| job.id != id);
    }
    pub fn prepared(&mut self, id: u64, bytes: usize, cost: i64) -> bool {
        let Some(job) = self.active.iter_mut().find(|job| job.id == id) else {
            return false;
        };
        if job.phase != Phase::Building || bytes > REPLY_LIMIT || cost < 1 || cost > job.cost {
            return false;
        }
        let refund = (job.cost - cost) * UNIT;
        let capacity = if job.validator { 32 } else { 16 };
        if let Some(peer) = self.peers.get_mut(&job.peer) {
            peer.bucket.refund(capacity, refund);
        }
        if let Some(peer) = self.networks.get_mut(&job.network) {
            peer.bucket.refund(capacity, refund);
        }
        if job.validator {
            self.validators.refund(64, refund);
        } else {
            self.public.refund(16, refund);
        }
        job.phase = Phase::Writing(bytes);
        job.cost = cost;
        true
    }
    pub fn start(
        &mut self,
        now: i64,
        peer: &[u8],
        network: &[u8],
        validator: bool,
        cost: i64,
    ) -> Option<u64> {
        let network = if validator {
            [b"validator:".as_slice(), peer].concat()
        } else {
            [b"public:".as_slice(), network].concat()
        };
        let count = self
            .active
            .iter()
            .filter(|job| job.validator == validator && job.phase == Phase::Building)
            .count();
        let bytes: usize = self
            .active
            .iter()
            .filter(|job| job.validator == validator)
            .map(Job::bytes)
            .sum();
        if self.active.iter().any(|job| job.peer == peer)
            || count >= 2
            || bytes > LANE_LIMIT - REPLY_LIMIT
            || !(1..=16).contains(&cost)
            || self.next == ((1u64 << 62) - 1)
        {
            return None;
        }
        let mut peers = self.peers.clone();
        let mut networks = self.networks.clone();
        peers.retain(|name, saved| {
            now < saved.seen
                || now.saturating_sub(saved.seen) < 60_000_000_000
                || self.active.iter().any(|job| job.peer == *name)
        });
        networks.retain(|name, saved| {
            now < saved.seen
                || now.saturating_sub(saved.seen) < 60_000_000_000
                || self.active.iter().any(|job| job.network == *name)
        });
        let tracked = peers
            .values()
            .filter(|saved| saved.validator == validator)
            .count();
        let same_lane = peers
            .get(peer)
            .is_some_and(|saved| saved.validator == validator);
        let groups = networks
            .values()
            .filter(|saved| saved.validator == validator)
            .count();
        if (!same_lane && tracked >= 256) || (!networks.contains_key(&network) && groups >= 256) {
            return None;
        }
        let (capacity, rate) = if validator { (32, 4) } else { (16, 1) };
        let available = |map: &BTreeMap<Bytes, Peer>, key: &[u8]| {
            map.get(key).map_or(Bucket::new(now, capacity), |saved| {
                saved.bucket.refill(now, capacity, rate)
            })
        };
        let mut saved = available(&peers, peer);
        let mut group = available(&networks, &network);
        let mut global = if validator {
            self.validators.refill(now, 64, 16)
        } else {
            self.public.refill(now, 16, 4)
        };
        let price = cost * UNIT;
        let mut waiting: Vec<_> = self
            .waiting
            .iter()
            .filter(|item| item.until > now)
            .cloned()
            .collect();
        for item in &mut waiting {
            if item.who == peer && item.group == network {
                item.until = now.saturating_add(WAIT_SPAN);
                item.cost = cost;
            }
        }
        let first = waiting.iter().find(|item| item.group == network);
        let head = waiting.iter().find(|item| {
            item.lane == validator
                && available(&peers, &item.who).credit >= item.cost * UNIT
                && available(&networks, &item.group).credit >= item.cost * UNIT
                && waiting
                    .iter()
                    .find(|before| before.group == item.group)
                    .is_some_and(|before| before.who == item.who)
        });
        let room = |funds: i64, head: Option<&Waiting>| {
            funds
                >= price
                    + head
                        .filter(|item| item.who != peer)
                        .map_or(0, |item| item.cost * UNIT)
        };
        if saved.credit < price
            || group.credit < price
            || !room(global.credit, head)
            || !room(group.credit, first)
        {
            if saved.credit >= price
                && !waiting
                    .iter()
                    .any(|item| item.who == peer && item.group == network)
                && waiting.iter().filter(|item| item.group == network).count() < 2
                && waiting.iter().filter(|item| item.lane == validator).count() < 256
            {
                waiting.push(Waiting {
                    who: peer.to_vec(),
                    group: network,
                    until: now.saturating_add(WAIT_SPAN),
                    lane: validator,
                    cost,
                });
            }
            self.peers = peers;
            self.networks = networks;
            self.waiting = waiting;
            return None;
        }
        saved.credit -= price;
        global.credit -= price;
        group.credit -= price;
        let id = self.next;
        self.next += 1;
        peers.insert(
            peer.to_vec(),
            Peer {
                bucket: saved,
                seen: now,
                validator,
            },
        );
        networks.insert(
            network.clone(),
            Peer {
                bucket: group,
                seen: now,
                validator,
            },
        );
        self.peers = peers;
        self.networks = networks;
        if validator {
            self.validators = global;
        } else {
            self.public = global;
        }
        self.active.push(Job {
            id,
            peer: peer.to_vec(),
            network: network.clone(),
            validator,
            cost,
            phase: Phase::Building,
        });
        waiting.retain(|item| item.who != peer || item.group != network);
        self.waiting = waiting;
        Some(id)
    }
}
