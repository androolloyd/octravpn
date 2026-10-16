//! Native legacy epoch announcements (0x40). These messages are diagnostics,
//! never a finalized-state, membership or catch-up authority.
use crate::{
    native_json::Document,
    oce1::{self, Reader, Writer},
    submit_rpc,
    transaction::Transaction,
};

pub const FRAME_TYPE: u8 = 0x40;
pub const MAX_PAYLOAD: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct Message {
    pub epoch: u64,
    pub root: Vec<u8>,
    pub declared_count: i32,
    pub producer: Vec<u8>,
    pub transactions: Vec<Transaction>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Silent,
    Ignored {
        epoch: i64,
        tx_count: usize,
        root: Vec<u8>,
        producer: Vec<u8>,
    },
}

/// Exact native OCE1 field order. Serialized transactions are supplied from the
/// genuinely committed record in its confirmed order, not reconstructed input.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)] // Native Int64.of_int / Int32.of_int retain low wire bits.
pub fn payload(
    epoch: i64,
    root: &[u8],
    confirmed_count: i64,
    producer: &[u8],
    serialized: &[Vec<u8>],
) -> Result<Vec<u8>, oce1::Error> {
    let too_large = || oce1::Error::from("legacy epoch exceeds frame limit");
    let mut bytes = 24_usize
        .checked_add(root.len())
        .and_then(|n| n.checked_add(producer.len()))
        .ok_or_else(too_large)?;
    for tx in serialized {
        bytes = bytes
            .checked_add(4)
            .and_then(|n| n.checked_add(tx.len()))
            .ok_or_else(too_large)?;
    }
    if bytes > MAX_PAYLOAD {
        return Err(too_large());
    }
    let mut out = Writer::new();
    out.put_u64(epoch as u64)?;
    out.put_bytes(root)?;
    out.put_u32(confirmed_count as u32)?;
    out.put_bytes(producer)?;
    out.put_u32(
        u32::try_from(serialized.len())
            .map_err(|_| oce1::Error::from("legacy epoch count exceeds wire range"))?,
    )?;
    for tx in serialized {
        out.put_bytes(tx)?;
    }
    let bytes = out.into_bytes();
    if bytes.len() > MAX_PAYLOAD {
        return Err("legacy epoch exceeds frame limit".into());
    }
    Ok(bytes)
}

#[allow(clippy::cast_possible_wrap)] // Native get_u32 -> int32 preserves the signed interpretation.
pub fn parse(raw: &[u8]) -> Result<Message, oce1::Error> {
    if raw.len() > MAX_PAYLOAD {
        return Err("legacy epoch exceeds frame limit".into());
    }
    let mut input = Reader::new(raw);
    let epoch = input.get_u64()?;
    let root = input.get_bytes()?.to_vec();
    let declared_count = input.get_u32()? as i32;
    let producer = input.get_bytes()?.to_vec();
    let count = input.get_u32()? as i32;
    if count < 0 {
        return Err("List.init".into());
    }
    // No allocation is made from an untrusted declared count. Each admitted
    // JSON transaction consumes bounded bytes before it can grow this vector.
    let mut transactions = Vec::new();
    for _ in 0..count {
        let raw = input.get_bytes()?;
        let doc = Document::parse(raw).map_err(|error| oce1::Error::from(error.to_string()))?;
        let tx = submit_rpc::decode(&doc, doc.root())
            .map_err(|error| oce1::Error::from(format!("tx decode: {error}")))?;
        transactions.push(tx);
    }
    // Native P2p_epoch_broadcast.parse does not enforce trailing-byte absence
    // or equate declared_count with actual count. Preserve that decoder here;
    // the authenticated host never consumes this message as state authority.
    Ok(Message {
        epoch,
        root,
        declared_count,
        producer,
        transactions,
    })
}

#[allow(clippy::cast_possible_wrap)] // OCaml Int64.to_int projects a signed native int63.
pub fn observer_event(observer: bool, raw: &[u8]) -> Result<Event, oce1::Error> {
    let message = parse(raw)?;
    if !observer {
        return Ok(Event::Silent);
    }
    let root = if message.root.len() >= 16 {
        [
            &message.root[..8],
            b"..",
            &message.root[message.root.len() - 8..],
        ]
        .concat()
    } else {
        message.root
    };
    Ok(Event::Ignored {
        epoch: (message.epoch as i64).wrapping_shl(1) >> 1,
        tx_count: message.transactions.len(),
        root,
        producer: message.producer[..message.producer.len().min(14)].to_vec(),
    })
}
