// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native bounded OCE1 consensus messages and canonical parent certificates.
use super::{
    policy, reward,
    types::{
        BundleQuery, BundleResponse, Bytes, CatchupEpochRecord, CatchupFinality, CatchupQuery,
        CatchupResponse, CommitCertificate, EpochHeader, EpochRootQuery, EpochRootResponse,
        Finalize, ParentCommit, Proposal, RoundFetch, RoundStep, RoundSync, Validator,
        ValidatorSet, Vote, VoteType, CURRENT_VERSION, LEGACY_VERSION, NIL,
    },
    Error,
};
use crate::oce1::{Reader, Writer};
use num_traits::One;
pub const MAX_ROUND: i64 = 1_000_000;
pub const MAX_TXS: usize = 2048;
pub const MAX_VALIDATORS: usize = 4096;
pub const MAX_JSON_BYTES: usize = 8 * 1024 * 1024;
pub trait Wire: Sized {
    fn put(&self, writer: &mut Writer) -> Result<(), Error>;
    fn get(reader: &mut Reader<'_>) -> Result<Self, Error>;
    fn encode(&self) -> Result<Bytes, Error> {
        let mut writer = Writer::new();
        self.put(&mut writer)?;
        Ok(writer.into_bytes())
    }
    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        let value = Self::get(&mut reader)?;
        reader.finish()?;
        Ok(value)
    }
}
fn string(reader: &mut Reader<'_>, maximum: usize) -> Result<Bytes, Error> {
    Ok(reader.get_bytes_bounded(maximum)?.to_vec())
}
fn exact(reader: &mut Reader<'_>, count: usize, string_type: bool) -> Result<Bytes, Error> {
    let value = string(reader, count)?;
    if value.len() != count {
        return Err(if string_type {
            "consensus codec: bad string length"
        } else {
            "consensus codec: bad byte length"
        }
        .into());
    }
    Ok(value)
}
fn hash(reader: &mut Reader<'_>) -> Result<Bytes, Error> {
    Ok(reader.get_hash32()?.to_vec())
}
fn round(reader: &mut Reader<'_>) -> Result<i64, Error> {
    let value = i64::from(reader.get_u32()? as i32);
    if !(0..=MAX_ROUND).contains(&value) {
        return Err("consensus codec: round out of range".into());
    }
    Ok(value)
}
fn hashes(reader: &mut Reader<'_>) -> Result<Vec<Bytes>, Error> {
    reader.get_list(MAX_TXS, hash)
}
fn json_list(reader: &mut Reader<'_>) -> Result<Vec<Bytes>, Error> {
    reader.get_list(MAX_TXS, |r| string(r, MAX_JSON_BYTES))
}
fn put_hashes(writer: &mut Writer, values: &[Bytes]) -> Result<(), Error> {
    writer.put_list(values, |w, v| w.put_hash32(v))
}
fn put_strings(writer: &mut Writer, values: &[Bytes]) -> Result<(), Error> {
    writer.put_list(values, |w, v| w.put_bytes(v))
}
impl Wire for EpochHeader {
    fn put(&self, w: &mut Writer) -> Result<(), Error> {
        w.put_u16(self.proto_version as u16)?;
        w.put_bytes(&self.chain_id)?;
        w.put_u64(self.epoch_id as u64)?;
        w.put_hash32(&self.prev_state_root)?;
        w.put_hash32(&self.tx_list_hash)?;
        w.put_hash32(&self.receipt_root)?;
        w.put_hash32(&self.proposed_state_root)?;
        match self.proto_version {
            LEGACY_VERSION => {
                if self.parent_commit_hash != NIL {
                    return Err("legacy epoch header has parent commit".into());
                }
            }
            CURRENT_VERSION => w.put_hash32(&self.parent_commit_hash)?,
            _ => return Err("unsupported epoch header protocol".into()),
        }
        w.put_bytes(&self.creator_addr)?;
        w.put_u64(self.txid_hi as u64)?;
        w.put_u64(self.ts.to_bits())
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        let proto_version = i64::from(r.get_u16()?);
        if !policy::supported_version(proto_version) {
            return Err("consensus codec: unsupported epoch header protocol".into());
        }
        let value = Self {
            proto_version,
            chain_id: string(r, 128)?,
            epoch_id: r.get_u64()? as i64,
            prev_state_root: hash(r)?,
            tx_list_hash: hash(r)?,
            receipt_root: hash(r)?,
            proposed_state_root: hash(r)?,
            parent_commit_hash: if proto_version == LEGACY_VERSION {
                NIL.to_vec()
            } else {
                hash(r)?
            },
            creator_addr: string(r, 128)?,
            txid_hi: r.get_u64()? as i64,
            ts: f64::from_bits(r.get_u64()?),
        };
        if !value.ts.is_finite() {
            return Err("epoch_header timestamp is not finite".into());
        }
        Ok(value)
    }
}
impl Wire for Vote {
    fn put(&self, w: &mut Writer) -> Result<(), Error> {
        w.put_bytes(&self.chain_id)?;
        w.put_u64(self.epoch_id as u64)?;
        w.put_u32(self.round as u32)?;
        w.put_u8(self.vote_type as u8)?;
        w.put_hash32(&self.proposal_id)?;
        w.put_bytes(&self.validator)?;
        w.put_bytes(&self.signature)
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self {
            chain_id: string(r, 128)?,
            epoch_id: r.get_u64()? as i64,
            round: round(r)?,
            vote_type: VoteType::from_byte(r.get_u8()?)?,
            proposal_id: hash(r)?,
            validator: string(r, 128)?,
            signature: exact(r, 64, false)?,
        })
    }
}
impl Wire for RoundSync {
    fn put(&self, w: &mut Writer) -> Result<(), Error> {
        w.put_bytes(&self.chain_id)?;
        w.put_u64(self.epoch_id as u64)?;
        w.put_u32(self.round as u32)?;
        w.put_u8(self.step as u8)?;
        w.put_bool(self.request)?;
        w.put_bytes(&self.validator)?;
        w.put_bytes(&self.signature)
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self {
            chain_id: string(r, 128)?,
            epoch_id: r.get_u64()? as i64,
            round: round(r)?,
            step: RoundStep::from_byte(r.get_u8()?)?,
            request: r.get_bool()?,
            validator: string(r, 128)?,
            signature: exact(r, 64, false)?,
        })
    }
}
impl Wire for RoundFetch {
    fn put(&self, w: &mut Writer) -> Result<(), Error> {
        w.put_bytes(&self.chain_id)?;
        w.put_u64(self.epoch_id as u64)?;
        w.put_u32(self.after_round as u32)?;
        w.put_u32(self.through_round as u32)
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self {
            chain_id: string(r, 128)?,
            epoch_id: r.get_u64()? as i64,
            after_round: round(r)?,
            through_round: round(r)?,
        })
    }
}
impl Wire for ValidatorSet {
    fn put(&self, w: &mut Writer) -> Result<(), Error> {
        w.put_bool(self.weighted)?;
        w.put_list(&self.validators, |w, v| {
            w.put_bytes(&v.address)?;
            w.put_bytes(&v.pubkey)?;
            let weight = self
                .weight(&v.address)
                .ok_or_else(|| Error::from("consensus codec: validator weight missing"))?;
            w.put_bytes(weight.to_string().as_bytes())
        })
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        let weighted = r.get_bool()?;
        let entries = r.get_list(MAX_VALIDATORS, |r| {
            let address = string(r, 128)?;
            let pubkey = exact(r, 32, false)?;
            let weight = string(r, 256)
                .ok()
                .and_then(|raw| reward::parse_weight(&raw))
                .ok_or_else(|| Error::from("consensus codec: invalid validator weight"))?;
            Ok((Validator { address, pubkey }, weight))
        })?;
        let set = Self::weighted(entries.clone())
            .map_err(|e| Error::from(format!("consensus codec: {e}")))?;
        if weighted {
            Ok(set)
        } else {
            if entries
                .iter()
                .any(|(_, weight)| weight != &num_bigint::BigInt::one())
            {
                return Err("consensus codec: unweighted validator has non-unit weight".into());
            }
            Ok(Self::unweighted(set.validators))
        }
    }
    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        let value = Self::get(&mut reader)?;
        reader.finish()?;
        if value.encode()? != bytes {
            return Err("consensus codec: validator set is not canonical".into());
        }
        Ok(value)
    }
}
impl Wire for CommitCertificate {
    fn put(&self, w: &mut Writer) -> Result<(), Error> {
        w.put_bytes(&self.chain_id)?;
        w.put_u64(self.epoch_id as u64)?;
        w.put_u32(self.commit_round as u32)?;
        self.header.put(w)?;
        w.put_hash32(&self.proposal_id)?;
        w.put_list(&self.precommits, |w, v| v.put(w))
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self {
            chain_id: string(r, 128)?,
            epoch_id: r.get_u64()? as i64,
            commit_round: round(r)?,
            header: EpochHeader::get(r)?,
            proposal_id: hash(r)?,
            precommits: r.get_list(MAX_VALIDATORS, Vote::get)?,
        })
    }
}
impl Wire for ParentCommit {
    fn put(&self, w: &mut Writer) -> Result<(), Error> {
        let mut certificate = self.certificate.clone();
        certificate
            .precommits
            .sort_by(|a, b| a.validator.cmp(&b.validator));
        w.put_bytes(&certificate.encode()?)?;
        w.put_bytes(&self.validator_set.encode()?)
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self {
            certificate: CommitCertificate::decode(r.get_bytes_bounded(16 * 1024 * 1024)?)?,
            validator_set: ValidatorSet::decode(r.get_bytes_bounded(4 * 1024 * 1024)?)?,
        })
    }
    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        let value = Self::get(&mut reader)?;
        reader.finish()?;
        if value.encode()? != bytes {
            return Err("consensus codec: parent commit is not canonical".into());
        }
        Ok(value)
    }
}
fn put_parent(w: &mut Writer, p: &ParentCommit) -> Result<(), Error> {
    w.put_bytes(&p.encode()?)
}
fn get_parent(r: &mut Reader<'_>) -> Result<ParentCommit, Error> {
    ParentCommit::decode(r.get_bytes_bounded(20 * 1024 * 1024)?)
}
impl Wire for Proposal {
    fn put(&self, w: &mut Writer) -> Result<(), Error> {
        if !policy::supported_version(self.header.proto_version) {
            return Err("consensus codec: proposal protocol mismatch".into());
        }
        w.put_bytes(&self.chain_id)?;
        w.put_u64(self.epoch_id as u64)?;
        w.put_u32(self.round as u32)?;
        w.put_option(self.valid_round.as_ref(), |w, v| w.put_u32(*v as u32))?;
        self.header.put(w)?;
        put_hashes(w, &self.tx_hashes)?;
        if self.header.proto_version == LEGACY_VERSION {
            if self.parent_commit.is_some() {
                return Err("legacy proposal has parent commit".into());
            }
        } else {
            w.put_option(self.parent_commit.as_ref(), put_parent)?;
        }
        w.put_bytes(&self.proposer)?;
        w.put_bytes(&self.signature)
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        let chain_id = string(r, 128)?;
        let epoch_id = r.get_u64()? as i64;
        let round = round(r)?;
        let valid_round = r.get_option(crate::consensus::codec::round)?;
        let header = EpochHeader::get(r)?;
        let tx_hashes = hashes(r)?;
        let parent_commit = if header.proto_version == LEGACY_VERSION {
            None
        } else {
            r.get_option(get_parent)?
        };
        let proposer = string(r, 128)?;
        let signature = exact(r, 64, false)?;
        Ok(Self {
            chain_id,
            epoch_id,
            round,
            valid_round,
            header,
            tx_hashes,
            parent_commit,
            proposer,
            signature,
        })
    }
}
impl Wire for Finalize {
    fn put(&self, w: &mut Writer) -> Result<(), Error> {
        w.put_bytes(&self.chain_id)?;
        w.put_u64(self.epoch_id as u64)?;
        w.put_u32(self.commit_round as u32)?;
        self.header.put(w)?;
        w.put_hash32(&self.proposal_id)?;
        w.put_list(&self.precommits, |w, v| v.put(w))?;
        match self.header.proto_version {
            LEGACY_VERSION => {
                if self.parent_commit.is_some() {
                    return Err("legacy finalize has parent commit".into());
                }
                Ok(())
            }
            CURRENT_VERSION => w.put_option(self.parent_commit.as_ref(), put_parent),
            _ => Err("unsupported finalize protocol".into()),
        }
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        let chain_id = string(r, 128)?;
        let epoch_id = r.get_u64()? as i64;
        let commit_round = round(r)?;
        let header = EpochHeader::get(r)?;
        let proposal_id = hash(r)?;
        let precommits = r.get_list(MAX_VALIDATORS, Vote::get)?;
        let parent_commit = if header.proto_version == LEGACY_VERSION {
            None
        } else {
            r.get_option(get_parent)?
        };
        Ok(Self {
            chain_id,
            epoch_id,
            commit_round,
            header,
            proposal_id,
            precommits,
            parent_commit,
        })
    }
}
impl Wire for EpochRootQuery {
    fn put(&self, w: &mut Writer) -> Result<(), Error> {
        w.put_bytes(&self.chain_id)?;
        w.put_u64(self.epoch_id as u64)
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self {
            chain_id: string(r, 128)?,
            epoch_id: r.get_u64()? as i64,
        })
    }
}
impl Wire for EpochRootResponse {
    fn put(&self, w: &mut Writer) -> Result<(), Error> {
        w.put_bytes(&self.chain_id)?;
        w.put_u64(self.epoch_id as u64)?;
        w.put_option(self.state_root.as_ref(), |w, v| w.put_hash32(v))?;
        w.put_bytes(&self.responder_addr)?;
        w.put_u64(self.responder_head_epoch as u64)?;
        w.put_bytes(&self.signature)
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self {
            chain_id: string(r, 128)?,
            epoch_id: r.get_u64()? as i64,
            state_root: r.get_option(hash)?,
            responder_addr: string(r, 128)?,
            responder_head_epoch: r.get_u64()? as i64,
            signature: exact(r, 64, true)?,
        })
    }
}
impl Wire for BundleQuery {
    fn put(&self, w: &mut Writer) -> Result<(), Error> {
        w.put_bytes(&self.chain_id)?;
        w.put_u64(self.epoch_id as u64)?;
        w.put_hash32(&self.proposal_id)
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self {
            chain_id: string(r, 128)?,
            epoch_id: r.get_u64()? as i64,
            proposal_id: hash(r)?,
        })
    }
}
impl Wire for BundleResponse {
    fn put(&self, w: &mut Writer) -> Result<(), Error> {
        w.put_bytes(&self.chain_id)?;
        w.put_u64(self.epoch_id as u64)?;
        w.put_hash32(&self.proposal_id)?;
        w.put_bytes(&self.responder_addr)?;
        put_hashes(w, &self.tx_hashes)?;
        put_strings(w, &self.txs_json)?;
        put_strings(w, &self.receipts_json)?;
        w.put_bytes(&self.signature)
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self {
            chain_id: string(r, 128)?,
            epoch_id: r.get_u64()? as i64,
            proposal_id: hash(r)?,
            responder_addr: string(r, 128)?,
            tx_hashes: hashes(r)?,
            txs_json: json_list(r)?,
            receipts_json: json_list(r)?,
            signature: exact(r, 64, true)?,
        })
    }
}
impl Wire for CatchupQuery {
    fn put(&self, w: &mut Writer) -> Result<(), Error> {
        w.put_bytes(&self.chain_id)?;
        w.put_bytes(&self.request_id)?;
        w.put_u64(self.from_epoch as u64)?;
        w.put_u32(self.max_epochs as u32)
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        let value = Self {
            chain_id: string(r, 128)?,
            request_id: string(r, 128)?,
            from_epoch: r.get_u64()? as i64,
            max_epochs: i64::from(r.get_u32()? as i32),
        };
        if !(1..=16).contains(&value.max_epochs) {
            return Err("consensus codec: catchup range out of bounds".into());
        }
        Ok(value)
    }
}
pub fn put_catchup_record(
    w: &mut Writer,
    value: &CatchupEpochRecord,
    v2: bool,
) -> Result<(), Error> {
    w.put_u64(value.epoch_id as u64)?;
    w.put_hash32(&value.prev_state_root)?;
    w.put_hash32(&value.state_root)?;
    w.put_hash32(&value.tx_list_hash)?;
    put_hashes(w, &value.tx_hashes)?;
    put_strings(w, &value.txs_json)?;
    if !v2 {
        return Ok(());
    }
    w.put_hash32(&value.receipt_root)?;
    put_strings(w, &value.receipts_json)?;
    w.put_u64(value.epoch_ts.to_bits())?;
    w.put_bytes(&value.creator_addr)?;
    w.put_u32(value.commit_round as u32)?;
    reward::put(
        w,
        value
            .reward_source
            .as_ref()
            .ok_or_else(|| Error::from("catchup reward source is missing"))?,
    )?;
    let finality = value
        .finality
        .as_ref()
        .ok_or_else(|| Error::from("catchup finality is missing"))?;
    w.put_bytes(&finality.finalize.encode()?)?;
    w.put_bytes(&finality.validator_set.encode()?)
}
#[allow(clippy::cast_precision_loss)] // Native v1 reconstructs time with Int64.to_float.
pub fn get_catchup_record(r: &mut Reader<'_>, v2: bool) -> Result<CatchupEpochRecord, Error> {
    let epoch_id = r.get_u64()? as i64;
    let prev_state_root = hash(r)?;
    let state_root = hash(r)?;
    let tx_list_hash = hash(r)?;
    let tx_hashes = hashes(r)?;
    let txs_json = json_list(r)?;
    let (
        receipt_root,
        receipts_json,
        epoch_ts,
        creator_addr,
        commit_round,
        reward_source,
        finality,
    ) = if v2 {
        let receipt_root = hash(r)?;
        let receipts_json = json_list(r)?;
        let epoch_ts = f64::from_bits(r.get_u64()?);
        policy::time_of_seconds(epoch_ts)
            .map_err(|e| Error::from(format!("consensus codec: {e}")))?;
        let creator_addr = string(r, 128)?;
        let commit_round = round(r)?;
        let reward_source = Some(reward::get(r)?);
        let finalize = Finalize::decode(r.get_bytes_bounded(32 * 1024 * 1024)?)?;
        let validator_set = ValidatorSet::decode(r.get_bytes_bounded(4 * 1024 * 1024)?)?;
        (
            receipt_root,
            receipts_json,
            epoch_ts,
            creator_addr,
            commit_round,
            reward_source,
            Some(CatchupFinality {
                finalize,
                validator_set,
            }),
        )
    } else {
        (
            crate::network::domain_hash(b"octra:preverify_receipt_root:v1", &[0; 4]).to_vec(),
            vec![],
            epoch_id as f64 * 10.0,
            vec![],
            0,
            None,
            None,
        )
    };
    Ok(CatchupEpochRecord {
        epoch_id,
        prev_state_root,
        state_root,
        tx_list_hash,
        tx_hashes,
        txs_json,
        receipt_root,
        receipts_json,
        epoch_ts,
        creator_addr,
        commit_round,
        reward_source,
        finality,
    })
}
impl CatchupResponse {
    pub fn encode(&self, v2: bool) -> Result<Bytes, Error> {
        let mut w = Writer::new();
        w.put_bytes(&self.chain_id)?;
        w.put_bytes(&self.request_id)?;
        w.put_bytes(&self.status)?;
        w.put_option(self.error_code.as_ref(), |w, v| w.put_bytes(v))?;
        w.put_list(&self.records, |w, v| put_catchup_record(w, v, v2))?;
        w.put_option(self.next_epoch.as_ref(), |w, v| w.put_u64(*v as u64))?;
        w.put_bytes(&self.responder_addr)?;
        w.put_bytes(&self.signature)?;
        Ok(w.into_bytes())
    }
    pub fn decode(bytes: &[u8], v2: bool) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        let value = Self {
            chain_id: string(&mut r, 128)?,
            request_id: string(&mut r, 128)?,
            status: string(&mut r, 64)?,
            error_code: r.get_option(|r| string(r, 256))?,
            records: r.get_list(16, |r| get_catchup_record(r, v2))?,
            next_epoch: r.get_option(|r| Ok(r.get_u64()? as i64))?,
            responder_addr: string(&mut r, 128)?,
            signature: exact(&mut r, 64, true)?,
        };
        r.finish()?;
        Ok(value)
    }
}
