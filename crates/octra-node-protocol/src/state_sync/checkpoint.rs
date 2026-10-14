// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Port of lib/bootstrap/state_sync_checkpoint.ml. Signer public keys here use
//! native canonical base64, unlike the raw-key sets used by peer consensus.
use super::{field, fields, int64, lower_hex, optional, require, text, Result};
use crate::{
    consensus::ValidatorSet,
    native_base64,
    native_json::{Document, Value},
    network,
    oce1::Writer,
};
use base64::{engine::general_purpose::STANDARD, Engine};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Body {
    pub chain_id: Vec<u8>,
    pub epoch: i64,
    pub state_root: Vec<u8>,
    pub ledger_state_root: Vec<u8>,
    pub txid_hi: i64,
    pub config_hash: Vec<u8>,
    pub validator_set_hash: Vec<u8>,
    pub quorum_cert_hash: Option<Vec<u8>>,
    pub epoch_index_hash: Option<Vec<u8>>,
    pub epoch_index_root: Option<Vec<u8>>,
    pub created_at: i64,
    pub valid_until: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub signer: Vec<u8>,
    pub signature: Vec<u8>,
}
impl Signature {
    pub fn parse(doc: &Document, value: &Value) -> Result<Self> {
        fields(value, &[b"signer", b"signature"], "checkpoint signature")?;
        Ok(Self {
            signer: text(field(doc, value, b"signer")?)?,
            signature: text(field(doc, value, b"signature")?)?,
        })
    }
}

impl Body {
    pub fn parse(doc: &Document, value: &Value) -> Result<Self> {
        fields(
            value,
            &[
                b"chain_id",
                b"epoch",
                b"state_root",
                b"ledger_state_root",
                b"txid_hi",
                b"config_hash",
                b"validator_set_hash",
                b"quorum_cert_hash",
                b"epoch_index_hash",
                b"epoch_index_root",
                b"created_at",
                b"valid_until",
            ],
            "checkpoint",
        )?;
        let get = |name: &[u8]| field(doc, value, name);
        Ok(Self {
            chain_id: text(get(b"chain_id")?)?,
            epoch: int64(get(b"epoch")?)?,
            state_root: text(get(b"state_root")?)?,
            ledger_state_root: text(get(b"ledger_state_root")?)?,
            txid_hi: int64(get(b"txid_hi")?)?,
            config_hash: text(get(b"config_hash")?)?,
            validator_set_hash: text(get(b"validator_set_hash")?)?,
            quorum_cert_hash: optional(get(b"quorum_cert_hash")?)?,
            epoch_index_hash: optional(get(b"epoch_index_hash")?)?,
            epoch_index_root: optional(get(b"epoch_index_root")?)?,
            created_at: int64(get(b"created_at")?)?,
            valid_until: int64(get(b"valid_until")?)?,
        })
    }
    pub fn validate(&self) -> Result<()> {
        require(
            !self.chain_id.is_empty() && self.chain_id.len() <= 128,
            "invalid chain id",
        )?;
        require(self.epoch >= 0, "negative checkpoint epoch")?;
        require(self.txid_hi >= 0, "negative checkpoint txid")?;
        require(self.txid_hi != i64::MAX, "checkpoint txid exceeds limit")?;
        require(
            lower_hex(&self.state_root, 64),
            "invalid checkpoint state root",
        )?;
        require(
            !self.ledger_state_root.is_empty() && self.ledger_state_root.len() <= 256,
            "invalid checkpoint ledger root",
        )?;
        require(
            lower_hex(&self.config_hash, 64),
            "invalid checkpoint config hash",
        )?;
        require(
            lower_hex(&self.validator_set_hash, 64),
            "invalid checkpoint validator set hash",
        )?;
        for (value, reason) in [
            (&self.quorum_cert_hash, "invalid checkpoint quorum hash"),
            (&self.epoch_index_hash, "invalid checkpoint index hash"),
            (&self.epoch_index_root, "invalid checkpoint index root"),
        ] {
            require(value.as_ref().map_or(true, |v| lower_hex(v, 64)), reason)?;
        }
        require(
            self.epoch_index_hash.is_some() && self.epoch_index_root.is_some(),
            "checkpoint index commitment is required",
        )?;
        require(self.created_at >= 0, "negative checkpoint creation time")?;
        require(
            self.valid_until > self.created_at,
            "checkpoint validity interval is empty",
        )?;
        require(
            self.valid_until - self.created_at <= 2_678_400,
            "checkpoint validity interval exceeds limit",
        )
    }
    pub fn hash(&self) -> Result<[u8; 32]> {
        self.validate()?;
        let mut w = Writer::new();
        w.put_bytes(&self.chain_id)?;
        w.put_u64(self.epoch as u64)?;
        w.put_hash32(&self.state_root)?;
        w.put_bytes(&self.ledger_state_root)?;
        w.put_u64(self.txid_hi as u64)?;
        w.put_hash32(&self.config_hash)?;
        w.put_hash32(&self.validator_set_hash)?;
        for value in [
            &self.quorum_cert_hash,
            &self.epoch_index_hash,
            &self.epoch_index_root,
        ] {
            w.put_option(value.as_ref(), |w, v| w.put_hash32(v))?;
        }
        w.put_u64(self.created_at as u64)?;
        w.put_u64(self.valid_until as u64)?;
        Ok(network::domain_hash(
            b"octra:state_sync_checkpoint",
            &w.into_bytes(),
        ))
    }
    pub fn same_finalized_state(&self, other: &Self) -> bool {
        self.chain_id == other.chain_id
            && self.epoch == other.epoch
            && self.state_root == other.state_root
            && self.ledger_state_root == other.ledger_state_root
            && self.txid_hi == other.txid_hi
            && self.config_hash == other.config_hash
            && self.validator_set_hash == other.validator_set_hash
            && self.epoch_index_hash == other.epoch_index_hash
            && self.epoch_index_root == other.epoch_index_root
    }
    pub fn verify_quorum(&self, validators: &ValidatorSet, signatures: &[Signature]) -> Result<()> {
        self.validate()?;
        require(
            signatures.windows(2).all(|w| w[0].signer < w[1].signer),
            "checkpoint signatures are not canonical",
        )?;
        let message = self.hash()?;
        for signature in signatures {
            verify_signature(validators, &message, signature)?;
        }
        let signers = signatures
            .iter()
            .map(|s| s.signer.clone())
            .collect::<Vec<_>>();
        require(
            validators.has_quorum_at(&self.chain_id, self.epoch, &signers)?,
            "checkpoint signature quorum missing",
        )
    }
}

fn decode(encoded: &[u8]) -> Result<Vec<u8>> {
    native_base64::decode(encoded).map_err(|e| format!("Invalid_argument(\"{e}\")").into())
}
pub fn raw_pubkey(encoded: &[u8]) -> Result<Vec<u8>> {
    let raw = decode(encoded)?;
    require(
        raw.len() == 32 && STANDARD.encode(&raw).as_bytes() == encoded,
        "invalid signer public key",
    )?;
    require(network::public_key_safe(&raw), "unsafe signer public key")?;
    Ok(raw)
}
pub fn raw_signature(encoded: &[u8]) -> Result<Vec<u8>> {
    let raw = decode(encoded)?;
    require(
        raw.len() == 64 && STANDARD.encode(&raw).as_bytes() == encoded,
        "invalid checkpoint signature",
    )?;
    Ok(raw)
}
pub fn verify_signature(
    signers: &ValidatorSet,
    message: &[u8],
    signature: &Signature,
) -> Result<()> {
    let public = signers
        .public_key(&signature.signer)
        .ok_or("signature belongs to an unknown signer")?;
    let public = raw_pubkey(public)?;
    let signature = raw_signature(&signature.signature)?;
    require(
        network::verify_ed25519(&public, message, &signature),
        "invalid checkpoint signature",
    )
}
