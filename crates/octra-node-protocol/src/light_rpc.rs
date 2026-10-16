// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Authenticated light-client records from the adopted native C_light_* modules.
//! JSON strings preserve native bytes. A witness hash alone is not an inclusion proof.
use crate::{
    consensus::{self, ValidatorSet},
    network,
    oce1::{Error, Writer},
};
use num_bigint::BigInt;
use num_traits::Zero;
pub mod json;
use json::{array, boolean, number, object, optional, string};

pub fn account_proof_json(
    root: Vec<u8>,
    account: Option<&AccountWitness>,
    path: &[&[u8]],
    ledger_root: &[u8],
    proof: &[u8],
    proof_kind: &[u8],
) -> Result<Vec<u8>, crate::rpc::Fault> {
    if account.is_some_and(|a| !a.witness_ok().unwrap_or(false)) {
        return Err(crate::rpc::Fault::new(-32000, b"invalid account witness"));
    }
    let exists = account.is_some();
    Ok(object(&[
        ("version", string(b"octra-account-proof-v2")),
        ("root", root),
        ("exists", boolean(exists)),
        (
            "account",
            account.map_or_else(json::null, |a| a.to_json(true)),
        ),
        (
            "irmin_proof",
            object(&[
                ("proof_kind", string(proof_kind)),
                ("path", array(path.iter().map(string))),
                ("ledger_state_root", string(ledger_root)),
                ("exists", boolean(exists)),
                ("proof", string(proof)),
            ]),
        ),
    ]))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Root {
    pub chain_id: Vec<u8>,
    pub validator_addr: Vec<u8>,
    pub head_epoch: i64,
    pub state_root: Vec<u8>,
    pub ledger_state_root: Option<Vec<u8>>,
    pub epoch_index_root: Option<Vec<u8>>,
    pub txid_hi: i64,
    pub config_hash: Vec<u8>,
    pub signature: Vec<u8>,
}
impl Root {
    pub fn sane(&self) -> bool {
        !self.chain_id.is_empty()
            && !self.validator_addr.is_empty()
            && self.head_epoch >= 0
            && self.txid_hi >= -1
            && self.state_root.len() == 32
            && self.config_hash.len() == 32
            && self
                .ledger_state_root
                .as_ref()
                .is_none_or(|v| !v.is_empty() && v.len() <= 256)
            && self.epoch_index_root.as_ref().is_none_or(|v| v.len() == 32)
    }
    pub fn sign_bytes(&self) -> Result<[u8; 32], Error> {
        let mut w = Writer::new();
        w.put_bytes(&self.chain_id)?;
        w.put_bytes(&self.validator_addr)?;
        w.put_u64(self.head_epoch as u64)?;
        w.put_hash32(&self.state_root)?;
        w.put_option(self.ledger_state_root.as_ref(), |w, v| w.put_bytes(v))?;
        w.put_option(self.epoch_index_root.as_ref(), |w, v| w.put_hash32(v))?;
        w.put_u64(self.txid_hi as u64)?;
        w.put_hash32(&self.config_hash)?;
        Ok(network::domain_hash(
            b"octra:light_root:v1",
            &w.into_bytes(),
        ))
    }
    pub fn sign(mut self, sign: impl FnOnce(&[u8]) -> Vec<u8>) -> Result<Self, Error> {
        if !self.sane() {
            return Err("invalid_root_attestation".into());
        }
        self.signature = sign(&self.sign_bytes()?);
        Ok(self)
    }
    pub fn verify(
        &self,
        validators: &ValidatorSet,
        chain_id: &[u8],
        config_hash: &[u8],
    ) -> Result<bool, Error> {
        if !self.sane() || self.chain_id != chain_id || self.config_hash != config_hash {
            return Ok(false);
        }
        Ok(match validators.public_key(&self.validator_addr) {
            None => false,
            Some(key) => network::verify_ed25519(key, &self.sign_bytes()?, &self.signature),
        })
    }
    pub fn to_json(&self, validator_pubkey: &[u8]) -> Vec<u8> {
        object(&[
            ("version", string(b"octra-signed-root-v1")),
            ("chain_id", string(&self.chain_id)),
            ("validator_addr", string(&self.validator_addr)),
            ("validator_pubkey", string(validator_pubkey)),
            ("head_epoch", string(self.head_epoch.to_string())),
            ("state_root", string(hex::encode(&self.state_root))),
            (
                "ledger_state_root",
                optional(self.ledger_state_root.as_deref()),
            ),
            (
                "epoch_index_root",
                self.epoch_index_root
                    .as_ref()
                    .map_or_else(json::null, |v| string(hex::encode(v))),
            ),
            ("txid_hi", string(self.txid_hi.to_string())),
            ("config_hash", string(hex::encode(&self.config_hash))),
            ("signature", string(json::base64(&self.signature))),
        ])
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Validator {
    pub address: Vec<u8>,
    pub pubkey: Vec<u8>,
    pub weight: BigInt,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scheduled {
    pub activate_epoch: i64,
    pub validators: Vec<Validator>,
    pub weighted: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorSetProof {
    pub chain_id: Vec<u8>,
    pub config_hash: Vec<u8>,
    pub validator_set_hash: Vec<u8>,
    pub n: i64,
    pub f: i64,
    pub quorum: i64,
    pub total_weight: BigInt,
    pub quorum_weight: BigInt,
    pub weighted: bool,
    pub validators: Vec<Validator>,
    pub scheduled: Option<Scheduled>,
    pub program_trust_hash: Option<Vec<u8>>,
    pub runtime_profile_hash: Option<Vec<u8>>,
}
fn members(set: &ValidatorSet) -> Vec<Validator> {
    set.validators
        .iter()
        .map(|v| Validator {
            address: v.address.clone(),
            pubkey: v.pubkey.clone(),
            weight: set.weight(&v.address).cloned().unwrap_or_else(BigInt::zero),
        })
        .collect()
}
fn rebuild(weighted: bool, values: &[Validator]) -> Result<ValidatorSet, Error> {
    let plain = |v: &Validator| consensus::Validator {
        address: v.address.clone(),
        pubkey: v.pubkey.clone(),
    };
    if weighted {
        ValidatorSet::weighted(
            values
                .iter()
                .map(|v| (plain(v), v.weight.clone()))
                .collect(),
        )
    } else {
        Ok(ValidatorSet::unweighted(values.iter().map(plain).collect()))
    }
}
impl ValidatorSetProof {
    pub fn of_set(
        chain_id: Vec<u8>,
        config_hash: Vec<u8>,
        set: &ValidatorSet,
        scheduled: Option<(i64, &ValidatorSet)>,
        program_trust_hash: Option<Vec<u8>>,
        runtime_profile_hash: Option<Vec<u8>>,
    ) -> Result<Self, Error> {
        Ok(Self {
            chain_id,
            config_hash,
            validator_set_hash: consensus::hash::validator_set_hash(set)?.to_vec(),
            n: set.n,
            f: set.f,
            quorum: set.quorum,
            total_weight: set.total_weight.clone(),
            quorum_weight: set.quorum_weight.clone(),
            weighted: set.weighted,
            validators: members(set),
            scheduled: scheduled.map(|(activate_epoch, set)| Scheduled {
                activate_epoch,
                validators: members(set),
                weighted: set.weighted,
            }),
            program_trust_hash,
            runtime_profile_hash,
        })
    }
    pub fn recomputed_config_hash(&self) -> Result<[u8; 32], Error> {
        let set = rebuild(self.weighted, &self.validators)?;
        let scheduled = self
            .scheduled
            .as_ref()
            .map(|s| rebuild(s.weighted, &s.validators).map(|v| (s.activate_epoch, v)))
            .transpose()?;
        consensus::hash::config_hash(
            &self.chain_id,
            &set,
            scheduled.as_ref().map(|(epoch, set)| (*epoch, set)),
            self.program_trust_hash.as_ref(),
            self.runtime_profile_hash.as_ref(),
        )
    }
    pub fn verify(&self) -> Result<bool, Error> {
        let Ok(set) = rebuild(self.weighted, &self.validators) else {
            return Ok(false);
        };
        if self.chain_id.is_empty()
            || self.config_hash.len() != 32
            || self.validator_set_hash.len() != 32
            || self.n != set.n
            || self.f != set.f
            || self.quorum != set.quorum
            || self.total_weight != set.total_weight
            || self.quorum_weight != set.quorum_weight
            || self.validator_set_hash != consensus::hash::validator_set_hash(&set)?
            || self
                .program_trust_hash
                .as_ref()
                .is_some_and(|v| v.len() != 32)
            || self
                .runtime_profile_hash
                .as_ref()
                .is_some_and(|v| v.len() != 32)
        {
            return Ok(false);
        }
        // Invalid scheduled membership is a proof refusal in native verify.
        match self.recomputed_config_hash() {
            Ok(hash) => Ok(self.config_hash == hash),
            Err(_) => Ok(false),
        }
    }
    pub fn to_json(&self) -> Vec<u8> {
        fn validators(weighted: bool, values: &[Validator]) -> Vec<u8> {
            array(values.iter().map(|v| {
                let mut fields = vec![
                    ("address", string(&v.address)),
                    ("pubkey", string(json::base64(&v.pubkey))),
                ];
                if weighted {
                    fields.push(("weight", string(v.weight.to_string())));
                }
                object(&fields)
            }))
        }
        let weighted = self.weighted || self.scheduled.as_ref().is_some_and(|s| s.weighted);
        let version = if weighted {
            "octra-validator-set-proof-v4"
        } else if self.runtime_profile_hash.is_some() {
            "octra-validator-set-proof-v3"
        } else if self.program_trust_hash.is_some() {
            "octra-validator-set-proof-v2"
        } else {
            "octra-validator-set-proof-v1"
        };
        let opt_hash = |v: &Option<Vec<u8>>| {
            v.as_ref()
                .map_or_else(json::null, |v| string(hex::encode(v)))
        };
        let scheduled = self.scheduled.as_ref().map_or_else(json::null, |s| {
            object(&[
                ("activate_epoch", string(s.activate_epoch.to_string())),
                ("weighted", boolean(s.weighted)),
                ("validators", validators(s.weighted, &s.validators)),
            ])
        });
        let mut fields = vec![
            ("version", string(version)),
            ("chain_id", string(&self.chain_id)),
            ("config_hash", string(hex::encode(&self.config_hash))),
            (
                "validator_set_hash",
                string(hex::encode(&self.validator_set_hash)),
            ),
            ("n", number(self.n)),
            ("f", number(self.f)),
            ("quorum", number(self.quorum)),
            ("validators", validators(self.weighted, &self.validators)),
            ("scheduled", scheduled),
        ];
        if weighted || self.runtime_profile_hash.is_some() || self.program_trust_hash.is_some() {
            fields.push(("program_trust_hash", opt_hash(&self.program_trust_hash)));
        }
        if weighted || self.runtime_profile_hash.is_some() {
            fields.push(("runtime_profile_hash", opt_hash(&self.runtime_profile_hash)));
        }
        if weighted {
            fields.extend([
                ("weighted", boolean(self.weighted)),
                ("total_weight", string(self.total_weight.to_string())),
                ("quorum_weight", string(self.quorum_weight.to_string())),
            ]);
        }
        object(&fields)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountWitness {
    pub chain_id: Vec<u8>,
    pub address: Vec<u8>,
    pub head_epoch: i64,
    pub state_root: Vec<u8>,
    pub balance: Vec<u8>,
    pub nonce: i64,
    pub public_key: Option<Vec<u8>>,
    pub encrypted_balance: Option<Vec<u8>>,
    pub decrypt_allowance: Vec<u8>,
    pub account_hash: Vec<u8>,
}
impl AccountWitness {
    pub fn sane(&self) -> bool {
        let digits = |v: &[u8]| !v.is_empty() && v.iter().all(u8::is_ascii_digit);
        !self.chain_id.is_empty()
            && !self.address.is_empty()
            && self.head_epoch >= 0
            && self.state_root.len() == 32
            && digits(&self.balance)
            && (0..=u32::MAX as i64).contains(&self.nonce)
            && self
                .public_key
                .as_ref()
                .is_none_or(|v| v.len() <= 100_000_000)
            && self
                .encrypted_balance
                .as_ref()
                .is_none_or(|v| v.len() <= 100_000_000)
            && digits(&self.decrypt_allowance)
            && self.account_hash.len() == 32
    }
    pub fn hash_fields(&self) -> Result<[u8; 32], Error> {
        let mut w = Writer::new();
        w.put_bytes(&self.chain_id)?;
        w.put_bytes(&self.address)?;
        w.put_u64(self.head_epoch as u64)?;
        w.put_hash32(&self.state_root)?;
        w.put_bytes(&self.balance)?;
        w.put_u32(self.nonce as u32)?;
        w.put_option(self.public_key.as_ref(), |w, v| w.put_bytes(v))?;
        w.put_option(self.encrypted_balance.as_ref(), |w, v| w.put_bytes(v))?;
        w.put_bytes(&self.decrypt_allowance)?;
        Ok(network::domain_hash(
            b"octra:light_account:v1",
            &w.into_bytes(),
        ))
    }
    pub fn make(mut self) -> Result<Self, Error> {
        self.account_hash = self.hash_fields()?.to_vec();
        Ok(self)
    }
    pub fn witness_ok(&self) -> Result<bool, Error> {
        Ok(self.sane() && self.account_hash == self.hash_fields()?)
    }
    pub fn to_json(&self, inclusion: bool) -> Vec<u8> {
        object(&[
            ("proof_kind", string(b"account_witness_v1")),
            ("inclusion", boolean(inclusion)),
            ("chain_id", string(&self.chain_id)),
            ("address", string(&self.address)),
            ("head_epoch", string(self.head_epoch.to_string())),
            ("state_root", string(hex::encode(&self.state_root))),
            ("balance", string(&self.balance)),
            ("nonce", number(self.nonce)),
            ("public_key", optional(self.public_key.as_deref())),
            (
                "encrypted_balance",
                optional(self.encrypted_balance.as_deref()),
            ),
            ("decrypt_allowance", string(&self.decrypt_allowance)),
            ("account_hash", string(hex::encode(&self.account_hash))),
        ])
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochProof {
    pub chain_id: Vec<u8>,
    pub epoch_id: i64,
    pub tx_hashes: Vec<Vec<u8>>,
    pub start_txid: i64,
    pub tx_count: i64,
    pub prev_epoch_index_root: Vec<u8>,
    pub epoch_index_root: Vec<u8>,
}
impl EpochProof {
    pub fn sane(&self) -> bool {
        fn hex64(v: &[u8]) -> bool {
            v.len() == 64 && v.iter().all(u8::is_ascii_hexdigit)
        }
        !self.chain_id.is_empty()
            && self.epoch_id >= 0
            && self.start_txid >= 0
            && self.tx_count >= 0
            && self.tx_hashes.len() as u64 == self.tx_count as u64
            && self.tx_hashes.iter().all(|v| hex64(v))
            && hex64(&self.prev_epoch_index_root)
            && hex64(&self.epoch_index_root)
    }
    pub fn computed_epoch_index_root(&self) -> Result<[u8; 32], crate::epoch_index::Error> {
        let items = crate::epoch_index::items_from_hashes(self.start_txid, &self.tx_hashes)?;
        Ok(crate::epoch_index::next_root(&self.prev_epoch_index_root, self.epoch_id, &items)?.1)
    }
    pub fn verify(&self) -> Result<bool, crate::epoch_index::Error> {
        Ok(self.sane()
            && self.epoch_index_root.to_ascii_lowercase()
                == hex::encode(self.computed_epoch_index_root()?).as_bytes())
    }
    pub fn verify_chain_step(&self, prev: &Self) -> Result<bool, crate::epoch_index::Error> {
        Ok(prev.verify()?
            && self.verify()?
            && prev.epoch_id.wrapping_add(1) == self.epoch_id
            && self.chain_id == prev.chain_id
            && self
                .prev_epoch_index_root
                .eq_ignore_ascii_case(&prev.epoch_index_root))
    }
    pub fn tx_position_ok(
        &self,
        tx_hash: &[u8],
        index: i64,
    ) -> Result<bool, crate::epoch_index::Error> {
        Ok(self.verify()?
            && index >= 0
            && index < self.tx_count
            && self.tx_hashes.get(index as usize) == Some(&tx_hash.to_ascii_lowercase()))
    }
    pub fn to_json(&self) -> Vec<u8> {
        object(&[
            ("chain_id", string(&self.chain_id)),
            ("epoch_id", string(self.epoch_id.to_string())),
            ("tx_hashes", array(self.tx_hashes.iter().map(string))),
            ("start_txid", string(self.start_txid.to_string())),
            ("tx_count", number(self.tx_count)),
            ("prev_epoch_index_root", string(&self.prev_epoch_index_root)),
            ("epoch_index_root", string(&self.epoch_index_root)),
        ])
    }
    pub fn proof_json(&self) -> Vec<u8> {
        object(&[
            ("proof_kind", string(b"epoch_inclusion")),
            ("epoch", self.to_json()),
        ])
    }
    /// `tx_json` must already be the native public transaction projection.
    pub fn tx_inclusion_json(&self, tx_hash: &[u8], index: i64, tx_json: Vec<u8>) -> Vec<u8> {
        object(&[
            ("proof_kind", string(b"tx_inclusion")),
            ("tx_hash", string(tx_hash)),
            ("index", number(index)),
            ("epoch", self.to_json()),
            ("tx", tx_json),
        ])
    }
}
