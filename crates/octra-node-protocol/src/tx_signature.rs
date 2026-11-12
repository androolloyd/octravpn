// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Epoch-selected transaction signature domain. Transaction identity remains
//! unchanged; activation is exclusively selected by the canonical rule graph.
use crate::{
    oce1::Writer,
    rules::{self, Rule},
    transaction::{self, RuleMode, Transaction},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Mode {
    #[default]
    Historical,
    Network(Vec<u8>),
}
pub const CONSENSUS_ID: &[u8] = b"ed25519:oce1:transaction_network:chain_id:signing_json";
pub fn at_plan(chain: &[u8], activation: Option<i64>, epoch: i64) -> Mode {
    if activation.is_some_and(|first| epoch >= first) {
        Mode::Network(chain.to_vec())
    } else {
        Mode::Historical
    }
}
pub fn at(chain: &[u8], epoch: i64) -> Mode {
    if rules::at(chain, Rule::TxNetwork, epoch) == RuleMode::Active {
        Mode::Network(chain.to_vec())
    } else {
        Mode::Historical
    }
}
impl Mode {
    pub fn bytes(&self, tx: &Transaction) -> Result<Vec<u8>, String> {
        let body = tx.signing_bytes().map_err(|e| e.to_string())?;
        match self {
            Self::Historical => Ok(body),
            Self::Network(chain) => {
                if chain.is_empty() {
                    return Err("transaction network is empty".into());
                }
                let mut writer = Writer::new();
                for part in [b"octra:transaction:network".as_slice(), chain, &body] {
                    writer.put_bytes(part).map_err(|e| e.to_string())?;
                }
                Ok(writer.into_bytes())
            }
        }
    }
    pub fn verify(&self, tx: &Transaction, public: &[u8]) -> bool {
        let (Ok(public), Ok(signature), Ok(message)) = (
            transaction::decode_base64(public),
            transaction::decode_base64(&tx.signature),
            self.bytes(tx),
        ) else {
            return false;
        };
        crate::network::verify_ed25519(&public, &message, &signature)
    }
    pub fn sign(&self, tx: &Transaction, key: &SigningKey) -> Result<Transaction, String> {
        let mut signed = tx.clone();
        signed.signature = STANDARD
            .encode(key.sign(&self.bytes(tx)?).to_bytes())
            .into_bytes();
        Ok(signed)
    }
    pub fn check(&self, tx: &Transaction) -> Result<(), &'static str> {
        match tx.public_key.as_deref() {
            Some(key)
                if transaction::address_from_public_key(key) == tx.from && self.verify(tx, key) =>
            {
                Ok(())
            }
            _ => Err("transaction network signature is invalid"),
        }
    }
    pub fn check_active(&self, txs: &[Transaction]) -> Result<(), &'static str> {
        if !matches!(self, Self::Historical) {
            for tx in txs {
                self.check(tx)?;
            }
        }
        Ok(())
    }
}
