// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! A local exit intent pauses automatic duty; it is not a consensus transaction.
use crate::{
    native_base64,
    native_json::{Document, Value},
    network,
    oce1::{Error, Writer},
    transaction,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub chain_id: Vec<u8>,
    pub address: Vec<u8>,
    pub pubkey: Vec<u8>,
    pub bonded_epoch: i64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Intent {
    identity: Identity,
    signature: Vec<u8>,
}
impl Identity {
    pub fn message(&self) -> Result<[u8; 32], Error> {
        let mut w = Writer::new();
        w.put_bytes(&self.chain_id)?;
        w.put_bytes(&self.address)?;
        w.put_bytes(&self.pubkey)?;
        w.put_u64(self.bonded_epoch as u64)?;
        Ok(network::domain_hash(
            b"octra:validator_exit_intent",
            &w.into_bytes(),
        ))
    }
    fn public_key(&self) -> Result<Vec<u8>, Error> {
        let raw = native_base64::decode(&self.pubkey)
            .map_err(|_| Error::from("invalid validator exit identity"))?;
        if raw.len() != 32
            || STANDARD.encode(&raw).as_bytes() != self.pubkey
            || self.chain_id.is_empty()
            || self.chain_id.len() > 128
            || self.bonded_epoch < 0
            || transaction::address_from_public_key(&self.pubkey) != self.address
        {
            return Err("invalid validator exit identity".into());
        }
        Ok(raw)
    }
}
impl Intent {
    pub fn create(identity: Identity, privkey: &[u8]) -> Result<Self, Error> {
        let public = identity.public_key()?;
        let raw = zeroize::Zeroizing::new(
            native_base64::decode(privkey)
                .map_err(|_| Error::from("invalid validator exit signing key"))?,
        );
        let raw: &[u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| Error::from("invalid validator exit signing key"))?;
        let key = SigningKey::from_bytes(raw);
        if key.verifying_key().as_bytes().as_slice() != public {
            return Err("validator exit signing key differs".into());
        }
        let signature = key.sign(&identity.message()?).to_bytes().to_vec();
        Ok(Self {
            identity,
            signature,
        })
    }
    pub fn encode(&self) -> Vec<u8> {
        use crate::light_rpc::json::{object, string};
        object(&[
            ("standard", string(b"octra-validator-exit-intent")),
            ("chain_id", string(&self.identity.chain_id)),
            ("address", string(&self.identity.address)),
            ("pubkey", string(&self.identity.pubkey)),
            (
                "bonded_epoch",
                string(self.identity.bonded_epoch.to_string()),
            ),
            ("signature", string(STANDARD.encode(&self.signature))),
        ])
    }
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() > 4096 {
            return Err("validator exit intent exceeds limit".into());
        }
        let doc = Document::parse(raw)
            .map_err(|_| Error::from("invalid validator exit intent encoding"))?;
        let Value::Object(fields) = doc.root() else {
            return Err("invalid validator exit intent object".into());
        };
        if fields.len() != 6 {
            return Err("invalid validator exit intent object".into());
        }
        let mut names = fields.iter().map(|(k, _)| k.as_slice()).collect::<Vec<_>>();
        names.sort();
        names.dedup();
        if names
            != [
                b"address".as_slice(),
                b"bonded_epoch",
                b"chain_id",
                b"pubkey",
                b"signature",
                b"standard",
            ]
        {
            return Err("validator exit intent fields differ".into());
        }
        let get = |key: &[u8]| match doc.field(doc.root(), key) {
            Some(Value::String(v)) => Ok(v.clone()),
            _ => Err(Error::from("invalid validator exit intent encoding")),
        };
        let epoch = get(b"bonded_epoch")?;
        let bonded_epoch = crate::native_integer::parse_int64(&epoch)
            .ok_or_else(|| Error::from("invalid validator exit intent encoding"))?;
        if get(b"standard")? != b"octra-validator-exit-intent"
            || bonded_epoch.to_string().as_bytes() != epoch
        {
            return Err("invalid validator exit intent format".into());
        }
        let identity = Identity {
            chain_id: get(b"chain_id")?,
            address: get(b"address")?,
            pubkey: get(b"pubkey")?,
            bonded_epoch,
        };
        let public = identity.public_key()?;
        let encoded = get(b"signature")?;
        let signature = native_base64::decode(&encoded)
            .map_err(|_| Error::from("invalid validator exit intent signature"))?;
        if signature.len() != 64
            || STANDARD.encode(&signature).as_bytes() != encoded
            || !network::verify_ed25519(&public, &identity.message()?, &signature)
        {
            return Err("invalid validator exit intent signature".into());
        }
        Ok(Self {
            identity,
            signature,
        })
    }
    pub fn applies(&self, expected: &Identity) -> Result<bool, Error> {
        let actual = &self.identity;
        if actual.chain_id != expected.chain_id
            || actual.address != expected.address
            || actual.pubkey != expected.pubkey
        {
            Err("validator exit intent identity differs".into())
        } else if actual.bonded_epoch > expected.bonded_epoch {
            Err("validator exit intent registration is ahead".into())
        } else {
            Ok(actual.bonded_epoch == expected.bonded_epoch)
        }
    }
    pub fn id(&self) -> Result<String, Error> {
        Ok(hex::encode(Sha256::digest(self.identity.message()?)))
    }
}
