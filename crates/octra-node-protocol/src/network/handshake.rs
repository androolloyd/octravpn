// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native authenticated HELLO / HELLO_ACK / HELLO_FINISH and PROFILE exchange.
use super::{domain_hash, verify_ed25519, Error};
use crate::oce1::{Reader, Writer};
use ed25519_dalek::{Signer, SigningKey};
use rand::{CryptoRng, RngCore};

pub const PROTOCOL_VERSION: u16 = 3;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hello {
    pub chain_id: Vec<u8>,
    pub protocol_version: u16,
    pub node_id: Vec<u8>,
    pub node_address: Vec<u8>,
    pub public_key: Vec<u8>,
    pub config_hash: Vec<u8>,
    pub listen_port: u16,
    pub best_epoch: i64,
    pub best_root: Vec<u8>,
    pub nonce: Vec<u8>,
    pub signature: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ack {
    pub hello: Hello,
    pub challenge_nonce: Vec<u8>,
    pub signature: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finish {
    pub chain_id: Vec<u8>,
    pub config_hash: Vec<u8>,
    pub initiator_node_id: Vec<u8>,
    pub responder_node_id: Vec<u8>,
    pub initiator_nonce: Vec<u8>,
    pub responder_nonce: Vec<u8>,
    pub signature: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    pub epoch: i64,
    pub config_hash: Vec<u8>,
    pub signature: Vec<u8>,
}

pub fn node_id(public_key: &[u8]) -> Vec<u8> {
    hex::encode(domain_hash(b"octra:node_id:v1", public_key)).into_bytes()
}

impl Hello {
    pub fn new<R: CryptoRng + RngCore>(
        key: &SigningKey,
        chain_id: Vec<u8>,
        node_address: Vec<u8>,
        config_hash: [u8; 32],
        listen_port: u16,
        best_epoch: i64,
        best_root: [u8; 32],
        rng: &mut R,
    ) -> Result<Self, Error> {
        if listen_port == 0 {
            return Err("invalid listen port".into());
        }
        let public_key = key.verifying_key().to_bytes().to_vec();
        let mut nonce = vec![0; 32];
        rng.fill_bytes(&mut nonce);
        let mut hello = Self {
            chain_id,
            protocol_version: PROTOCOL_VERSION,
            node_id: node_id(&public_key),
            node_address,
            public_key,
            config_hash: config_hash.to_vec(),
            listen_port,
            best_epoch,
            best_root: best_root.to_vec(),
            nonce,
            signature: vec![0; 64],
        };
        hello.signature = key.sign(&hello.sign_bytes()?).to_bytes().to_vec();
        Ok(hello)
    }
    fn put_unsigned(&self, writer: &mut Writer) -> Result<(), Error> {
        writer.put_bytes(&self.chain_id)?;
        writer.put_u16(self.protocol_version)?;
        writer.put_bytes(&self.node_id)?;
        writer.put_bytes(&self.node_address)?;
        writer.put_raw(&self.public_key)?;
        writer.put_hash32(&self.config_hash)?;
        writer.put_u16(self.listen_port)?;
        writer.put_u64(self.best_epoch as u64)?;
        writer.put_hash32(&self.best_root)?;
        writer.put_hash32(&self.nonce)
    }
    fn put(&self, writer: &mut Writer) -> Result<(), Error> {
        self.put_unsigned(writer)?;
        writer.put_bytes(&self.signature)
    }
    fn get(reader: &mut Reader<'_>) -> Result<Self, Error> {
        let value = Self {
            chain_id: reader.get_bytes_bounded(128)?.to_vec(),
            protocol_version: reader.get_u16()?,
            node_id: reader.get_bytes_bounded(64)?.to_vec(),
            node_address: reader.get_bytes_bounded(128)?.to_vec(),
            public_key: reader.get_raw(32)?.to_vec(),
            config_hash: reader.get_hash32()?.to_vec(),
            listen_port: reader.get_u16()?,
            best_epoch: reader.get_u64()? as i64,
            best_root: reader.get_hash32()?.to_vec(),
            nonce: reader.get_hash32()?.to_vec(),
            signature: reader.get_bytes_bounded(64)?.to_vec(),
        };
        if value.node_id.len() != 64 {
            return Err("p2p hello: invalid node id length".into());
        }
        if value.signature.len() != 64 {
            return Err("p2p hello: invalid signature length".into());
        }
        Ok(value)
    }
    pub fn sign_bytes(&self) -> Result<[u8; 32], Error> {
        let mut writer = Writer::new();
        self.put_unsigned(&mut writer)?;
        Ok(domain_hash(b"octra:p2p_hello:v1", &writer.into_bytes()))
    }
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut writer = Writer::new();
        self.put(&mut writer)?;
        Ok(writer.into_bytes())
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        let value = Self::get(&mut reader)?;
        reader.finish()?;
        Ok(value)
    }
    pub fn validate(
        &self,
        chain_id: &[u8],
        config_hash: &[u8],
        allowed: &[Vec<u8>],
    ) -> Result<(), Error> {
        if self.chain_id != chain_id {
            let mut error = b"chain_id mismatch: ".to_vec();
            error.extend_from_slice(&self.chain_id);
            error.extend_from_slice(b" vs ");
            error.extend_from_slice(chain_id);
            return Err(Error::new(error));
        }
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(format!(
                "p2p proto mismatch: peer={} local={PROTOCOL_VERSION}",
                self.protocol_version
            )
            .into());
        }
        if self.config_hash != config_hash {
            return Err(format!(
                "consensus_config_hash mismatch: peer={} local={}",
                hex::encode(&self.config_hash[..8.min(self.config_hash.len())]),
                hex::encode(&config_hash[..8.min(config_hash.len())])
            )
            .into());
        }
        if self.node_id != node_id(&self.public_key) {
            return Err("node_id does not match pubkey".into());
        }
        if self.listen_port == 0 {
            return Err("invalid listen port".into());
        }
        if !verify_ed25519(&self.public_key, &self.sign_bytes()?, &self.signature) {
            return Err("invalid Ed25519 signature on HELLO".into());
        }
        if !allowed.is_empty() && !allowed.contains(&self.public_key) {
            return Err(format!(
                "unknown validator pubkey (node_id={})",
                String::from_utf8_lossy(&self.node_id[..12])
            )
            .into());
        }
        Ok(())
    }
}

impl Ack {
    pub fn new(hello: Hello, challenge_nonce: Vec<u8>, key: &SigningKey) -> Result<Self, Error> {
        let mut value = Self {
            hello,
            challenge_nonce,
            signature: vec![0; 64],
        };
        value.signature = key.sign(&value.sign_bytes()?).to_bytes().to_vec();
        Ok(value)
    }
    pub fn sign_bytes(&self) -> Result<[u8; 32], Error> {
        let mut writer = Writer::new();
        writer.put_hash32(&self.hello.sign_bytes()?)?;
        writer.put_hash32(&self.challenge_nonce)?;
        Ok(domain_hash(b"octra:p2p_hello_ack:v1", &writer.into_bytes()))
    }
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut writer = Writer::new();
        self.hello.put(&mut writer)?;
        writer.put_hash32(&self.challenge_nonce)?;
        writer.put_sig64(&self.signature)?;
        Ok(writer.into_bytes())
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        let value = Self {
            hello: Hello::get(&mut reader)?,
            challenge_nonce: reader.get_hash32()?.to_vec(),
            signature: reader.get_sig64()?.to_vec(),
        };
        reader.finish()?;
        Ok(value)
    }
    pub fn validate(&self, local: &Hello, allowed: &[Vec<u8>]) -> Result<(), Error> {
        self.hello
            .validate(&local.chain_id, &local.config_hash, allowed)?;
        if self.challenge_nonce != local.nonce {
            return Err("HELLO_ACK challenge mismatch".into());
        }
        if !verify_ed25519(&self.hello.public_key, &self.sign_bytes()?, &self.signature) {
            return Err("invalid Ed25519 signature on HELLO_ACK".into());
        }
        Ok(())
    }
}
impl Finish {
    pub fn new(initiator: &Hello, responder: &Hello, key: &SigningKey) -> Result<Self, Error> {
        let mut value = Self {
            chain_id: initiator.chain_id.clone(),
            config_hash: initiator.config_hash.clone(),
            initiator_node_id: initiator.node_id.clone(),
            responder_node_id: responder.node_id.clone(),
            initiator_nonce: initiator.nonce.clone(),
            responder_nonce: responder.nonce.clone(),
            signature: vec![0; 64],
        };
        value.signature = key.sign(&value.sign_bytes()?).to_bytes().to_vec();
        Ok(value)
    }
    fn put_unsigned(&self, writer: &mut Writer) -> Result<(), Error> {
        writer.put_bytes(&self.chain_id)?;
        writer.put_hash32(&self.config_hash)?;
        writer.put_bytes(&self.initiator_node_id)?;
        writer.put_bytes(&self.responder_node_id)?;
        writer.put_hash32(&self.initiator_nonce)?;
        writer.put_hash32(&self.responder_nonce)
    }
    pub fn sign_bytes(&self) -> Result<[u8; 32], Error> {
        let mut writer = Writer::new();
        self.put_unsigned(&mut writer)?;
        Ok(domain_hash(
            b"octra:p2p_hello_finish:v1",
            &writer.into_bytes(),
        ))
    }
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut writer = Writer::new();
        self.put_unsigned(&mut writer)?;
        writer.put_sig64(&self.signature)?;
        Ok(writer.into_bytes())
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        let value = Self {
            chain_id: reader.get_bytes_bounded(128)?.to_vec(),
            config_hash: reader.get_hash32()?.to_vec(),
            initiator_node_id: reader.get_bytes_bounded(64)?.to_vec(),
            responder_node_id: reader.get_bytes_bounded(64)?.to_vec(),
            initiator_nonce: reader.get_hash32()?.to_vec(),
            responder_nonce: reader.get_hash32()?.to_vec(),
            signature: reader.get_sig64()?.to_vec(),
        };
        if value.initiator_node_id.len() != 64 || value.responder_node_id.len() != 64 {
            return Err("p2p finish: invalid node id length".into());
        }
        reader.finish()?;
        Ok(value)
    }
    pub fn validate(&self, initiator: &Hello, responder: &Hello) -> Result<(), Error> {
        if self.chain_id != initiator.chain_id || self.chain_id != responder.chain_id {
            return Err("HELLO_FINISH chain mismatch".into());
        }
        if self.config_hash != initiator.config_hash || self.config_hash != responder.config_hash {
            return Err("HELLO_FINISH config mismatch".into());
        }
        if self.initiator_node_id != initiator.node_id
            || self.responder_node_id != responder.node_id
        {
            return Err("HELLO_FINISH identity mismatch".into());
        }
        if self.initiator_nonce != initiator.nonce || self.responder_nonce != responder.nonce {
            return Err("HELLO_FINISH challenge mismatch".into());
        }
        if !verify_ed25519(&initiator.public_key, &self.sign_bytes()?, &self.signature) {
            return Err("invalid Ed25519 signature on HELLO_FINISH".into());
        }
        Ok(())
    }
}
impl Profile {
    pub fn new(
        chain_id: &[u8],
        node_id: &[u8],
        epoch: i64,
        config_hash: [u8; 32],
        key: &SigningKey,
    ) -> Result<Self, Error> {
        if node_id.len() != 64 {
            return Err("invalid profile node id".into());
        }
        let mut value = Self {
            epoch,
            config_hash: config_hash.to_vec(),
            signature: vec![0; 64],
        };
        value.signature = key
            .sign(&value.sign_bytes(chain_id, node_id)?)
            .to_bytes()
            .to_vec();
        Ok(value)
    }
    pub fn sign_bytes(&self, chain_id: &[u8], node_id: &[u8]) -> Result<[u8; 32], Error> {
        let mut writer = Writer::new();
        writer.put_bytes(chain_id)?;
        writer.put_bytes(node_id)?;
        writer.put_u64(self.epoch as u64)?;
        writer.put_hash32(&self.config_hash)?;
        Ok(domain_hash(b"octra:p2p_profile:v1", &writer.into_bytes()))
    }
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut writer = Writer::new();
        writer.put_u64(self.epoch as u64)?;
        writer.put_hash32(&self.config_hash)?;
        writer.put_sig64(&self.signature)?;
        Ok(writer.into_bytes())
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        let value = Self {
            epoch: reader.get_u64()? as i64,
            config_hash: reader.get_hash32()?.to_vec(),
            signature: reader.get_sig64()?.to_vec(),
        };
        reader.finish()?;
        Ok(value)
    }
    pub fn validate(
        &self,
        chain_id: &[u8],
        node_id: &[u8],
        public_key: &[u8],
    ) -> Result<(), Error> {
        if node_id.len() != 64 {
            return Err("profile node id is invalid".into());
        }
        if public_key.len() != 32 {
            return Err("profile public key is invalid".into());
        }
        if self.config_hash.len() != 32 {
            return Err("profile config hash is invalid".into());
        }
        if self.signature.len() != 64
            || !verify_ed25519(
                public_key,
                &self.sign_bytes(chain_id, node_id)?,
                &self.signature,
            )
        {
            return Err("profile signature is invalid".into());
        }
        Ok(())
    }
}
