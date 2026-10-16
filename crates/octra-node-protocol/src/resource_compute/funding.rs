// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Signed compute permissions and deposit lifecycle. No function here can
//! publish state or move ledger funds; those belong to staged epoch execution.
use super::{
    bill::{self, Bill},
    call::Header,
    frame, hash, Error, Result,
};
use crate::{
    network::verify_ed25519,
    oce1::{Reader, Writer},
    transaction::{address_from_public_key, decode_base64, is_valid_address},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use num_bigint::BigInt;
use num_traits::Zero;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Terms {
    chain_id: Vec<u8>,
    payer: Vec<u8>,
    public_key: Vec<u8>,
    target: Vec<u8>,
    call_hash: Vec<u8>,
    nonce: i64,
    amount: i64,
    expires_epoch: i64,
}
impl Terms {
    pub fn chain_id(&self) -> &[u8] {
        &self.chain_id
    }
    pub fn payer(&self) -> &[u8] {
        &self.payer
    }
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
    pub fn target(&self) -> &[u8] {
        &self.target
    }
    pub fn call_hash(&self) -> &[u8] {
        &self.call_hash
    }
    pub fn nonce(&self) -> i64 {
        self.nonce
    }
    pub fn amount(&self) -> i64 {
        self.amount
    }
    pub fn expires_epoch(&self) -> i64 {
        self.expires_epoch
    }
    fn shape(&self) -> bool {
        !self.chain_id.is_empty()
            && self.chain_id.len() <= 128
            && is_valid_address(&self.payer)
            && is_valid_address(&self.target)
            && self.public_key.len() == 32
            && self.payer == address_from_public_key(STANDARD.encode(&self.public_key).as_bytes())
            && self.call_hash.len() == 32
            && self.nonce > 0
            && self.amount > 0
            && self.expires_epoch >= 0
    }
    fn put(&self, out: &mut Writer) -> std::result::Result<(), crate::oce1::Error> {
        out.put_bytes(&self.chain_id)?;
        out.put_bytes(&self.payer)?;
        out.put_hash32(&self.public_key)?;
        out.put_bytes(&self.target)?;
        out.put_hash32(&self.call_hash)?;
        out.put_u64(self.nonce as u64)?;
        out.put_u64(self.amount as u64)?;
        out.put_u64(self.expires_epoch as u64)
    }
    fn get(input: &mut Reader<'_>) -> std::result::Result<Self, crate::oce1::Error> {
        let chain_id = input.get_bytes_bounded(128)?.to_vec();
        let payer = input.get_bytes_bounded(47)?.to_vec();
        let public_key = input.get_hash32()?.to_vec();
        let target = input.get_bytes_bounded(47)?.to_vec();
        let call_hash = input.get_hash32()?.to_vec();
        let nonce = input.get_u64()? as i64;
        let amount = input.get_u64()? as i64;
        let expires_epoch = input.get_u64()? as i64;
        Ok(Self {
            chain_id,
            payer,
            public_key,
            target,
            call_hash,
            nonce,
            amount,
            expires_epoch,
        })
    }
    pub fn sign_bytes(&self) -> Result<[u8; 32]> {
        if !self.shape() {
            return Err(Error::rejected(b"compute funding terms"));
        }
        hash(b"octra:compute_funding", |out| self.put(out))
    }
    pub fn prepare(header: &Header, target: &[u8], nonce: i64) -> Result<Self> {
        Self::prepare_until(header, target, nonce, header.request().expires_epoch)
    }
    pub fn prepare_until(
        header: &Header,
        target: &[u8],
        nonce: i64,
        expires_epoch: i64,
    ) -> Result<Self> {
        let request = header.request();
        if expires_epoch < request.expires_epoch
            || expires_epoch > header.valid_until().unwrap_or(request.expires_epoch)
        {
            return Err(Error::rejected(b"compute funding payment deadline"));
        }
        if bill::resources(request).is_err() {
            return Err(Error::rejected(b"compute funding resource limits"));
        }
        if !is_valid_address(&request.caller)
            || request.caller
                != address_from_public_key(STANDARD.encode(header.caller_public_key()).as_bytes())
        {
            return Err(Error::rejected(b"compute funding payer identity"));
        }
        if !verify_ed25519(
            header.caller_public_key(),
            &header.intent()?,
            header.caller_signature(),
        ) {
            return Err(Error::rejected(b"compute funding call signature"));
        }
        let amount = request
            .limits
            .fee_cap
            .ok_or_else(|| Error::rejected(b"compute funding fee absent"))?;
        let signed = header.sign_bytes()?;
        let call_hash = hash(b"octra:compute_funding_call", |out| {
            out.put_hash32(&signed)?;
            out.put_sig64(header.signature())
        })?
        .to_vec();
        let terms = Self {
            chain_id: request.chain_id.clone(),
            payer: request.caller.clone(),
            public_key: header.caller_public_key().to_vec(),
            target: target.to_vec(),
            call_hash,
            nonce,
            amount,
            expires_epoch,
        };
        if terms.shape() {
            Ok(terms)
        } else {
            Err(Error::rejected(b"compute funding terms"))
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Permission {
    terms: Terms,
    signature: Vec<u8>,
}
impl Permission {
    pub fn terms(&self) -> &Terms {
        &self.terms
    }
    fn signature_valid(terms: &Terms, signature: &[u8]) -> Result<bool> {
        Ok(signature.len() == 64
            && verify_ed25519(&terms.public_key, &terms.sign_bytes()?, signature))
    }
    pub fn authorize(terms: Terms, signature: &[u8]) -> Result<Self> {
        if terms.shape() && Self::signature_valid(&terms, signature)? {
            Ok(Self {
                terms,
                signature: signature.to_vec(),
            })
        } else {
            Err(Error::rejected(b"compute funding signature"))
        }
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Writer::new();
        out.put_bytes(b"compute_funding")?;
        self.terms.put(&mut out)?;
        out.put_sig64(&self.signature)?;
        Ok(out.into_bytes())
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > 1024 {
            return Err(Error::rejected(b"compute funding size"));
        }
        frame(raw, b"compute funding encoding", |input| {
            if input.get_bytes_bounded(15)? != b"compute_funding" {
                return Err("compute funding format".into());
            }
            let terms = Terms::get(input)?;
            let signature = input.get_sig64()?;
            Ok(Self::authorize(terms, &signature))
        })
    }
    pub fn verify(
        &self,
        chain: &[u8],
        epoch: i64,
        nonce: i64,
        target: &[u8],
        header: &Header,
        extended: bool,
    ) -> Result<i64> {
        if chain != self.terms.chain_id {
            return Err(Error::rejected(b"compute funding chain differs"));
        }
        if epoch < header.request().epoch_id || epoch > header.request().expires_epoch {
            return Err(Error::rejected(b"compute funding epoch outside window"));
        }
        let expires = if extended {
            self.terms.expires_epoch
        } else {
            header.request().expires_epoch
        };
        let expected = Terms::prepare_until(header, target, nonce, expires)?;
        if expected != self.terms {
            return Err(Error::rejected(b"compute funding scope differs"));
        }
        if !Self::signature_valid(&self.terms, &self.signature)? {
            return Err(Error::rejected(b"compute funding signature"));
        }
        Ok(self.terms.amount)
    }
}
pub fn escrow() -> &'static [u8] {
    static ADDRESS: OnceLock<Vec<u8>> = OnceLock::new();
    ADDRESS.get_or_init(|| {
        address_from_public_key(
            STANDARD
                .encode(Sha256::digest(b"octra:compute_funding:escrow"))
                .as_bytes(),
        )
    })
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum Status {
    Open,
    Returned(i64),
    Paid(i64, Vec<u8>),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Deposit {
    request_id: Vec<u8>,
    permission: Permission,
    opened_epoch: i64,
    status: Status,
}
impl Deposit {
    pub fn request_id(&self) -> &[u8] {
        &self.request_id
    }
    pub fn permission(&self) -> &Permission {
        &self.permission
    }
    pub fn opened_epoch(&self) -> i64 {
        self.opened_epoch
    }
    pub fn returned_epoch(&self) -> Option<i64> {
        if let Status::Returned(epoch) = &self.status {
            Some(*epoch)
        } else {
            None
        }
    }
    pub fn paid(&self) -> Option<(i64, &[u8])> {
        if let Status::Paid(epoch, root) = &self.status {
            Some((*epoch, root))
        } else {
            None
        }
    }
    pub fn reserve(
        chain: &[u8],
        epoch: i64,
        nonce: i64,
        header: &Header,
        permission: Permission,
        extended: bool,
    ) -> Result<Self> {
        permission.verify(chain, epoch, nonce, escrow(), header, extended)?;
        if permission.terms.payer == escrow() {
            return Err(Error::rejected(b"compute funding payer is escrow"));
        }
        Ok(Self {
            request_id: header.request().id()?.to_vec(),
            permission,
            opened_epoch: epoch,
            status: Status::Open,
        })
    }
    pub fn return_deposit(&self, chain: &[u8], epoch: i64) -> Result<Self> {
        if self.permission.terms.chain_id != chain {
            return Err(Error::rejected(b"compute funding chain differs"));
        }
        if self.returned_epoch().is_some() {
            return Err(Error::rejected(b"compute deposit returned"));
        }
        if self.paid().is_some() {
            return Err(Error::rejected(b"compute deposit paid"));
        }
        if epoch <= self.permission.terms.expires_epoch {
            return Err(Error::rejected(b"compute deposit has not expired"));
        }
        Ok(Self {
            status: Status::Returned(epoch),
            ..self.clone()
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Writer::new();
        out.put_bytes(b"compute_deposit")?;
        out.put_hash32(&self.request_id)?;
        out.put_bytes(&self.permission.encode()?)?;
        out.put_u64(self.opened_epoch as u64)?;
        match &self.status {
            Status::Open => out.put_u8(0)?,
            Status::Returned(epoch) => {
                out.put_u8(1)?;
                out.put_u64(*epoch as u64)?;
            }
            Status::Paid(epoch, root) => {
                out.put_u8(2)?;
                out.put_u64(*epoch as u64)?;
                out.put_hash32(root)?;
            }
        }
        Ok(out.into_bytes())
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > 2048 {
            return Err(Error::rejected(b"compute deposit size"));
        }
        frame(raw, b"compute deposit encoding", |input| {
            if input.get_bytes_bounded(15)? != b"compute_deposit" {
                return Err("compute deposit format".into());
            }
            let request_id = input.get_hash32()?.to_vec();
            let permission = match Permission::decode(input.get_bytes_bounded(1024)?) {
                Ok(permission) => permission,
                Err(error) => return Ok(Err(error)),
            };
            let opened_epoch = input.get_u64()? as i64;
            let status = match input.get_u8()? {
                0 => Status::Open,
                1 => Status::Returned(input.get_u64()? as i64),
                2 => Status::Paid(input.get_u64()? as i64, input.get_hash32()?.to_vec()),
                _ => return Err("compute deposit status".into()),
            };
            let value = Self {
                request_id,
                permission,
                opened_epoch,
                status,
            };
            if value.permission.terms.target != escrow()
                || opened_epoch < 0
                || opened_epoch > value.permission.terms.expires_epoch
            {
                return Ok(Err(Error::rejected(b"compute deposit scope")));
            }
            if value
                .returned_epoch()
                .is_some_and(|epoch| epoch <= value.permission.terms.expires_epoch)
            {
                return Ok(Err(Error::rejected(b"compute deposit return epoch")));
            }
            if value.paid().is_some_and(|(epoch, _)| {
                epoch < opened_epoch || epoch > value.permission.terms.expires_epoch
            }) {
                return Ok(Err(Error::rejected(b"compute deposit payment epoch")));
            }
            Ok(Ok(value))
        })
    }
    // Keep the explicit ordered native tuple/field projection at this boundary.
    #[allow(clippy::type_complexity)]
    pub fn payment(
        &self,
        chain: &[u8],
        epoch: i64,
        bill: &Bill,
    ) -> Result<(Self, Vec<(Vec<u8>, BigInt)>)> {
        verify_deposit(&self.encode()?, chain, epoch, bill.header())?;
        let total = bill
            .payments()
            .iter()
            .map(|(_, value)| value)
            .sum::<BigInt>()
            + bill.refund();
        if total != BigInt::from(self.permission.terms.amount)
            || bill.refund() < &BigInt::zero()
            || bill
                .payments()
                .iter()
                .any(|(_, value)| value < &BigInt::zero())
        {
            return Err(Error::rejected(b"compute payment total differs"));
        }
        let mut credits = vec![(self.permission.terms.payer.clone(), bill.refund().clone())];
        credits.extend_from_slice(bill.payments());
        Ok((
            Self {
                status: Status::Paid(epoch, bill.root().to_vec()),
                ..self.clone()
            },
            credits,
        ))
    }
}
pub fn deposit_path(id: &[u8]) -> Result<[Vec<u8>; 3]> {
    if id.len() != 32 {
        return Err(Error::rejected(b"compute deposit id"));
    }
    Ok([
        b"compute".to_vec(),
        b"funds".to_vec(),
        hex::encode(id).into_bytes(),
    ])
}
pub fn encode_request(header: &Header, permission: &Permission) -> Result<Vec<u8>> {
    let mut out = Writer::new();
    out.put_bytes(&header.encode()?)?;
    out.put_bytes(&permission.encode()?)?;
    Ok(STANDARD.encode(out.into_bytes()).into_bytes())
}
pub fn decode_request(raw: &[u8]) -> Result<(Header, Permission)> {
    if raw.len() > 8192 {
        return Err(Error::rejected(b"compute funding message size"));
    }
    let bytes =
        decode_base64(raw).map_err(|_| Error::rejected(b"compute funding message encoding"))?;
    frame(&bytes, b"compute funding message encoding", |input| {
        let header = Header::decode(input.get_bytes_bounded(4096)?);
        if let Some(error) = header.as_ref().err().filter(|error| error.is_operational()) {
            return Ok(Err(error.clone()));
        }
        let permission = Permission::decode(input.get_bytes_bounded(1024)?);
        if let Some(error) = permission
            .as_ref()
            .err()
            .filter(|error| error.is_operational())
        {
            return Ok(Err(error.clone()));
        }
        Ok(header.and_then(|header| permission.map(|permission| (header, permission))))
    })
}
pub fn verify_deposit(raw: &[u8], chain: &[u8], epoch: i64, header: &Header) -> Result<Deposit> {
    let deposit = Deposit::decode(raw)?;
    if deposit.request_id.as_slice() != header.request().id()?.as_slice() {
        return Err(Error::rejected(b"compute deposit request differs"));
    }
    if deposit.returned_epoch().is_some() {
        return Err(Error::rejected(b"compute deposit returned"));
    }
    if deposit.paid().is_some() {
        return Err(Error::rejected(b"compute deposit paid"));
    }
    if epoch < deposit.opened_epoch || epoch > deposit.permission.terms.expires_epoch {
        return Err(Error::rejected(b"compute deposit epoch outside window"));
    }
    deposit.permission.verify(
        chain,
        deposit.opened_epoch,
        deposit.permission.terms.nonce,
        escrow(),
        header,
        true,
    )?;
    Ok(deposit)
}
