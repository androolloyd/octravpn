// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! The native loaded-account ledger transition and nested rollback semantics.
//! This state does not authenticate transactions, run contracts, or claim an Irmin
//! commitment. Its dirty account set must be persisted by a canonical commit host.
use crate::transaction::{json_optional, json_string, Error, Nonce};
use num_bigint::BigInt;
use num_traits::{Signed, Zero};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_SUPPLY: u64 = 1_000_000_000_000_000;
const CAP_ERROR: &str = "supply violation: would exceed 1B hard cap";
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Account {
    pub balance: BigInt,
    pub nonce: Nonce,
    pub public_key: Option<Vec<u8>>,
    pub encrypted_balance: Option<Vec<u8>>,
    pub decrypt_allowance: BigInt,
}
impl Account {
    pub fn to_json_bytes(&self) -> Vec<u8> {
        let mut out = b"{\"balance\":".to_vec();
        json_string(&mut out, self.balance.to_string().as_bytes());
        out.extend_from_slice(b",\"nonce\":");
        out.extend_from_slice(self.nonce.get().to_string().as_bytes());
        out.extend_from_slice(b",\"public_key\":");
        json_optional(&mut out, self.public_key.as_deref());
        out.extend_from_slice(b",\"encrypted_balance\":");
        json_optional(&mut out, self.encrypted_balance.as_deref());
        out.extend_from_slice(b",\"decrypt_allowance\":");
        json_string(&mut out, self.decrypt_allowance.to_string().as_bytes());
        out.push(b'}');
        out
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Journal {
    accounts: BTreeMap<Vec<u8>, Option<Account>>,
    dirty_addresses: BTreeSet<Vec<u8>>,
    dirty: bool,
    total_supply: BigInt,
    active_accounts: usize,
    spent_nonces: BTreeSet<(Vec<u8>, Nonce)>,
}
#[derive(Debug, PartialEq, Eq)]
pub struct Ledger {
    accounts: BTreeMap<Vec<u8>, Account>,
    total_supply: BigInt,
    active_accounts: usize,
    dirty_addresses: BTreeSet<Vec<u8>>,
    dirty: bool,
    spent_nonces: BTreeSet<(Vec<u8>, Nonce)>,
    journals: Vec<Journal>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    accounts: BTreeMap<Vec<u8>, Account>,
    supply: BigInt,
    active: usize,
}
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TransferError {
    #[error("{0}")]
    DebitRejected(&'static str),
    #[error("{0}")]
    CreditRejected(&'static str),
}
pub fn valid_cipher(cipher: Option<&[u8]>) -> bool {
    cipher.map_or(true, |value| {
        value.is_empty() || value.starts_with(b"hfhe_v1")
    })
}
impl Ledger {
    /// Load the complete native account view. Legacy string "0" ciphers are
    /// cleared and marked dirty exactly as in `Ledger.create_from_store`.
    pub fn from_accounts(accounts: BTreeMap<Vec<u8>, Account>) -> Result<Self, Error> {
        if accounts.values().any(|a| {
            a.encrypted_balance.as_deref() != Some(b"0")
                && !valid_cipher(a.encrypted_balance.as_deref())
        }) {
            return Err(Error(
                "ledger cipher format unsupported; run fhe_audit on a data copy".into(),
            ));
        }
        let mut ledger = Self {
            accounts,
            total_supply: BigInt::zero(),
            active_accounts: 0,
            dirty_addresses: BTreeSet::new(),
            dirty: false,
            spent_nonces: BTreeSet::new(),
            journals: Vec::new(),
        };
        for (address, account) in &mut ledger.accounts {
            if account.encrypted_balance.as_deref() == Some(b"0") {
                account.encrypted_balance = None;
                ledger.dirty_addresses.insert(address.clone());
                ledger.dirty = true;
            }
            ledger.total_supply += &account.balance;
            ledger.active_accounts += usize::from(account.balance.is_positive());
        }
        Ok(ledger)
    }
    pub fn empty() -> Self {
        Self::from_accounts(BTreeMap::new()).expect("empty native account view")
    }
    pub fn accounts(&self) -> &BTreeMap<Vec<u8>, Account> {
        &self.accounts
    }
    pub fn account(&self, address: &[u8]) -> Option<&Account> {
        self.accounts.get(address)
    }
    pub fn total_supply(&self) -> &BigInt {
        &self.total_supply
    }
    pub const fn active_accounts(&self) -> usize {
        self.active_accounts
    }
    pub fn dirty_addresses(&self) -> &BTreeSet<Vec<u8>> {
        &self.dirty_addresses
    }
    pub const fn is_dirty(&self) -> bool {
        self.dirty
    }
    pub fn spent_nonces(&self) -> &BTreeSet<(Vec<u8>, Nonce)> {
        &self.spent_nonces
    }
    pub fn journal_depth(&self) -> usize {
        self.journals.len()
    }
    pub fn journal_active(&self) -> bool {
        !self.journals.is_empty()
    }
    pub fn begin_journal(&mut self) {
        self.journals.push(Journal {
            accounts: BTreeMap::new(),
            dirty_addresses: self.dirty_addresses.clone(),
            dirty: self.dirty,
            total_supply: self.total_supply.clone(),
            active_accounts: self.active_accounts,
            spent_nonces: self.spent_nonces.clone(),
        });
    }
    pub fn commit_journal(&mut self) -> Result<(), Error> {
        self.journals
            .pop()
            .map(|_| ())
            .ok_or_else(|| Error("ledger journal is not active".into()))
    }
    pub fn abort_journal(&mut self) {
        if let Some(journal) = self.journals.pop() {
            for (address, previous) in journal.accounts {
                if let Some(account) = previous {
                    self.accounts.insert(address, account);
                } else {
                    self.accounts.remove(&address);
                }
            }
            self.total_supply = journal.total_supply;
            self.active_accounts = journal.active_accounts;
            self.dirty_addresses = journal.dirty_addresses;
            self.dirty = journal.dirty;
            self.spent_nonces = journal.spent_nonces;
        }
    }
    pub fn clear_spent_nonces(&mut self) {
        self.spent_nonces.clear();
    }
    /// Only the persistence host may call this after all dirty accounts have
    /// durably flushed. It does not claim a canonical epoch commit.
    pub fn acknowledge_account_flush(&mut self) {
        self.dirty = false;
        self.dirty_addresses.clear();
    }
    pub fn freeze(&self) -> Result<Snapshot, Error> {
        if self.dirty || !self.dirty_addresses.is_empty() {
            return Err(Error("ledger clone requires flushed accounts".into()));
        }
        if self.journal_active() {
            return Err(Error("ledger clone requires no active journal".into()));
        }
        Ok(Snapshot {
            accounts: self.accounts.clone(),
            supply: self.total_supply.clone(),
            active: self.active_accounts,
        })
    }
    pub fn thaw(snapshot: Snapshot) -> Self {
        Self {
            accounts: snapshot.accounts,
            total_supply: snapshot.supply,
            active_accounts: snapshot.active,
            dirty_addresses: BTreeSet::new(),
            dirty: false,
            spent_nonces: BTreeSet::new(),
            journals: Vec::new(),
        }
    }
    fn set_account(&mut self, address: &[u8], account: Account) {
        let previous = self.accounts.get(address);
        for journal in &mut self.journals {
            journal
                .accounts
                .entry(address.to_vec())
                .or_insert_with(|| previous.cloned());
        }
        let was_active = previous.is_some_and(|a| a.balance.is_positive());
        let active = account.balance.is_positive();
        if was_active && !active {
            self.active_accounts = self.active_accounts.saturating_sub(1);
        }
        if !was_active && active {
            self.active_accounts += 1;
        }
        self.accounts.insert(address.to_vec(), account);
        self.dirty_addresses.insert(address.to_vec());
        self.dirty = true;
    }
    fn check_supply(&self, delta: &BigInt) -> Result<(), Error> {
        if &self.total_supply + delta > BigInt::from(MAX_SUPPLY) {
            Err(Error(CAP_ERROR.into()))
        } else {
            Ok(())
        }
    }
    /// Native low-level initializer: replaces an existing account and adds the
    /// supplied amount to total supply. Callers must enforce genesis uniqueness.
    pub fn add_account(
        &mut self,
        address: &[u8],
        amount: BigInt,
        public_key: Option<Vec<u8>>,
    ) -> Result<(), Error> {
        self.check_supply(&amount)?;
        self.set_account(
            address,
            Account {
                balance: amount.clone(),
                public_key,
                ..Account::default()
            },
        );
        self.total_supply += amount;
        Ok(())
    }
    pub fn credit(
        &mut self,
        address: &[u8],
        amount: &BigInt,
        encrypted_balance: Option<Vec<u8>>,
    ) -> Result<(), Error> {
        if amount.is_negative() {
            return Err(Error("negative credit amount".into()));
        }
        self.check_supply(amount)?;
        let mut account = self.accounts.get(address).cloned().unwrap_or_default();
        account.balance += amount;
        if encrypted_balance.is_some() {
            account.encrypted_balance = encrypted_balance;
        }
        self.set_account(address, account);
        self.total_supply += amount;
        Ok(())
    }
    fn debit_sender(
        &self,
        address: &[u8],
        amount: &BigInt,
        nonce: Nonce,
    ) -> Result<Account, &'static str> {
        if amount.is_negative() {
            return Err("negative debit amount");
        }
        let account = self.accounts.get(address).ok_or("Sender not found")?;
        if account.balance < *amount {
            return Err("Insufficient balance");
        }
        if nonce != account.nonce.successor() {
            return Err("Invalid nonce");
        }
        if self.spent_nonces.contains(&(address.to_vec(), nonce)) {
            return Err("Nonce already spent");
        }
        Ok(account.clone())
    }
    pub fn debit(
        &mut self,
        address: &[u8],
        amount: &BigInt,
        nonce: Nonce,
        encrypted_balance: Option<Vec<u8>>,
    ) -> Result<(), Error> {
        let mut account = self
            .debit_sender(address, amount, nonce)
            .map_err(|e| Error(e.into()))?;
        account.balance -= amount;
        account.nonce = nonce;
        if encrypted_balance.is_some() {
            account.encrypted_balance = encrypted_balance;
        }
        self.set_account(address, account);
        self.total_supply -= amount;
        self.spent_nonces.insert((address.to_vec(), nonce));
        Ok(())
    }
    pub fn transfer(
        &mut self,
        from: &[u8],
        to: &[u8],
        amount: &BigInt,
        fee: &BigInt,
        nonce: Nonce,
    ) -> Result<(), TransferError> {
        let total = amount + fee;
        let mut sender = self
            .debit_sender(from, &total, nonce)
            .map_err(TransferError::DebitRejected)?;
        if amount.is_negative() {
            return Err(TransferError::CreditRejected("negative credit amount"));
        }
        if fee.is_negative() {
            return Err(TransferError::CreditRejected("negative fee amount"));
        }
        sender.balance -= total;
        sender.nonce = nonce;
        if from == to {
            sender.balance += amount;
            self.set_account(from, sender);
        } else {
            let mut receiver = self.accounts.get(to).cloned().unwrap_or_default();
            receiver.balance += amount;
            self.set_account(from, sender);
            self.set_account(to, receiver);
        }
        self.total_supply -= fee;
        self.spent_nonces.insert((from.to_vec(), nonce));
        Ok(())
    }
    pub fn debit_amount_only(&mut self, address: &[u8], amount: &BigInt) -> Result<(), Error> {
        if amount.is_negative() {
            return Err(Error("negative debit_amount_only".into()));
        }
        let mut account = self
            .accounts
            .get(address)
            .cloned()
            .ok_or_else(|| Error("Account not found".into()))?;
        if account.balance < *amount {
            return Err(Error("Insufficient balance".into()));
        }
        account.balance -= amount;
        self.set_account(address, account);
        self.total_supply -= amount;
        Ok(())
    }
    pub fn register_public_key(&mut self, address: &[u8], key: Vec<u8>) {
        if let Some(mut account) = self.accounts.get(address).cloned() {
            account.public_key = Some(key);
            self.set_account(address, account);
        }
    }
    pub fn update_decrypt_allowance(&mut self, address: &[u8], allowance: BigInt) {
        if let Some(mut account) = self.accounts.get(address).cloned() {
            account.decrypt_allowance = allowance;
            self.set_account(address, account);
        }
    }
    pub fn update_encrypted_balance(&mut self, address: &[u8], cipher: Vec<u8>) {
        if let Some(mut account) = self.accounts.get(address).cloned() {
            account.encrypted_balance = Some(cipher);
            self.set_account(address, account);
        }
    }
}
