// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Program_journal overlays and snapshot costs, without canonical publication.
use super::{
    store::{self, Meta},
    Error, Result,
};
use crate::state_batch::StateBatch;
use num_bigint::BigInt;
use octra_node_protocol::circle_storage::StorageTable;
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub struct Deploy {
    pub meta: Meta,
    pub bytecode: Vec<u8>,
    pub storage: StorageTable,
}
#[derive(Clone, Debug)]
pub struct Upgrade {
    pub meta: Meta,
    pub expected_code_hash: Vec<u8>,
    pub bytecode: Vec<u8>,
}
#[derive(Clone, Debug, Default)]
pub struct Journal {
    deploys: Vec<Deploy>,
    upgrades: Vec<Upgrade>,
    storage: BTreeMap<Vec<u8>, StorageTable>,
    circles: BTreeMap<Vec<u8>, StorageTable>,
}
#[derive(Clone, Debug)]
pub struct Snapshot(Journal);
impl Journal {
    pub fn snapshot_effort(&self) -> BigInt {
        let tables = |values: &BTreeMap<Vec<u8>, StorageTable>| -> BigInt {
            values
                .values()
                .map(|table| BigInt::from(table.values().len()) + 1)
                .sum()
        };
        let deploys: BigInt = self
            .deploys
            .iter()
            .map(|deploy| BigInt::from(deploy.storage.values().len()) + 1)
            .sum();
        (deploys + tables(&self.storage) + tables(&self.circles)) * 32
    }
    pub fn snapshot(&self) -> Snapshot {
        Snapshot(self.clone())
    }
    pub fn restore(&mut self, snapshot: Snapshot) {
        *self = snapshot.0;
    }
    pub fn discard(&mut self) {
        *self = Self::default();
    }
    pub fn add_deploy(&mut self, deploy: Deploy) {
        self.storage
            .insert(deploy.meta.address.clone(), deploy.storage.clone());
        self.deploys.push(deploy);
    }
    pub fn find_deploy(&self, address: &[u8]) -> Option<&Deploy> {
        self.deploys
            .iter()
            .rev()
            .find(|entry| entry.meta.address == address)
    }
    pub fn add_upgrade(&mut self, upgrade: Upgrade) {
        self.upgrades.push(upgrade);
    }
    pub fn find_upgrade(&self, address: &[u8]) -> Option<&Upgrade> {
        self.upgrades
            .iter()
            .rev()
            .find(|entry| entry.meta.address == address)
    }
    pub fn storage(&self, address: &[u8]) -> Option<&StorageTable> {
        self.storage.get(address)
    }
    pub fn checkout(
        &mut self,
        address: &[u8],
        fallback: impl FnOnce() -> StorageTable,
    ) -> &mut StorageTable {
        self.storage
            .entry(address.to_vec())
            .or_insert_with(fallback)
    }
    pub fn set_storage(&mut self, address: &[u8], storage: StorageTable) {
        self.storage.insert(address.to_vec(), storage);
    }
    pub fn circle(&self, address: &[u8]) -> Option<&StorageTable> {
        self.circles.get(address)
    }
    pub fn circle_storage(
        &mut self,
        address: &[u8],
        fallback: impl FnOnce() -> StorageTable,
    ) -> &mut StorageTable {
        self.circles
            .entry(address.to_vec())
            .or_insert_with(fallback)
    }
    pub fn set_circle(&mut self, address: &[u8], storage: StorageTable) {
        self.circles.insert(address.to_vec(), storage);
    }
    pub fn circles(&self) -> &BTreeMap<Vec<u8>, StorageTable> {
        &self.circles
    }
    pub fn deploys(&self) -> &[Deploy] {
        &self.deploys
    }
    pub fn upgrades(&self) -> &[Upgrade] {
        &self.upgrades
    }
    pub fn storage_entries(&self) -> &BTreeMap<Vec<u8>, StorageTable> {
        &self.storage
    }
    /// The outer transaction owns rollback, including partial staging failure.
    pub fn stage(&self, state: &mut StateBatch) -> Result<()> {
        for deploy in &self.deploys {
            store::deploy(state, &deploy.meta, &deploy.bytecode)?;
            store::save_abi(state, &deploy.meta)?;
        }
        for upgrade in &self.upgrades {
            store::upgrade(
                state,
                &upgrade.meta,
                &upgrade.expected_code_hash,
                &upgrade.bytecode,
            )
            .map_err(Error::unavailable)?;
            store::save_abi(state, &upgrade.meta)?;
        }
        for (address, values) in &self.storage {
            store::save_storage(state, address, values)?;
        }
        Ok(())
    }
}
pub use crate::circle_store::{storage_effort, write_effort};
