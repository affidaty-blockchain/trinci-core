// This file is part of TRINCI.
//
// Copyright (C) 2021 Affidaty Spa.
//
// TRINCI is free software: you can redistribute it and/or modify it under
// the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// TRINCI is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License
// for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with TRINCI. If not, see <https://www.gnu.org/licenses/>.

use crate::{base::schema::Block, crypto::Hash, error::*, Account, Receipt, Transaction};
#[cfg(test)]
use mockall::automock;

#[cfg(feature = "with-rocksdb")]
pub mod rocks;
#[cfg(feature = "with-rocksdb")]
pub use rocks::{RocksDb, RocksDbFork};

/// Trait providing access to the database.
#[cfg_attr(test, automock(type DbForkType = MockDbFork;))]
pub trait Db: Send + Sync + 'static {
    /// Type representing a database fork.
    type DbForkType: DbFork;

    /// Load account by id.
    fn load_account(&self, id: &str) -> Option<Account>;

    /// Load full keys list associated to the account data.
    fn load_account_keys(&self, id: &str) -> Vec<String>;

    /// Load data associated to the given account `id`.
    fn load_account_data(&self, id: &str, key: &str) -> Option<Vec<u8>>;

    /// Check if transaction is present.
    fn contains_transaction(&self, key: &Hash) -> bool;

    /// Load transaction by hash.
    fn load_transaction(&self, hash: &Hash) -> Option<Transaction>;

    /// Load transaction receipt using transaction data hash.
    fn load_receipt(&self, hash: &Hash) -> Option<Receipt>;

    /// Load block at a given `height` (position in the blockchain).
    /// This can be used to fetch the last block by passing u64::MAX as the height.
    fn load_block(&self, height: u64) -> Option<Block>;

    /// Get transactions hashes associated to a given block identified by `height`.
    /// The `height` refers to the block position within the blockchain.
    fn load_transactions_hashes(&self, height: u64) -> Option<Vec<Hash>>;

    /// Create database fork.
    /// A fork is a set of uncommited modifications to the database.
    fn fork_create(&mut self) -> Self::DbForkType;

    /// Commit modifications contained in a database fork.
    fn fork_merge(&mut self, fork: Self::DbForkType) -> Result<()>;

    /// Read configuration from the DB
    fn load_configuration(&self, id: &str) -> Option<Vec<u8>>;
}

/// Database fork trait.
/// Used to atomically apply a sequence of transactions to the database.
/// Instances of this trait cannot be safelly shared between threads.
#[cfg_attr(test, automock)]
pub trait DbFork: 'static {
    /// Get accounts state hash.
    /// For global accounts hash use an empty string.
    fn state_hash(&self, id: &str) -> Hash;

    /// Load account by id.
    fn load_account(&self, id: &str) -> Option<Account>;

    /// Store account using account id as the key.
    fn store_account(&mut self, account: Account);

    /// Load data associated to the given account `id`.
    fn load_account_data(&self, id: &str, key: &str) -> Option<Vec<u8>>;

    /// Store data associated to the given account `id`.
    fn store_account_data(&mut self, id: &str, key: &str, data: Vec<u8>);

    /// Remove data associated to the given account `id`.
    fn remove_account_data(&mut self, id: &str, key: &str);

    /// Load full keys list associated to the account data.
    fn load_account_keys(&self, id: &str) -> Vec<String>;

    /// Store transaction using transaction hash as the key.
    fn store_transaction(&mut self, hash: &Hash, tx: Transaction);

    /// Store transaction execution receipt using transaction hash as the key.
    fn store_receipt(&mut self, hash: &Hash, receipt: Receipt);

    /// Insert block in the blockchain tail.
    fn store_block(&mut self, block: Block);

    /// Insert transactions hashes associated to a given block identified by `height`.
    /// The `height` refers to the block position within the blockchain.
    /// Returns the corresponding Merkle tree root hash.
    fn store_transactions_hashes(&mut self, height: u64, hashes: Vec<Hash>) -> Hash;

    /// Insert transactions receipts associated to a given block identified by `height`.
    /// The `height` refers to the block position within the blockchain.
    /// Returns the relative Merkle tree root hash.
    fn store_receipts_hashes(&mut self, height: u64, hashes: Vec<Hash>) -> Hash;

    /// Creates a fork checkpoint.
    fn flush(&mut self);

    /// Rollback to the last checkpoint (`flush` point).
    fn rollback(&mut self);

    /// Store configuration on the DB
    fn store_configuration(&mut self, id: &str, config: Vec<u8>);
}
