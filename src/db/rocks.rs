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

use std::path::Path;

use crate::{
    base::{
        schema::{Account, Block, Receipt, Transaction},
        serialize::{rmp_deserialize, rmp_serialize},
    },
    crypto::{Hash, HashAlgorithm},
    db::{Db, DbFork},
    Error, ErrorKind,
};
use merkledb::{
    access::CopyAccessExt,
    BinaryKey, BinaryValue, Database, DbOptions, Fork, ListIndex, MapIndex, ObjectHash,
    ProofListIndex, ProofMapIndex, RocksDB, Snapshot,
    _reexports::{Error as MisteryError, Hash as MerkleDbHash},
};
use std::borrow::Cow;

impl From<MerkleDbHash> for Hash {
    fn from(hash: MerkleDbHash) -> Self {
        // This is safe as far as MerkleDbHash is using SHA256.
        Hash::new(HashAlgorithm::Sha256, hash.as_ref()).unwrap()
    }
}

impl BinaryKey for Hash {
    fn size(&self) -> usize {
        Hash::size(self)
    }

    fn write(&self, buffer: &mut [u8]) -> usize {
        buffer.clone_from_slice(self.as_bytes());
        self.size()
    }

    fn read(buffer: &[u8]) -> Self::Owned {
        Hash::from_bytes(buffer).unwrap()
    }
}

impl BinaryValue for Hash {
    fn to_bytes(&self) -> Vec<u8> {
        Hash::to_bytes(self)
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> std::result::Result<Self, MisteryError> {
        let err: MisteryError = Error::new(ErrorKind::MalformedData).into();
        Hash::from_bytes(bytes.as_ref()).map_err(|_| err)
    }
}

impl BinaryValue for Transaction {
    fn to_bytes(&self) -> Vec<u8> {
        rmp_serialize(self).unwrap()
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> std::result::Result<Self, MisteryError> {
        rmp_deserialize(bytes.as_ref()).map_err(|err| err.into())
    }
}

impl BinaryValue for Receipt {
    fn to_bytes(&self) -> Vec<u8> {
        rmp_serialize(self).unwrap()
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> std::result::Result<Self, MisteryError> {
        rmp_deserialize(bytes.as_ref()).map_err(|err| err.into())
    }
}

impl BinaryValue for Account {
    fn to_bytes(&self) -> Vec<u8> {
        rmp_serialize(self).unwrap()
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> std::result::Result<Self, MisteryError> {
        rmp_deserialize(bytes.as_ref()).map_err(|err| err.into())
    }
}

impl BinaryValue for Block {
    fn to_bytes(&self) -> Vec<u8> {
        rmp_serialize(self).unwrap()
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> std::result::Result<Self, MisteryError> {
        rmp_deserialize(bytes.as_ref()).map_err(|err| err.into())
    }
}

const ACCOUNTS: &str = "accounts";
const TRANSACTIONS: &str = "transactions";
const RECEIPTS: &str = "receipts";
const TRANSACTIONS_HASH: &str = "transactions_hash";
const RECEIPTS_HASH: &str = "receipts_hash";
const BLOCKS: &str = "blocks";

/// Database implementation using rocks db.
pub struct RocksDb {
    /// Backend implementing the `Database` trait (defined by merkledb crate).
    backend: RocksDB,
    /// Last state read-only snapshot.
    snap: Box<dyn Snapshot>,
}

/// Database writeable snapshot.
/// This structure is obtained via the `fork` method and allows to atomically
/// apply a set of changes to the database.
/// In the end, the changes shall be merged into the database using the database
/// `merge` method.
pub struct RocksDbFork(Fork);

impl RocksDb {
    /// Create/Open a database from the filesystem.
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        let options = DbOptions::default();
        let backend = RocksDB::open(path, &options).unwrap_or_else(|err| {
            panic!("Error opening rocks-db backend: {}", err);
        });
        let snap = backend.snapshot();
        RocksDb { backend, snap }
    }
}

impl Db for RocksDb {
    /// Fork type.
    type DbForkType = RocksDbFork;

    /// Fetch account.
    fn load_account(&self, id: &str) -> Option<Account> {
        let map: ProofMapIndex<_, str, Account> = self.snap.get_proof_map(ACCOUNTS);
        map.get(id)
    }

    /// Load full keys list associated to the account data.
    fn load_account_keys(&self, id: &str) -> Vec<String> {
        let map: ProofMapIndex<_, str, Vec<u8>> = self.snap.get_proof_map((ACCOUNTS, id));
        map.keys().collect()
    }

    /// Load data associated to the given account `id`.
    fn load_account_data(&self, id: &str, key: &str) -> Option<Vec<u8>> {
        let map: ProofMapIndex<_, str, Vec<u8>> = self.snap.get_proof_map((ACCOUNTS, id));
        map.get(key)
    }

    /// Check if transaction is present.
    fn contains_transaction(&self, hash: &Hash) -> bool {
        let map: MapIndex<_, Hash, Vec<u8>> = self.snap.get_map(TRANSACTIONS);
        map.contains(hash)
    }

    /// Fetch transaction.
    fn load_transaction(&self, hash: &Hash) -> Option<Transaction> {
        let map: MapIndex<_, Hash, Transaction> = self.snap.get_map(TRANSACTIONS);
        map.get(hash)
    }

    /// Load transaction receipt using transaction hash.
    fn load_receipt(&self, hash: &Hash) -> Option<Receipt> {
        let map: MapIndex<_, Hash, Receipt> = self.snap.get_map(RECEIPTS);
        map.get(hash)
    }

    /// Get block at a given `height` (position in the blockchain).
    /// This can also be used to fetch the last block by passing u64::max_value as the height.
    fn load_block(&self, height: u64) -> Option<Block> {
        let list: ListIndex<_, Block> = self.snap.get_list(BLOCKS);
        match height {
            u64::MAX => list.last(),
            _ => list.get(height),
        }
    }

    /// Get transactions hashes associated to a given block identified by `height`.
    /// The `height` refers to the block position within the blockchain.
    fn load_transactions_hashes(&self, height: u64) -> Option<Vec<Hash>> {
        let map: ProofListIndex<_, Hash> = self.snap.get_proof_list((TRANSACTIONS_HASH, &height));
        if map.is_empty() {
            None
        } else {
            Some(map.into_iter().collect())
        }
    }

    /// Create a fork.
    /// A fork is a set of uncommited modifications to the database.
    fn fork_create(&mut self) -> RocksDbFork {
        RocksDbFork(self.backend.fork())
    }

    /// Commit a fork.
    /// Apply the modifications to the database.
    /// If two conflicting forks are merged into a database, this can lead to an
    /// inconsistent state. If you need to consistently apply several sets of changes
    /// to the same data, the next fork should be created after the previous fork has
    /// been merged.
    fn fork_merge(&mut self, fork: RocksDbFork) -> crate::Result<()> {
        let patch = fork.0.into_patch();
        self.backend
            .merge(patch)
            .map_err(|err| Error::new_ext(ErrorKind::DatabaseFault, err))?;
        self.snap = self.backend.snapshot();
        Ok(())
    }
}

impl DbFork for RocksDbFork {
    /// Get state hash.
    fn state_hash(&self, id: &str) -> Hash {
        match id.is_empty() {
            false => {
                let map: ProofMapIndex<_, str, Vec<u8>> = self.0.get_proof_map((ACCOUNTS, id));
                map.object_hash()
            }
            true => {
                let map: ProofMapIndex<_, str, Vec<u8>> = self.0.get_proof_map(ACCOUNTS);
                map.object_hash()
            }
        }
        .into()
    }

    /// Fetch account.
    fn load_account(&self, id: &str) -> Option<Account> {
        let map: ProofMapIndex<_, str, Account> = self.0.get_proof_map(ACCOUNTS);
        map.get(id)
    }

    /// Insert/Update account.
    fn store_account(&mut self, account: Account) {
        let mut map: ProofMapIndex<_, str, Account> = self.0.get_proof_map(ACCOUNTS);
        let id = account.id.clone();
        map.put(&id, account);
    }

    /// Load data associated to the given account `id`.
    fn load_account_data(&self, id: &str, key: &str) -> Option<Vec<u8>> {
        let map: ProofMapIndex<_, str, Vec<u8>> = self.0.get_proof_map((ACCOUNTS, id));
        map.get(key)
    }

    /// Store data associated to the given account `id`.
    fn store_account_data(&mut self, id: &str, key: &str, data: Vec<u8>) {
        let mut map: ProofMapIndex<_, str, Vec<u8>> = self.0.get_proof_map((ACCOUNTS, id));
        map.put(key, data);
    }

    /// Remove data associated to the given account `id`.
    fn remove_account_data(&mut self, id: &str, key: &str) {
        let mut map: ProofMapIndex<_, str, Vec<u8>> = self.0.get_proof_map((ACCOUNTS, id));
        map.remove(key)
    }

    /// Insert transaction.
    fn store_transaction(&mut self, hash: &Hash, transaction: Transaction) {
        let mut map: MapIndex<_, Hash, Transaction> = self.0.get_map(TRANSACTIONS);
        map.put(hash, transaction);
    }

    /// Insert transaction result.
    fn store_receipt(&mut self, hash: &Hash, receipt: Receipt) {
        let mut map: MapIndex<_, Hash, Receipt> = self.0.get_map(RECEIPTS);
        map.put(hash, receipt);
    }

    /// Insert new block.
    fn store_block(&mut self, block: Block) {
        let mut list: ListIndex<_, Block> = self.0.get_list(BLOCKS);
        list.push(block)
    }

    /// Insert transactions hashes associated to a given block identified by `height`.
    /// The `height` refers to the block position within the blockchain.
    /// Returns the transactions trie root.
    fn store_transactions_hashes(&mut self, height: u64, hashes: Vec<Hash>) -> Hash {
        let mut map: ProofListIndex<_, Hash> = self.0.get_proof_list((TRANSACTIONS_HASH, &height));
        hashes.into_iter().for_each(|hash| map.push(hash));
        map.object_hash().into()
    }

    /// Insert the transactions results (receipts) associated with a given block.
    /// The `height` refers to the associated block height within the blockchain.
    /// Returns the receipts trie root.
    fn store_receipts_hashes(&mut self, height: u64, hashes: Vec<Hash>) -> Hash {
        let mut map: ProofListIndex<_, Hash> = self.0.get_proof_list((RECEIPTS_HASH, &height));
        hashes.into_iter().for_each(|hash| map.push(hash));
        map.object_hash().into()
    }

    /// Creates a fork checkpoint.
    fn flush(&mut self) {
        self.0.flush();
    }

    /// Rollback to the last checkpoint (`flush` point).
    fn rollback(&mut self) {
        self.0.rollback();
    }

    fn load_account_keys(&self, id: &str) -> Vec<String> {
        let map: ProofMapIndex<_, str, Vec<u8>> = self.0.get_proof_map((ACCOUNTS, id));
        map.keys().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        base::schema::tests::{create_test_account, create_test_block, create_test_unit_tx},
        base::schema::Account,
        crypto::Hashable,
    };
    use std::{
        fs,
        ops::{Deref, DerefMut},
        path::PathBuf,
    };
    use tempfile::TempDir;

    const ACCOUNT_ID1: &str = "QmNLei78zWmzUdbeRB3CiUfAizWUrbeeZh5K1rhAQKCh51";
    const ACCOUNT_ID2: &str = "QmYHnEQLdf5h7KYbjFPuHSRk2SPgdXrJWFh5W696HPfq7i";

    struct TempDb {
        inner: RocksDb,
        path: PathBuf,
    }

    impl TempDb {
        fn new() -> Self {
            let path = TempDir::new().unwrap().into_path();
            let inner = RocksDb::new(path.clone());
            TempDb { inner, path }
        }
    }

    impl Deref for TempDb {
        type Target = RocksDb;

        fn deref(&self) -> &Self::Target {
            &self.inner
        }
    }

    impl DerefMut for TempDb {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.inner
        }
    }

    impl Drop for TempDb {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.path).unwrap_or_else(|err| {
                println!(
                    "failed to remove temporary db folder '{:?}' ({})",
                    self.path, err
                );
            });
        }
    }

    #[test]
    fn store_account_no_merge() {
        let mut db = TempDb::new();
        let mut fork = db.fork_create();
        let account = create_test_account();
        let id = account.id.clone();

        fork.store_account(account);

        assert_eq!(db.load_account(&id), None);
    }

    #[test]
    fn store_account_merge() {
        let mut db = TempDb::new();
        let mut fork = db.fork_create();
        let account = create_test_account();
        let id = account.id.clone();
        fork.store_account(account.clone());

        let result = db.fork_merge(fork);

        assert!(result.is_ok());
        assert_eq!(db.load_account(&id), Some(account));
    }

    #[test]
    fn store_account_data_no_merge() {
        let mut db = TempDb::new();
        let mut fork = db.fork_create();
        let data = vec![1, 2, 3];

        fork.store_account_data(ACCOUNT_ID1, "data", data);

        assert_eq!(
            fork.load_account_data(ACCOUNT_ID1, "data"),
            Some(vec![1, 2, 3])
        );
        assert_eq!(db.load_account_data(ACCOUNT_ID1, "data"), None);
    }

    #[test]
    fn store_account_data_merge() {
        let mut db = TempDb::new();
        let mut fork = db.fork_create();
        let data = vec![1, 2, 3];
        fork.store_account_data(ACCOUNT_ID1, "data", data);

        let result = db.fork_merge(fork);

        assert!(result.is_ok());
        assert_eq!(
            db.load_account_data(ACCOUNT_ID1, "data"),
            Some(vec![1, 2, 3])
        );
        assert_eq!(db.load_account_data(ACCOUNT_ID2, "data"), None);
    }

    #[test]
    fn delete_account_data_merge() {
        let mut db = TempDb::new();
        let mut fork = db.fork_create();
        fork.store_account_data(ACCOUNT_ID1, "data1", vec![1, 2, 3]);
        fork.store_account_data(ACCOUNT_ID1, "data2", vec![4, 5, 6]);
        db.fork_merge(fork).unwrap();
        let mut fork = db.fork_create();
        fork.remove_account_data(ACCOUNT_ID1, "data1");

        db.fork_merge(fork).unwrap();

        assert_eq!(db.load_account_data(ACCOUNT_ID1, "data1"), None);
        assert_eq!(
            db.load_account_data(ACCOUNT_ID1, "data2"),
            Some(vec![4, 5, 6])
        );
    }

    #[test]
    fn get_account_keys() {
        let mut db = TempDb::new();
        let mut fork = db.fork_create();

        fork.store_account_data(ACCOUNT_ID1, "data1", vec![1, 2, 3]);
        fork.store_account_data(ACCOUNT_ID1, "data2", vec![1, 2, 3]);
        fork.store_account_data(ACCOUNT_ID1, "data3", vec![1, 2, 3]);

        let res = fork.load_account_keys(ACCOUNT_ID1);

        assert_eq!(
            res,
            vec![
                "data1".to_string(),
                "data2".to_string(),
                "data3".to_string()
            ]
        );
    }

    #[test]
    fn store_transaction_no_merge() {
        let mut db = TempDb::new();
        let mut fork = db.fork_create();
        let tx = create_test_unit_tx();
        let hash = tx.primary_hash();

        fork.store_transaction(&hash, tx);

        assert_eq!(db.load_transaction(&hash), None);
    }

    #[test]
    fn store_transaction_merge() {
        let mut db = TempDb::new();
        let mut fork = db.fork_create();
        let tx = create_test_unit_tx();
        let hash = tx.primary_hash();
        fork.store_transaction(&hash, tx.clone());

        let result = db.fork_merge(fork);

        assert!(result.is_ok());
        assert_eq!(db.load_transaction(&hash), Some(tx));
    }

    #[test]
    fn store_block_no_merge() {
        let mut db = TempDb::new();
        let mut fork = db.fork_create();
        let block = create_test_block();

        fork.store_block(block);

        assert_eq!(db.load_block(0), None);
    }

    #[test]
    fn store_block_merge() {
        let mut db = TempDb::new();
        let mut fork = db.fork_create();
        let block = create_test_block();

        fork.store_block(block.clone());

        let result = db.fork_merge(fork);

        assert!(result.is_ok());
        assert_eq!(db.load_block(0), Some(block));
    }

    #[test]
    fn store_transactions_hashes() {
        let mut db = TempDb::new();
        let mut fork = db.fork_create();
        let txs_hash = vec![
            "1220b706053eb366e5a649ec7117dd896c63707d52b9a02f38bb01f13ab17a798f61",
            "12200194fa02f34ddedb3f6d9bd09d774a865f26ec498e361e082240ac9ed1b82005",
            "1220b09d7f52bba3792ce81d011aa213c96de4ce4203312aa8fe1c3be933b3725df5",
            "1220816e1626269c0f8f7c1861101516f83cc6528cd59560f64cf13127f1fd0017b0",
        ];
        let txs_hash: Vec<Hash> = txs_hash
            .into_iter()
            .map(|h| Hash::from_hex(h).unwrap())
            .collect();

        let root_hash = fork.store_transactions_hashes(0, txs_hash);

        assert_eq!(
            "1220d76a63134cc183deca8e35eb005e249ea3308b6d339419b2d777e09c7637e548",
            hex::encode(&root_hash.to_bytes())
        );

        // Experiments to fetch PROOF
        // db.fork_merge(fork).unwrap();
        // let i = 0u64;
        // let map: ProofListIndex<_, Hash> = db.snap.get_proof_list((BLOCK_TRANSACTIONS, &i));
        // let _len = map.len();
        // let proof = map.get_proof(0);
        // debug!("{}", root_hash);
        // debug!("{:#?}", proof);
        // let entries = proof.entries_unchecked();
        // debug!("{:#?}", entries);
        // let asd = proof.indexes_unchecked();
        // let indexes: Vec<_> = asd.collect();
        // debug!("{:?}", indexes);
    }

    #[test]
    fn merge_conflict() {
        let mut db = TempDb::new();
        let mut fork1 = db.fork_create();
        let mut fork2 = db.fork_create();

        let mut account = Account::new("123", None);
        account.store_asset("abc", &[1]);
        fork1.store_account(account);

        let mut account = Account::new("123", None);
        account.store_asset("abc", &[3]);
        fork2.store_account(account);

        // Merge conflicting forks
        db.fork_merge(fork1).unwrap();
        db.fork_merge(fork2).unwrap();

        let account = db.load_account("123").unwrap();
        let asset = account.load_asset("abc");
        assert_eq!(asset, &[3]);
    }

    #[test]
    fn fork_rollback() {
        let mut db = TempDb::new();
        let mut fork = db.fork_create();

        // Modifications to hold.
        let a1 = Account::new("123", None);
        fork.store_account(a1.clone());
        let mut t1 = create_test_unit_tx();

        match t1 {
            Transaction::UnitTransaction(tx) => tx.data.set_nonce(vec![1]),
            Transaction::BullkTransaction(tx) => tx.data.set_nonce(vec![1]),
        }

        fork.store_transaction(&t1.primary_hash(), t1.clone());

        // Checkpoint.
        fork.flush();

        // Modifications to discard.
        let h2 =
            Hash::from_hex("12200194fa02f34ddedb3f6d9bd09d774a865f26ec498e361e082240ac9ed1b82005")
                .unwrap();
        let a2 = Account::new("456", Some(h2));
        fork.store_account(a2.clone());
        let mut t2 = create_test_unit_tx();

        match t2 {
            Transaction::UnitTransaction(tx) => tx.data.set_nonce(vec![2]),
            Transaction::BullkTransaction(tx) => tx.data.set_nonce(vec![2]),
        }

        fork.store_transaction(&t2.primary_hash(), t2.clone());

        // Rollback
        fork.rollback();

        // Add some other modifications to hold
        let a3 = Account::new("789", None);
        fork.store_account(a3.clone());
        let mut t3 = create_test_unit_tx();

        match t3 {
            Transaction::UnitTransaction(tx) => tx.data.set_nonce(vec![3]),
            Transaction::BullkTransaction(tx) => tx.data.set_nonce(vec![3]),
        }

        fork.store_transaction(&t3.primary_hash(), t3.clone());

        // Merge
        db.fork_merge(fork).unwrap();

        // Check that modifications between checkpoint and rollback are lost.
        assert_eq!(db.load_account(&a1.id), Some(a1));
        assert_eq!(db.load_account(&a2.id), None);
        assert_eq!(db.load_account(&a3.id), Some(a3));
        assert_eq!(db.load_transaction(&t1.primary_hash()), Some(t1));
        assert_eq!(db.load_transaction(&t2.primary_hash()), None);
        assert_eq!(db.load_transaction(&t3.primary_hash()), Some(t3));
    }
}
