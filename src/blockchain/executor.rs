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

//! Blockchain component in charge of confirmed blocks transactions execution.
//!
//! Transactions are pulled from the confirmed pool blocks and executed in the
//! exact same order as declared in the block.
//!
//! When the confirmed block contains a block-header hash the executor checks
//! that the hash resulting from the local execution is equal to the expected
//! one before commiting the execution changes.

use super::{
    message::Message,
    pool::{BlockInfo, Pool},
    pubsub::{Event, PubSub},
};
use crate::{
    base::{
        schema::{Block, BlockData, SmartContractEvent},
        serialize::rmp_serialize,
        Mutex, RwLock,
    },
    crypto::{Hash, Hashable},
    db::{Db, DbFork},
    wm::Wm,
    Error, ErrorKind, KeyPair, Receipt, Result, Transaction,
};
use std::{collections::HashMap, sync::Arc};

/// result struct for bulk trasnsaction
#[derive(Serialize, Deserialize)]
pub struct BulkResult {
    success: Option<bool>,
    result: Option<Result<Vec<u8>>>,
}

/// Executor context data.
pub(crate) struct Executor<D: Db, W: Wm> {
    /// Unconfirmed transactions pool
    pub pool: Arc<RwLock<Pool>>,
    /// Instance of a type implementing Database trait.
    db: Arc<RwLock<D>>,
    /// Instance of a type implementing Wasm Machine trait.
    wm: Arc<Mutex<W>>,
    /// PubSub subsystem to publish blockchain events.
    pubsub: Arc<Mutex<PubSub>>,
    /// Node keypair
    keypair: Arc<KeyPair>,
}

impl<D: Db, W: Wm> Clone for Executor<D, W> {
    fn clone(&self) -> Self {
        Executor {
            pool: self.pool.clone(),
            db: self.db.clone(),
            wm: self.wm.clone(),
            pubsub: self.pubsub.clone(),
            keypair: self.keypair.clone(),
        }
    }
}

impl<D: Db, W: Wm> Executor<D, W> {
    /// Constructs a new executor.
    pub fn new(
        pool: Arc<RwLock<Pool>>,
        db: Arc<RwLock<D>>,
        wm: Arc<Mutex<W>>,
        pubsub: Arc<Mutex<PubSub>>,
        keypair: Arc<KeyPair>,
    ) -> Self {
        Executor {
            pool,
            db,
            wm,
            pubsub,
            keypair,
        }
    }

    fn exec_transaction(
        &mut self,
        tx: &Transaction,
        fork: &mut <D as Db>::DbForkType,
        height: u64,
        index: u32,
    ) -> Receipt {
        fork.flush();
        let mut events: Vec<SmartContractEvent> = vec![];

        let recepit = match tx {
            Transaction::UnitTransaction(tx) => {
                let result = self.wm.lock().call(
                    fork,
                    0,
                    tx.data.get_network(),
                    &tx.data.get_caller().to_account_id(),
                    tx.data.get_account(),
                    &tx.data.get_caller().to_account_id(),
                    *tx.data.get_contract(),
                    tx.data.get_method(),
                    tx.data.get_args(),
                    &mut events,
                );

                let event_tx = tx.data.primary_hash();
                events.iter_mut().for_each(|e| e.event_tx = event_tx);

                if result.is_err() {
                    fork.rollback();
                } else if self.pubsub.lock().has_subscribers(Event::CONTRACT_EVENTS) {
                    events.iter().for_each(|event| {
                        // Notify subscribers about contract events
                        let msg = Message::GetContractEvent {
                            event: event.clone(),
                        };

                        self.pubsub.lock().publish(Event::CONTRACT_EVENTS, msg);
                    });
                }

                let events = if events.is_empty() {
                    None
                } else {
                    Some(events)
                };

                // On error, receipt data shall contain the full error description
                // only if error kind is a SmartContractFailure. This is to prevent
                // internal error conditions leaks to the user.
                let (success, returns) = match result {
                    Ok(value) => (true, value),
                    Err(err) => {
                        let msg = match err.kind {
                            ErrorKind::SmartContractFault | ErrorKind::ResourceNotFound => {
                                err.to_string_full()
                            }
                            _ => err.to_string(),
                        };
                        debug!("Execution failure: {}", msg);
                        (false, msg.as_bytes().to_vec())
                    }
                };
                Receipt {
                    height,
                    burned_fuel: 0, // TODO
                    index: index as u32,
                    success,
                    returns,
                    events,
                }
            }
            Transaction::BulkTransaction(tx) => {
                let mut results = HashMap::new();
                let mut execution_fail = false;

                let (events, results) = match &tx.data {
                    crate::base::schema::TransactionData::BulkV1(bulk_tx) => {
                        let root_tx = &bulk_tx.txs.root;
                        let hash = root_tx.data.primary_hash();
                        let mut bulk_events: Vec<SmartContractEvent> = vec![];

                        let result = self.wm.lock().call(
                            fork,
                            0,
                            root_tx.data.get_network(),
                            &root_tx.data.get_caller().to_account_id(),
                            root_tx.data.get_account(),
                            &root_tx.data.get_caller().to_account_id(),
                            *root_tx.data.get_contract(),
                            root_tx.data.get_method(),
                            root_tx.data.get_args(),
                            &mut bulk_events,
                        );

                        match result {
                            Ok(rcpt) => {
                                results.insert(
                                    hash,
                                    BulkResult {
                                        success: Some(true),
                                        result: Some(Ok(rcpt)),
                                    },
                                );

                                let event_tx = hash;
                                bulk_events.iter_mut().for_each(|e| e.event_tx = event_tx);

                                if self.pubsub.lock().has_subscribers(Event::CONTRACT_EVENTS) {
                                    bulk_events.iter().for_each(|bulk_event| {
                                        // Notify subscribers about contract events
                                        let msg = Message::GetContractEvent {
                                            event: bulk_event.clone(),
                                        };

                                        self.pubsub.lock().publish(Event::CONTRACT_EVENTS, msg);
                                    });
                                }

                                events.append(&mut bulk_events);
                            }
                            Err(error) => {
                                execution_fail = true;
                                results.insert(
                                    hash,
                                    BulkResult {
                                        success: Some(false),
                                        result: Some(Err(error)),
                                    },
                                );
                            }
                        }

                        match &bulk_tx.txs.nodes {
                            Some(nodes) => {
                                for node in nodes {
                                    let mut bulk_events: Vec<SmartContractEvent> = vec![];

                                    if execution_fail {
                                        results.insert(
                                            node.get_primary_hash(),
                                            BulkResult {
                                                success: None,
                                                result: None,
                                            },
                                        );
                                    } else {
                                        let result = self.wm.lock().call(
                                            fork,
                                            0,
                                            node.get_network(),
                                            &node.get_caller().to_account_id(),
                                            node.get_account(),
                                            &node.get_caller().to_account_id(),
                                            *node.get_contract(),
                                            node.get_method(),
                                            node.get_args(),
                                            &mut bulk_events,
                                        );
                                        println!("{:?}", result);
                                        match result {
                                            Ok(rcpt) => {
                                                results.insert(
                                                    node.get_primary_hash(),
                                                    BulkResult {
                                                        success: Some(true),
                                                        result: Some(Ok(rcpt)),
                                                    },
                                                );

                                                let event_tx = node.primary_hash();
                                                bulk_events
                                                    .iter_mut()
                                                    .for_each(|e| e.event_tx = event_tx);

                                                if self
                                                    .pubsub
                                                    .lock()
                                                    .has_subscribers(Event::CONTRACT_EVENTS)
                                                {
                                                    bulk_events.iter().for_each(|bulk_event| {
                                                        // Notify subscribers about contract events
                                                        let msg = Message::GetContractEvent {
                                                            event: bulk_event.clone(),
                                                        };

                                                        self.pubsub
                                                            .lock()
                                                            .publish(Event::CONTRACT_EVENTS, msg);
                                                    });
                                                }

                                                events.append(&mut bulk_events);
                                            }
                                            Err(error) => {
                                                println!("Execution failure: {}", error);
                                                results.insert(
                                                    node.primary_hash(),
                                                    BulkResult {
                                                        success: Some(false),
                                                        result: Some(Err(error)),
                                                    },
                                                );
                                                execution_fail = true;
                                            }
                                        }
                                    }
                                }
                            }
                            None => (),
                        }

                        if execution_fail {
                            fork.rollback();
                        }

                        let events = if events.is_empty() {
                            None
                        } else {
                            Some(events)
                        };

                        (events, rmp_serialize(&results))
                    }
                    // this hould never happen because previous controls
                    // mabye warn
                    _ => {
                        fork.rollback();

                        (None, rmp_serialize(&results))
                    } // Recepit should be empty?
                };

                Receipt {
                    height,
                    index,
                    burned_fuel: 0, // TODO
                    success: !execution_fail,
                    returns: results.unwrap(), //mabye handle unwrap
                    events,
                }
            }
        };

        recepit
    }

    /// Returns a vector of executed transactions
    fn exec_transactions(
        &mut self,
        fork: &mut <D as Db>::DbForkType,
        height: u64,
        txs_hashes: &[Hash],
    ) -> Vec<Hash> {
        let mut rxs_hashes = vec![];

        for (index, hash) in txs_hashes.iter().enumerate() {
            debug!("Executing transaction: {}", hex::encode(hash));

            // Execute the transaction.
            let tx = match self.pool.read().txs.get(hash) {
                Some(Some(tx)) => tx.to_owned(),
                _ => panic!(
                    "Unexpected missing transaction during execution: {}",
                    hex::encode(hash)
                ),
            };

            let rx = self.exec_transaction(&tx, fork, height, index as u32);

            rxs_hashes.push(rx.primary_hash());

            fork.store_transaction(hash, tx);
            fork.store_receipt(hash, rx);
        }

        rxs_hashes
    }

    // Draft version of the logic to be actuated for block construction.
    // Final code can follow a much more complex logic that takes consensus into
    // consideration.
    fn exec_block(
        &mut self,
        height: u64,
        txs_hashes: &[Hash],
        prev_hash: Hash,
        exp_hash: Option<Hash>,
        is_validator: bool,
    ) -> Result<Hash> {
        // Write on a fork.
        let mut fork = self.db.write().fork_create();

        // Get a vector of executed transactions hashes.
        let rxs_hashes = self.exec_transactions(&mut fork, height, txs_hashes);

        let txs_hash = fork.store_transactions_hashes(height, txs_hashes.to_owned());
        let rxs_hash = fork.store_receipts_hashes(height, rxs_hashes);

        // Construct a new block.
        let data = BlockData::new(
            self.keypair.public_key(),
            height,
            txs_hashes.len() as u32,
            prev_hash,
            txs_hash,
            rxs_hash,
            fork.state_hash(""),
        );

        let buf = rmp_serialize(&data)?;
        let signature = self.keypair.sign(&buf)?;

        let block_hash = data.primary_hash();

        let block = Block { data, signature };

        if let Some(exp_hash) = exp_hash {
            if exp_hash != block_hash {
                error!(
                    "unexpected block hash\n\tExpected: {:?}\n\tCalculated: {:?}",
                    exp_hash, block_hash
                ); // Deleteme

                // Somethig has gone wrong.
                return Err(Error::new_ext(ErrorKind::Other, "unexpected block hash"));
            }
        }

        fork.store_block(block.clone());

        // Final step, merge the fork.
        self.db.write().fork_merge(fork)?;

        // if self.validator && self.pubsub.lock().has_subscribers(Event::BLOCK) { // FIXME retrieve information about be a validator or not

        if is_validator && self.pubsub.lock().has_subscribers(Event::BLOCK) {
            // Notify subscribers about block generation.
            let msg = Message::GetBlockResponse {
                block,
                txs: Some(txs_hashes.to_owned()),
            };
            self.pubsub.lock().publish(Event::BLOCK, msg);
        }

        Ok(block_hash)
    }

    /// Check if the executor can be run to produce the block at the given height.
    /// If `height` is `u64::MAX` the test is performed using the height after
    /// the last block in the database.
    pub fn can_run(&self, mut height: u64) -> bool {
        if height == u64::MAX {
            height = self
                .db
                .read()
                .load_block(u64::MAX)
                .map(|blk| blk.data.height + 1)
                .unwrap_or_default();
        }
        let pool = self.pool.read();
        match pool.confirmed.get(&height) {
            Some(BlockInfo {
                hash: _,
                txs_hashes: Some(hashes),
            }) => hashes
                .iter()
                .all(|hash| matches!(pool.txs.get(hash), Some(Some(_)))),
            _ => false,
        }
    }

    pub fn run(&mut self, is_validator: bool) {
        let (mut prev_hash, mut height) = match self.db.read().load_block(u64::MAX) {
            Some(block) => (block.primary_hash(), block.data.height + 1),
            None => (Hash::default(), 0),
        };

        #[allow(clippy::while_let_loop)]
        loop {
            // Try to steal the hashes vector leaving the height slot busy.
            let (block_hash, txs_hashes) = match self.pool.write().confirmed.get_mut(&height) {
                Some(BlockInfo {
                    hash,
                    txs_hashes: Some(hashes),
                }) => (*hash, std::mem::take(hashes)),
                _ => break,
            };

            debug!("Executing block {}", height);

            match self.exec_block(height, &txs_hashes, prev_hash, block_hash, is_validator) {
                Ok(hash) => {
                    let mut pool = self.pool.write();
                    pool.confirmed.remove(&height);
                    txs_hashes.iter().for_each(|hash| {
                        let _ = pool.txs.remove(hash);
                    });
                    prev_hash = hash;
                    height += 1;
                }
                Err(err) => {
                    let blk_info = BlockInfo {
                        hash: block_hash,
                        txs_hashes: Some(txs_hashes),
                    };
                    self.pool.write().confirmed.insert(height, blk_info);
                    error!("Block execution error: {}", err.to_string_full());
                    break;
                }
            }

            if !self.can_run(height) {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        base::{
            schema::{
                BulkTransaction, BulkTransactions, SignedTransaction, TransactionData,
                TransactionDataBulkNodeV1, TransactionDataBulkV1, UnsignedTransaction,
            },
            serialize::{rmp_deserialize, rmp_serialize},
        },
        blockchain::pool::tests::create_pool,
        crypto::{
            sign::tests::{create_test_keypair, create_test_public_key},
            HashAlgorithm,
        },
        db::*,
        wm::*,
        Error, ErrorKind, TransactionDataV1,
    };

    use serde_value::{value, Value};

    const BLOCK_HEX: &str = "929793a56563647361a9736563703338347231c461045936d631b849bb5760bcf62e0d1261b6b6e227dc0a3892cbeec91be069aaa25996f276b271c2c53cba4be96d67edcadd66b793456290609102d5401f413cd1b5f4130b9cfaa68d30d0d25c3704cb72734cd32064365ff7042f5a3eee09b06cc10103c4221220648263253df78db6c2f1185e832c546f2f7a9becbdc21d3be41c80dc96b86011c4221220f937696c204cc4196d48f3fe7fc95c80be266d210b95397cc04cfc6b062799b8c4221220dec404bd222542402ffa6b32ebaa9998823b7bb0a628152601d1da11ec70b867c422122005db394ef154791eed2cb97e7befb2864a5702ecfd44fab7ef1c5ca215475c7dc403000102";

    const TEST_WASM: &[u8] = include_bytes!("../wm/test.wasm");

    fn create_executor(db_fail: bool) -> Executor<MockDb, MockWm> {
        let pool = Arc::new(RwLock::new(create_pool()));
        let db = Arc::new(RwLock::new(create_db_mock(db_fail)));
        let wm = Arc::new(Mutex::new(create_wm_mock()));
        let sub = Arc::new(Mutex::new(PubSub::new()));

        let keypair = Arc::new(crate::crypto::sign::tests::create_test_keypair());

        Executor::new(pool, db, wm, sub, keypair)
    }

    fn create_executor_bulk(db_fail: bool) -> Executor<MockDb, MockWm> {
        let pool = Arc::new(RwLock::new(create_pool()));
        let db = Arc::new(RwLock::new(create_db_mock(db_fail)));
        let wm = Arc::new(Mutex::new(create_wm_mock_bulk()));
        let sub = Arc::new(Mutex::new(PubSub::new()));

        let keypair = Arc::new(crate::crypto::sign::tests::create_test_keypair());

        Executor::new(pool, db, wm, sub, keypair)
    }

    fn create_db_mock(fail: bool) -> MockDb {
        let mut db = MockDb::new();
        db.expect_load_block().returning(|_| {
            let buf = hex::decode(BLOCK_HEX).unwrap();
            Some(rmp_deserialize(&buf).unwrap())
        });
        db.expect_fork_create().returning(create_fork_mock);
        db.expect_fork_merge().returning(move |_| match fail {
            false => Ok(()),
            true => Err(Error::new_ext(ErrorKind::DatabaseFault, "merge error")),
        });
        db
    }

    fn create_fork_mock() -> MockDbFork {
        let mut fork = MockDbFork::new();
        fork.expect_store_transaction().returning(|_, _| ());
        fork.expect_store_receipt().returning(|_, _| ());
        fork.expect_store_transactions_hashes().returning(|_, _| {
            Hash::from_hex("1220b950d8111feed13ad9ca7f2b8b81a3449da1cc572e973e8c6fed7623aedc7cd7")
                .unwrap()
        });
        fork.expect_store_receipts_hashes().returning(|_, _| {
            Hash::from_hex("12209b369faa46585ceaf95e12b709ceb28a3c29b2f4abb7b7da0e8c04dba74f4d25")
                .unwrap()
        });
        fork.expect_store_block().returning(|_| ());
        fork.expect_state_hash().returning(|_id| Hash::default());
        fork.expect_flush().returning(|| ());
        fork.expect_rollback().returning(|| ());
        fork
    }

    fn create_wm_mock() -> MockWm {
        let mut wm = MockWm::new();
        let mut count = 0;
        wm.expect_call()
            .returning(move |_: &mut dyn DbFork, _, _, _, _, _, _, _, _, _| {
                count += 1;
                match count {
                    1 => {
                        // Dummy opaque information returned the the smart contract.
                        Ok(hex::decode("4f706171756544617461").unwrap())
                    }
                    2 => Err(Error::new_ext(
                        ErrorKind::SmartContractFault,
                        "bad contract args",
                    )),
                    _ => Err(Error::new_ext(
                        ErrorKind::WasmMachineFault,
                        "internal error",
                    )),
                }
            });
        wm
    }

    fn create_wm_mock_bulk() -> MockWm {
        let mut wm = MockWm::new();
        let mut count = 0;
        wm.expect_call()
            .returning(move |_: &mut dyn DbFork, _, _, _, _, _, _, _, _, _| {
                count += 1;
                match count {
                    1 | 2 | 3 => {
                        // Dummy opaque information returned the the smart contract.
                        Ok(hex::decode("4f706171756544617461").unwrap())
                    }
                    4 => Err(Error::new_ext(
                        ErrorKind::SmartContractFault,
                        "bad contract args",
                    )),
                    _ => Err(Error::new_ext(
                        ErrorKind::WasmMachineFault,
                        "internal error",
                    )),
                }
            });
        wm
    }

    fn test_contract_hash() -> Hash {
        Hash::from_data(HashAlgorithm::Sha256, TEST_WASM)
    }

    fn create_test_bulk_data(method: &str, args: Value) -> TransactionData {
        let contract_hash = test_contract_hash();
        let public_key = create_test_public_key();
        let keypair = create_test_keypair();
        let id = public_key.to_account_id();

        let data_tx0 = TransactionData::BulkRootV1(TransactionDataV1 {
            account: id,
            fuel_limit: 1000,
            nonce: [0xab, 0x82, 0xb7, 0x41, 0xe0, 0x23, 0xa4, 0x12].to_vec(),
            network: "arya".to_string(),
            contract: Some(contract_hash), // Smart contract HASH
            method: method.to_string(),
            caller: public_key,
            args: rmp_serialize(&args).unwrap(),
        });

        let contract_hash = test_contract_hash();
        let public_key = create_test_public_key();
        let id = public_key.to_account_id();

        let data_tx1 = TransactionData::BulkNodeV1(TransactionDataBulkNodeV1 {
            account: id,
            fuel_limit: 1000,
            nonce: [0xab, 0x82, 0xb7, 0x41, 0xe0, 0x23, 0xa4, 0x12].to_vec(),
            network: "arya".to_string(),
            contract: Some(contract_hash), // Smart contract HASH
            method: method.to_string(),
            caller: public_key,
            args: rmp_serialize(&value!(null)).unwrap(),
            depends_on: data_tx0.primary_hash(),
        });
        let sign_tx1 = data_tx1.sign(&keypair);

        let contract_hash = test_contract_hash();
        let public_key = create_test_public_key();
        let id = public_key.to_account_id();

        let data_tx2 = TransactionData::BulkNodeV1(TransactionDataBulkNodeV1 {
            account: id,
            fuel_limit: 1000,
            nonce: [0xab, 0x82, 0xb7, 0x41, 0xe0, 0x23, 0xa4, 0x12].to_vec(),
            network: "arya".to_string(),
            contract: Some(contract_hash), // Smart contract HASH
            method: method.to_string(),
            caller: public_key,
            args: rmp_serialize(&args).unwrap(),
            depends_on: data_tx0.primary_hash(),
        });
        let sign_tx2 = data_tx2.sign(&keypair);

        let tx1 = Transaction::UnitTransaction(SignedTransaction {
            data: data_tx1,
            signature: sign_tx1.unwrap(),
        });

        let tx2 = Transaction::UnitTransaction(SignedTransaction {
            data: data_tx2,
            signature: sign_tx2.unwrap(),
        });

        let nodes = vec![tx1, tx2];

        TransactionData::BulkV1(TransactionDataBulkV1 {
            schema: "schema".to_string(),
            txs: BulkTransactions {
                root: Box::new(UnsignedTransaction { data: data_tx0 }),
                nodes: Some(nodes),
            },
        })
    }

    fn create_bulk_tx() -> Transaction {
        let keypair = create_test_keypair();

        let data = create_test_bulk_data("get_random_sequence", value!(null));
        let signature = data.sign(&keypair).unwrap();
        Transaction::BulkTransaction(BulkTransaction { data, signature })
    }

    #[test]
    fn test_bulk() {
        let mut executor = create_executor_bulk(false);
        let mut fork = executor.db.write().fork_create();

        let tx = create_bulk_tx();

        let rcpt = executor.exec_transaction(&tx, &mut fork, 0, 0);

        assert!(rcpt.success);
    }

    #[test]
    fn can_run() {
        let executor = create_executor(false);

        let runnable = executor.can_run(0);

        assert!(runnable);
    }

    #[test]
    fn cant_run_missing_next_block() {
        let executor = create_executor(false);

        let runnable = executor.can_run(u64::MAX);

        assert!(!runnable);
    }

    #[test]
    fn cant_run_missing_block_tx_hashes() {
        let executor = create_executor(false);
        {
            // Steal transaction hashes list.
            let mut pool = executor.pool.write();
            pool.confirmed.get_mut(&0).unwrap().txs_hashes.take();
        }

        let runnable = executor.can_run(0);

        assert!(!runnable);
    }

    #[test]
    fn cant_run_missing_transaction() {
        let executor = create_executor(false);
        {
            // Steal one transaction required by the first block.
            let mut pool = executor.pool.write();
            let hash = pool
                .confirmed
                .get(&0)
                .unwrap()
                .txs_hashes
                .as_ref()
                .unwrap()
                .get(0)
                .unwrap()
                .to_owned();
            let _ = pool.txs.get_mut(&hash).unwrap().take();
        }

        let runnable = executor.can_run(0);

        assert!(!runnable);
    }

    #[test]
    fn exec_block() {
        let mut executor = create_executor(false);
        let hashes = executor
            .pool
            .write()
            .confirmed
            .get_mut(&0)
            .unwrap()
            .txs_hashes
            .take()
            .unwrap();

        let hash = executor
            .exec_block(0, &hashes, Hash::default(), None, true)
            .unwrap();

        assert_eq!(
            hex::encode(hash),
            "1220385797fe75a8488bcf4a4ffc330be4c57edcd8d2c832b0c7d809bef7ade6098c"
        );
    }

    #[test]
    fn exec_block_expected_hash_mismatch() {
        let mut executor = create_executor(true);
        let hashes = executor
            .pool
            .write()
            .confirmed
            .get_mut(&0)
            .unwrap()
            .txs_hashes
            .take()
            .unwrap();

        let err = executor
            .exec_block(0, &hashes, Hash::default(), Some(Hash::default()), true)
            .unwrap_err();

        assert_eq!(err.to_string_full(), "other: unexpected block hash");
    }

    #[test]
    fn exec_block_merge_fail() {
        let mut executor = create_executor(true);
        let hashes = executor
            .pool
            .write()
            .confirmed
            .get_mut(&0)
            .unwrap()
            .txs_hashes
            .take()
            .unwrap();

        let err = executor
            .exec_block(0, &hashes, Hash::default(), None, true)
            .unwrap_err();

        assert_eq!(err.to_string_full(), "database fault: merge error");
    }

    #[test]
    #[should_panic(expected = "Unexpected missing transaction")]
    fn exec_block_missing_tx() {
        let mut executor = create_executor(true);
        let hashes = {
            let mut pool = executor.pool.write();
            let hashes = pool
                .confirmed
                .get_mut(&0)
                .unwrap()
                .txs_hashes
                .take()
                .unwrap();
            let _ = pool.txs.get_mut(&hashes[0]).unwrap().take();
            hashes
        };

        executor
            .exec_block(0, &hashes, Hash::default(), None, true)
            .unwrap();
    }
}
