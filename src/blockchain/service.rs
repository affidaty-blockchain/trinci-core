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

#[cfg(feature = "indexer")]
use super::indexer::IndexerConfig;

use super::{
    message::{BlockRequestSender, Message},
    worker::{BlockWorker, IsValidator},
};

use crate::{
    base::{serialize::rmp_serialize, BlockchainSettings, Mutex, RwLock},
    channel::confirmed_channel,
    crypto::drand::SeedSource,
    db::{Db, DbFork},
    wm::Wm,
    KeyPair, Transaction,
};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

/// Blockchain service configuration.
pub struct BlockConfig {
    /// Max number of transactions within a block.
    pub threshold: usize,
    /// Max number of seconds to trigger block creation if the threshold has not
    /// been reached. Block is created with at least one transaction.
    pub timeout: u16,
    /// Blockchain network identifier.
    pub network: String,
    /// Node KeyPair
    pub keypair: Arc<KeyPair>,
}

/// Block service data.
pub struct BlockService<D: Db, W: Wm> {
    /// Worker object.
    worker: Option<BlockWorker<D, W>>,
    /// Threads data.
    handler: Option<JoinHandle<BlockWorker<D, W>>>,
    /// To send messages to worker.
    tx_chan: BlockRequestSender,
    /// Database shared reference.
    db: Arc<RwLock<D>>,
    /// Wasm machine shared reference.
    wm: Arc<Mutex<W>>,
    /// To check if the worker thread is still alive.
    canary: Arc<()>,
    /// Node Account Id
    account_id: String,
}

impl<D: Db, W: Wm> BlockService<D, W> {
    /// Create a new blockchain service instance.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: &str,
        worker_is_validator: impl IsValidator,
        config: BlockConfig,
        db: D,
        wm: W,
        seed: Arc<SeedSource>,
        p2p_id: String,
        #[cfg(feature = "indexer")] indexer_config: IndexerConfig,
    ) -> Self {
        let (tx_chan, rx_chan) = confirmed_channel::<Message, Message>();

        let mut worker = BlockWorker::new(
            worker_is_validator,
            config,
            db,
            wm,
            rx_chan,
            seed,
            p2p_id,
            #[cfg(feature = "indexer")]
            indexer_config,
        );
        let db = worker.db_arc();
        let wm = worker.wm_arc();

        BlockService {
            worker: Some(worker),
            handler: None,
            tx_chan,
            db,
            wm,
            canary: Arc::new(()),
            account_id: account_id.to_string(),
        }
    }

    /// Start blockchain service.
    pub fn start(&mut self) {
        debug!("Starting blockchain service");
        let mut worker = match self.worker.take() {
            Some(worker) => worker,
            None => {
                warn!("service was already running");
                return;
            }
        };

        let mut canary = Arc::clone(&self.canary);
        let account_id = self.account_id.clone();
        let handle = thread::spawn(move || {
            let _ = Arc::get_mut(&mut canary);
            worker.run_sync(&account_id);
            worker
        });
        self.handler = Some(handle);
    }

    /// Stop blockchain service.
    pub fn stop(&mut self) {
        debug!("Stopping block service");
        match self.handler.take() {
            Some(handle) => {
                if let Err(err) = self.tx_chan.send_sync(Message::Stop) {
                    error!("Error stopping listener service thread: {:?}", err);
                }
                let worker = handle.join().unwrap();
                self.worker = Some(worker);
            }
            None => {
                debug!("service was not running");
            }
        };
    }

    /// Check if service is running.
    pub fn is_running(&self) -> bool {
        // Hack to intercept crashed sub threads.
        Arc::strong_count(&self.canary) == 2 && self.worker.is_none()
    }

    /// Get a clone of block-service input channel.
    pub fn request_channel(&self) -> BlockRequestSender {
        self.tx_chan.clone()
    }

    /// Get a shared reference to the database.
    pub fn db_arc(&mut self) -> Arc<RwLock<D>> {
        self.db.clone()
    }

    /// Get a shared reference to the wasm machine.
    pub fn wm_arc(&mut self) -> Arc<Mutex<W>> {
        self.wm.clone()
    }

    /// Set the block config
    /// If this panics, it panics early at node boot. Not a big deal.
    pub fn set_block_config(&mut self, network: String, threshold: usize, timeout: u16) {
        self.worker
            .as_mut()
            .unwrap()
            .set_config(network, threshold, timeout);
    }

    // Store the blockchain config in the DB
    pub fn store_config_into_db(&mut self, config: BlockchainSettings) {
        let mut db = self.db.write();
        let mut fork = db.fork_create();
        let data = rmp_serialize(&config).unwrap(); // If this fails is at the very beginning
        fork.store_configuration("blockchain:settings", data);

        db.fork_merge(fork).unwrap();
    }

    /// Set the Node Validator check
    /// If this panics, it panics early at node boot. Not a big deal.
    pub fn set_validator(&mut self, is_validator: impl IsValidator) {
        self.worker.as_mut().unwrap().set_validator(is_validator);
    }

    /// Put transactions directly in the pool
    /// If this panics, it panics early at node boot. Not a big deal.
    pub fn put_txs(&mut self, txs: Vec<Transaction>) {
        self.worker.as_mut().unwrap().put_txs(txs)
    }

    /// Set the burn fuel method
    /// If this panics, it panics early at node boot. Not a big deal.
    pub fn set_burn_fuel_method(&mut self, burn_fuel_method: String) {
        self.worker
            .as_mut()
            .unwrap()
            .set_burn_fuel_method(burn_fuel_method);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto::Hash, db::*, wm::*};

    #[cfg(feature = "indexer")]
    use crate::blockchain::indexer::IndexerConfig;

    fn is_validator_function() -> impl IsValidator {
        move |_account_id| Ok(true)
    }

    fn create_block_service() -> BlockService<MockDb, MockWm> {
        let wm = MockWm::new();
        let db = MockDb::new();

        let config = BlockConfig {
            threshold: 42,
            timeout: 3,
            network: "skynet".to_string(),
            keypair: Arc::new(crate::crypto::sign::tests::create_test_keypair()),
        };

        let is_validator = is_validator_function();

        let nw_name = String::from("skynet");
        let nonce: Vec<u8> = vec![0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56];
        let prev_hash =
            Hash::from_hex("1220a4cea0f0f6eddc6865fd6092a319ccc6d2387cd8bb65e64bdc486f1a9a998569")
                .unwrap();
        let txs_hash =
            Hash::from_hex("1220a4cea0f1f6eddc6865fd6092a319ccc6d2387cf8bb63e64b4c48601a9a998569")
                .unwrap();
        let rxs_hash =
            Hash::from_hex("1220a4cea0f0f6edd46865fd6092a319ccc6d5387cd8bb65e64bdc486f1a9a998569")
                .unwrap();
        let seed = SeedSource::new(nw_name, nonce, prev_hash, txs_hash, rxs_hash);
        let seed = Arc::new(seed);

        BlockService::new(
            "MyAccount",
            is_validator,
            config,
            db,
            wm,
            seed,
            "TEST".to_string(),
            #[cfg(feature = "indexer")]
            IndexerConfig::default(),
        )
    }

    #[test]
    fn start_stop() {
        let mut svc = create_block_service();

        svc.start();
        assert!(svc.is_running());

        svc.stop();
        assert!(!svc.is_running());
    }

    #[test]
    fn stopped_subthread() {
        let mut svc = create_block_service();

        svc.start();
        assert!(svc.is_running());

        svc.tx_chan.send_sync(Message::Stop).unwrap();
        std::thread::sleep(std::time::Duration::from_secs(1));

        assert!(!svc.is_running());
        svc.stop();
    }
}
