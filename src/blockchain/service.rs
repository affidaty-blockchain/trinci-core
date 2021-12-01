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

use super::{
    message::{BlockRequestSender, Message},
    worker::BlockWorker,
};
use crate::{
    base::{Mutex, RwLock},
    channel::confirmed_channel,
    db::Db,
    wm::Wm,
    Transaction,
};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

/// Blockchain service configuration.
pub struct BlockConfig {
    /// Validator node.
    pub validator: bool,
    /// Max number of transactions within a block.
    pub threshold: usize,
    /// Max number of seconds to trigger block creation if the threshold has not
    /// been reached. Block is created with at least one transaction.
    pub timeout: u16,
    /// Blockchain network identifier.
    pub network: String,
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
}

impl<D: Db, W: Wm> BlockService<D, W> {
    /// Create a new blockchain service instance.
    pub fn new(config: BlockConfig, db: D, wm: W) -> Self {
        let (tx_chan, rx_chan) = confirmed_channel::<Message, Message>();

        let mut worker = BlockWorker::new(config, db, wm, rx_chan);
        let db = worker.db_arc();
        let wm = worker.wm_arc();

        BlockService {
            worker: Some(worker),
            handler: None,
            tx_chan,
            db,
            wm,
            canary: Arc::new(()),
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
        let handle = thread::spawn(move || {
            let _ = Arc::get_mut(&mut canary);
            worker.run_sync();
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
        // Hack to intercept crashed subthreads.
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

    /// Put transactions directly in the pool
    /// If this panics, it panics early at node boot. Not a big deal.
    pub fn put_txs(&mut self, txs: Vec<Transaction>) {
        self.worker.as_mut().unwrap().put_txs(txs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{db::*, wm::*};

    fn create_block_service() -> BlockService<MockDb, MockWm> {
        let wm = MockWm::new();
        let db = MockDb::new();

        let config = BlockConfig {
            validator: false,
            threshold: 42,
            timeout: 3,
            network: "skynet".to_string(),
        };

        BlockService::new(config, db, wm)
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
