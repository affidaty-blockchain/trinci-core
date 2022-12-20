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

use crate::channel::confirmed_channel;
use crate::crypto::drand::SeedSource;
use crate::crypto::hash::Hashable;
use crate::{
    base::{Mutex, RwLock},
    blockchain::{
        builder::Builder, dispatcher::Dispatcher, executor::Executor, message::*, pool::*,
        pubsub::PubSub, BlockConfig,
    },
    db::Db,
    wm::Wm,
    Result, Transaction,
};

use async_std::task::{self, Context, Poll};
use futures::future::FutureExt;
use futures::{future, prelude::*};
use std::sync::{Arc, Condvar, Mutex as StdMutex};
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use super::aligner::{AlignerWorker, NodeAligner};
use super::dispatcher::AlignerInterface;

#[cfg(feature = "indexer")]
use super::indexer::{Indexer, IndexerConfig};

/// Closure trait to load a wasm binary.
pub trait IsValidator: Fn(String) -> Result<bool> + Send + Sync + 'static {}

impl<T: Fn(String) -> Result<bool> + Send + Sync + 'static> IsValidator for T {}

pub struct BlockWorker<D: Db, W: Wm> {
    /// Blockchain service configuration.
    config: Arc<Mutex<BlockConfig>>,
    /// Database shared reference.
    db: Arc<RwLock<D>>,
    /// Wasm machine shared reference.
    wm: Arc<Mutex<W>>,
    /// Blockchain requests receiver.
    rx_chan: BlockRequestReceiver,
    /// Dispatcher subsystem, in charge of handling incoming blockchain messages.
    dispatcher: Dispatcher<D, W>,
    /// Builder subsystem, in charge of building new blocks (validator only).
    builder: Builder<D>,
    /// Executor subsystem, in charge of executing block transactions.
    executor: Executor<D, W>,
    /// Builder running flag.
    building: Arc<AtomicBool>,
    /// Executor running flag.
    executing: Arc<AtomicBool>,
    /// Method to tell if the Node is validator
    is_validator_closure: Arc<dyn IsValidator>,
    /// Variable that store the validator status of the node
    is_validator: Arc<bool>,
    /// Check the status of the aligner. If true cannot build blocks
    aligner_status: Arc<(StdMutex<bool>, Condvar)>,
}

impl<D: Db, W: Wm> BlockWorker<D, W> {
    #[allow(clippy::mutex_atomic)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        is_validator_closure: impl IsValidator,
        config: BlockConfig,
        db: D,
        wm: W,
        rx_chan: BlockRequestReceiver,
        seed: Arc<SeedSource>,
        p2p_id: String,
        #[cfg(feature = "indexer")] indexer_config: IndexerConfig,
    ) -> Self {
        let pool = Arc::new(RwLock::new(Pool::default()));
        let pubsub = Arc::new(Mutex::new(PubSub::new()));

        let config = Arc::new(Mutex::new(config));
        let db = Arc::new(RwLock::new(db));
        let wm = Arc::new(Mutex::new(wm));

        let (aligner_tx_chan, aligner_rx_chan) = confirmed_channel::<Message, Message>();

        let aligner_status = Arc::new((StdMutex::new(true), Condvar::new()));
        let aligner_rx_chan = Arc::new(Mutex::new(aligner_rx_chan));
        let aligner_tx_chan = Arc::new(Mutex::new(aligner_tx_chan));
        let node_aligner = NodeAligner {
            aligner_worker: Some(AlignerWorker {
                status: aligner_status.clone(),
                pubsub: pubsub.clone(),
                db: db.clone(),
                pool: pool.clone(),
                rx_chan: aligner_rx_chan,
                tx_chan: aligner_tx_chan.clone(),
            }),
        };

        let dispatcher = Dispatcher::new(
            config.clone(),
            pool.clone(),
            db.clone(),
            pubsub.clone(),
            seed.clone(),
            p2p_id.clone(),
            AlignerInterface(aligner_tx_chan, aligner_status.clone()),
            node_aligner,
            wm.clone(),
        );

        let builder = Builder::new(config.lock().threshold, pool.clone(), db.clone());
        let executor = Executor::new(
            pool,
            db.clone(),
            wm.clone(),
            pubsub,
            config.lock().keypair.clone(),
            seed,
            p2p_id,
            #[cfg(feature = "indexer")]
            Indexer::new(indexer_config),
        );

        let building = Arc::new(AtomicBool::new(false));
        let executing = Arc::new(AtomicBool::new(false));

        Self {
            config,
            db,
            wm,
            rx_chan,
            dispatcher,
            builder,
            executor,
            building,
            executing,
            is_validator_closure: Arc::new(is_validator_closure),
            is_validator: Arc::new(false),
            aligner_status,
        }
    }

    /// Set the Node Validator check
    pub fn set_validator(&mut self, is_validator: impl IsValidator) {
        self.is_validator_closure = Arc::new(is_validator);
    }

    /// Set the Burn Fuel Method
    pub fn set_burn_fuel_method(&mut self, burn_fuel_method: String) {
        self.executor.set_burn_fuel_method(burn_fuel_method);
    }

    /// Set the block configuration
    pub fn set_config(&mut self, network: String, threshold: usize, timeout: u16) {
        self.config.clone().lock().network = network;
        self.config.clone().lock().threshold = threshold;
        self.config.clone().lock().timeout = timeout;

        self.builder.set_block_threshold(threshold);
        self.dispatcher.set_block_timeout(timeout);
    }

    /// Insert transactions directly in the pool
    pub fn put_txs(&mut self, txs: Vec<Transaction>) {
        txs.iter().for_each(|tx| {
            let hash = tx.primary_hash();
            debug!("Received transaction: {}", hex::encode(hash));

            // Check the network.
            if self.config.lock().network != tx.get_network() {
                panic!();
            }

            // Check if already present in db.
            if self.db.read().contains_transaction(&hash) {
                panic!();
            }

            let mut pool = self.executor.pool.write();
            match pool.txs.get_mut(&hash) {
                None => {
                    pool.txs.insert(hash, Some(tx.to_owned()));
                    pool.unconfirmed.push(hash);
                }
                _ => panic!(),
            }
        });
    }

    fn try_build_block(&self, threshold: usize) {
        if !self.builder.can_run(threshold) {
            return;
        }
        if self.building.swap(true, Ordering::Relaxed) {
            return;
        }

        let mut builder = self.builder.clone();
        let building = self.building.clone();
        task::spawn(async move {
            builder.run();
            building.store(false, Ordering::Relaxed);
        });
    }

    fn try_exec_block(&self, is_validator: bool, is_validator_closure: Arc<dyn IsValidator>) {
        if !self.executor.can_run(u64::MAX) {
            return;
        }
        if self.executing.swap(true, Ordering::Relaxed) {
            return;
        }

        let mut executor = self.executor.clone();
        let executing = self.executing.clone();
        task::spawn(async move {
            executor.run(is_validator, is_validator_closure);
            executing.store(false, Ordering::Relaxed);
        });
    }

    fn handle_message(&self, req: Message, res_chan: BlockResponseSender) {
        let mut dispatcher = self.dispatcher.clone();
        task::spawn(async move {
            if let Some(res) = dispatcher.message_handler(req, &res_chan, 0) {
                if let Err(_err) = res_chan.send(res).await {
                    warn!("blockchain response send error");
                }
            }
        });
    }

    /// Blockchain worker asynchronous task.
    /// This can be stopped by submitting a `Stop` message to its input channel.
    #[allow(clippy::mutex_atomic)]
    pub async fn run(&mut self, account_id: &str) {
        let threshold = self.config.lock().threshold;

        let exec_timeout = self.config.lock().timeout as u64;
        let mut exec_sleep = Box::pin(task::sleep(Duration::from_secs(exec_timeout)));
        let is_validator_closure = self.is_validator_closure.clone();

        // FIXME This call must be only read/mode
        self.is_validator =
            Arc::new((*is_validator_closure)(account_id.to_string()).unwrap_or_default());

        let future = future::poll_fn(move |cx: &mut Context<'_>| -> Poll<()> {
            while exec_sleep.poll_unpin(cx).is_ready() {
                if *self.is_validator && *self.aligner_status.0.lock().unwrap() {
                    self.try_build_block(1);
                }
                self.try_exec_block(*self.is_validator, self.is_validator_closure.clone());
                exec_sleep = Box::pin(task::sleep(Duration::from_secs(exec_timeout)));
            }

            loop {
                match self.rx_chan.poll_next_unpin(cx) {
                    Poll::Ready(Some((Message::Stop, _))) => return Poll::Ready(()),
                    Poll::Ready(Some((req, res_chan))) => {
                        self.handle_message(req, res_chan.clone())
                    }
                    Poll::Ready(None) => return Poll::Ready(()),
                    Poll::Pending => break,
                }

                // We use try_lock because the lock may be held the "builder" in another thread.
                if *self.is_validator {
                    self.try_exec_block(*self.is_validator, self.is_validator_closure.clone());
                    if *self.aligner_status.0.lock().unwrap() {
                        self.try_build_block(threshold);
                    }
                }
            }
            Poll::Pending
        });

        future.await
    }

    /// Blockchain worker synchronous task.
    /// This can be stopped by submitting a `Stop` message to its input channel.
    pub fn run_sync(&mut self, account_id: &str) {
        task::block_on(self.run(account_id));
    }

    // Get a shared reference to the database.
    pub fn db_arc(&mut self) -> Arc<RwLock<D>> {
        self.db.clone()
    }

    // Get a shared reference to the wasm machine.
    pub fn wm_arc(&mut self) -> Arc<Mutex<W>> {
        self.wm.clone()
    }
}
