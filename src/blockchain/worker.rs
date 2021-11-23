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

use crate::{
    base::{Mutex, RwLock},
    blockchain::{
        builder::Builder, dispatcher::Dispatcher, executor::Executor, message::*, pool::*,
        pubsub::PubSub, BlockConfig,
    },
    db::Db,
    wm::Wm,
};
use async_std::task::{self, Context, Poll};
use futures::future::FutureExt;
use futures::{future, prelude::*};
use std::sync::Arc;
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use super::synchronizer::Synchronizer;

pub struct BlockWorker<D: Db, W: Wm> {
    /// Blockchain service configuration.
    config: Arc<BlockConfig>,
    /// Database shared reference.
    db: Arc<RwLock<D>>,
    /// Wasm machine shared reference.
    wm: Arc<Mutex<W>>,
    /// Blockchain requests receiver.
    rx_chan: BlockRequestReceiver,
    /// Dispatcher subsystem, in charge of handling incoming blockchain messages.
    dispatcher: Dispatcher<D>,
    /// Builder subsystem, in charge of building new blocks (validator only).
    builder: Builder<D>,
    /// Executor subsystem, in charge of executing block transactions.
    executor: Executor<D, W>,
    ///
    synchronizer: Synchronizer<D>,
    /// Builder running flag.
    building: Arc<AtomicBool>,
    /// Executor running flag.
    executing: Arc<AtomicBool>,
    ///
    synchronizing: Arc<AtomicBool>,
}

impl<D: Db, W: Wm> BlockWorker<D, W> {
    pub fn new(config: BlockConfig, db: D, wm: W, rx_chan: BlockRequestReceiver) -> Self {
        let pool = Arc::new(RwLock::new(Pool::default()));
        let pubsub = Arc::new(Mutex::new(PubSub::new()));

        let config = Arc::new(config);
        let db = Arc::new(RwLock::new(db));
        let wm = Arc::new(Mutex::new(wm));

        let dispatcher = Dispatcher::new(config.clone(), pool.clone(), db.clone(), pubsub.clone());
        let builder = Builder::new(config.threshold, pool.clone(), db.clone());
        let executor = Executor::new(
            pool.clone(),
            db.clone(),
            wm.clone(),
            pubsub.clone(),
            config.validator,
            Arc::clone(&config.keypair),
        );
        let synchronizer = Synchronizer::new(pool, db.clone(), pubsub);

        let building = Arc::new(AtomicBool::new(false));
        let executing = Arc::new(AtomicBool::new(false));
        let synchronizing = Arc::new(AtomicBool::new(false));

        Self {
            config,
            db,
            wm,
            rx_chan,
            dispatcher,
            builder,
            executor,
            synchronizer,
            building,
            executing,
            synchronizing,
        }
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

    fn try_exec_block(&self) {
        if !self.executor.can_run(u64::MAX) {
            return;
        }
        if self.executing.swap(true, Ordering::Relaxed) {
            return;
        }

        let mut executor = self.executor.clone();
        let executing = self.executing.clone();
        task::spawn(async move {
            executor.run();
            executing.store(false, Ordering::Relaxed);
        });
    }

    fn try_synchronization(&self) {
        if self.synchronizing.swap(true, Ordering::Relaxed) {
            return;
        }

        let synchronizer = self.synchronizer.clone();
        let synchronizing = self.synchronizing.clone();
        task::spawn(async move {
            synchronizer.run();
            synchronizing.store(false, Ordering::Relaxed);
        });
    }

    fn handle_message(&self, req: Message, res_chan: BlockResponseSender) {
        let dispatcher = self.dispatcher.clone();
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
    pub async fn run(&mut self) {
        let threshold = self.config.threshold;
        let exec_timeout = self.config.timeout as u64;
        let sync_timeout = 3 * self.config.timeout as u64;
        let mut exec_sleep = Box::pin(task::sleep(Duration::from_secs(exec_timeout)));
        let mut sync_sleep = Box::pin(task::sleep(Duration::from_secs(sync_timeout)));

        let future = future::poll_fn(move |cx: &mut Context<'_>| -> Poll<()> {
            while exec_sleep.poll_unpin(cx).is_ready() {
                if self.config.validator {
                    self.try_build_block(1);
                }
                self.try_exec_block();
                exec_sleep = Box::pin(task::sleep(Duration::from_secs(exec_timeout)));
            }

            while sync_sleep.poll_unpin(cx).is_ready() {
                self.try_synchronization();
                sync_sleep = Box::pin(task::sleep(Duration::from_secs(sync_timeout)));
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
                if self.config.validator {
                    self.try_exec_block();
                    self.try_build_block(threshold);
                }
            }
            Poll::Pending
        });

        future.await
    }

    /// Blockchain worker synchronous task.
    /// This can be stopped by submitting a `Stop` message to its input channel.
    pub fn run_sync(&mut self) {
        task::block_on(self.run());
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
