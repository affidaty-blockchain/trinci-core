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

use async_std::future;
use futures::StreamExt;
use rand::prelude::SliceRandom;

use crate::{
    base::{Mutex, RwLock},
    blockchain::pool::BlockInfo,
    channel::confirmed_channel,
    crypto::{Hash, HashAlgorithm, Hashable},
    db::Db,
    Block,
};

use super::{
    message::Message, pool::Pool, pubsub::PubSub, BlockRequestReceiver, BlockRequestSender, Event,
};
use std::{
    collections::HashMap,
    sync::{Arc, Condvar, Mutex as StdMutex},
    task::{Context, Poll},
    time::{Duration, Instant},
};

const PEER_COLLECTION_TIME_WINDOW: u64 = 10;
const SLEEP_TIME: u64 = 3;
const TIME_OUT_SEC: u64 = 5;
const MAX_ATTEMPTS: i32 = 3;
/// Most common blocks range.
const LATEST_WINDOW: usize = 5;

/// Synchronization context data.
pub(crate) struct Aligner<D: Db> {
    /// Trusted peers (peer, last block hash).
    trusted_peers: Arc<Mutex<Vec<(String, String, Block)>>>,
    /// Missing blocks.
    missing_blocks: Arc<Mutex<Vec<Message>>>,
    /// Unexpected blocks.
    /// Height grather than most common last block.
    unexpected_blocks: Arc<Mutex<Vec<Message>>>,
    /// Black-listed blocks Hashes.
    blacklist_blocks: Arc<Mutex<Vec<Hash>>>,
    /// Missing transactions.
    missing_txs: Arc<Mutex<Vec<Hash>>>,
    /// Rx channel.
    rx_chan: Arc<Mutex<BlockRequestReceiver>>,
    /// Tx channel.
    tx_chan: Arc<Mutex<BlockRequestSender>>,
    /// Pubsub channel.
    pubsub: Arc<Mutex<PubSub>>,
    /// Align status. false => not aligned.
    pub status: Arc<(StdMutex<bool>, Condvar)>,
    /// Hash of local last block.
    db: Arc<RwLock<D>>,
    /// Outstanding blocks and transactions.
    pool: Arc<RwLock<Pool>>,
}

#[allow(clippy::mutex_atomic)]
impl<D: Db> Aligner<D> {
    pub fn new(pubsub: Arc<Mutex<PubSub>>, db: Arc<RwLock<D>>, pool: Arc<RwLock<Pool>>) -> Self {
        let (tx_chan, rx_chan) = confirmed_channel::<Message, Message>();

        Aligner {
            trusted_peers: Arc::new(Mutex::new(vec![])),
            missing_blocks: Arc::new(Mutex::new(vec![])),
            blacklist_blocks: Arc::new(Mutex::new(vec![])),
            unexpected_blocks: Arc::new(Mutex::new(vec![])),
            rx_chan: Arc::new(Mutex::new(rx_chan)),
            tx_chan: Arc::new(Mutex::new(tx_chan)),
            pubsub,
            status: Arc::new((StdMutex::new(true), Condvar::new())),
            db,
            pool,
            missing_txs: Arc::new(Mutex::new(vec![])),
        }
    }

    fn find_trusted_peers(&self, cx: &mut Context) -> Poll<bool> {
        // Send a `GetBlockRequest` in broadcast to retrieve
        // as many peers as possible in a predetermined time window.
        let msg = Message::GetBlockRequest {
            height: u64::MAX,
            txs: false,
            destination: None,
        };
        self.pubsub.lock().publish(Event::GOSSIP_REQUEST, msg);

        let collection_time = Duration::from_secs(PEER_COLLECTION_TIME_WINDOW);
        let start = Instant::now();

        debug!("[aligner] collecting peers to find most common last block");
        while collection_time.checked_sub(start.elapsed()).is_some() {
            if let Poll::Ready(Some((
                Message::GetBlockResponse {
                    block,
                    txs: None,
                    origin,
                },
                _res_chan,
            ))) = self.rx_chan.lock().poll_next_unpin(cx)
            {
                // The messages recieved from the p2p nw (unicast layer)
                // are in packed format, need to be deserialized
                // and the only messages expected are `GetBlockResponse`.
                debug!(
                    "[aligner] last block proposal recieved by {} (height {})",
                    origin.clone().unwrap(),
                    block.data.height.clone()
                );

                let hash = block.hash(HashAlgorithm::Sha256);
                let hash = hex::encode(hash.as_bytes());

                if !self.trusted_peers.lock().contains(&(
                    origin.clone().unwrap().to_string(),
                    hash.clone(),
                    block.clone(),
                )) {
                    self.trusted_peers
                        .lock()
                        .push((origin.unwrap().to_string(), hash, block));
                }
            }
        }
        debug!("[aligner] peer collection ended");
        if self.trusted_peers.lock().len() > 0 {
            std::task::Poll::Ready(true)
        } else {
            std::task::Poll::Ready(false)
        }
    }

    fn collect_missing_blocks(
        &self,
        max_block_height: u64,
        peer: &str,
        cx: &mut Context,
    ) -> Poll<bool> {
        // Send first request.
        let mut msg = Message::GetBlockRequest {
            height: u64::MAX,
            txs: true,
            destination: Some(peer.to_string()),
        };
        self.pubsub
            .lock()
            .publish(Event::UNICAST_REQUEST, msg.clone());

        // Until "local_last.next" retrieved ask for "remote_last.previous".
        let mut timeout = Duration::from_secs(TIME_OUT_SEC);
        let mut start = Instant::now();
        let mut attempt = 0;
        let mut over = false;
        let local_last = self.db.read().load_block(u64::MAX).unwrap();
        let hash_local_last = local_last.hash(HashAlgorithm::Sha256);

        while !over && attempt < MAX_ATTEMPTS {
            if timeout.checked_sub(start.elapsed()).is_some() {
                if let Poll::Ready(Some((req, _res_chan))) = self.rx_chan.lock().poll_next_unpin(cx)
                {
                    debug!("[aligner] new message recieved");
                    // Check if the recieved message is
                    // from previous peer collection task,
                    // in that case discard the message.
                    if let Message::GetBlockResponse {
                        ref block,
                        txs: Some(ref txs_hashes),
                        ref origin,
                    } = req
                    {
                        // Check if the block was expected or not
                        if block.data.height > max_block_height
                            && !self.unexpected_blocks.lock().contains(&req)
                        {
                            debug!(
                                "[aligner] block with height grather than 
                                                            alignment height limit recieved, 
                                                            collecting for possible pool insertion"
                            );
                            self.unexpected_blocks.lock().push(req);
                        } else {
                            // reset timeout and attempts
                            timeout = Duration::from_secs(TIME_OUT_SEC);
                            start = Instant::now();
                            attempt = 0;

                            debug!(
                                "[aligner] align block {} recieved by {}",
                                block.data.height,
                                origin.clone().unwrap()
                            );

                            self.missing_blocks.lock().push(req.clone());
                            for tx in txs_hashes {
                                debug!("[aligner] adding hash tx");
                                self.missing_txs.lock().push(*tx);
                            }

                            // Check alignment status.
                            if block.data.height > (local_last.data.height + 1) {
                                // Get previous block.
                                let peers = self.trusted_peers.lock().clone();
                                let peer = &peers.choose(&mut rand::thread_rng()).unwrap().0;

                                msg = Message::GetBlockRequest {
                                    height: block.data.height - 1,
                                    txs: true,
                                    destination: Some(peer.to_string()),
                                };
                                self.pubsub
                                    .lock()
                                    .publish(Event::UNICAST_REQUEST, msg.clone());
                            } else {
                                // Alignment block gathering completed.
                                debug!("[aligner] alignment blocks gathering completed");
                                over = true;
                            }
                        }
                    }
                }
            } else {
                debug!(
                    "[aligner] alignment block request timed out (attempt: {})",
                    attempt
                );
                attempt += 1;

                // Send message again (to another peer) and reset TO count.
                if attempt < MAX_ATTEMPTS {
                    let peers = self.trusted_peers.lock().clone();
                    let peer = &peers.choose(&mut rand::thread_rng()).unwrap().0;
                    if let Message::GetBlockRequest {
                        height,
                        txs,
                        destination: _,
                    } = msg
                    {
                        msg = Message::GetBlockRequest {
                            height,
                            txs,
                            destination: Some(peer.to_string()),
                        };

                        self.pubsub
                            .lock()
                            .publish(Event::UNICAST_REQUEST, msg.clone());
                        timeout = Duration::from_secs(TIME_OUT_SEC);
                        start = Instant::now();
                    }
                } else {
                    return std::task::Poll::Ready(false);
                }
            }
        }

        if let Some(Message::GetBlockResponse { block, .. }) = self.missing_blocks.lock().last() {
            if attempt >= MAX_ATTEMPTS {
                // If last block recieved doesn't point to local last block,
                // then the most common remote block is compromised.
                if hash_local_last.ne(&block.data.prev_hash) {
                    if let Some(Message::GetBlockResponse { block, .. }) =
                        self.missing_blocks.lock().first()
                    {
                        self.blacklist_blocks
                            .lock()
                            .push(block.hash(HashAlgorithm::Sha256));
                    }
                }
                std::task::Poll::Ready(false)
            } else {
                std::task::Poll::Ready(true)
            }
        } else {
            std::task::Poll::Ready(false)
        }
    }

    fn collect_missing_txs(
        &self,
        peer: &str,
        max_block_height: u64,
        cx: &mut Context,
    ) -> Poll<bool> {
        // Send unicast request to a random trusted peer for every transaction in `missing_txs`.

        let mut timeout = Duration::from_secs(TIME_OUT_SEC);
        let mut start = Instant::now();
        let mut attempt = 0;

        let missing_txs = self.missing_txs.lock().clone();
        let mut missing_txs = missing_txs.iter();
        let mut requested_tx = missing_txs.next();
        let mut over = requested_tx.is_none();

        debug!("[aligner] first requested tx: {:?}", requested_tx.unwrap());

        if !over {
            let mut msg = Message::GetTransactionRequest {
                hash: *requested_tx.unwrap(),
                destination: Some(peer.to_string()),
            };
            self.pubsub
                .lock()
                .publish(Event::UNICAST_REQUEST, msg.clone());

            while !over && attempt < MAX_ATTEMPTS {
                if timeout.checked_sub(start.elapsed()).is_some() {
                    if let Poll::Ready(Some((req, _res_chan))) =
                        self.rx_chan.lock().poll_next_unpin(cx)
                    {
                        debug!("[aligner] new message recieved");
                        match req {
                            Message::GetTransactionResponse { tx, origin } => {
                                if tx.get_primary_hash().eq(requested_tx.unwrap()) {
                                    // reset timet and attempts
                                    timeout = Duration::from_secs(TIME_OUT_SEC);
                                    start = Instant::now();
                                    attempt = 0;

                                    debug!(
                                        "[aligner] align tx {:?} recieved by {}",
                                        tx.get_primary_hash(),
                                        origin.unwrap()
                                    );

                                    // Once the expected TX is recieved, ask for the next one.
                                    // Note: submission to pool and DB is handled by dispatcher.
                                    requested_tx = missing_txs.next();

                                    if let Some(requested_tx) = requested_tx {
                                        // Ask to a random trusted peer the transaction.
                                        let peers = self.trusted_peers.lock().clone();
                                        let peer =
                                            &peers.choose(&mut rand::thread_rng()).unwrap().0;
                                        msg = Message::GetTransactionRequest {
                                            hash: *requested_tx,
                                            destination: Some(peer.to_string()),
                                        };
                                        self.pubsub
                                            .lock()
                                            .publish(Event::UNICAST_REQUEST, msg.clone());
                                    } else {
                                        over = true;
                                    }
                                }
                            }
                            Message::GetBlockResponse {
                                ref block,
                                txs: Some(ref _txs_hashes),
                                origin: _,
                            } => {
                                // Check if the block was expected or not
                                if block.data.height > max_block_height {
                                    debug!(
                                        "[aligner] block with height grather than 
                                                            alignment height limit recieved, 
                                                            collecting for possible pool insertion"
                                    );
                                    self.unexpected_blocks.lock().push(req.clone());
                                }
                            }
                            _ => debug!("[aligner] unexpected message"),
                        }
                    }
                } else {
                    debug!(
                        "[aligner] alignment transaction request timed out (attempt: {})",
                        attempt
                    );
                    attempt += 1;

                    // Send message again and reset TO count.
                    if attempt < MAX_ATTEMPTS {
                        let peers = self.trusted_peers.lock().clone();
                        let peer = &peers.choose(&mut rand::thread_rng()).unwrap().0;

                        if let Message::GetTransactionRequest {
                            hash,
                            destination: _,
                        } = msg
                        {
                            msg = Message::GetTransactionRequest {
                                hash,
                                destination: Some(peer.to_string()),
                            };

                            self.pubsub
                                .lock()
                                .publish(Event::UNICAST_REQUEST, msg.clone());
                            timeout = Duration::from_secs(TIME_OUT_SEC);
                            start = Instant::now();
                        }
                    } else {
                        return std::task::Poll::Ready(false);
                    }
                }
            }
        }
        if attempt >= MAX_ATTEMPTS {
            std::task::Poll::Ready(false)
        } else {
            std::task::Poll::Ready(true)
        }
    }

    fn update_pool(&self) {
        let missing_blocks = self.missing_blocks.lock().clone();
        for msg in missing_blocks.iter().rev() {
            if let Message::GetBlockResponse {
                block,
                txs,
                origin: _,
            } = msg
            {
                let mut pool = self.pool.write();
                if let Some(ref hashes) = txs {
                    for hash in hashes {
                        if pool.unconfirmed.contains(hash) {
                            pool.unconfirmed.remove(hash);
                        }
                        if !pool.txs.contains_key(hash) {
                            pool.txs.insert(*hash, None);
                        }
                    }
                }
                let blk_info = BlockInfo {
                    hash: Some(block.data.primary_hash()),
                    validator: block.data.validator.to_owned(),
                    signature: Some(block.signature.clone()),
                    txs_hashes: txs.to_owned(),
                    timestamp: block.data.timestamp,
                };
                pool.confirmed.insert(block.data.height, blk_info);
                debug!(
                    "[aligner] block {} inserted in confirmed pool",
                    block.data.height
                );
            }
        }

        // Update pools with unexpected blocks
        let mut last_block = self.trusted_peers.lock()[0].2.data.height + 1;

        let unexpected_blocks = self.unexpected_blocks.lock().clone();
        while unexpected_blocks
            .iter()
            .find_map(|msg| match msg {
                Message::GetBlockResponse { block, txs, .. } => {
                    if block.data.height == last_block {
                        let mut pool = self.pool.write();
                        if let Some(ref hashes) = txs {
                            for hash in hashes {
                                if pool.unconfirmed.contains(hash) {
                                    pool.unconfirmed.remove(hash);
                                }
                                if !pool.txs.contains_key(hash) {
                                    pool.txs.insert(*hash, None);
                                }
                            }
                        }
                        let blk_info = BlockInfo {
                            hash: Some(block.data.primary_hash()),
                            validator: block.data.validator.to_owned(),
                            signature: Some(block.signature.clone()),
                            txs_hashes: txs.to_owned(),
                            timestamp: block.data.timestamp,
                        };
                        pool.confirmed.insert(block.data.height, blk_info);
                        debug!(
                            "[aligner] unexpected block {} inserted in confirmed pool",
                            block.data.height
                        );
                        Some(())
                    } else {
                        None
                    }
                }
                _ => None,
            })
            .is_some()
        {
            last_block += 1;
        }
    }

    async fn run_async(&self) {
        debug!("[aligner] service up");

        loop {
            {
                let _guard = self
                    .status
                    .1
                    .wait_while(self.status.0.lock().unwrap(), |pending| *pending);
            }

            debug!("[aligner] new align instance initialised");

            // Wait some time before collecting new peers in case of a flood of "new added peer" messages
            let collection_time = Duration::from_secs(SLEEP_TIME);
            let start = Instant::now();
            while collection_time.checked_sub(start.elapsed()).is_some() {}

            // Collect trusted peers.
            let future = future::poll_fn(move |cx: &mut Context<'_>| -> Poll<bool> {
                self.find_trusted_peers(cx)
            });

            let result = future.await;

            if result {
                // Once the collection task ended, to find the trusted peers,
                // the peers with the most common last block are chosen.
                // (occurencies, height)
                debug!("[aligner] removing black list blocks");
                let mut hashmap = HashMap::<String, (i64, u64)>::new();
                for entry in self.trusted_peers.lock().iter() {
                    let counter = hashmap.entry(entry.1.clone()).or_default();
                    counter.0 += 1;
                    counter.1 = entry.2.data.height;
                }

                let sorted_blocks_candidates: Vec<_> = hashmap.iter().collect();
                let mut sorted_blocks: Vec<(&String, &(i64, u64))> = vec![];

                // Remove black-listed blocks.
                for block in sorted_blocks_candidates {
                    let hash: Hash = Hash::from_hex(block.0).unwrap();
                    if !self.blacklist_blocks.lock().contains(&hash) {
                        sorted_blocks.push(block);
                    }
                }

                sorted_blocks.sort_by_key(|block| (block.1).0); // Sort by occurencies (ascendent).
                if sorted_blocks.len() > LATEST_WINDOW {
                    sorted_blocks = sorted_blocks[..LATEST_WINDOW].to_vec();
                }
                sorted_blocks.sort_by_key(|block| (block.1).1); // Sort by height (ascendent).
                let most_common_block = sorted_blocks.last().unwrap().0.to_owned();

                {
                    debug!("[aligner] removing not trusted peers");
                    let local_last = self.db.read().load_block(u64::MAX).unwrap();
                    let trusted_peers = self.trusted_peers.lock();
                    let mut helper: Vec<(String, String, Block)> = vec![];
                    for entry in trusted_peers.iter() {
                        if entry.1 == most_common_block
                            && (entry.2).data.height < local_last.data.height + 1
                        {
                            helper.push(entry.to_owned());
                        }
                    }
                    std::mem::drop(trusted_peers);
                    let mut trusted_peers = self.trusted_peers.lock();
                    *trusted_peers = helper;
                    std::mem::drop(trusted_peers);
                }

                {
                    debug!("[aligner] trusted peers:");
                    let trusted_peers = self.trusted_peers.lock();
                    for peer in trusted_peers.iter() {
                        debug!("\t\t{}", peer.0);
                    }
                    debug!("==========");
                    std::mem::drop(trusted_peers);
                }

                // Get last block height
                let max_block_height = if self.trusted_peers.lock().len() > 0 {
                    self.trusted_peers.lock()[0].2.data.height
                } else {
                    0
                };

                debug!("[aligner] requesting last block to random trusted peer");
                let peers = self.trusted_peers.lock().clone();
                let peer = &peers.choose(&mut rand::thread_rng());
                match peer {
                    Some((peer, ..)) => {
                        let future = future::poll_fn(move |cx: &mut Context<'_>| -> Poll<bool> {
                            self.collect_missing_blocks(max_block_height, peer, cx)
                        });

                        let outcome = future.await;

                        // Only progress the procedure if the block
                        // and transaction's hash collection ended succesfully
                        if outcome {
                            debug!(
                                "[aligner] requesting transactions from missing blocks to trusted peers");
                            let future =
                                future::poll_fn(move |cx: &mut Context<'_>| -> Poll<bool> {
                                    self.collect_missing_txs(peer, max_block_height, cx)
                                });

                            let outcome = future.await;

                            // Only progress if previous tastks were succesfully completed.
                            if outcome {
                                // Update pools with the retrieved blocks.
                                // Note: in the `missing_block` array blocks are collected
                                //       from the most recent (first array element),
                                //       to the least recenf (last array element).
                                debug!("[aligner] submitting alignment blocks to pool service");
                                self.update_pool();
                                debug!("[aligner] pool updated");
                                // Wait untill all blocks are executed.
                                let mut executed_block =
                                    self.db.read().load_block(u64::MAX).unwrap();
                                let most_common_block = self.trusted_peers.lock()[0].2.data.height;
                                while executed_block.data.height < most_common_block {
                                    executed_block = self.db.read().load_block(u64::MAX).unwrap();
                                }
                            } else {
                                debug!(
                                    "[aligner] unable to retrieve missing blocks and txs, aborting alignment"
                                );
                            }
                        }
                    }
                    None => (), // If no trusted peers, complete alignment task.
                };
            } else {
                debug!("[aligner] unable to find trusted peers, aborting alignment");
            }

            // Reinitialise aligner structures.
            debug!("[aligner] reset aligner");
            {
                //debug!("trusted peers: {}", self.trusted_peers.is_locked());
                let mut trusted_peers = self.trusted_peers.lock();
                let empty: Vec<(String, String, Block)> = vec![];
                *trusted_peers = empty;

                //debug!("missing blocks: {}", self.missing_blocks.is_locked());
                let mut missing_blocks = self.missing_blocks.lock();
                let empty: Vec<Message> = vec![];
                *missing_blocks = empty;

                //debug!("unexpected blocks: {}", self.unexpected_blocks.is_locked());
                let mut unexpected_blocks = self.unexpected_blocks.lock();
                let empty: Vec<Message> = vec![];
                *unexpected_blocks = empty;

                //debug!("status: {}", self.status.0.is_poisoned());
                *self.status.0.lock().unwrap() = true;
                self.status.1.notify_all();
            }

            {
                // It should be 0.
                debug!(
                    "[aligner] trusted_peers {}",
                    self.trusted_peers.lock().len()
                );
                // It should be 0.
                debug!(
                    "[aligner] missing_blocks {}",
                    self.missing_blocks.lock().len()
                );
                // It should be 0.
                debug!(
                    "[aligner] unexpected blocks {}",
                    self.unexpected_blocks.lock().len()
                );
                // It should be true
                debug!("[aligner] status {:?}", self.status.0.lock().unwrap());
            }

            debug!("[aligner] alignment task completed");
        }
    }

    pub fn run(&mut self) {
        let fut = self.run_async();
        async_std::task::block_on(fut);
    }

    /// Get a clone of block-service input channel.
    pub fn request_channel(&self) -> Arc<Mutex<BlockRequestSender>> {
        self.tx_chan.clone()
    }
}
