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
const MAX_ATTEMPTS: u8 = 3;
/// Most common blocks range.
const LATEST_WINDOW: usize = 5;

/// Synchronization context data.
pub(crate) struct Aligner<D: Db> {
    /// Trusted peers (peer, last block proposal hash, last block proposal).
    trusted_peers: Arc<Mutex<Vec<(String, String, Block)>>>,
    /// Missing blocks.
    missing_blocks: Arc<Mutex<Vec<Message>>>,
    /// Unexpected blocks.
    /// Height greater than most common last block.
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

    fn find_trusted_peers(&self, cx: &mut Context) -> Poll<Option<Vec<(String, String, Block)>>> {
        // Send a `GetBlockRequest` in broadcast to retrieve
        // as many peers as possible in a predetermined time window.
        let mut collected_peers: Vec<(String, String, Block)> = vec![];
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
                    origin: Some(origin),
                },
                _res_chan,
            ))) = self.rx_chan.lock().poll_next_unpin(cx)
            {
                // The messages received from the p2p nw (unicast layer)
                // are in packed format, need to be deserialized
                // and the only messages expected are `GetBlockResponse`.
                debug!(
                    "[aligner] last block proposal received by {} (height {})",
                    &origin, block.data.height
                );

                let hash = hex::encode(block.primary_hash());

                collected_peers
                    .iter()
                    .position(|(o, h, b)| o == &origin && h == &hash && b == &block)
                    .unwrap_or_else(|| {
                        collected_peers.push((origin, hash, block));
                        collected_peers.len() - 1
                    });
            }
        }
        error!(
            "[aligner] peer collection ended: {} peers found",
            collected_peers.len()
        );
        if !collected_peers.is_empty() {
            std::task::Poll::Ready(Some(collected_peers))
        } else {
            std::task::Poll::Ready(None)
        }
    }

    // TODO Refactoring of this method
    #[allow(clippy::too_many_arguments)]
    fn try_to_retrieve_a_block(
        &self,
        over: &mut bool,
        timeout: &mut Duration,
        start: &mut Instant,
        attempt: &mut u8,
        max_block_height: u64,
        last_block_height: u64,
        cx: &mut Context,
    ) {
        if let Poll::Ready(Some((req, _res_chan))) = self.rx_chan.lock().poll_next_unpin(cx) {
            debug!("[aligner] new message received");
            // Check if the received message is
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
                        "[aligner] block with height greater than 
                                 alignment height limit received, 
                                 collecting for possible pool insertion"
                    );
                    self.unexpected_blocks.lock().push(req);
                } else {
                    // reset timeout and attempts
                    *timeout = Duration::from_secs(TIME_OUT_SEC);
                    *start = Instant::now();
                    *attempt = 0;

                    debug!(
                        "[aligner] align block {} received by {:?}",
                        block.data.height, &origin
                    );

                    self.missing_blocks.lock().push(req.clone());
                    for tx in txs_hashes {
                        debug!("[aligner] adding hash tx");
                        self.missing_txs.lock().push(*tx);
                    }

                    // Check alignment status.
                    if block.data.height > (last_block_height + 1) {
                        // Get previous block.
                        let peers = self.trusted_peers.lock();
                        let peer = &peers.choose(&mut rand::thread_rng()).unwrap().0;

                        let msg = Message::GetBlockRequest {
                            height: block.data.height - 1,
                            txs: true,
                            destination: Some(peer.to_string()),
                        };
                        self.pubsub.lock().publish(Event::UNICAST_REQUEST, msg);
                    } else {
                        // Alignment block gathering completed.
                        debug!("[aligner] alignment blocks gathering completed");
                        *over = true;
                    }
                }
            }
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
        let mut attempt: u8 = 0;
        let mut over = false;
        let local_last = self.db.read().load_block(u64::MAX).unwrap();
        let hash_local_last = local_last.hash(HashAlgorithm::Sha256);

        while !over && attempt < MAX_ATTEMPTS {
            if timeout.checked_sub(start.elapsed()).is_some() {
                self.try_to_retrieve_a_block(
                    &mut over,
                    &mut timeout,
                    &mut start,
                    &mut attempt,
                    max_block_height,
                    local_last.data.height,
                    cx,
                );
            } else {
                debug!(
                    "[aligner] alignment block request timed out (attempt: {})",
                    attempt
                );
                attempt += 1;

                // Send message again (to another peer) and reset TO count.
                if attempt < MAX_ATTEMPTS {
                    let peers = self.trusted_peers.lock();
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
                // If last block received doesn't point to local last block,
                // then the most common remote block is compromised.
                if hash_local_last.ne(&block.data.prev_hash) {
                    if let Some(Message::GetBlockResponse { block, .. }) =
                        self.missing_blocks.lock().first()
                    {
                        self.blacklist_blocks.lock().push(block.primary_hash());
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
        initial_peer: String,
        max_block_height: u64,
        cx: &mut Context,
    ) -> Poll<bool> {
        // Send unicast request to a random trusted peer for every transaction in `missing_txs`.

        // TODO Use Box::pin(timeout)
        let mut timeout = Duration::from_secs(TIME_OUT_SEC);
        let mut start = Instant::now();
        let mut attempt = 0;

        let missing_txs = self.missing_txs.lock().clone();
        let mut missing_txs = missing_txs.iter();
        let mut requested_tx = missing_txs.next();
        let mut over = false;
        let mut current_peer = initial_peer;
        let mut send_message = true;
        debug!("[aligner] first requested tx: {:?}", requested_tx.unwrap());

        if requested_tx.is_some() {
            while !over && attempt < MAX_ATTEMPTS {
                if send_message {
                    let msg = Message::GetTransactionRequest {
                        hash: *requested_tx.unwrap(),
                        destination: Some(current_peer.clone()),
                    };
                    self.pubsub
                        .lock()
                        .publish(Event::UNICAST_REQUEST, msg.clone());
                    send_message = false;
                }

                if timeout.checked_sub(start.elapsed()).is_some() {
                    if let Poll::Ready(Some((req, _res_chan))) =
                        self.rx_chan.lock().poll_next_unpin(cx)
                    {
                        debug!("[aligner] new message received");
                        match req {
                            Message::GetTransactionResponse { tx, origin } => {
                                if tx.get_primary_hash().eq(requested_tx.unwrap()) {
                                    // reset timer and attempts
                                    timeout = Duration::from_secs(TIME_OUT_SEC);
                                    start = Instant::now();
                                    attempt = 0;

                                    debug!(
                                        "[aligner] align tx {:?} received by {}",
                                        tx.get_primary_hash(),
                                        origin.unwrap()
                                    );

                                    // Once the expected TX is received, ask for the next one.
                                    // Note: submission to pool and DB is handled by dispatcher.
                                    requested_tx = missing_txs.next();

                                    if requested_tx.is_some() {
                                        // Ask to a random trusted peer the transaction.
                                        let peers = self.trusted_peers.lock().clone();
                                        let peer =
                                            &peers.choose(&mut rand::thread_rng()).unwrap().0;
                                        current_peer = peer.clone();
                                        send_message = true;
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
                                                            alignment height limit received, 
                                                            collecting for possible pool insertion"
                                    );
                                    self.unexpected_blocks.lock().push(req.clone());
                                }
                            }
                            _ => error!("[aligner] unexpected message"),
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

                        current_peer = peer.clone();

                        timeout = Duration::from_secs(TIME_OUT_SEC);
                        start = Instant::now();
                        send_message = true;
                    } else {
                        return std::task::Poll::Ready(false);
                    }
                }
            }
        }
        if attempt >= MAX_ATTEMPTS {
            // NOTE This should be redundant
            std::task::Poll::Ready(false)
        } else {
            std::task::Poll::Ready(true)
        }
    }

    fn add_txs_to_the_pool(&self, block: &Block, txs: &Option<Vec<Hash>>, unexpected: bool) {
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
            signature: Some(block.signature.to_owned()),
            txs_hashes: txs.to_owned(),
            timestamp: block.data.timestamp,
        };
        pool.confirmed.insert(block.data.height, blk_info);

        // TMP only for early debug
        let block_type = if unexpected { "unexpected " } else { "" };
        debug!(
            "[aligner] {}block {} inserted in confirmed pool",
            block_type, block.data.height
        );
    }

    fn update_pool(&self) {
        let missing_blocks = self.missing_blocks.lock();
        for msg in missing_blocks.iter().rev() {
            if let Message::GetBlockResponse {
                block,
                txs,
                origin: _,
            } = msg
            {
                self.add_txs_to_the_pool(block, txs, false);
            }
        }

        // Update pools with unexpected blocks
        let mut last_block = self.trusted_peers.lock()[0].2.data.height + 1;

        let unexpected_blocks = self.unexpected_blocks.lock();

        // TODO sort the unexpected blocks
        while unexpected_blocks
            .iter()
            .find_map(|msg| match msg {
                Message::GetBlockResponse { block, txs, .. } => {
                    if block.data.height == last_block {
                        self.add_txs_to_the_pool(block, txs, true);
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

    fn filter_peers(
        &self,
        collected_peers: Vec<(String, String, Block)>,
        last_block_height: u64,
    ) -> u64 {
        debug!("[aligner] removing black list blocks");
        let mut map = HashMap::<String, (i64, u64)>::new();

        collected_peers.iter().for_each(|peer| {
            let counter = map.entry(peer.1.clone()).or_default();
            counter.0 += 1;
            counter.1 = peer.2.data.height;
        });

        // Remove black-listed blocks.
        let mut sorted_blocks: Vec<(&String, &(i64, u64))> = map
            .iter()
            .filter(|block| {
                let hash: Hash = Hash::from_hex(block.0).unwrap_or_default();
                !self.blacklist_blocks.lock().contains(&hash)
            })
            .collect();

        sorted_blocks.sort_by_key(|block| (block.1).0); // Sort by occurrences (ascendant).
        if sorted_blocks.len() > LATEST_WINDOW {
            sorted_blocks = sorted_blocks[..LATEST_WINDOW].to_vec();
        }
        sorted_blocks.sort_by_key(|block| (block.1).1); // Sort by height (ascendant).
        let most_common_block = sorted_blocks.last().unwrap().0.to_owned();

        debug!("[aligner] removing not trusted peers");
        let block_height = collected_peers[0].2.data.height;

        let trusted_peers: Vec<(String, String, Block)> = collected_peers
            .into_iter()
            .filter(|entry| {
                !(entry.1 != most_common_block || (entry.2).data.height < last_block_height + 1)
            })
            .collect();

        // DELETE ME
        debug!("[aligner] trusted peers:");
        for peer in trusted_peers.iter() {
            debug!("\t\t{}", peer.0);
        }
        debug!("==========");
        debug!(
            "[aligner] locking trusted peers: {}",
            self.trusted_peers.is_locked()
        );

        debug!("[aligner]  moving peers in self.trusted_peers");
        self.trusted_peers
            .lock()
            .append(&mut trusted_peers.to_vec());

        // Get last block height
        if !trusted_peers.is_empty() {
            block_height
        } else {
            0
        }
    }

    fn reset(&self) {
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

    async fn run_async(&self) {
        debug!("[aligner] service up");

        loop {
            {
                let _guard = self
                    .status
                    .1
                    .wait_while(self.status.0.lock().unwrap(), |pending| *pending);
            }

            debug!("[aligner] new align instance initialized");

            // Wait some time before collecting new peers in case of a flood of "new added peer" messages
            let collection_time = Duration::from_secs(SLEEP_TIME);
            let start = Instant::now();
            while collection_time.checked_sub(start.elapsed()).is_some() {}

            // Collect trusted peers.
            let collected_peers_fut = future::poll_fn(
                move |cx: &mut Context<'_>| -> Poll<Option<Vec<(String, String, Block)>>> {
                    self.find_trusted_peers(cx)
                },
            );

            let result = collected_peers_fut.await;

            debug!("[aligner] acquiring local last");
            let local_last = self.db.read().load_block(u64::MAX);

            if let (Some(collected_peers), Some(local_last)) = (result, local_last) {
                // Once the collection task ended, to find the trusted peers,
                // the peers with the most common last block are chosen.
                // (occurrences, height)
                let max_block_height = self.filter_peers(collected_peers, local_last.data.height);

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
                        // and transaction's hash collection ended successfully
                        if outcome {
                            debug!(
                                "[aligner] requesting transactions from missing blocks to trusted peers");
                            let future =
                                future::poll_fn(move |cx: &mut Context<'_>| -> Poll<bool> {
                                    self.collect_missing_txs(peer.clone(), max_block_height, cx)
                                });

                            let outcome = future.await;

                            // Only progress if previous tasks were successfully completed.
                            if outcome {
                                // Update pools with the retrieved blocks.
                                // Note: in the `missing_block` array blocks are collected
                                //       from the most recent (first array element),
                                //       to the least recent (last array element).
                                debug!("[aligner] submitting alignment blocks to pool service");
                                self.update_pool();
                                // Wait until all blocks are executed.
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

            // Reinitialize aligner structures.
            debug!("[aligner] reset aligner");
            self.reset();

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
