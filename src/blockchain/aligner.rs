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
    crypto::{HashAlgorithm, Hashable},
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

/// Synchronization context data.
pub(crate) struct Aligner<D: Db> {
    /// Trusted peers (peer, last block hash).
    trusted_peers: Arc<Mutex<Vec<(String, String, Block)>>>,
    /// Missing blocks.
    missing_blocks: Arc<Mutex<Vec<Message>>>,
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

impl<D: Db> Aligner<D> {
    pub fn new(pubsub: Arc<Mutex<PubSub>>, db: Arc<RwLock<D>>, pool: Arc<RwLock<Pool>>) -> Self {
        let (tx_chan, rx_chan) = confirmed_channel::<Message, Message>();

        Aligner {
            trusted_peers: Arc::new(Mutex::new(vec![])),
            missing_blocks: Arc::new(Mutex::new(vec![])),
            rx_chan: Arc::new(Mutex::new(rx_chan)),
            tx_chan: Arc::new(Mutex::new(tx_chan)),
            pubsub,
            status: Arc::new((StdMutex::new(true), Condvar::new())),
            db,
            pool,
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
            let trusted_peers = self.trusted_peers.clone();
            let rx_chan = self.rx_chan.clone();
            let pubsub = self.pubsub.clone();

            // Collect trusted peers.
            let future = future::poll_fn(move |cx: &mut Context<'_>| -> Poll<()> {
                // Send a `GetBlockRequest` in broadcast to retrieve
                // as many peers as possible in a predetermined time window.
                let msg = Message::GetBlockRequest {
                    height: u64::MAX,
                    txs: false,
                    destination: None,
                };
                pubsub.lock().publish(Event::GOSSIP_REQUEST, msg);

                let collection_time = Duration::from_secs(10);
                let start = Instant::now();

                debug!("[aligner] collecting peers to find most common last block");
                // TODO: check if other poll needed or not.
                while collection_time.checked_sub(start.elapsed()).is_some() {
                    match rx_chan.lock().poll_next_unpin(cx) {
                        Poll::Ready(Some((req, _res_chan))) => {
                            // The messages recieved from the p2p nw (unicast layer)
                            // are in packed format, need to be deserialized
                            // and the only messages expected are `GetBlockResponse`.
                            debug!("[aligner] MESSAGE RECIEVED!");

                            match req {
                                Message::GetBlockResponse {
                                    block,
                                    txs: _,
                                    origin,
                                } => {
                                    debug!(
                                        "[alinger] last block proposal recieved by {}",
                                        origin.clone().unwrap()
                                    );
                                    let hash = block.hash(HashAlgorithm::Sha256);
                                    let hash = hex::encode(hash.as_bytes());
                                    trusted_peers.lock().push((
                                        origin.unwrap().to_string(),
                                        hash,
                                        block,
                                    ));
                                }
                                _ => (),
                            }
                        }
                        //Poll::Ready(Some((Message::Stop, _))) => return Poll::Ready(()),
                        //Poll::Ready(None) => return Poll::Ready(()),
                        //Poll::Pending => break,
                        _ => (),
                    }
                }
                debug!("[aligner] peer collection ended");
                std::task::Poll::Ready(())
            });

            future.await;

            // Once the collection task ended, to find the trusted peers,
            // the peers with the most common last block are chosen.
            let mut hashmap = HashMap::<String, i64>::new();
            for entry in self.trusted_peers.lock().iter() {
                let counter = hashmap.entry(entry.1.clone()).or_default();
                *counter += 1;
            }

            let mut most_common_block = String::from("");
            let max_occurences: i64 = 0;
            for (block_hash, occurence) in hashmap.iter() {
                if max_occurences < *occurence {
                    most_common_block = block_hash.clone();
                }
            }

            let mut j: usize = 0;
            for entry in self.trusted_peers.lock().iter() {
                if entry.1 != most_common_block {
                    self.trusted_peers.lock().remove(j);
                }
                j += 1;
            }

            debug!("[aligner] trusted peers:");
            for peer in self.trusted_peers.lock().iter() {
                debug!("\t\t{}", peer.0);
            }
            debug!("==========");

            // Send unicast request to a random trusted peer for every block in `missing_blocks`.
            let rx_chan = self.rx_chan.clone();
            let pubsub = self.pubsub.clone();
            let local_last = self.db.read().load_block(u64::MAX).unwrap();

            debug!("[alinger] requesting last block to random trusted peer");
            let peers = self.trusted_peers.lock().clone();
            let peer = &peers.choose(&mut rand::thread_rng());
            match peer {
                Some((peer, ..)) => {
                    // Send first request.
                    let msg = Message::GetBlockRequest {
                        height: u64::MAX,
                        txs: true,
                        destination: Some(peer.to_string()),
                    };
                    pubsub.lock().publish(Event::UNICAST_REQUEST, msg);

                    // Until "local_last.next" retrieved ask for "remote_last.previous".
                    let mut over = false;
                    let trusted_peers = self.trusted_peers.clone();
                    let future = future::poll_fn(move |cx: &mut Context<'_>| -> Poll<()> {
                        while !over {
                            match rx_chan.lock().poll_next_unpin(cx) {
                                Poll::Ready(Some((req, _res_chan))) => {
                                    debug!("[aligner] new message recieved");
                                    match req {
                                        // Check if the recieved message is
                                        // from previous peer collection task,
                                        // in that case discard the message.
                                        Message::GetBlockResponse {
                                            ref block,
                                            txs: Some(ref _txs_hashes),
                                            ref origin,
                                        } => {
                                            debug!(
                                                "[aligner] align bock {} recieved by {}",
                                                block.data.height,
                                                origin.clone().unwrap()
                                            );

                                            self.missing_blocks.lock().push(req.clone());
                                            // TO REMOVE
                                            debug!(
                                                "missing block dim: {}",
                                                self.missing_blocks.lock().len()
                                            );

                                            // Check alignment status.
                                            //if !block.data.prev_hash.eq(&local_last_hash)
                                            if block.data.height > (local_last.data.height + 1) {
                                                // Get previous block.
                                                let peers = trusted_peers.lock().clone();
                                                let peer = &peers
                                                    .choose(&mut rand::thread_rng())
                                                    .unwrap()
                                                    .0;

                                                let msg = Message::GetBlockRequest {
                                                    height: block.data.height - 1,
                                                    txs: true,
                                                    destination: Some(peer.to_string()),
                                                };
                                                pubsub.lock().publish(Event::UNICAST_REQUEST, msg);
                                            } else {
                                                // Alignment block gathering completed.
                                                debug!(
                                                    "[aligner] alignment blocks gathering completed"
                                                );
                                                over = true;
                                            }
                                        }
                                        _ => (),
                                    }
                                }
                                //Poll::Ready(Some((Message::Stop, _))) => return Poll::Ready(()),
                                //Poll::Ready(None) => return Poll::Ready(()),
                                //Poll::Pending => break,
                                _ => (),
                            }
                        }

                        std::task::Poll::Ready(())
                    });

                    future.await;

                    // Update DB with the retrieved blocks.
                    // Note: in the `missing_block` array blocks are collected
                    //       from the most recent (first array element),
                    //       to the least recenf (last array element).
                    debug!("[aligner] alignment blocks execution");
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
                            };
                            //debug!("{:?}", blk_info.hash);
                            pool.confirmed.insert(block.data.height, blk_info);
                            debug!(
                                "[aligner] block {} inserted in confirmed pool",
                                block.data.height
                            );
                        }
                    }
                }
                None => (), // If no trusted peers, complete alignment task.
            };

            // Reinitialise aligner structures.
            debug!("[aligner] reset aligner");
            {
                //debug!("trusted peers: {}", self.trusted_peers.is_locked());
                let mut trusted_peers = self.trusted_peers.lock();
                let empty: Vec<(String, String, Block)> = vec![];
                *trusted_peers = empty;
            }

            {
                //debug!("missing blocks: {}", self.missing_blocks.is_locked());
                let mut missing_blocks = self.missing_blocks.lock();
                let empty: Vec<Message> = vec![];
                *missing_blocks = empty;
            }

            {
                //debug!("status: {}", self.status.0.is_poisoned());
                *self.status.0.lock().unwrap() = true;
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
                debug!("[aligner] status {:?}", self.status.0.lock());
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
