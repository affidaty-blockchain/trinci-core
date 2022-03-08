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

use async_std::{future, task};
use futures::{FutureExt, StreamExt};

use crate::{
    base::{serialize::rmp_deserialize, Mutex},
    channel::confirmed_channel,
    crypto::{HashAlgorithm, Hashable},
    Block,
};

use super::{
    message::{Message, MultiMessage},
    pubsub::PubSub,
    BlockRequestReceiver, BlockRequestSender, Event,
};
use core::hash::Hash;
use std::{
    collections::{hash_map::DefaultHasher, HashMap},
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

const MAX_SYNC_REQUESTS: usize = 512;

/// Synchronization context data.
pub(crate) struct Aligner {
    /// Trusted peers (peer, last block hash)
    trusted_peers: Arc<Mutex<Vec<(String, String, Block)>>>,
    /// Missing blocks
    missing_blocks: Vec<Block>,
    /// Rx channel
    rx_chan: Arc<Mutex<BlockRequestReceiver>>,
    /// Tx channel
    tx_chan: BlockRequestSender,
    // Pubsub channel
    pubsub: Arc<Mutex<PubSub>>,
}

impl Aligner {
    pub fn new(pubsub: Arc<Mutex<PubSub>>) -> Self {
        let (tx_chan, rx_chan) = confirmed_channel::<Message, Message>();

        Aligner {
            trusted_peers: Arc::new(Mutex::new(vec![])),
            missing_blocks: vec![],
            rx_chan: Arc::new(Mutex::new(rx_chan)),
            tx_chan,
            pubsub,
        }
    }

    pub async fn run(&mut self) {
        // first task to complete is to recieve candidates to trusted peers
        let msg = Message::GetBlockRequest {
            height: u64::MAX,
            txs: false,
            destination: None,
        };
        self.pubsub.lock().publish(Event::GOSSIP_REQUEST, msg);

        let mut collect_candidate_time_window = Box::pin(task::sleep(Duration::from_secs(10)));

        let trusted_peers = self.trusted_peers.clone();
        let rx_chan = self.rx_chan.clone();

        let future = future::poll_fn(move |cx: &mut Context<'_>| -> Poll<()> {
            // collect trusted peers
            while !collect_candidate_time_window.poll_unpin(cx).is_ready() {
                match rx_chan.lock().poll_next_unpin(cx) {
                    Poll::Ready(Some((Message::Stop, _))) => return Poll::Ready(()),
                    Poll::Ready(Some((req, res_chan))) => {
                        // the nessages recieved are in packed format,
                        // need to be deserialize
                        match req {
                            Message::Packed { buf } => match rmp_deserialize(&buf) {
                                Ok(MultiMessage::Simple(req)) => match req {
                                    Message::GetBlockResponse {
                                        block,
                                        txs: _,
                                        origin,
                                    } => {
                                        let hash = block.hash(HashAlgorithm::Sha256);
                                        let hash = hex::encode(hash.as_bytes());
                                        trusted_peers.lock().push((
                                            origin.unwrap().to_string(),
                                            hash,
                                            block,
                                        ));
                                    }
                                    _ => (),
                                },
                                _ => (),
                            },
                            _ => (),
                        }
                    }
                    Poll::Ready(None) => return Poll::Ready(()),
                    Poll::Pending => break,
                }
            }
            Poll::Pending
        });

        future.await;

        // once the time window is timed out pick the peers with most common block
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

        // send unicast request for every block in missing_blocks
        // should it wait that a block has been executed to send another req?

        // stop aligner
    }

    /// Get a clone of block-service input channel.
    pub fn request_channel(&self) -> BlockRequestSender {
        self.tx_chan.clone()
    }
}
