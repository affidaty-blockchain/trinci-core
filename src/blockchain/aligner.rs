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

use crate::{channel::confirmed_channel, crypto::Hashable, Block};

use super::{message::Message, BlockRequestReceiver, BlockRequestSender};
use core::hash::Hash;
use std::{
    collections::hash_map::DefaultHasher,
    sync::Arc,
    task::{Context, Poll},
};

const MAX_SYNC_REQUESTS: usize = 512;

/// Synchronization context data.
pub(crate) struct Aligner {
    /// Trusted peers (peer, last block hash)
    trusted_peers: Vec<(String, String, Block)>,
    /// Missing blocks
    missing_blocks: Vec<Block>,
    /// Rx channel
    rx_chan: BlockRequestReceiver,
    /// Tx channel
    tx_chan: BlockRequestSender,
    /// Canary
    canary: Arc<()>,
    // TODO: add db mabye
}

impl Aligner {
    pub fn new() -> Self {
        let (tx_chan, rx_chan) = confirmed_channel::<Message, Message>();

        Aligner {
            trusted_peers: vec![],
            missing_blocks: vec![],
            rx_chan,
            tx_chan,
            canary: Arc::new(()),
        }
    }

    pub async fn run(&mut self) {
        // first task to complete is to recieve candidates to trusted peers

        // once the time window is timed out pick the peers with most common block
        // mabye drop channel?

        // pick a random trusted peer

        // send unicast request for every block in missing_blocks
        // should it wait that a block has been executed to send another req?

        // stop aligner
    }

    fn collect_peers() {
        todo!()
    }

    fn handle_message(&self, req: Message) {
        match req {
            Message::AlignBlockInfo { peer_id, block } => {
                let mut hasher = DefaultHasher::new();
                let hash = block.hash(hasher);
                if self.trusted_peers.is_empty() {
                    self.trusted_peers.push((peer_id, hash, block));
                    // launch collector. It should wai for 10 sec
                    // let time_window = collect();
                } else {
                    self.trusted_peers.push((peer_id, hash, block));
                }
                // time_window.await
            }
            _ => (),
        }
    }

    /// Get a clone of block-service input channel.
    pub fn request_channel(&self) -> BlockRequestSender {
        self.tx_chan.clone()
    }

    /// Check if service is running.
    pub fn is_running(&self) -> bool {
        // Hack to intercept crashed subthreads.
        Arc::strong_count(&self.canary) == 2
    }
}
