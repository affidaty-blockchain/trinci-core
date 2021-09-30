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

use crate::{blockchain::BlockRequestSender, crypto::KeyPair, p2p::worker};
//use libp2p::identity::Keypair;
use std::{
    sync::Arc,
    thread::{self, JoinHandle},
};

/// Peer2Peer service configuration.
pub struct PeerConfig {
    /// Peer key-pair (used to assign an identity to the peer)
    /// If `None` it will be dynamically generated.
    pub keypair: Option<KeyPair>,
    /// Listening IP address
    pub addr: String,
    /// Network identifier.
    pub network: String,
}

/// Peer2Peer service data.
pub struct PeerService {
    /// Service configuration.
    config: Arc<PeerConfig>,
    /// Working thread handler.
    handle: Option<JoinHandle<()>>,
    /// Message queue sender to send messages to blockchain service.
    bc_chan: BlockRequestSender,
}

impl PeerService {
    /// Create a new peer service instance.
    pub fn new(config: PeerConfig, bc_chan: BlockRequestSender) -> Self {
        PeerService {
            config: Arc::new(config),
            handle: None,
            bc_chan,
        }
    }

    pub fn start(&mut self) {
        debug!("Starting p2p service");
        if self.is_running() {
            return;
        }

        let config = self.config.clone();
        let bc_chan = self.bc_chan.clone();
        let handle = thread::spawn(move || {
            worker::run(config, bc_chan);
        });
        self.handle = Some(handle);
    }

    pub fn stop(&mut self) {
        debug!("Stopping p2p service");
        match self.handle.take() {
            Some(handle) => {
                // if let Err(err) = self.listener_tx.request(BlockRequest::Stop) {
                //     error!("Error stopping listener service thread: {:?}", err);
                // }
                error!("Not implemented...");
                handle.join().unwrap();
            }
            None => {
                debug!("service was not running");
            }
        }
    }

    pub fn is_running(&self) -> bool {
        Arc::strong_count(&self.config) == 2
    }
}
