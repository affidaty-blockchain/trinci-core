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

use crate::blockchain::BlockRequestSender;
use std::{
    sync::Arc,
    thread::{self, JoinHandle},
};

use super::worker::KafkaWorker;

/// Bridge service configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KafkaConfig {
    /// Listening IP address (e.g. "127.0.0.1" for localhost)
    pub addr: String,
    /// Listening TCP port.
    pub port: u16,
}

/// Bridge service data.
pub struct KafkaService {
    /// Worker object.
    worker: Option<KafkaWorker>,
    /// Worker thread handler.
    handler: Option<JoinHandle<KafkaWorker>>,
    /// To check if the worker thread is alive.
    canary: Arc<()>,
}

impl KafkaService {
    pub fn new(config: KafkaConfig, bc_chan: BlockRequestSender) -> Self {
        let worker = KafkaWorker::new(config, bc_chan);

        KafkaService {
            worker: Some(worker),
            handler: None,
            canary: Arc::new(()),
        }
    }

    /// Start the service.
    pub fn start(&mut self) {
        debug!("Starting KAFKA service");

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

    /// Stop the service.
    pub fn stop(&mut self) {
        debug!("Stopping KAFKA service (TODO)");
        // match self.handler.take() {
        //     Some(handle) => {
        //         // TODO
        //         // if let Err(err) = self.tx_chan.send_sync(Message::Stop) {
        //         //     error!("Error stopping listener service thread: {:?}", err);
        //         // }
        //         //let worker = handle.join().unwrap();
        //         //self.worker = Some(worker);
        //     }
        //     None => {
        //         debug!("service was not running");
        //     }
        // };
    }

    /// Check if service is running.
    pub fn is_running(&self) -> bool {
        // Hack to intercept crashed sub threads.
        Arc::strong_count(&self.canary) == 2
    }
}
