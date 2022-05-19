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

use crate::{blockchain::BlockRequestSender, bridge::worker::BridgeWorker};
use std::{
    sync::Arc,
    thread::{self, JoinHandle},
};

/// Bridge service configuration.
#[derive(Clone)]
pub struct BridgeConfig {
    /// Listening IP address (e.g. "127.0.0.1" for localhost)
    pub addr: String,
    /// Listening TCP port.
    pub port: u16,
}

/// Bridge service data.
pub struct BridgeService {
    /// Worker object.
    worker: Option<BridgeWorker>,
    /// Worker thread handler.
    handler: Option<JoinHandle<BridgeWorker>>,
    /// To check if the worker thread is alive.
    canary: Arc<()>,
}

impl BridgeService {
    pub fn new(config: BridgeConfig, bc_chan: BlockRequestSender) -> Self {
        let worker = BridgeWorker::new(config, bc_chan);

        BridgeService {
            worker: Some(worker),
            handler: None,
            canary: Arc::new(()),
        }
    }

    /// Start the service.
    pub fn start(&mut self) {
        debug!("Starting BRIDGE service");

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
        debug!("Stopping BRIDGE service (TODO)");
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel;

    fn create_rest_service() -> BridgeService {
        let config = BridgeConfig {
            addr: "localhost".to_owned(),
            port: 8000,
        };

        let (tx_chan, _rx_chan) = channel::confirmed_channel();
        BridgeService::new(config, tx_chan)
    }

    #[test]
    fn start_stop() {
        let mut svc = create_rest_service();

        svc.start();
        assert!(svc.is_running());

        svc.stop();
        // FIXME: this is a known issue.
        //assert!(!svc.is_running());
    }
}
