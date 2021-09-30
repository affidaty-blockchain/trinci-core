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

use crate::{blockchain::BlockRequestSender, rest::worker};
use std::{
    sync::Arc,
    thread::{self, JoinHandle},
};

/// REST service configuration.
#[derive(Clone)]
pub struct RestConfig {
    /// IP address (e.g. 127.0.0.1 for localhost)
    pub addr: String,
    /// TCP port.
    pub port: u16,
}

/// REST service data.
pub struct RestService {
    /// Server configuration.
    config: RestConfig,
    /// Worker thread handler.
    handle: Option<JoinHandle<()>>,
    /// Message queue sender to send messages to blockchain service.
    bc_chan: BlockRequestSender,
    /// To check if the worker thread is alive.
    canary: Arc<()>,
}

impl RestService {
    pub fn new(config: RestConfig, bc_chan: BlockRequestSender) -> Self {
        RestService {
            config,
            handle: None,
            bc_chan,
            canary: Arc::new(()),
        }
    }

    /// Start the service.
    pub fn start(&mut self) {
        debug!("Starting REST service");
        if self.is_running() {
            warn!("service was already running");
            return;
        }
        let bc_chan = self.bc_chan.clone();
        let addr = self.config.addr.clone();
        let port = self.config.port;
        let mut canary = Arc::clone(&self.canary);
        let handle = thread::spawn(move || {
            let _ = Arc::get_mut(&mut canary);
            worker::run(addr, port, bc_chan);
        });
        self.handle = Some(handle);
    }

    /// Stop the service.
    pub fn stop(&mut self) {
        // TODO: Find a way to kill the working thread
        debug!("Stopping REST service");
        match self.handle.take() {
            Some(_handle) => (),
            None => debug!("service was not running"),
        };
    }

    /// Check if service is running.
    pub fn is_running(&self) -> bool {
        // Hack to intercept crashed subthreads.
        Arc::strong_count(&self.canary) == 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel;

    fn create_rest_service() -> RestService {
        let config = RestConfig {
            addr: "localhost".to_owned(),
            port: 8000,
        };

        let (tx_chan, _rx_chan) = channel::confirmed_channel();
        RestService::new(config, tx_chan)
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
