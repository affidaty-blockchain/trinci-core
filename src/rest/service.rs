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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NodeInfo {
    pub public_ip: String,
    pub p2p_account_id: String,
    pub p2p_port: u16,
    pub bootstrap_url_access: String,
    pub bootstrap_file_path: String,
    pub node_version: (String, String),
}

/// REST service configuration.
#[derive(Clone)]
pub struct RestConfig {
    /// IP address (e.g. 127.0.0.1 for localhost)
    pub addr: String,
    /// TCP port.
    pub port: u16,
    /// Node Info
    pub node_info: NodeInfo,
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
        let node_info = self.config.node_info.clone();
        let mut canary = Arc::clone(&self.canary);
        let handle = thread::spawn(move || {
            let _ = Arc::get_mut(&mut canary);
            worker::run(addr, port, node_info, bc_chan);
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
        // Hack to intercept crashed sub threads.
        Arc::strong_count(&self.canary) == 2
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::channel;

    pub fn create_node_info() -> NodeInfo {
        NodeInfo {
            public_ip: "10.10.10.1".to_string(),
            p2p_account_id: "AAAA".to_string(),
            p2p_port: 10,
            bootstrap_url_access: "www.test.com".to_string(),
            node_version: ("0.0.0".to_string(), "0.0.0".to_string()),
            bootstrap_file_path: "./here.bin".to_string(),
        }
    }

    fn create_rest_service() -> RestService {
        let config = RestConfig {
            addr: "localhost".to_owned(),
            port: 8000,
            node_info: create_node_info(),
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
