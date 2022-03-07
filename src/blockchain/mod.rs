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

//! Blockchain service components.
//!
//! This module contains the logic to construct and execute blocks from the
//! outstanding transactions pool.
//!
//! The service exploits several sub-modules to perform specialized works, in
//! particular:
//! - dispatcher: handle incoming blockchain messages.
//! - builder: constructs new blocks. This is used by validator nodes.
//! - executor: runs the transactions composing a block.
//! - synchronizer: keeps our state up-to-date with the other nodes.
//!
//! The blockchain service is the main user of the wm, db and consensus modules.
//!
//! External components can interact with blockchain service via message
//! passing.

pub(crate) mod builder;
pub(crate) mod dispatcher;
pub(crate) mod executor;
pub(crate) mod pool;
pub(crate) mod synchronizer;

pub mod aligner;
pub mod message;
pub mod pubsub;
pub mod service;
pub mod worker;

pub use message::{
    BlockRequestReceiver, BlockRequestSender, BlockResponseReceiver, BlockResponseSender, Message,
};
pub use pubsub::Event;
pub use service::{BlockConfig, BlockService};

pub use worker::IsValidator;
