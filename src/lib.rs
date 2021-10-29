mod tpm;
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

// External crates macros.
#[macro_use]
extern crate serde;
#[macro_use]
extern crate log;

// Internal modules.
#[macro_use]
mod macros;

// Public modules.
pub mod base;
pub mod blockchain;
pub mod channel;
pub mod crypto;
pub mod db;
pub mod error;
pub mod wm;

// Optional public modules.
#[cfg(feature = "bridge")]
pub mod bridge;
#[cfg(feature = "tpm")]
pub mod tpm;
#[cfg(feature = "p2p")]
pub mod p2p;
#[cfg(feature = "rest")]
pub mod rest;

pub use base::{Account, Block, Receipt, Transaction, TransactionData};
pub use blockchain::{BlockConfig, BlockService, Message};
pub use crypto::{KeyPair, PublicKey};
pub use error::{Error, ErrorKind, Result};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const VERSION_MAJOR: &str = env!("CARGO_PKG_VERSION_MAJOR");
pub const VERSION_MINOR: &str = env!("CARGO_PKG_VERSION_MINOR");
pub const VERSION_PATCH: &str = env!("CARGO_PKG_VERSION_PATCH");
pub const VERSION_PRE: &str = env!("CARGO_PKG_VERSION_PRE");
