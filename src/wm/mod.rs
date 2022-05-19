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

//! WASM machine module.
//!
//! The module provides a generic WM trait plus a local implementation
//! using wasmtime.

use std::sync::Arc;

use crate::{
    base::schema::SmartContractEvent,
    crypto::{drand::SeedSource, Hash},
    db::DbFork,
    Result,
};

pub mod host_func;
#[cfg(feature = "with-wasmtime")]
pub mod local;

#[cfg(test)]
use mockall::automock;

#[cfg(feature = "with-wasmtime")]
pub use local::WmLocal;

/// Web-Assembly machine trait.
#[cfg_attr(test, automock)]
pub trait Wm: Send + 'static {
    /// Execute the smart contract method as defined within the `data` parameter.
    /// It is required to pass the database to contextualize the operations.
    #[allow(clippy::too_many_arguments)]
    fn call(
        &mut self,
        db: &mut dyn DbFork,
        depth: u16,
        network: &str,
        origin: &str,
        owner: &str,
        caller: &str,
        contract: Hash,
        method: &str,
        args: &[u8],
        seed: Arc<SeedSource>,
        events: &mut Vec<SmartContractEvent>,
        initial_fuel: u64,
        block_timestamp: u64,
    ) -> (u64, Result<Vec<u8>>);

    /// Execute the smart contract `is_callable` method
    /// It is required to pass the database to contextualize the operations.
    #[allow(clippy::too_many_arguments)]
    fn callable_call(
        &mut self,
        db: &mut dyn DbFork,
        depth: u16,
        network: &str,
        origin: &str,
        owner: &str,
        caller: &str,
        contract: Hash,
        args: &[u8],
        seed: Arc<SeedSource>,
        events: &mut Vec<SmartContractEvent>,
        initial_fuel: u64,
        block_timestamp: u64,
    ) -> (u64, Result<i32>);

    fn app_hash_check<'a>(
        &mut self,
        db: &mut dyn DbFork,
        app_hash: Option<Hash>,
        ctx_args: CtxArgs<'a>,
        seed: Arc<SeedSource>,
        block_timestamp: u64,
    ) -> Result<Hash>;

    fn contract_updatable<'a>(
        &mut self,
        fork: &mut dyn DbFork,
        hash_args: CheckHashArgs<'a>,
        ctx_args: CtxArgs<'a>,
        seed: Arc<SeedSource>,
        block_timestamp: u64,
    ) -> bool;
}

pub struct CheckHashArgs<'a> {
    pub account: &'a str,
    pub current_hash: Option<Hash>,
    pub new_hash: Option<Hash>,
}

pub struct CtxArgs<'a> {
    pub origin: &'a str,
    pub owner: &'a str,
    pub caller: &'a str,
}

pub const MAX_FUEL: u64 = 1_000_000_000; // Internal wm fuel units

/// Structure passed from the host to the wasm smart contracts.
/// WARNING: ANY MODIFICATION CAN BREAK COMPATIBILITY WITH THE CORE
#[derive(Serialize, Deserialize)]
#[cfg_attr(test, derive(Debug, PartialEq))]
struct AppInput<'a> {
    /// Nested call depth.
    depth: u16,
    /// Network identifier (from Tx)
    network: &'a str,
    /// Identifier of the account that the method is targeting.
    owner: &'a str,
    /// Caller's identifier.
    caller: &'a str,
    /// Method name.
    method: &'a str,
    /// Original transaction submitter (from Tx)
    origin: &'a str,
}

/// Structure returned from the wasm smart contracts to the host.
/// WARNING: ANY MODIFICATION CAN BREAK COMPATIBILITY WITH THE CORE
#[derive(Serialize, Deserialize)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct AppOutput<'a> {
    /// If the method has been executed successfully
    pub success: bool,
    /// Execution result data of success. Error string on failure.
    #[serde(with = "serde_bytes")]
    pub data: &'a [u8],
}
