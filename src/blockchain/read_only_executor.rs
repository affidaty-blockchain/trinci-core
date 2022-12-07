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

//! Blockchain component in charge of confirmed blocks transactions execution.
//!
//! Transactions are pulled from the confirmed pool blocks and executed in the
//! exact same order as declared in the block.
//!
//! When the confirmed block contains a block-header hash the executor checks
//! that the hash resulting from the local execution is equal to the expected
//! one before committing the execution changes.

use crate::{
    base::{
        schema::{SmartContractEvent, FUEL_LIMIT},
        Mutex, RwLock,
    },
    crypto::{drand::SeedSource, Hash},
    db::{Db, DbFork},
    wm::{get_fuel_consumed_for_error, CtxArgs, Wm, WmLocal, MAX_FUEL},
    ErrorKind, Receipt,
};

use std::{sync::Arc, time::SystemTime};

/// Result struct for bulk transaction
#[derive(Serialize, Deserialize)]
pub struct BulkResult {
    success: bool,
    result: Vec<u8>,
    fuel_consumed: u64,
}

// Struct that holds the consume fuel return value
#[derive(Serialize, Deserialize)]
struct ConsumeFuelReturns {
    success: bool,
    units: u64,
}

/// Executor context data.
pub(crate) struct Executor<D: Db> {
    /// Instance of a type implementing Database trait.
    db: Arc<RwLock<D>>,
    /// Instance of a type implementing Wasm Machine trait.
    wm: WmLocal,
    /// Burn fuel method
    burn_fuel_method: String,
    /// Drand Seed
    seed: Arc<SeedSource>,
    /// Validator flag
    is_validator: Arc<bool>,
}

// impl<D: Db> Clone for Executor<D> {
//     fn clone(&self) -> Self {
//         Executor {
//             db: self.db.clone(),
//             wm: self.wm.clone(),
//             burn_fuel_method: self.burn_fuel_method.clone(),
//             seed: self.seed.clone(),
//             is_validator: self.is_validator.clone(),
//             #[cfg(feature = "indexer")]
//             indexer: self.indexer.clone(),
//         }
//     }
// }

// DELETE
fn log_wm_fuel_consumed(hash: &str, account: &str, method: &str, data: &[u8], fuel_consumed: u64) {
    let (data, data_suffix) = {
        if data.len() > 250 {
            (&data[0..250], format!("...{}", data.len()))
        } else {
            (data, "".to_string())
        }
    };

    debug!(
        "\nTX: {:?}\n\taccount: {}\n\tmethod: {}\n\targs: {}{}\n\tburned_wt_fuel: {}\n",
        hash,
        account,
        method,
        hex::encode(&data),
        data_suffix,
        fuel_consumed
    );
}

// DELETE
fn log_wm_fuel_consumed_st(
    hash: Hash,
    origin: String,
    method: String,
    args: &[u8],
    fuel_consumed: u64,
) {
    log_wm_fuel_consumed(
        &hex::encode(hash.as_bytes()),
        &origin,
        &method,
        args,
        fuel_consumed,
    )
}

impl<D: Db> Executor<D> {
    /// Constructs a new executor.
    #[allow(clippy::too_many_arguments)]
    pub fn new(db: Arc<RwLock<D>>, seed: Arc<SeedSource>) -> Self {
        let wm = WmLocal::new(10);

        Executor {
            db,
            wm,
            burn_fuel_method: String::new(),
            seed,
            is_validator: Arc::new(false),
        }
    }

    // Calculates the fuel consumed by the transaction execution
    fn calculate_burned_fuel(&self, wm_fuel: u64) -> u64 {
        // TODO find a f(_wm_fuel) to calculate the fuel in TRINCI
        warn!("calculate_burned_fuel::{}", wm_fuel);
        // wm_fuel
        if wm_fuel == 0 {
            0
        } else {
            FUEL_LIMIT
        }
    }

    // Calculated the max fuel allow to spend
    // from the tx fuel_limit field
    fn calculate_internal_fuel_limit(&self, _fuel_limit: u64) -> u64 {
        // TODO create a method the get the fuel_limit
        MAX_FUEL
    }

    pub fn exec(
        &mut self,
        fork: &mut <D as Db>::DbForkType,
        max_fuel: u64,
        origin: String,
        target: String,
        contract: Option<Hash>,
        method: String,
        args: Vec<u8>,
        network: String,
    ) -> Receipt {
        fork.flush();

        let initial_fuel = self.calculate_internal_fuel_limit(max_fuel);

        let ctx_args = CtxArgs {
            origin: &origin,
            owner: &target,
            caller: &origin,
        };

        let hash_hex: &str =
            "c4221220879ecb0adedfa6a8aa19d972d225c3ce74d95619fda302ab4090fcff2ab45e6f";
        let hash = Hash::from_hex(&hash_hex[4..]).unwrap();

        let seed = Arc::new(SeedSource::new(
            network.clone(),
            hash.to_bytes(),
            hash,
            hash,
            hash,
        ));

        let block_timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let app_hash =
            self.wm
                .app_hash_check(fork, contract, ctx_args, seed.clone(), block_timestamp);

        match app_hash {
            Ok(app_hash) => {
                let mut events: Vec<SmartContractEvent> = vec![];

                // TODO: call ro_call: it replace hf_drand w/ hf_ephemeral_drand

                let (fuel_consumed, result) = self.wm.call(
                    fork,
                    0,
                    &network,
                    &origin,
                    &target,
                    &origin,
                    app_hash,
                    &method,
                    &args,
                    seed.clone(),
                    &mut events,
                    #[cfg(feature = "indexer")]
                    &mut store_asset_db,
                    initial_fuel,
                    block_timestamp,
                );

                if result.is_err() {
                    fork.rollback();
                }
                let events = if events.is_empty() {
                    None
                } else {
                    Some(events)
                };

                // On error, receipt data shall contain the full error description
                // only if error kind is a SmartContractFailure. This is to prevent
                // internal error conditions leaks to the user.
                let (success, returns) = match result {
                    Ok(value) => (true, value),
                    Err(err) => {
                        let msg = match err.kind {
                            ErrorKind::SmartContractFault | ErrorKind::ResourceNotFound => {
                                err.to_string_full()
                            }
                            _ => err.to_string(),
                        };
                        debug!("Execution failure: {}", msg);
                        (false, msg.as_bytes().to_vec())
                    }
                };

                // FIXME LOG REAL CONSUMPTION
                log_wm_fuel_consumed_st(hash, origin, method, &args, fuel_consumed);

                // Total fuel burned
                let burned_fuel = self.calculate_burned_fuel(fuel_consumed);

                fork.rollback();

                debug!("seed: {:?}", seed);

                return Receipt {
                    height: 0,
                    burned_fuel,
                    index: 0 as u32,
                    success,
                    returns,
                    events,
                };
            }
            Err(e) => {
                fork.rollback();

                Receipt {
                    height: 0,
                    burned_fuel: get_fuel_consumed_for_error(), // FIXME * How much should the caller pay for this operation?
                    index: 0 as u32,
                    success: false,
                    returns: e.to_string_full().as_bytes().to_vec(),
                    events: None,
                }
            }
        }
    }
}
