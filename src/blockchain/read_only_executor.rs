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

#[cfg(feature = "indexer")]
use crate::blockchain::indexer::{Indexer, StoreAssetDb};

use crate::{
    base::{
        schema::{SmartContractEvent, FUEL_LIMIT},
        Mutex, RwLock,
    },
    crypto::{drand::SeedSource, Hash},
    db::{Db, DbFork},
    wm::{get_fuel_consumed_for_error, CtxArgs, Wm, MAX_FUEL},
    ErrorKind, Receipt,
};

use std::{sync::Arc, time::SystemTime};

#[cfg(feature = "rt-monitor")]
use crate::network_monitor::{
    tools::send_update,
    types::{Action, Event as MonitorEvent},
};

#[cfg(feature = "rt-monitor")]
use crate::base::schema::BlockchainSettings;

/// Result struct for bulk transaction
#[derive(Serialize, Deserialize)]
pub struct BulkResult {
    success: bool,
    result: Vec<u8>,
    fuel_consumed: u64,
}

// /// Block values when a block is executed to sync
// struct BlockValues {
//     exp_hash: Option<Hash>,
//     signature: Option<Vec<u8>>,
//     validator: Option<PublicKey>,
//     timestamp: u64,
// }

// Struct that holds the consume fuel return value
#[derive(Serialize, Deserialize)]
struct ConsumeFuelReturns {
    success: bool,
    units: u64,
}

// struct BurnFuelArgs {
//     account: String,
//     fuel_to_burn: u64,
//     fuel_limit: u64,
// }

/// Executor context data.
pub(crate) struct Executor<D: Db, W: Wm> {
    /// Instance of a type implementing Database trait.
    db: Arc<RwLock<D>>,
    /// Instance of a type implementing Wasm Machine trait.
    wm: Arc<Mutex<W>>,
    /// Burn fuel method
    burn_fuel_method: String,
    /// Drand Seed
    seed: Arc<SeedSource>,
    /// Validator flag
    is_validator: Arc<bool>,
    #[cfg(feature = "indexer")]
    /// Indexer structure
    indexer: Indexer,
}

impl<D: Db, W: Wm> Clone for Executor<D, W> {
    fn clone(&self) -> Self {
        Executor {
            db: self.db.clone(),
            wm: self.wm.clone(),
            burn_fuel_method: self.burn_fuel_method.clone(),
            seed: self.seed.clone(),
            is_validator: self.is_validator.clone(),
            #[cfg(feature = "indexer")]
            indexer: self.indexer.clone(),
        }
    }
}

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

// // DELETE
// fn log_wm_fuel_consumed_bt(tx: &UnsignedTransaction, fuel_consumed: u64) {
//     log_wm_fuel_consumed(
//         &hex::encode(tx.data.primary_hash().as_bytes()),
//         tx.data.get_account(),
//         tx.data.get_method(),
//         tx.data.get_args(),
//         fuel_consumed,
//     )
// }

// struct HandleTransactionReturns {
//     burn_fuel_args: BurnFuelArgs,
//     receipt: Receipt,
//     #[cfg(feature = "indexer")]
//     store_asset_db: Vec<StoreAssetDb>,
// }

impl<D: Db, W: Wm> Executor<D, W> {
    /// Constructs a new executor.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        db: Arc<RwLock<D>>,
        wm: Arc<Mutex<W>>,
        seed: Arc<SeedSource>,
        #[cfg(feature = "indexer")] indexer: Indexer,
    ) -> Self {
        Executor {
            db,
            wm,
            burn_fuel_method: String::new(),
            seed,
            is_validator: Arc::new(false),
            #[cfg(feature = "indexer")]
            indexer,
        }
    }

    // // Allows to set the burn fuel method
    // pub fn set_burn_fuel_method(&mut self, burn_fuel_method: String) {
    //     self.burn_fuel_method = burn_fuel_method;
    // }

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

    // fn call_burn_fuel(
    //     &self,
    //     fork: &mut <D as Db>::DbForkType,
    //     burn_fuel_method: &str,
    //     origin: &str,
    //     fuel: u64,
    //     block_timestamp: u64,
    // ) -> (u64, Result<Vec<u8>>) {
    //     let args = value!({
    //         "from": origin,
    //         "units": fuel
    //     });

    //     let args = match rmp_serialize(&args) {
    //         Ok(value) => value,
    //         Err(_) => {
    //             // Note: this should not happen
    //             panic!();
    //         }
    //     };
    //     let account = match fork.load_account(SERVICE_ACCOUNT_ID) {
    //         Some(acc) => acc,
    //         None => {
    //             return (
    //                 0,
    //                 Err(Error::new_ext(ErrorKind::Other, "Service not found")),
    //             )
    //         }
    //     };
    //     let service_app_hash = match account.contract {
    //         Some(contract) => contract,
    //         None => {
    //             return (
    //                 0,
    //                 Err(Error::new_ext(ErrorKind::Other, "Service has no contract")),
    //             )
    //         }
    //     };

    //     self.wm.lock().call(
    //         fork,
    //         0,
    //         SERVICE_ACCOUNT_ID,
    //         SERVICE_ACCOUNT_ID,
    //         SERVICE_ACCOUNT_ID,
    //         SERVICE_ACCOUNT_ID,
    //         service_app_hash,
    //         burn_fuel_method,
    //         &args,
    //         self.seed.clone(),
    //         &mut vec![],
    //         #[cfg(feature = "indexer")]
    //         &mut vec![],
    //         MAX_FUEL,
    //         block_timestamp,
    //     )
    // }

    // // Tries to burn fuel from the origin account
    // fn try_burn_fuel(
    //     &self,
    //     fork: &mut <D as Db>::DbForkType,
    //     burn_fuel_method: &str,
    //     burn_fuel_args: BurnFuelArgs,
    //     block_timestamp: u64,
    // ) -> (bool, u64) {
    //     let mut global_result: bool = true;
    //     let mut global_burned_fuel = 0;

    //     let mut max_fuel_result = true;

    //     if burn_fuel_method.is_empty() {
    //         return (true, 0);
    //     }

    //     let fuel = if burn_fuel_args.fuel_to_burn > burn_fuel_args.fuel_limit {
    //         max_fuel_result = false;
    //         burn_fuel_args.fuel_limit
    //     } else {
    //         burn_fuel_args.fuel_to_burn
    //     };

    //     // Call to consume fuel
    //     let (_, result) = self.call_burn_fuel(
    //         fork,
    //         burn_fuel_method,
    //         &burn_fuel_args.account,
    //         fuel,
    //         block_timestamp,
    //     );
    //     match result {
    //         Ok(value) => match rmp_deserialize::<ConsumeFuelReturns>(&value) {
    //             Ok(res) => {
    //                 global_result &= res.success & max_fuel_result;
    //                 global_burned_fuel += res.units;
    //             }
    //             Err(_) => {
    //                 global_result = false;
    //             }
    //         },
    //         Err(_) => global_result = false,
    //     }

    //     (global_result, global_burned_fuel)
    // }

    // fn emit_events(&mut self, events: &[SmartContractEvent]) {
    //     if self.pubsub.lock().has_subscribers(Event::CONTRACT_EVENTS) {
    //         events.iter().for_each(|event| {
    //             // Notify subscribers about contract events
    //             let msg = Message::GetContractEvent {
    //                 event: event.clone(),
    //             };

    //             self.pubsub.lock().publish(Event::CONTRACT_EVENTS, msg);
    //         });
    //     }
    // }

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
                .lock()
                .app_hash_check(fork, contract, ctx_args, seed.clone(), block_timestamp);

        match app_hash {
            Ok(app_hash) => {
                let mut events: Vec<SmartContractEvent> = vec![];

                let (fuel_consumed, result) = self.wm.lock().call(
                    fork,
                    0,
                    &network,
                    &origin,
                    &target,
                    &origin,
                    app_hash,
                    &method,
                    &args,
                    self.seed.clone(),
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
