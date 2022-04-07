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

use serde_value::value;

use super::{
    message::Message,
    pool::{BlockInfo, Pool},
    pubsub::{Event, PubSub},
    IsValidator,
};
use crate::{
    base::{
        schema::{
            Block, BlockData, BulkTransaction, SignedTransaction, SmartContractEvent,
            UnsignedTransaction,
        },
        serialize::{rmp_deserialize, rmp_serialize},
        Mutex, RwLock,
    },
    crypto::{drand::SeedSource, Hash, Hashable},
    db::{Db, DbFork},
    wm::{CtxArgs, Wm, MAX_FUEL},
    Error, ErrorKind, KeyPair, PublicKey, Receipt, Result, Transaction, SERVICE_ACCOUNT_ID,
};
use std::{collections::HashMap, sync::Arc};

/// Result struct for bulk transaction
#[derive(Serialize, Deserialize)]
pub struct BulkResult {
    success: bool,
    result: Vec<u8>,
    fuel_consumed: u64,
}

/// Block values when a block is executed to sync
struct BlockValues {
    exp_hash: Option<Hash>,
    signature: Option<Vec<u8>>,
    validator: Option<PublicKey>,
}

// Struct that holds the consume fuel return value
#[derive(Serialize, Deserialize)]
struct ConsumeFuelReturns {
    success: bool,
    units: u64,
}

struct BurnFuelArgs {
    account: String,
    fuel_to_burn: u64,
    fuel_limit: u64,
}

/// Executor context data.
pub(crate) struct Executor<D: Db, W: Wm> {
    /// Unconfirmed transactions pool
    pub pool: Arc<RwLock<Pool>>,
    /// Instance of a type implementing Database trait.
    db: Arc<RwLock<D>>,
    /// Instance of a type implementing Wasm Machine trait.
    wm: Arc<Mutex<W>>,
    /// PubSub subsystem to publish blockchain events.
    pubsub: Arc<Mutex<PubSub>>,
    /// Node keypair
    keypair: Arc<KeyPair>,
    /// Burn fuel method
    burn_fuel_method: String,
    /// Drand Seed
    seed: Arc<SeedSource>,
    /// P2P peer id
    p2p_id: String,
    /// Validator flag
    is_validator: Arc<bool>,
}

impl<D: Db, W: Wm> Clone for Executor<D, W> {
    fn clone(&self) -> Self {
        Executor {
            pool: self.pool.clone(),
            db: self.db.clone(),
            wm: self.wm.clone(),
            pubsub: self.pubsub.clone(),
            keypair: self.keypair.clone(),
            burn_fuel_method: self.burn_fuel_method.clone(),
            seed: self.seed.clone(),
            p2p_id: self.p2p_id.clone(),
            is_validator: self.is_validator.clone(),
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

    error!(
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
fn log_wm_fuel_consumed_st(tx: &SignedTransaction, fuel_consumed: u64) {
    log_wm_fuel_consumed(
        &hex::encode(tx.data.primary_hash().as_bytes()),
        tx.data.get_account(),
        tx.data.get_method(),
        tx.data.get_args(),
        fuel_consumed,
    )
}

// DELETE
fn log_wm_fuel_consumed_bt(tx: &UnsignedTransaction, fuel_consumed: u64) {
    log_wm_fuel_consumed(
        &hex::encode(tx.data.primary_hash().as_bytes()),
        tx.data.get_account(),
        tx.data.get_method(),
        tx.data.get_args(),
        fuel_consumed,
    )
}

impl<D: Db, W: Wm> Executor<D, W> {
    /// Constructs a new executor.
    pub fn new(
        pool: Arc<RwLock<Pool>>,
        db: Arc<RwLock<D>>,
        wm: Arc<Mutex<W>>,
        pubsub: Arc<Mutex<PubSub>>,
        keypair: Arc<KeyPair>,
        seed: Arc<SeedSource>,
        p2p_id: String,
    ) -> Self {
        Executor {
            pool,
            db,
            wm,
            pubsub,
            keypair,
            burn_fuel_method: String::new(),
            seed,
            p2p_id,
            is_validator: Arc::new(false),
        }
    }

    // Allows to set the burn fuel method
    pub fn set_burn_fuel_method(&mut self, burn_fuel_method: String) {
        self.burn_fuel_method = burn_fuel_method;
    }

    // Calculates the fuel consumed by the transaction execution
    fn calculate_burned_fuel(&self, wm_fuel: u64) -> u64 {
        // TODO find a f(_wm_fuel) to calculate the fuel in TRINCI
        warn!("calculate_burned_fuel::{}", wm_fuel);
        // wm_fuel
        1000
    }

    // Calculated the max fuel allow to spend
    // from the tx fuel_limit field
    fn calculate_internal_fuel_limit(&self, _fuel_limit: u64) -> u64 {
        // TODO create a method the get the fuel_limit
        MAX_FUEL
    }

    // Get the fuel spent when the tx generates an internal error
    fn get_fuel_consumed_for_error(&self) -> u64 {
        // TODO create a method the get the fuel_limit
        1000
    }

    fn call_burn_fuel(
        &self,
        fork: &mut <D as Db>::DbForkType,
        burn_fuel_method: &str,
        origin: &str,
        fuel: u64,
    ) -> (u64, Result<Vec<u8>>) {
        let args = value!({
            "from": origin,
            "units": fuel
        });

        let args = match rmp_serialize(&args) {
            Ok(value) => value,
            Err(_) => {
                // Note: this should not happen
                panic!();
            }
        };
        let account = match fork.load_account(SERVICE_ACCOUNT_ID) {
            Some(acc) => acc,
            None => {
                return (
                    0,
                    Err(Error::new_ext(ErrorKind::Other, "Service not found")),
                )
            }
        };
        let service_app_hash = match account.contract {
            Some(contract) => contract,
            None => {
                return (
                    0,
                    Err(Error::new_ext(ErrorKind::Other, "Service has no contract")),
                )
            }
        };

        self.wm.lock().call(
            fork,
            0,
            SERVICE_ACCOUNT_ID,
            SERVICE_ACCOUNT_ID,
            SERVICE_ACCOUNT_ID,
            SERVICE_ACCOUNT_ID,
            service_app_hash,
            burn_fuel_method,
            &args,
            self.seed.clone(),
            &mut vec![],
            MAX_FUEL,
        )
    }

    // Tries to burn fuel from the origin account
    fn try_burn_fuel(
        &self,
        fork: &mut <D as Db>::DbForkType,
        burn_fuel_method: &str,
        burn_fuel_args_array: Vec<BurnFuelArgs>,
    ) -> (bool, u64) {
        let mut global_result: bool = true;
        let mut global_burned_fuel = 0;

        for burn_fuel_args in burn_fuel_args_array {
            let mut max_fuel_result = true;

            if burn_fuel_method.is_empty() {
                return (true, 0);
            }

            let fuel = if burn_fuel_args.fuel_to_burn > burn_fuel_args.fuel_limit {
                max_fuel_result = false;
                burn_fuel_args.fuel_limit
            } else {
                burn_fuel_args.fuel_to_burn
            };

            // Call to consume fuel
            let (_, result) =
                self.call_burn_fuel(fork, burn_fuel_method, &burn_fuel_args.account, fuel);
            match result {
                Ok(value) => match rmp_deserialize::<ConsumeFuelReturns>(&value) {
                    Ok(res) => {
                        global_result &= res.success & max_fuel_result;
                        global_burned_fuel += res.units;
                    }
                    Err(_) => {
                        global_result = false;
                    }
                },
                Err(_) => global_result = false,
            }
        }
        (global_result, global_burned_fuel)
    }

    fn handle_unit_transaction(
        &mut self,
        tx: &SignedTransaction,
        fork: &mut <D as Db>::DbForkType,
        height: u64,
        index: u32,
        mut events: Vec<SmartContractEvent>,
    ) -> (Vec<BurnFuelArgs>, Receipt) {
        let initial_fuel = self.calculate_internal_fuel_limit(tx.data.get_fuel_limit());

        let ctx_args = CtxArgs {
            origin: &tx.data.get_caller().to_account_id(),
            owner: tx.data.get_account(),
            caller: &tx.data.get_caller().to_account_id(),
        };
        let app_hash = self.wm.lock().app_hash_check(
            fork,
            *tx.data.get_contract(),
            ctx_args,
            self.seed.clone(),
        );

        match app_hash {
            Ok(app_hash) => {
                let (fuel_consumed, result) = self.wm.lock().call(
                    fork,
                    0,
                    tx.data.get_network(),
                    &tx.data.get_caller().to_account_id(),
                    tx.data.get_account(),
                    &tx.data.get_caller().to_account_id(),
                    app_hash,
                    tx.data.get_method(),
                    tx.data.get_args(),
                    self.seed.clone(),
                    &mut events,
                    initial_fuel,
                );

                let event_tx = tx.data.primary_hash();
                events.iter_mut().for_each(|e| e.event_tx = event_tx);

                if result.is_err() {
                    fork.rollback();
                } else if self.pubsub.lock().has_subscribers(Event::CONTRACT_EVENTS) {
                    events.iter().for_each(|event| {
                        // Notify subscribers about contract events
                        let msg = Message::GetContractEvent {
                            event: event.clone(),
                        };

                        self.pubsub.lock().publish(Event::CONTRACT_EVENTS, msg);
                    });
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
                log_wm_fuel_consumed_st(tx, fuel_consumed);

                // Total fuel burned
                let burned_fuel = self.calculate_burned_fuel(fuel_consumed);

                (
                    vec![BurnFuelArgs {
                        account: tx.data.get_caller().to_account_id(),
                        fuel_to_burn: burned_fuel,
                        fuel_limit: tx.data.get_fuel_limit(),
                    }],
                    Receipt {
                        height,
                        burned_fuel,
                        index: index as u32,
                        success,
                        returns,
                        events,
                    },
                )
            }
            Err(e) => (
                vec![BurnFuelArgs {
                    account: tx.data.get_caller().to_account_id(),
                    fuel_to_burn: self.get_fuel_consumed_for_error(), // FIXME * How much should the caller pay for this operation?
                    fuel_limit: tx.data.get_fuel_limit(),
                }],
                Receipt {
                    height,
                    burned_fuel: self.get_fuel_consumed_for_error(), // FIXME * How much should the caller pay for this operation?
                    index: index as u32,
                    success: false,
                    returns: e.to_string().as_bytes().to_vec(),
                    events: None,
                },
            ),
        }
    }

    fn handle_bulk_transaction(
        &mut self,
        tx: &BulkTransaction,
        fork: &mut <D as Db>::DbForkType,
        height: u64,
        index: u32,
        mut events: Vec<SmartContractEvent>,
    ) -> (Vec<BurnFuelArgs>, Receipt) {
        let mut results = HashMap::new();
        let mut execution_fail = false;
        let mut burned_fuel = 0;

        let mut burn_fuel_args = Vec::<BurnFuelArgs>::new();

        let (events, results) = match &tx.data {
            crate::base::schema::TransactionData::BulkV1(bulk_tx) => {
                let root_tx = &bulk_tx.txs.root;
                let hash = root_tx.data.primary_hash();
                let mut bulk_events: Vec<SmartContractEvent> = vec![];

                let initial_fuel =
                    self.calculate_internal_fuel_limit(root_tx.data.get_fuel_limit());

                let ctx_args = CtxArgs {
                    origin: &root_tx.data.get_caller().to_account_id(),
                    owner: root_tx.data.get_account(),
                    caller: &root_tx.data.get_caller().to_account_id(),
                };

                let app_hash = match self.wm.lock().app_hash_check(
                    fork,
                    *root_tx.data.get_contract(),
                    ctx_args,
                    self.seed.clone(),
                ) {
                    Ok(app_hash) => app_hash,
                    Err(e) => {
                        let root_fuel = BurnFuelArgs {
                            account: root_tx.data.get_caller().to_account_id(),
                            fuel_to_burn: self.get_fuel_consumed_for_error(), // FIXME * How much should the caller pay for this operation?
                            fuel_limit: root_tx.data.get_fuel_limit(),
                        };

                        return (
                            vec![root_fuel],
                            Receipt {
                                height,
                                index,
                                burned_fuel: self.get_fuel_consumed_for_error(), // FIXME * How much should the caller pay for this operation?
                                success: false,
                                returns: e.to_string().as_bytes().to_vec(),
                                events: None,
                            },
                        );
                    }
                };

                let (fuel_consumed, result) = self.wm.lock().call(
                    fork,
                    0,
                    root_tx.data.get_network(),
                    &root_tx.data.get_caller().to_account_id(),
                    root_tx.data.get_account(),
                    &root_tx.data.get_caller().to_account_id(),
                    app_hash,
                    root_tx.data.get_method(),
                    root_tx.data.get_args(),
                    self.seed.clone(),
                    &mut bulk_events,
                    initial_fuel,
                );

                burn_fuel_args.push(BurnFuelArgs {
                    account: root_tx.data.get_caller().to_account_id(),
                    fuel_to_burn: fuel_consumed,
                    fuel_limit: root_tx.data.get_fuel_limit(),
                });

                // FIXME * LOG REAL CONSUMPTION
                log_wm_fuel_consumed_bt(root_tx, fuel_consumed);

                // Convert wm fuel in TRINCI
                let fuel_consumed = self.calculate_burned_fuel(fuel_consumed);

                burned_fuel += fuel_consumed;

                match result {
                    Ok(rcpt) => {
                        results.insert(
                            hex::encode(hash),
                            BulkResult {
                                success: true,
                                result: rcpt,
                                fuel_consumed,
                            },
                        );

                        let event_tx = hash;
                        bulk_events.iter_mut().for_each(|e| e.event_tx = event_tx);

                        if self.pubsub.lock().has_subscribers(Event::CONTRACT_EVENTS) {
                            bulk_events.iter().for_each(|bulk_event| {
                                // Notify subscribers about contract events
                                let msg = Message::GetContractEvent {
                                    event: bulk_event.clone(),
                                };

                                self.pubsub.lock().publish(Event::CONTRACT_EVENTS, msg);
                            });
                        }

                        events.append(&mut bulk_events);
                    }
                    Err(error) => {
                        execution_fail = true;
                        results.insert(
                            hex::encode(hash),
                            BulkResult {
                                success: false,
                                result: error.to_string().as_bytes().to_vec(),
                                fuel_consumed,
                            },
                        );
                    }
                }
                if !execution_fail {
                    if let Some(nodes) = &bulk_tx.txs.nodes {
                        for node in nodes {
                            let mut bulk_events: Vec<SmartContractEvent> = vec![];

                            let initial_fuel =
                                self.calculate_internal_fuel_limit(node.data.get_fuel_limit());
                            let ctx_args = CtxArgs {
                                origin: &node.data.get_caller().to_account_id(),
                                owner: node.data.get_account(),
                                caller: &node.data.get_caller().to_account_id(),
                            };

                            let mut t_wm = self.wm.lock();

                            match t_wm.app_hash_check(
                                fork,
                                *node.data.get_contract(),
                                ctx_args,
                                self.seed.clone(),
                            ) {
                                Ok(app_hash) => {
                                    let (fuel_consumed, result) = t_wm.call(
                                        fork,
                                        0,
                                        node.data.get_network(),
                                        &node.data.get_caller().to_account_id(),
                                        node.data.get_account(),
                                        &node.data.get_caller().to_account_id(),
                                        app_hash,
                                        node.data.get_method(),
                                        node.data.get_args(),
                                        self.seed.clone(),
                                        &mut bulk_events,
                                        initial_fuel,
                                    );
                                    burn_fuel_args.push(BurnFuelArgs {
                                        account: node.data.get_caller().to_account_id(),
                                        fuel_to_burn: fuel_consumed,
                                        fuel_limit: node.data.get_fuel_limit(),
                                    });
                                    // FIXME * LOG REAL CONSUMPTION
                                    log_wm_fuel_consumed_st(node, fuel_consumed);

                                    // Convert wm fuel in TRINCI
                                    let fuel_consumed = self.calculate_burned_fuel(fuel_consumed);

                                    burned_fuel += fuel_consumed;

                                    match result {
                                        Ok(rcpt) => {
                                            results.insert(
                                                hex::encode(node.data.primary_hash()),
                                                BulkResult {
                                                    success: true,
                                                    result: rcpt,
                                                    fuel_consumed,
                                                },
                                            );

                                            let event_tx = node.data.primary_hash();
                                            bulk_events
                                                .iter_mut()
                                                .for_each(|e| e.event_tx = event_tx);

                                            if self
                                                .pubsub
                                                .lock()
                                                .has_subscribers(Event::CONTRACT_EVENTS)
                                            {
                                                bulk_events.iter().for_each(|bulk_event| {
                                                    // Notify subscribers about contract events
                                                    let msg = Message::GetContractEvent {
                                                        event: bulk_event.clone(),
                                                    };

                                                    self.pubsub
                                                        .lock()
                                                        .publish(Event::CONTRACT_EVENTS, msg);
                                                });
                                            }

                                            events.append(&mut bulk_events);
                                        }
                                        Err(error) => {
                                            results.insert(
                                                hex::encode(node.data.primary_hash()),
                                                BulkResult {
                                                    success: false,
                                                    result: error.to_string().as_bytes().to_vec(),
                                                    fuel_consumed,
                                                },
                                            );
                                            execution_fail = true;
                                            break;
                                        }
                                    }
                                }
                                Err(e) => {
                                    results.insert(
                                        hex::encode(node.data.primary_hash()),
                                        BulkResult {
                                            success: false,
                                            result: e.to_string().as_bytes().to_vec(),
                                            fuel_consumed: self.get_fuel_consumed_for_error(), // FIXME * How much should the caller pay for this operation?
                                        },
                                    );
                                    execution_fail = true;
                                }
                            }
                        }
                    }
                }
                if execution_fail {
                    fork.rollback();
                }

                let events = if events.is_empty() {
                    None
                } else {
                    Some(events)
                };

                (events, rmp_serialize(&results))
            }
            // This should never happen because previous controls
            // maybe warn
            _ => {
                fork.rollback();

                (None, rmp_serialize(&results))
            } // Receipt should be empty?
        };
        let burned_fuel = self.calculate_burned_fuel(burned_fuel);

        (
            burn_fuel_args,
            Receipt {
                height,
                index,
                burned_fuel,
                success: !execution_fail,
                returns: results.unwrap_or_default(),
                events,
            },
        )
    }

    fn exec_transaction(
        &mut self,
        tx: &Transaction,
        fork: &mut <D as Db>::DbForkType,
        height: u64,
        index: u32,
        burn_fuel_method: &str,
    ) -> Receipt {
        fork.flush();

        let events: Vec<SmartContractEvent> = vec![];

        let (fuel_to_burn, mut receipt) = match tx {
            Transaction::UnitTransaction(tx) => {
                self.handle_unit_transaction(tx, fork, height, index, events)
            }
            Transaction::BulkTransaction(tx) => {
                self.handle_bulk_transaction(tx, fork, height, index, events)
            }
        };

        // Try to burn fuel from the caller account
        let (res_burning, mut burned) = self.try_burn_fuel(fork, burn_fuel_method, fuel_to_burn);
        if res_burning {
            receipt.burned_fuel = burned;
            receipt
        } else {
            // Fuel consumption error, the transaction needs to fail
            fork.rollback();
            // Try again to burn fuel. Ignoring the result.
            if self
                .call_burn_fuel(
                    fork,
                    burn_fuel_method,
                    &tx.get_caller().to_account_id(),
                    burned,
                )
                .1
                .is_err()
            {
                burned = 0;
            }

            return Receipt {
                height,
                index,
                burned_fuel: burned,
                success: false,
                returns: String::from("error burning fuel").as_bytes().to_vec(),
                events: receipt.events,
            };
        }
    }

    /// Returns a vector of executed transactions
    fn exec_transactions(
        &mut self,
        fork: &mut <D as Db>::DbForkType,
        height: u64,
        txs_hashes: &[Hash],
    ) -> Vec<Hash> {
        let mut rxs_hashes = vec![];

        for (index, hash) in txs_hashes.iter().enumerate() {
            debug!("Executing transaction: {}", hex::encode(hash));

            // Execute the transaction.
            let tx = match self.pool.read().txs.get(hash) {
                Some(Some(tx)) => tx.to_owned(),
                _ => panic!(
                    "Unexpected missing transaction during execution: {}",
                    hex::encode(hash)
                ),
            };

            let rx = self.exec_transaction(
                &tx,
                fork,
                height,
                index as u32,
                &self.burn_fuel_method.clone(),
            );

            rxs_hashes.push(rx.primary_hash());

            fork.store_transaction(hash, tx);
            fork.store_receipt(hash, rx);
        }

        rxs_hashes
    }

    // Draft version of the logic to be actuated for block construction.
    // Final code can follow a much more complex logic that takes consensus into
    // consideration.
    fn exec_block(
        &mut self,
        height: u64,
        txs_hashes: &[Hash],
        prev_hash: Hash,
        block_info: BlockValues,
        is_validator: bool,
        is_validator_closure: Arc<dyn IsValidator>,
    ) -> Result<Hash> {
        debug!("EXEC BLOCK: {}", height);
        // Write on a fork.
        let mut fork = self.db.write().fork_create();

        // Get a vector of executed transactions hashes.
        let rxs_hashes = self.exec_transactions(&mut fork, height, txs_hashes);

        let txs_hash = fork.store_transactions_hashes(height, txs_hashes.to_owned());
        let rxs_hash = fork.store_receipts_hashes(height, rxs_hashes);

        let validator = match block_info.validator.clone() {
            Some(pk) => Some(pk),
            None => {
                if height == 0 {
                    None
                } else {
                    Some(self.keypair.public_key())
                }
            }
        };

        // Construct a new block.
        let data = BlockData::new(
            validator,
            height,
            txs_hashes.len() as u32,
            prev_hash,
            txs_hash,
            rxs_hash,
            fork.state_hash(""),
        );

        // Verify the block signature
        if let Some(pk) = block_info.validator {
            if let Some(ref sig) = block_info.signature {
                let buf = rmp_serialize(&data)?;
                if !pk.verify(&buf, sig) {
                    return Err(Error::new_ext(ErrorKind::Other, "bad block signature"));
                };
                // Check that the signer is a validator.
                match is_validator_closure(pk.to_account_id()) {
                    Ok(res) => {
                        if !res {
                            return Err(Error::new_ext(
                                ErrorKind::Other,
                                "unexpected block validator",
                            ));
                        }
                    }
                    Err(_) => {
                        return Err(Error::new_ext(
                            ErrorKind::Other,
                            "unexpected error in block validator check",
                        ));
                    }
                }
            }
        }

        let buf = rmp_serialize(&data)?;

        let signature = if height == 0 {
            vec![0u8; 5]
        } else if block_info.signature.is_some() {
            block_info.signature.unwrap()
        } else {
            self.keypair.sign(&buf)?
        };

        let block_hash = data.primary_hash();

        let block = Block { data, signature };

        if let Some(exp_hash) = block_info.exp_hash {
            if exp_hash != block_hash {
                // Something has gone wrong.
                return Err(Error::new_ext(ErrorKind::Other, "unexpected block hash"));
            }
        }

        fork.store_block(block.clone());

        // Final step, merge the fork.
        self.db.write().fork_merge(fork)?;

        if is_validator && self.pubsub.lock().has_subscribers(Event::BLOCK) {
            // Notify subscribers about block generation.
            let msg = Message::GetBlockResponse {
                block,
                txs: Some(txs_hashes.to_owned()),
                origin: None, // send it in gossip
            };
            self.pubsub.lock().publish(Event::BLOCK, msg);
        }

        if is_validator {
            let node_account_id = self.keypair.public_key().to_account_id();
            let valid = (*is_validator_closure)(node_account_id).unwrap_or_default();
            self.is_validator = Arc::new(valid);
        }

        Ok(block_hash)
    }

    /// Check if the executor can be run to produce the block at the given height.
    /// If `height` is `u64::MAX` the test is performed using the height after
    /// the last block in the database.
    pub fn can_run(&self, mut height: u64) -> bool {
        if height == u64::MAX {
            height = self
                .db
                .read()
                .load_block(u64::MAX)
                .map(|blk| blk.data.height + 1)
                .unwrap_or_default();
        }
        let pool = self.pool.read();
        match pool.confirmed.get(&height) {
            Some(BlockInfo {
                hash: _,
                signature: _,
                validator: _,
                txs_hashes: Some(hashes),
            }) => {
                debug!("\tcan run height: {}", height);
                debug!(
                    "\t\t{:?}",
                    hashes
                        .iter()
                        .all(|hash| matches!(pool.txs.get(hash), Some(Some(_))))
                );
                debug!("\t\t{:?}", hashes.iter());
                hashes
                    .iter()
                    .all(|hash| matches!(pool.txs.get(hash), Some(Some(_)))) // it might not put tcx in pool
            }
            _ => false,
        }
    }

    pub fn run(&mut self, is_validator: bool, is_validator_closure: Arc<dyn IsValidator>) {
        let (mut prev_hash, mut height) = match self.db.read().load_block(u64::MAX) {
            Some(block) => (block.data.primary_hash(), block.data.height + 1),
            None => (Hash::default(), 0),
        };

        debug!("EXECUTOR:  last height: {}", height);

        // TODO Maybe change seed here?
        #[allow(clippy::while_let_loop)]
        loop {
            // Try to steal the hashes vector leaving the height slot busy.
            let (block_hash, block_signature, block_validator, txs_hashes) =
                match self.pool.write().confirmed.get_mut(&height) {
                    Some(BlockInfo {
                        hash,
                        signature,
                        validator,
                        txs_hashes: Some(hashes),
                    }) => (
                        *hash,
                        std::mem::take(signature),
                        std::mem::take(validator),
                        std::mem::take(hashes),
                    ),
                    _ => break,
                };

            debug!("Executing block {}", height);
            match self.exec_block(
                height,
                &txs_hashes,
                prev_hash,
                BlockValues {
                    exp_hash: block_hash,
                    signature: block_signature.clone(),
                    validator: block_validator.clone(),
                },
                is_validator,
                is_validator_closure.clone(),
            ) {
                Ok(hash) => {
                    let mut pool = self.pool.write();
                    pool.confirmed.remove(&height);
                    txs_hashes.iter().for_each(|hash| {
                        let _ = pool.txs.remove(hash);
                    });
                    prev_hash = hash;
                    height += 1;
                }
                Err(err) => {
                    let blk_info = BlockInfo {
                        hash: block_hash,
                        signature: block_signature,
                        validator: block_validator,
                        txs_hashes: Some(txs_hashes),
                    };
                    self.pool.write().confirmed.insert(height, blk_info);
                    error!("Block execution error: {}", err.to_string_full());
                    break;
                }
            }

            if !self.can_run(height) {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        base::{
            schema::{
                tests::FUEL_LIMIT, BulkTransaction, BulkTransactions, SignedTransaction,
                TransactionData, TransactionDataBulkNodeV1, TransactionDataBulkV1,
                UnsignedTransaction,
            },
            serialize::{rmp_deserialize, rmp_serialize},
        },
        blockchain::pool::tests::create_pool,
        crypto::{
            //drand::Drand,
            sign::tests::{create_test_keypair, create_test_public_key},
            HashAlgorithm,
        },
        db::*,
        wm::*,
        Error, ErrorKind, TransactionDataV1,
    };

    use serde_value::{value, Value};

    const BLOCK_HEX: &str = "929793a56563647361a9736563703338347231c461045936d631b849bb5760bcf62e0d1261b6b6e227dc0a3892cbeec91be069aaa25996f276b271c2c53cba4be96d67edcadd66b793456290609102d5401f413cd1b5f4130b9cfaa68d30d0d25c3704cb72734cd32064365ff7042f5a3eee09b06cc10103c4221220648263253df78db6c2f1185e832c546f2f7a9becbdc21d3be41c80dc96b86011c4221220f937696c204cc4196d48f3fe7fc95c80be266d210b95397cc04cfc6b062799b8c4221220dec404bd222542402ffa6b32ebaa9998823b7bb0a628152601d1da11ec70b867c422122005db394ef154791eed2cb97e7befb2864a5702ecfd44fab7ef1c5ca215475c7dc403000102";

    const TEST_WASM: &[u8] = include_bytes!("../wm/test.wasm");

    fn create_executor(db_fail: bool, fuel_limit: u64) -> Executor<MockDb, MockWm> {
        let pool = Arc::new(RwLock::new(create_pool(fuel_limit)));
        let db = Arc::new(RwLock::new(create_db_mock(db_fail)));
        let wm = Arc::new(Mutex::new(create_wm_mock()));
        let sub = Arc::new(Mutex::new(PubSub::new()));

        let keypair = Arc::new(crate::crypto::sign::tests::create_test_keypair());

        let nw_name = String::from("skynet");
        let nonce: Vec<u8> = vec![0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56];
        let prev_hash =
            Hash::from_hex("1220a4cea0f0f6eddc6865fd6092a319ccc6d2387cd8bb65e64bdc486f1a9a998569")
                .unwrap();
        let txs_hash =
            Hash::from_hex("1220a4cea0f1f6eddc6865fd6092a319ccc6d2387cf8bb63e64b4c48601a9a998569")
                .unwrap();
        let rxs_hash =
            Hash::from_hex("1220a4cea0f0f6edd46865fd6092a319ccc6d5387cd8bb65e64bdc486f1a9a998569")
                .unwrap();
        let seed = SeedSource::new(nw_name, nonce, prev_hash, txs_hash, rxs_hash);
        let seed = Arc::new(seed);

        let mut executor = Executor::new(
            pool,
            db,
            wm,
            sub,
            keypair,
            seed.clone(),
            "test_id".to_string(),
        );

        if fuel_limit < FUEL_LIMIT {
            executor.set_burn_fuel_method(String::from("burn_fuel_method"));
        }
        executor
    }

    fn create_executor_bulk(db_fail: bool, fuel_limit: u64) -> Executor<MockDb, MockWm> {
        let pool = Arc::new(RwLock::new(create_pool(fuel_limit)));
        let db = Arc::new(RwLock::new(create_db_mock(db_fail)));
        let wm = Arc::new(Mutex::new(create_wm_mock_bulk()));
        let sub = Arc::new(Mutex::new(PubSub::new()));

        let keypair = Arc::new(crate::crypto::sign::tests::create_test_keypair());

        let nw_name = String::from("skynet");
        let nonce: Vec<u8> = vec![0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56];
        let prev_hash =
            Hash::from_hex("1220a4cea0f0f6eddc6865fd6092a319ccc6d2387cd8bb65e64bdc486f1a9a998569")
                .unwrap();
        let txs_hash =
            Hash::from_hex("1220a4cea0f1f6eddc6865fd6092a319ccc6d2387cf8bb63e64b4c48601a9a998569")
                .unwrap();
        let rxs_hash =
            Hash::from_hex("1220a4cea0f0f6edd46865fd6092a319ccc6d5387cd8bb65e64bdc486f1a9a998569")
                .unwrap();
        let seed = SeedSource::new(nw_name, nonce, prev_hash, txs_hash, rxs_hash);
        let seed = Arc::new(seed);

        Executor::new(
            pool,
            db,
            wm,
            sub,
            keypair,
            seed.clone(),
            "test_id".to_string(),
        )
    }

    fn create_executor_drand(db_fail: bool, seed: Arc<SeedSource>) -> Executor<MockDb, MockWm> {
        let pool = Arc::new(RwLock::new(create_pool(FUEL_LIMIT)));
        let db = Arc::new(RwLock::new(create_db_mock(db_fail)));
        let wm = Arc::new(Mutex::new(create_wm_mock()));
        let sub = Arc::new(Mutex::new(PubSub::new()));

        let keypair = Arc::new(crate::crypto::sign::tests::create_test_keypair());

        Executor::new(pool, db, wm, sub, keypair, seed, "test_id".to_string())
    }

    fn create_db_mock(fail: bool) -> MockDb {
        let mut db = MockDb::new();
        db.expect_load_block().returning(|_| {
            let buf = hex::decode(BLOCK_HEX).unwrap();
            Some(rmp_deserialize(&buf).unwrap())
        });
        db.expect_fork_create().returning(create_fork_mock);
        db.expect_fork_merge().returning(move |_| match fail {
            false => Ok(()),
            true => Err(Error::new_ext(ErrorKind::DatabaseFault, "merge error")),
        });
        db
    }

    fn create_fork_mock() -> MockDbFork {
        let mut fork = MockDbFork::new();
        fork.expect_store_transaction().returning(|_, _| ());
        fork.expect_store_receipt().returning(|_, _| ());
        fork.expect_store_transactions_hashes().returning(|_, _| {
            Hash::from_hex("1220b950d8111feed13ad9ca7f2b8b81a3449da1cc572e973e8c6fed7623aedc7cd7")
                .unwrap()
        });
        fork.expect_store_receipts_hashes().returning(|_, _| {
            Hash::from_hex("12209b369faa46585ceaf95e12b709ceb28a3c29b2f4abb7b7da0e8c04dba74f4d25")
                .unwrap()
        });
        fork.expect_store_block().returning(|_| ());
        fork.expect_state_hash().returning(|_id| Hash::default());
        fork.expect_flush().returning(|| ());
        fork.expect_rollback().returning(|| ());
        fork
    }

    fn create_wm_mock() -> MockWm {
        let mut wm = MockWm::new();
        let mut count = 0;
        wm.expect_call()
            .returning(move |_: &mut dyn DbFork, _, _, _, _, _, _, _, _, _, _, _| {
                count += 1;
                match count {
                    1 => {
                        // Dummy opaque information returned the the smart contract.
                        (0, Ok(hex::decode("4f706171756544617461").unwrap()))
                    }
                    2 => (
                        0,
                        Err(Error::new_ext(
                            ErrorKind::SmartContractFault,
                            "bad contract args",
                        )),
                    ),
                    _ => (
                        0,
                        Err(Error::new_ext(
                            ErrorKind::WasmMachineFault,
                            "internal error",
                        )),
                    ),
                }
            });
        wm.expect_app_hash_check()
            .returning(move |_, _, _, _| Ok(Hash::from_data(HashAlgorithm::Sha256, TEST_WASM)));

        wm
    }

    fn create_wm_mock_bulk() -> MockWm {
        let mut wm = MockWm::new();
        let mut count = 0;
        wm.expect_call()
            .returning(move |_: &mut dyn DbFork, _, _, _, _, _, _, _, _, _, _, _| {
                count += 1;
                match count {
                    1 | 2 | 3 => {
                        // Dummy opaque information returned the the smart contract.
                        (0, Ok(hex::decode("4f706171756544617461").unwrap()))
                    }
                    4 => (
                        0,
                        Err(Error::new_ext(
                            ErrorKind::SmartContractFault,
                            "bad contract args",
                        )),
                    ),
                    _ => (
                        0,
                        Err(Error::new_ext(
                            ErrorKind::WasmMachineFault,
                            "internal error",
                        )),
                    ),
                }
            });
        wm.expect_app_hash_check()
            .returning(move |_, _, _, _| Ok(Hash::from_data(HashAlgorithm::Sha256, TEST_WASM)));

        wm
    }

    fn test_contract_hash() -> Hash {
        Hash::from_data(HashAlgorithm::Sha256, TEST_WASM)
    }

    fn create_test_bulk_data(method: &str, args: Value) -> TransactionData {
        let contract_hash = test_contract_hash();
        let public_key = create_test_public_key();
        let keypair = create_test_keypair();
        let id = public_key.to_account_id();

        let data_tx0 = TransactionData::BulkRootV1(TransactionDataV1 {
            account: id,
            fuel_limit: 1000,
            nonce: [0xab, 0x82, 0xb7, 0x41, 0xe0, 0x23, 0xa4, 0x12].to_vec(),
            network: "arya".to_string(),
            contract: Some(contract_hash), // Smart contract HASH
            method: method.to_string(),
            caller: public_key,
            args: rmp_serialize(&args).unwrap(),
        });

        let contract_hash = test_contract_hash();
        let public_key = create_test_public_key();
        let id = public_key.to_account_id();

        let data_tx1 = TransactionData::BulkNodeV1(TransactionDataBulkNodeV1 {
            account: id,
            fuel_limit: 1000,
            nonce: [0xab, 0x82, 0xb7, 0x41, 0xe0, 0x23, 0xa4, 0x12].to_vec(),
            network: "arya".to_string(),
            contract: Some(contract_hash), // Smart contract HASH
            method: method.to_string(),
            caller: public_key,
            args: rmp_serialize(&value!(null)).unwrap(),
            depends_on: data_tx0.primary_hash(),
        });
        let sign_tx1 = data_tx1.sign(&keypair);

        let contract_hash = test_contract_hash();
        let public_key = create_test_public_key();
        let id = public_key.to_account_id();

        let data_tx2 = TransactionData::BulkNodeV1(TransactionDataBulkNodeV1 {
            account: id,
            fuel_limit: 1000,
            nonce: [0xab, 0x82, 0xb7, 0x41, 0xe0, 0x23, 0xa4, 0x12].to_vec(),
            network: "arya".to_string(),
            contract: Some(contract_hash), // Smart contract HASH
            method: method.to_string(),
            caller: public_key,
            args: rmp_serialize(&args).unwrap(),
            depends_on: data_tx0.primary_hash(),
        });
        let sign_tx2 = data_tx2.sign(&keypair);

        let tx1 = SignedTransaction {
            data: data_tx1,
            signature: sign_tx1.unwrap(),
        };

        let tx2 = SignedTransaction {
            data: data_tx2,
            signature: sign_tx2.unwrap(),
        };

        let nodes = vec![tx1, tx2];

        TransactionData::BulkV1(TransactionDataBulkV1 {
            txs: BulkTransactions {
                root: Box::new(UnsignedTransaction { data: data_tx0 }),
                nodes: Some(nodes),
            },
        })
    }

    fn create_bulk_tx() -> Transaction {
        let keypair = create_test_keypair();

        let data = create_test_bulk_data("get_random_sequence", value!(null));
        let signature = data.sign(&keypair).unwrap();
        Transaction::BulkTransaction(BulkTransaction { data, signature })
    }

    fn is_validator_function() -> impl IsValidator {
        move |_account_id| Ok(true)
    }

    #[test]
    fn test_bulk() {
        let mut executor = create_executor_bulk(false, FUEL_LIMIT);
        let mut fork = executor.db.write().fork_create();

        let tx = create_bulk_tx();

        let rcpt = executor.exec_transaction(&tx, &mut fork, 0, 0, &String::new());

        assert!(rcpt.success);
    }

    #[test]
    fn can_run() {
        let executor = create_executor(false, FUEL_LIMIT);

        let runnable = executor.can_run(0);

        assert!(runnable);
    }

    #[test]
    fn cant_run_missing_next_block() {
        let executor = create_executor(false, FUEL_LIMIT);

        let runnable = executor.can_run(u64::MAX);

        assert!(!runnable);
    }

    #[test]
    fn cant_run_missing_block_tx_hashes() {
        let executor = create_executor(false, FUEL_LIMIT);
        {
            // Steal transaction hashes list.
            let mut pool = executor.pool.write();
            pool.confirmed.get_mut(&0).unwrap().txs_hashes.take();
        }

        let runnable = executor.can_run(0);

        assert!(!runnable);
    }

    #[test]
    fn cant_run_missing_transaction() {
        let executor = create_executor(false, FUEL_LIMIT);
        {
            // Steal one transaction required by the first block.
            let mut pool = executor.pool.write();
            let hash = pool
                .confirmed
                .get(&0)
                .unwrap()
                .txs_hashes
                .as_ref()
                .unwrap()
                .get(0)
                .unwrap()
                .to_owned();
            let _ = pool.txs.get_mut(&hash).unwrap().take();
        }

        let runnable = executor.can_run(0);

        assert!(!runnable);
    }

    #[test]
    fn exec_block() {
        let mut executor = create_executor(false, FUEL_LIMIT);
        let hashes = executor
            .pool
            .write()
            .confirmed
            .get_mut(&0)
            .unwrap()
            .txs_hashes
            .take()
            .unwrap();
        let is_validator_closure = is_validator_function();
        let hash = executor
            .exec_block(
                0,
                &hashes,
                Hash::default(),
                BlockValues {
                    exp_hash: None,
                    signature: None,
                    validator: None,
                },
                true,
                Arc::new(is_validator_closure),
            )
            .unwrap();

        assert_eq!(
            hex::encode(hash),
            "1220bdf5305a19f7561132693e57ffd30015311d372568879727a1577d8773ceb48d"
        );
    }

    #[test]
    fn exec_block_expected_hash_mismatch() {
        let mut executor = create_executor(true, FUEL_LIMIT);
        let hashes = executor
            .pool
            .write()
            .confirmed
            .get_mut(&0)
            .unwrap()
            .txs_hashes
            .take()
            .unwrap();

        let is_validator_closure = is_validator_function();

        let err = executor
            .exec_block(
                0,
                &hashes,
                Hash::default(),
                BlockValues {
                    exp_hash: Some(Hash::default()),
                    signature: None,
                    validator: None,
                },
                true,
                Arc::new(is_validator_closure),
            )
            .unwrap_err();

        assert_eq!(err.to_string_full(), "other: unexpected block hash");
    }

    #[test]
    fn exec_block_merge_fail() {
        let mut executor = create_executor(true, FUEL_LIMIT);
        let hashes = executor
            .pool
            .write()
            .confirmed
            .get_mut(&0)
            .unwrap()
            .txs_hashes
            .take()
            .unwrap();

        let is_validator_closure = is_validator_function();

        let err = executor
            .exec_block(
                0,
                &hashes,
                Hash::default(),
                BlockValues {
                    exp_hash: None,
                    signature: None,
                    validator: None,
                },
                true,
                Arc::new(is_validator_closure),
            )
            .unwrap_err();

        assert_eq!(err.to_string_full(), "database fault: merge error");
    }

    #[test]
    #[should_panic(expected = "Unexpected missing transaction")]
    fn exec_block_missing_tx() {
        let mut executor = create_executor(true, FUEL_LIMIT);
        let hashes = {
            let mut pool = executor.pool.write();
            let hashes = pool
                .confirmed
                .get_mut(&0)
                .unwrap()
                .txs_hashes
                .take()
                .unwrap();
            let _ = pool.txs.get_mut(&hashes[0]).unwrap().take();
            hashes
        };
        let is_validator_closure = is_validator_function();

        executor
            .exec_block(
                0,
                &hashes,
                Hash::default(),
                BlockValues {
                    exp_hash: Some(Hash::default()),
                    signature: None,
                    validator: None,
                },
                true,
                Arc::new(is_validator_closure),
            )
            .unwrap();
    }

    #[test]
    fn test_drad_seed() {
        let nw_name = String::from("skynet");
        let nonce: Vec<u8> = vec![0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56];
        let prev_hash =
            Hash::from_hex("1220a4cea0f0f6eddc6865fd6092a319ccc6d2387cd8bb65e64bdc486f1a9a998569")
                .unwrap();
        let txs_hash =
            Hash::from_hex("1220a4cea0f1f6eddc6865fd6092a319ccc6d2387cf8bb63e64b4c48601a9a998569")
                .unwrap();
        let rxs_hash =
            Hash::from_hex("1220a4cea0f0f6edd46865fd6092a319ccc6d5387cd8bb65e64bdc486f1a9a998569")
                .unwrap();
        let seed = SeedSource::new(nw_name, nonce, prev_hash, txs_hash, rxs_hash);
        let seed = Arc::new(seed);

        /* cSpell:disable */
        //let drand = Drand::new(seed.clone());

        //let seed_test = seed.clone();

        //println!(
        //    "prev_hash: {:?}\ntxs_hash: {:?}\nrxs_hash: {:?}\nprev seed:{:?}\n---",
        //    seed_test.prev_hash.lock(),
        //    seed_test.txs_hash.lock(),
        //    seed_test.rxs_hash.lock(),
        //    seed_test.previous_seed.lock(),
        //);

        //println!("pre exec;{}\n---", drand.rand(9));

        //println!(
        //    "prev_hash: {:?}\ntxs_hash: {:?}\nrxs_hash: {:?}\nprev seed:{:?}\n---",
        //    seed_test.prev_hash.lock(),
        //    seed_test.txs_hash.lock(),
        //    seed_test.rxs_hash.lock(),
        //    seed_test.previous_seed.lock(),
        //);
        /* cSpell:enable */

        let mut executor = create_executor_drand(false, seed.clone());

        let hashes = executor
            .pool
            .write()
            .confirmed
            .get_mut(&0)
            .unwrap()
            .txs_hashes
            .take()
            .unwrap();

        let is_validator_closure = is_validator_function();

        let hash = executor
            .exec_block(
                0,
                &hashes,
                Hash::default(),
                BlockValues {
                    exp_hash: None,
                    signature: None,
                    validator: None,
                },
                true,
                Arc::new(is_validator_closure),
            )
            .unwrap();

        /* cSpell:disable */

        //println!(
        //    "AFTER BLOCK GEN\nprev_hash: {:?}\ntxs_hash: {:?}\nrxs_hash: {:?}\nprev seed:{:?}\n---",
        //    seed_test.prev_hash.lock(),
        //    seed_test.txs_hash.lock(),
        //    seed_test.rxs_hash.lock(),
        //    seed_test.previous_seed.lock(),
        //);

        //println!("post exec;{}", drand.rand(9));

        //println!(
        //    "prev_hash: {:?}\ntxs_hash: {:?}\nrxs_hash: {:?}\nprev seed:{:?}\n---",
        //    seed_test.prev_hash.lock(),
        //    seed_test.txs_hash.lock(),
        //    seed_test.rxs_hash.lock(),
        //    seed_test.previous_seed.lock(),
        //);
        /* cSpell:enable */

        assert_eq!(
            hex::encode(hash),
            "1220bdf5305a19f7561132693e57ffd30015311d372568879727a1577d8773ceb48d"
        );
    }
}
