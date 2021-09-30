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

//! Blockchain component in charge of keeping the blockchain up-to-date.
//!
//! Synchronization is started when some confirmed partial information enters
//! the pool, in particular:
//! - transactions hashes without transaction payload.
//! - blocks without transactions hashes list.
//!
//! Synchronization terminates as soon as we fill missing information.
//!
//! This component also takes care of propagating unconfirmed transactions,
//! this is vital for secondary stations wishing to see their pending
//! transactions confirmed in some future block.

use super::{
    message::Message,
    pool::{BlockInfo, Pool},
    pubsub::{Event, PubSub},
};
use crate::{
    base::{Mutex, RwLock},
    db::Db,
};
use std::sync::Arc;

const MAX_SYNC_REQUESTS: usize = 512;

/// Synchronization context data.
pub(crate) struct Synchronizer<D: Db> {
    /// Outstanding transactions pool
    pool: Arc<RwLock<Pool>>,
    /// Persistent storage.
    db: Arc<RwLock<D>>,
    /// PubSub system to propagate unsolicited messages.
    pubsub: Arc<Mutex<PubSub>>,
}

impl<D: Db> Clone for Synchronizer<D> {
    fn clone(&self) -> Self {
        Synchronizer {
            pool: self.pool.clone(),
            db: self.db.clone(),
            pubsub: self.pubsub.clone(),
        }
    }
}

impl<D: Db> Synchronizer<D> {
    /// Construct a new synchronizer.
    pub fn new(pool: Arc<RwLock<Pool>>, db: Arc<RwLock<D>>, pubsub: Arc<Mutex<PubSub>>) -> Self {
        Self { pool, db, pubsub }
    }

    /// Prepare messages to recover confirmed blocks and transactions.
    fn prepare_request_messages(&self, pool: &Pool, last_height: u64, messages: &mut Vec<Message>) {
        let mut height = self
            .db
            .read()
            .load_block(u64::MAX)
            .map(|blk| blk.height + 1)
            .unwrap_or_default();

        while height <= last_height {
            match pool.confirmed.get(&height) {
                Some(BlockInfo {
                    hash: _,
                    txs_hashes: Some(hashes),
                }) => {
                    // We have hases, check if we have every transaction payload
                    for hash in hashes {
                        if !matches!(pool.txs.get(hash), Some(Some(_))) {
                            let req = Message::GetTransactionRequest { hash: *hash };
                            messages.push(req);
                        }
                    }
                }
                _ => {
                    // We don't have the hashes or we've never saw the block, ask for complete block
                    let req = Message::GetBlockRequest { height, txs: true };
                    messages.push(req);
                }
            }
            height += 1;
        }
    }

    /// Prepare messages to propagate unconfirmed transactions.
    fn prepare_response_messages(&self, pool: &Pool, messages: &mut Vec<Message>) {
        for hash in pool.unconfirmed.iter() {
            match pool.txs.get(hash) {
                Some(Some(tx)) => {
                    let req = Message::GetTransactionResponse { tx: tx.clone() };
                    messages.push(req);
                }
                _ => {
                    error!(
                        "[sync] unexpected null transaction in unconfirmed pool: {}",
                        hex::encode(hash)
                    );
                }
            }
        }
    }

    /// Run the synchronizer once.
    pub fn run(&self) {
        let mut messages = vec![];

        {
            let pool = self.pool.read();
            if let Some((&last_height, _)) = pool.confirmed.iter().next_back() {
                self.prepare_request_messages(&pool, last_height, &mut messages);
            }
            self.prepare_response_messages(&pool, &mut messages);
        }

        for req in messages.into_iter().take(MAX_SYNC_REQUESTS) {
            match req {
                Message::GetTransactionRequest { hash } => {
                    debug!("[sync] get-transaction: {}", hex::encode(hash))
                }
                Message::GetBlockRequest { height, txs: _ } => {
                    debug!("[sync] get-block: {}", height)
                }
                Message::GetTransactionResponse { tx: _ } => {
                    debug!("[sync] put-transaction");
                }
                _ => (),
            }
            self.pubsub.lock().publish(Event::REQUEST, req);
        }
    }
}
