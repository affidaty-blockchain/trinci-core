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

//! Blockchain component in charge of building and confirming new blocks by
//! picking unconfirmed transactions from the outstanding pool (`Pool`).
//!
//! The new blocks are pushed in the pool confirmed blocks queue ready to be
//! picked up by the executor.
//!
//! This component runs only on validator nodes that has acquired the
//! right to produce new blocks via a consensus algorithm.

use crate::{
    base::RwLock,
    blockchain::pool::{BlockInfo, Pool},
    db::Db,
};
use std::sync::Arc;

/// Builder context data.
pub(crate) struct Builder<D: Db> {
    /// Transactions per block upper limit.
    threshold: usize,
    /// Unconfirmed transactions pool.
    pool: Arc<RwLock<Pool>>,
    /// Instance of a type implementing Database trait.
    db: Arc<RwLock<D>>,
}

impl<D: Db> Clone for Builder<D> {
    fn clone(&self) -> Self {
        Builder {
            threshold: self.threshold,
            pool: self.pool.clone(),
            db: self.db.clone(),
        }
    }
}

impl<D: Db> Builder<D> {
    /// Constructs a new builder.
    pub fn new(threshold: usize, pool: Arc<RwLock<Pool>>, db: Arc<RwLock<D>>) -> Self {
        Builder {
            threshold,
            pool,
            db,
        }
    }

    /// Checks if a block can be produced using the given
    /// max-transactions-per-block threshold.
    pub fn can_run(&self, threshold: usize) -> bool {
        // We use try_read because we don't want to wait.
        // It the pool is locked, we can't run.
        self.pool
            .try_read()
            .map(|pool| pool.unconfirmed.len())
            .unwrap_or_default()
            .ge(&threshold)
    }

    /// Adds a bunch of entries to the blockchain confirmed blocks queue.
    /// The added blocks are ready to be executed.
    /// Each block will have at most `threshold` transactions.
    pub fn run(&mut self) {
        let mut height = match self.pool.read().confirmed.iter().next_back() {
            Some((height, _)) => *height + 1,
            None => self
                .db
                .read()
                .load_block(u64::MAX)
                .map(|block| block.height + 1)
                .unwrap_or_default(),
        };
        let mut count = self.pool.read().unconfirmed.len();
        loop {
            while count > 0 {
                let mut pool = self.pool.write();
                let mut txs_hashes = vec![];
                for _ in 0..self.threshold {
                    match pool.unconfirmed.pop() {
                        Some(hash) => txs_hashes.push(hash),
                        None => break,
                    }
                }
                count = count.checked_sub(txs_hashes.len()).unwrap_or_default();

                let blk_info = BlockInfo {
                    hash: None,
                    txs_hashes: Some(txs_hashes),
                };
                pool.confirmed.insert(height, blk_info);
                height += 1;
            }
            count = self.pool.read().unconfirmed.len();
            if count < self.threshold {
                break;
            }
        }
    }
}
