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

//! Blockchain outstanding transaction and blocks pool.

use crate::{
    base::{queue_set::QueueSet, schema::Transaction},
    crypto::hash::Hash,
};
use std::collections::{BTreeMap, HashMap};

/// Confirmed block information.
///
/// This structure is created due to one of the following condition:
/// 1. a new block is created;
/// 2. we discover that a block has been already confirmed;
///
/// The first case typically happens when a node has acquired the right to do
/// the operationi, in this case the node injecting a new block is called a
/// validator.
///
/// The second case typically happens when a node discovers from other peers
/// a block that has been already validated by someone else.
pub struct BlockInfo {
    /// Optional block header hash.
    /// This is `None` when we're the builder of this block since the hash is
    /// unknown up to the execution phase.
    pub hash: Option<Hash>,
    /// Block transactions hashes. This is `None` when we're aware of only the
    /// block header.
    pub txs_hashes: Option<Vec<Hash>>,
}

/// Pool of outstanding transactions and blocks.
/// The structure contains both confirmed and unconfirmed transactions.
#[derive(Default)]
pub struct Pool {
    /// Contains both confirmed and unconfirmed transactions payload.
    /// The payload may be temporary missing in case of confirmed transaction
    /// discovered during synchronization.
    pub txs: HashMap<Hash, Option<Transaction>>,
    /// Unconfirmed transactions queue. This contains the transactions waiting
    /// to be inserted in a new confirmed block.
    pub unconfirmed: QueueSet<Hash>,
    /// Confirmed blocks information.
    pub confirmed: BTreeMap<u64, BlockInfo>,
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::base::schema::tests::create_test_unit_tx;
    use crate::crypto::Hashable;

    pub fn create_pool() -> Pool {
        let mut pool = Pool::default();
        let mut tx_hashes = vec![];
        for i in 0..3 {
            let mut tx = create_test_unit_tx();

            match tx {
                Transaction::UnitTransaction(ref mut test) => test.data.set_nonce(vec![i as u8; 8]),
                Transaction::BullkTransaction(ref mut test) => {
                    test.data.set_nonce(vec![i as u8; 8])
                }
            }

            let hash = tx.primary_hash();
            pool.txs.insert(hash, Some(tx));
            tx_hashes.push(hash);
        }
        let blk_info = BlockInfo {
            hash: Some(Hash::default()),
            txs_hashes: Some(tx_hashes),
        };
        pool.confirmed.insert(0, blk_info);
        pool
    }
}
