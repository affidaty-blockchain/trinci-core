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

use crate::crypto::Hash;

/// Store asset data to store in the external db
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct StoreAssetDb {
    pub account: String,
    pub asset: String,
    pub prev_amount: Vec<u8>,
    pub amount: Vec<u8>,
    pub tx_hash: Hash,
    pub smartcontract_hash: Hash,
    pub block_height: u64,
    pub block_hash: Hash,
    pub block_timestamp: u64,
}

// pub trait ExternalDb {}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Indexer {
    // pub struct Indexer<D: ExternalDb> {  // TODO
    /// External DB interface
    // external_db: D, // TODO
    pub data: Vec<StoreAssetDb>,
}

impl Indexer {
    pub fn new() -> Self {
        Indexer { data: Vec::new() }
    }
}
