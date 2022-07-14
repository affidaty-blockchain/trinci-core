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

use curl::easy::{Easy, List};
use std::io::Read;
use uuid::Uuid;

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

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct StoreAssetDbStr {
    pub _id: String,
    pub account: String,
    pub asset: String,
    pub prev_amount: String,
    pub amount: String,
    pub tx_hash: String,
    pub smartcontract_hash: String,
    pub block_height: u64,
    pub block_hash: String,
    pub block_timestamp: u64,
}

// pub trait ExternalDb {}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Indexer {
    pub data: Vec<StoreAssetDb>,
}

impl Indexer {
    pub fn new() -> Self {
        Indexer { data: Vec::new() }
    }

    fn get_amount(value: &[u8]) -> String {
        match rmp_serde::from_slice::<u64>(value) {
            Ok(val) => val.to_string(),
            Err(_) => format!("{:?}", value).replace(' ', ""),
        }
    }

    fn prepare_json_for_db(&self) -> String {
        let mut template = String::from("{\"docs\": [");

        let mut prefix = String::new();
        for d in &self.data {
            // TODO impl from StoreAssetDb or Display for StoreAssetDb
            let val = StoreAssetDbStr {
                _id: Uuid::new_v4().to_string(),
                account: d.account.clone(),
                asset: d.asset.clone(),
                prev_amount: Self::get_amount(&d.prev_amount),
                amount: Self::get_amount(&d.amount),
                tx_hash: hex::encode(d.tx_hash.as_bytes()),
                smartcontract_hash: hex::encode(d.smartcontract_hash.as_bytes()),
                block_height: d.block_height,
                block_hash: hex::encode(d.block_hash.as_bytes()),
                block_timestamp: d.block_timestamp,
            };
            let data_str = serde_json::to_string(&val).unwrap();
            template.push_str(&prefix);
            template.push_str(&data_str);
            if prefix.is_empty() {
                prefix = ",".to_string();
            }
        }

        template.push_str("]}");
        template
    }

    fn write_data_to_db(mut data: &[u8]) {
        // TODO errors handling
        // TODO pass DB configuration
        let mut easy = Easy::new();
        easy.url("http://admin:password@localhost:5984/trinci/_bulk_docs")
            .unwrap();
        easy.post(true).unwrap();
        easy.post_field_size(data.len() as u64).unwrap();

        let mut list = List::new();
        list.append("Content-Type:application/json").unwrap();
        easy.http_headers(list).unwrap();

        let mut transfer = easy.transfer();
        transfer
            .read_function(|buf| Ok(data.read(buf).unwrap_or(0)))
            .unwrap();
        transfer.perform().unwrap();
    }

    pub fn store_data(&self) {
        let data = self.prepare_json_for_db().as_bytes().to_vec();
        Self::write_data_to_db(&data);
    }
}

impl Default for Indexer {
    fn default() -> Self {
        Self::new()
    }
}
