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

use crate::{base::serialize::rmp_deserialize, crypto::Hash};

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
    pub prev_amount: serde_json::Value,
    pub amount: serde_json::Value,
    pub tx_hash: String,
    pub smartcontract_hash: String,
    pub block_height: u64,
    pub block_hash: String,
    pub block_timestamp: u64,
}

// #[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
// pub struct IndexerConfig {
//     host: String,
//     port: u16,
//     user: String,
//     password: String,
// }

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Indexer {
    // pub config: IndexerConfig,
    pub data: Vec<StoreAssetDb>,
}

impl Indexer {
    pub fn new(/*config: IndexerConfig*/) -> Self {
        Indexer {
            data: Vec::new(), /*config: todo!()*/
        }
    }

    fn get_amount(buf: &[u8]) -> serde_json::Value {
        if buf.is_empty() {
            serde_json::Value::Null
        } else {
            match rmp_deserialize::<serde_json::Value>(&buf) {
                Ok(val) => {
                    serde_json::json!({
                        "source": buf,
                        "value": val,
                        "decoded": true
                    })
                }
                Err(e) => {
                    serde_json::json!({
                        "source": buf,
                        "value": e.to_string(),
                        "decoded": false
                    })
                }
            }
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

    fn write_data_to_db(&self, mut data: &[u8]) {
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
        self.write_data_to_db(&data);
    }
}

impl Default for Indexer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::Indexer;

    #[test]
    fn get_amount_empty_value() {
        let buf = [];

        let amount = Indexer::get_amount(&buf);

        assert_eq!(amount, r#"{"amount":null}"#);
    }

    #[test]
    fn get_amount_integer_1() {
        let buf = [42];
        let amount = Indexer::get_amount(&buf);

        assert_eq!(amount, r#"{"amount":42}"#);
    }

    #[test]
    fn get_amount_integer_2() {
        let buf = [205, 3, 232];
        let amount = Indexer::get_amount(&buf);

        assert_eq!(amount, r#"{"amount":1000}"#);
    }

    #[test]
    fn get_amount_json_data() {
        let buf = [
            130, 165, 117, 110, 105, 116, 115, 42, 167, 109, 101, 115, 115, 97, 103, 101, 167, 109,
            101, 115, 115, 97, 103, 101,
        ];

        let amount = Indexer::get_amount(&buf);

        assert_eq!(amount, r#"{"amount":{"message":"message","units":42}}"#);
    }
}
