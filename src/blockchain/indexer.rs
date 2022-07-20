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

use crate::crypto::hash::Hashable;
use crate::{base::serialize::rmp_deserialize, crypto::Hash, Error, ErrorKind, Result};

use curl::easy::{Easy, List};
use std::{io::Read, thread::spawn};

/// Store asset data to store in the external db
#[derive(Serialize, Debug, PartialEq, Clone)]
pub struct StoreAssetDb {
    pub account: String,
    pub origin: String,
    pub asset: String,
    pub prev_amount: Vec<u8>,
    pub amount: Vec<u8>,
    pub tx_hash: Hash,
    pub smartcontract_hash: Hash,
    pub block_height: u64,
    pub block_hash: Hash,
    pub block_timestamp: u64,
}

#[derive(Serialize, Debug)]
pub struct StoreAssetDbStr {
    pub _id: String,
    pub account: String,
    pub origin: String,
    pub asset: String,
    pub prev_amount: serde_json::Value,
    pub amount: serde_json::Value,
    pub tx_hash: String,
    pub smartcontract_hash: String,
    pub block_height: u64,
    pub block_hash: String,
    pub block_timestamp: u64,
}

fn get_amount(buf: &[u8]) -> serde_json::Value {
    if buf.is_empty() {
        serde_json::Value::Null
    } else {
        match rmp_deserialize::<serde_json::Value>(buf) {
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

fn json_string_from_store_asset_db(data: &StoreAssetDb) -> String {
    let val = serde_json::json!({
        "_id": hex::encode(&data.primary_hash().as_bytes()),
        "account": data.account.clone(),
        "origin": data.origin.clone(),
        "asset": data.asset.clone(),
        "prev_amount": get_amount(&data.prev_amount),
        "amount": get_amount(&data.amount),
        "tx_hash": hex::encode(data.tx_hash.as_bytes()),
        "smartcontract_hash": hex::encode(data.smartcontract_hash.as_bytes()),
        "block_height": data.block_height,
        "block_hash": hex::encode(data.block_hash.as_bytes()),
        "block_timestamp": data.block_timestamp,
    });
    serde_json::to_string(&val).unwrap() // This should be safe
}

/// Indexer configuration
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct IndexerConfig {
    /// hostname
    pub host: String,
    /// port
    pub port: u16,
    /// database name
    pub db_name: String,
    /// username
    pub user: String,
    /// password
    pub password: String,
}

#[derive(Debug, PartialEq, Clone)]
pub struct Indexer {
    pub config: IndexerConfig,
    pub data: Vec<StoreAssetDb>,
}

impl Indexer {
    pub fn new(config: IndexerConfig) -> Self {
        Indexer {
            data: Vec::new(),
            config,
        }
    }

    pub fn clear_data(&mut self) {
        self.data = Vec::new();
    }

    fn prepare_json_for_db(&self) -> String {
        let mut template = String::from("{\"docs\": [");

        let mut prefix = String::new();
        for d in &self.data {
            let data_str = json_string_from_store_asset_db(d);
            template.push_str(&prefix);
            template.push_str(&data_str);
            if prefix.is_empty() {
                prefix = ",".to_string();
            }
        }

        template.push_str("]}");
        template
    }

    fn write_data_to_db(data: Vec<u8>, config: &IndexerConfig) -> Result<()> {
        let mut data: &[u8] = data.as_ref();
        let mut easy = Easy::new();

        let url = format!(
            "http://{}:{}@{}:{}/{}/_bulk_docs",
            config.user, config.password, config.host, config.port, config.db_name
        );
        easy.url(&url)
            .map_err(|err| Error::new_ext(ErrorKind::Other, err))?;
        easy.post(true)
            .map_err(|err| Error::new_ext(ErrorKind::Other, err))?;
        easy.post_field_size(data.len() as u64)
            .map_err(|err| Error::new_ext(ErrorKind::Other, err))?;

        let mut list = List::new();
        list.append("Content-Type:application/json")
            .map_err(|err| Error::new_ext(ErrorKind::Other, err))?;
        easy.http_headers(list)
            .map_err(|err| Error::new_ext(ErrorKind::Other, err))?;

        let mut transfer = easy.transfer();
        transfer
            .read_function(|buf| Ok(data.read(buf).unwrap_or(0)))
            .map_err(|err| Error::new_ext(ErrorKind::Other, err))?;
        transfer
            .perform()
            .map_err(|err| Error::new_ext(ErrorKind::Other, err))?;
        Ok(())
    }

    pub fn store_data(&self) {
        let data = self.prepare_json_for_db().as_bytes().to_vec();
        let config = self.config.clone();
        let _ = spawn(move || {
            if let Err(e) = Indexer::write_data_to_db(data, &config) {
                error!("Error DB: {}", e.to_string_full());
            }
        });
    }
}

impl Default for IndexerConfig {
    fn default() -> Self {
        Self {
            host: "localhost".to_string(),
            port: 5984,
            db_name: "trinci".to_string(),
            user: "admin".to_string(),
            password: "password".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use crate::blockchain::indexer::get_amount;

    #[test]
    fn get_amount_empty_value() {
        let buf = [];

        let amount = get_amount(&buf);

        assert_eq!(amount, Value::Null);
    }

    #[test]
    fn get_amount_integer_1() {
        let buf = [42];

        let amount = get_amount(&buf);

        let expected: Value = json!({
            "value":42,
            "source": buf,
            "decoded":true
        });

        assert_eq!(amount, expected);
    }

    #[test]
    fn get_amount_integer_2() {
        let buf = [205, 3, 232];
        let amount = get_amount(&buf);

        let expected: Value = json!({
            "value":1000,
            "source": buf,
            "decoded":true
        });

        assert_eq!(amount, expected);
    }

    #[test]
    fn get_amount_json_data() {
        let buf = [
            130, 165, 117, 110, 105, 116, 115, 42, 167, 109, 101, 115, 115, 97, 103, 101, 167, 109,
            101, 115, 115, 97, 103, 101,
        ];

        let amount = get_amount(&buf);

        let expected: Value = json!({
            "value":json!({"units":42,"message":"message"}),
            "source": buf,
            "decoded":true
        });

        assert_eq!(amount, expected);
    }
}
