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

use crate::{
    base::serialize::MessagePack,
    crypto::{Hash, Hashable, KeyPair, PublicKey},
    Error, ErrorKind, Result,
};
use serde_bytes::ByteBuf;
use std::collections::BTreeMap;

/// Transaction payload.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct TransactionDataV1 {
    /// Target account identifier.
    pub account: String,
    /// Max allowed blockchain asset units for fee.
    pub fuel_limit: u64,
    /// Nonce to differentiate different transactions with same payload.
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    /// Network identifier.
    pub network: String,
    /// Expected smart contract application identifier.
    pub contract: Option<Hash>,
    /// Method name.
    pub method: String,
    /// Submitter public key.
    pub caller: PublicKey,
    /// Smart contract arguments.
    #[serde(with = "serde_bytes")]
    pub args: Vec<u8>,
}

/// Transaction payload for bulk node tx.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct TransactionDataBulkNodeV1 {
    /// Target account identifier.
    pub account: String,
    /// Max allowed blockchain asset units for fee.
    pub fuel_limit: u64,
    /// Nonce to differentiate different transactions with same payload.
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    /// Network identifier.
    pub network: String,
    /// Expected smart contract application identifier.
    pub contract: Option<Hash>,
    /// Method name.
    pub method: String,
    /// Submitter public key.
    pub caller: PublicKey,
    /// Smart contract arguments.
    #[serde(with = "serde_bytes")]
    pub args: Vec<u8>,
    /// It express the tx on which is dependant
    pub depends_on: Hash,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
/// Set of transactions inside a bulk transaction
pub struct BulkTransactions {
    pub root: Box<UnsignedTransaction>,
    pub nodes: Option<Vec<SignedTransaction>>,
}

/// Transaction payload for bulk tx.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct TransactionDataBulkV1 {
    /// array of transactions
    pub txs: BulkTransactions,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(tag = "schema")]
pub enum TransactionData {
    #[serde(rename = "d8af8f563f25eb065651ccdd05b9726fd27ff9dc40e3b9c8b4d2c55fa9819f36")]
    V1(TransactionDataV1),
    #[serde(rename = "097e5f552c79d4f64e15f853ad19d013973343aea557d5c1482d9cef71915db8")]
    BulkNodeV1(TransactionDataBulkNodeV1),
    #[serde(rename = "0bccf5dce4f25036de1ef091ea9e862fa348e6de82ef16fbcfc84c1f1314b86e")]
    BulkRootV1(TransactionDataV1),
    #[serde(rename = "0ec3469e3509682d7599797a9d1c5cdf56b2d9bd435f853a3b999cbb717e0337")]
    BulkV1(TransactionDataBulkV1),
}

impl TransactionData {
    /// Transaction data sign
    pub fn sign(&self, keypair: &KeyPair) -> Result<Vec<u8>> {
        match &self {
            TransactionData::V1(tx_data) => tx_data.sign(keypair),
            TransactionData::BulkNodeV1(tx_data) => tx_data.sign(keypair),
            TransactionData::BulkV1(tx_data) => tx_data.sign(keypair),
            _ => Err(Error::new_ext(
                ErrorKind::NotImplemented,
                "signature method not implemented for this tx data type",
            )),
        }
    }
    /// Transaction data signature verification.
    pub fn verify(&self, public_key: &PublicKey, sig: &[u8]) -> Result<()> {
        match &self {
            TransactionData::V1(tx_data) => tx_data.verify(public_key, sig),
            TransactionData::BulkNodeV1(tx_data) => tx_data.verify(public_key, sig),
            TransactionData::BulkV1(tx_data) => tx_data.verify(public_key, sig),
            _ => Err(Error::new_ext(
                ErrorKind::NotImplemented,
                "verify method not implemented for this tx data type",
            )),
        }
    }
    /// Transaction data integrity check.
    pub fn check_integrity(&self) -> Result<()> {
        match &self {
            TransactionData::BulkV1(tx_data) => tx_data.check_integrity(),
            TransactionData::V1(tx_data) => tx_data.check_integrity(),
            _ => Err(Error::new_ext(
                ErrorKind::NotImplemented,
                "verify method not implemented for this tx data type",
            )),
        }
    }

    pub fn get_caller(&self) -> &PublicKey {
        match &self {
            TransactionData::V1(tx_data) => &tx_data.caller,
            TransactionData::BulkNodeV1(tx_data) => &tx_data.caller,
            TransactionData::BulkRootV1(tx_data) => &tx_data.caller,
            TransactionData::BulkV1(tx_data) => tx_data.txs.root.data.get_caller(),
        }
    }
    pub fn get_network(&self) -> &str {
        match &self {
            TransactionData::V1(tx_data) => &tx_data.network,
            TransactionData::BulkNodeV1(tx_data) => &tx_data.network,
            TransactionData::BulkRootV1(tx_data) => &tx_data.network,
            TransactionData::BulkV1(tx_data) => tx_data.txs.root.data.get_network(),
        }
    }
    pub fn get_account(&self) -> &str {
        match &self {
            TransactionData::V1(tx_data) => &tx_data.account,
            TransactionData::BulkNodeV1(tx_data) => &tx_data.account,
            TransactionData::BulkRootV1(tx_data) => &tx_data.account,
            TransactionData::BulkV1(tx_data) => tx_data.txs.root.data.get_account(),
        }
    }
    pub fn get_method(&self) -> &str {
        match &self {
            TransactionData::V1(tx_data) => &tx_data.method,
            TransactionData::BulkNodeV1(tx_data) => &tx_data.method,
            TransactionData::BulkRootV1(tx_data) => &tx_data.method,
            TransactionData::BulkV1(tx_data) => tx_data.txs.root.data.get_method(),
        }
    }
    pub fn get_args(&self) -> &[u8] {
        match &self {
            TransactionData::V1(tx_data) => &tx_data.args,
            TransactionData::BulkNodeV1(tx_data) => &tx_data.args,
            TransactionData::BulkRootV1(tx_data) => &tx_data.args,
            TransactionData::BulkV1(tx_data) => tx_data.txs.root.data.get_args(),
        }
    }
    pub fn get_fuel_limit(&self) -> u64 {
        match &self {
            TransactionData::V1(tx_data) => tx_data.fuel_limit,
            TransactionData::BulkV1(tx_data) => match &tx_data.txs.root.data {
                TransactionData::BulkRootV1(tx_data_v1) => tx_data_v1.fuel_limit,
                _ => 0,
            },
            _ => 0,
        }
    }
    pub fn get_contract(&self) -> &Option<Hash> {
        match &self {
            TransactionData::V1(tx_data) => &tx_data.contract,
            TransactionData::BulkNodeV1(tx_data) => &tx_data.contract,
            TransactionData::BulkRootV1(tx_data) => &tx_data.contract,
            TransactionData::BulkV1(tx_data) => tx_data.txs.root.data.get_contract(),
        }
    }
    pub fn get_dependency(&self) -> Result<Hash> {
        match &self {
            TransactionData::BulkNodeV1(tx_data) => Ok(tx_data.depends_on),
            _ => Err(Error::new_ext(
                ErrorKind::NotImplemented,
                "verify method not implemented for this tx data type",
            )),
        }
    }
    pub fn set_contract(&mut self, contract: Option<Hash>) {
        match self {
            TransactionData::V1(tx_data) => tx_data.contract = contract,
            TransactionData::BulkNodeV1(tx_data) => tx_data.contract = contract,
            TransactionData::BulkRootV1(tx_data) => tx_data.contract = contract,
            TransactionData::BulkV1(tx_data) => tx_data.txs.root.data.set_contract(contract),
        }
    }
    pub fn set_account(&mut self, account: String) {
        match self {
            TransactionData::V1(tx_data) => tx_data.account = account,
            TransactionData::BulkNodeV1(tx_data) => tx_data.account = account,
            TransactionData::BulkRootV1(tx_data) => tx_data.account = account,
            TransactionData::BulkV1(tx_data) => tx_data.txs.root.data.set_account(account),
        }
    }
    pub fn set_nonce(&mut self, nonce: Vec<u8>) {
        match self {
            TransactionData::V1(tx_data) => tx_data.nonce = nonce,
            TransactionData::BulkNodeV1(tx_data) => tx_data.nonce = nonce,
            TransactionData::BulkRootV1(tx_data) => tx_data.nonce = nonce,
            TransactionData::BulkV1(tx_data) => tx_data.txs.root.data.set_nonce(nonce),
        }
    }
}

impl TransactionDataV1 {
    /// Sign transaction data.
    /// Serialization is performed using message pack format with named field.
    pub fn sign(&self, keypair: &KeyPair) -> Result<Vec<u8>> {
        let data = self.serialize();
        keypair.sign(&data)
    }

    /// Transaction data signature verification.
    pub fn verify(&self, public_key: &PublicKey, sig: &[u8]) -> Result<()> {
        let data = self.serialize();
        match public_key.verify(&data, sig) {
            true => Ok(()),
            false => Err(ErrorKind::InvalidSignature.into()),
        }
    }

    /// Check if tx is intact and coherent
    pub fn check_integrity(&self) -> Result<()> {
        if !self.account.is_empty()
            && !self.nonce.is_empty()
            && !self.network.is_empty()
            && !self.method.is_empty()
        {
            Ok(())
        } else {
            Err(ErrorKind::BrokenIntegrity.into())
        }
    }
}

impl TransactionDataBulkNodeV1 {
    /// Sign transaction data.
    /// Serialization is performed using message pack format with named field.
    pub fn sign(&self, keypair: &KeyPair) -> Result<Vec<u8>> {
        let data = self.serialize();
        keypair.sign(&data)
    }

    /// Transaction data signature verification.
    pub fn verify(&self, public_key: &PublicKey, sig: &[u8]) -> Result<()> {
        let data = self.serialize();
        match public_key.verify(&data, sig) {
            true => Ok(()),
            false => Err(ErrorKind::InvalidSignature.into()),
        }
    }
}

impl TransactionDataBulkV1 {
    /// Sign transaction data.
    /// Serialization is performed using message pack format with named field.
    pub fn sign(&self, keypair: &KeyPair) -> Result<Vec<u8>> {
        let data = self.serialize();
        keypair.sign(&data)
    }

    /// Transaction data signature verification.
    // it should take the public key of the first tx
    // check sign
    pub fn verify(&self, public_key: &PublicKey, sig: &[u8]) -> Result<()> {
        let data = self.serialize();
        match public_key.verify(&data, sig) {
            true => match &self.txs.nodes {
                Some(nodes) => {
                    for node in nodes {
                        match &node.data {
                            TransactionData::BulkNodeV1(tx_data) => {
                                tx_data.verify(&tx_data.caller, &node.signature)?;
                            }
                            _ => return Err(ErrorKind::WrongTxType.into()),
                        }
                    }
                    Ok(())
                }
                None => Ok(()),
            },
            false => Err(ErrorKind::InvalidSignature.into()),
        }
    }

    /// It checks that all the txs are intact and coherent
    pub fn check_integrity(&self) -> Result<()> {
        // calculate root hash
        let root_hash = self.txs.root.data.primary_hash();
        let network = self.txs.root.data.get_network();
        match &self.txs.nodes {
            Some(nodes) => {
                // check depends on
                // check nws all equals && != none
                for node in nodes {
                    // check depends_on filed
                    let dependency = node.data.get_dependency();
                    match dependency {
                        Ok(dep_hash) => {
                            if dep_hash != root_hash {
                                return Err(Error::new_ext(
                                    ErrorKind::BrokenIntegrity,
                                    "The node has incoherent dependency",
                                ));
                            }
                        }
                        Err(error) => return Err(error),
                    }

                    // check network field
                    if node.data.get_network() != network {
                        return Err(Error::new_ext(
                            ErrorKind::BrokenIntegrity,
                            "The node has incoherent network",
                        ));
                    }
                }

                Ok(())
            }
            None => Ok(()),
        }
    }
}

/// Signed transaction.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct SignedTransaction {
    /// Transaction payload.
    pub data: TransactionData,
    /// Data field signature verifiable using the `caller` within the `data`.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

/// Unsigned Transaction
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct UnsignedTransaction {
    /// Transaction payload.
    pub data: TransactionData,
}

/// Bulk Transaction
// it might not be needed, just use signed transaction, where data == transaction Data::BulkData
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct BulkTransaction {
    /// Transaction payload.
    pub data: TransactionData,
    /// Data field signature verifiable using the `caller` within the `data`.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

/// Enum for transaction types
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(tag = "type")]
pub enum Transaction {
    /// Unit signed transaction
    #[serde(rename = "unit_tx")]
    UnitTransaction(SignedTransaction),
    /// Bulk transaction
    #[serde(rename = "bulk_tx")]
    BulkTransaction(BulkTransaction),
}

impl Transaction {
    pub fn sign(&self, keypair: &KeyPair) -> Result<Vec<u8>> {
        match self {
            Transaction::UnitTransaction(tx) => {
                let data = tx.data.serialize();
                keypair.sign(&data)
            }
            Transaction::BulkTransaction(tx) => {
                let data = tx.data.serialize();
                keypair.sign(&data)
            }
        }
    }
    pub fn verify(&self, public_key: &PublicKey, sig: &[u8]) -> Result<()> {
        match self {
            Transaction::UnitTransaction(tx) => {
                let data = tx.data.serialize();
                match public_key.verify(&data, sig) {
                    true => Ok(()),
                    false => Err(ErrorKind::InvalidSignature.into()),
                }
            }
            Transaction::BulkTransaction(tx) => {
                let data = tx.data.serialize();
                match public_key.verify(&data, sig) {
                    true => Ok(()),
                    false => Err(ErrorKind::InvalidSignature.into()),
                }
            }
        }
    }
    pub fn check_integrity(&self) -> Result<()> {
        match self {
            Transaction::UnitTransaction(tx) => tx.data.check_integrity(), //TODO
            Transaction::BulkTransaction(tx) => tx.data.check_integrity(),
        }
    }

    pub fn get_caller(&self) -> &PublicKey {
        match self {
            Transaction::UnitTransaction(tx) => tx.data.get_caller(),
            Transaction::BulkTransaction(tx) => tx.data.get_caller(),
        }
    }
    pub fn get_network(&self) -> &str {
        match &self {
            Transaction::UnitTransaction(tx) => tx.data.get_network(),
            Transaction::BulkTransaction(tx) => tx.data.get_network(),
        }
    }
    pub fn get_account(&self) -> &str {
        match &self {
            Transaction::UnitTransaction(tx) => tx.data.get_account(),
            Transaction::BulkTransaction(tx) => tx.data.get_account(),
        }
    }
    pub fn get_method(&self) -> &str {
        match &self {
            Transaction::UnitTransaction(tx) => tx.data.get_method(),
            Transaction::BulkTransaction(tx) => tx.data.get_method(),
        }
    }
    pub fn get_args(&self) -> &[u8] {
        match &self {
            Transaction::UnitTransaction(tx) => tx.data.get_args(),
            Transaction::BulkTransaction(tx) => tx.data.get_args(),
        }
    }
    pub fn get_contract(&self) -> &Option<Hash> {
        match &self {
            Transaction::UnitTransaction(tx) => tx.data.get_contract(),
            Transaction::BulkTransaction(tx) => tx.data.get_contract(),
        }
    }
    pub fn get_dependency(&self) -> Result<Hash> {
        match &self {
            Transaction::UnitTransaction(tx) => tx.data.get_dependency(),
            Transaction::BulkTransaction(tx) => tx.data.get_dependency(),
        }
    }
    pub fn get_signature(&self) -> &Vec<u8> {
        match &self {
            Transaction::UnitTransaction(tx) => &tx.signature,
            Transaction::BulkTransaction(tx) => &tx.signature,
        }
    }
    pub fn get_primary_hash(&self) -> Hash {
        match &self {
            Transaction::UnitTransaction(tx) => tx.data.primary_hash(),
            Transaction::BulkTransaction(tx) => tx.data.primary_hash(),
        }
    }
    pub fn get_fuel_limit(&self) -> u64 {
        match &self {
            Transaction::UnitTransaction(tx) => tx.data.get_fuel_limit(),
            Transaction::BulkTransaction(tx) => tx.data.get_fuel_limit(),
        }
    }
}

/// Events risen by the smart contract execution
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct SmartContractEvent {
    /// Identifier of the transaction that produced this event
    pub event_tx: Hash,

    /// The account that produced this event
    pub emitter_account: String,

    pub emitter_smart_contract: Hash,

    /// Arbitrary name given to this event
    pub event_name: String,

    /// Data emitted with this event
    #[serde(with = "serde_bytes")]
    pub event_data: Vec<u8>,
}

/// Transaction execution receipt.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Receipt {
    /// Transaction block location.
    pub height: u64,
    /// Transaction index within the block.
    pub index: u32,
    /// Actual burned fuel used to perform the submitted actions.
    pub burned_fuel: u64,
    /// Execution outcome.
    pub success: bool,
    // Follows contract specific result data.
    #[serde(with = "serde_bytes")]
    pub returns: Vec<u8>,
    /// Optional Vector of smart contract events
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events: Option<Vec<SmartContractEvent>>,
}

/// Block structure.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Block {
    /// Block content
    pub data: BlockData,
    /// Block content signature
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

/// Block Data structure.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct BlockData {
    /// Block Validator public key
    pub validator: Option<PublicKey>,
    /// Index in the blockchain, which is also the number of ancestors blocks.
    pub height: u64,
    /// Number of transactions in this block.
    pub size: u32,
    /// Previous block hash.
    pub prev_hash: Hash,
    /// Root of block transactions trie.
    pub txs_hash: Hash,
    /// Root of block receipts trie.
    pub rxs_hash: Hash,
    /// Root of accounts state after applying the block transactions.
    pub state_hash: Hash,
    /// Timestamp in which the block was created by validator.
    pub timestamp: u64,
}

impl BlockData {
    /// Instance a new block structure.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        validator: Option<PublicKey>,
        height: u64,
        size: u32,
        prev_hash: Hash,
        txs_hash: Hash,
        rxs_hash: Hash,
        state_hash: Hash,
        timestamp: u64,
    ) -> Self {
        BlockData {
            validator,
            height,
            size,
            prev_hash,
            txs_hash,
            rxs_hash,
            state_hash,
            timestamp,
        }
    }
}

/// Account structure.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Account {
    /// Account identifier.
    pub id: String,
    /// Assets map.
    pub assets: BTreeMap<String, ByteBuf>,
    /// Associated smart contract application hash (wasm binary hash).
    pub contract: Option<Hash>,
    /// Merkle tree root of the data associated with the account.
    pub data_hash: Option<Hash>,
}

impl Account {
    /// Creates a new account by associating to it the owner's public key and a
    /// contract unique identifier (wasm binary sha-256).
    pub fn new(id: &str, contract: Option<Hash>) -> Account {
        Account {
            id: id.to_owned(),
            assets: BTreeMap::new(),
            contract,
            data_hash: None,
        }
    }

    /// Get account balance for the given asset.
    pub fn load_asset(&self, asset: &str) -> Vec<u8> {
        self.assets
            .get(asset)
            .cloned()
            .unwrap_or_default()
            .into_vec()
    }

    /// Set account balance for the given asset.
    pub fn store_asset(&mut self, asset: &str, value: &[u8]) {
        let buf = ByteBuf::from(value);
        self.assets.insert(asset.to_string(), buf);
    }

    /// Remove the given asset from the account.
    pub fn remove_asset(&mut self, asset: &str) {
        self.assets.remove(asset);
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BlockchainSettings {
    /// Not yet implemented
    pub accept_broadcast: bool,
    /// Number max of transactions in a block
    pub block_threshold: usize,
    /// Max time elapsed from blocks
    pub block_timeout: u16,
    /// Name of the method in Trinci account to burn fuel
    pub burning_fuel_method: String,
    /// Name of the blockchain network
    pub network_name: Option<String>,
    /// Flag that identify a production environment
    pub is_production: bool, // DELETE ME at soon will be deleted in the service contract BlockchainSettings
    /// Compatibility of the bootstrap.bin
    pub min_node_version: String,
}

#[cfg(test)]
pub mod tests {

    use super::*;
    use crate::{
        base::serialize::MessagePack,
        crypto::{
            ecdsa::tests::{ecdsa_secp384_test_keypair, ecdsa_secp384_test_public_key},
            Hashable,
        },
        ErrorKind,
    };

    const ACCOUNT_ID: &str = "QmNLei78zWmzUdbeRB3CiUfAizWUrbeeZh5K1rhAQKCh51";

    const UNIT_TRANSACTION_DATA_HEX: &str = "99d94064386166386635363366323565623036353635316363646430356239373236666432376666396463343065336239633862346432633535666139383139663336d92e516d59486e45514c64663568374b59626a4650754853526b325350676458724a5746683557363936485066713769cd03e8c408ab82b741e023a412a6736b796e6574c42212202c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7aea97465726d696e61746593a56563647361a9736563703338347231c461045936d631b849bb5760bcf62e0d1261b6b6e227dc0a3892cbeec91be069aaa25996f276b271c2c53cba4be96d67edcadd66b793456290609102d5401f413cd1b5f4130b9cfaa68d30d0d25c3704cb72734cd32064365ff7042f5a3eee09b06cc1c40a4f706171756544617461";
    const UNIT_TRANSACTION_DATA_HASH_HEX: &str =
        "12207cfff11a272ad3f5cb60606717adc9984d1cd4dc4c491fdf4c56661ee40caaad";

    const BULK_TRANSACTION_DATA_HEX: &str = "92d94030656333343639653335303936383264373539393739376139643163356364663536623264396264343335663835336133623939396362623731376530333337929199d94030626363663564636534663235303336646531656630393165613965383632666133343865366465383265663136666263666338346331663133313462383665d92e516d59486e45514c64663568374b59626a4650754853526b325350676458724a5746683557363936485066713769cd03e8c408ab82b741e023a412a6736b796e6574c42212202c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7aea97465726d696e61746593a56563647361a9736563703338347231c461045936d631b849bb5760bcf62e0d1261b6b6e227dc0a3892cbeec91be069aaa25996f276b271c2c53cba4be96d67edcadd66b793456290609102d5401f413cd1b5f4130b9cfaa68d30d0d25c3704cb72734cd32064365ff7042f5a3eee09b06cc1c40a4f706171756544617461c0";
    const BULK_WITH_NODES_TRANSACTION_DATA_HASH_HEX: &str =
        "1220cb7525e6f80b116271e6fc4bbf99b3a10815b3380fc32be2c990a0b2c547bbad";
    const BULK_WITH_NODES_TRANSACTION_DATA_HEX: &str = "92d94030656333343639653335303936383264373539393739376139643163356364663536623264396264343335663835336133623939396362623731376530333337929199d94030626363663564636534663235303336646531656630393165613965383632666133343865366465383265663136666263666338346331663133313462383665d92e516d59486e45514c64663568374b59626a4650754853526b325350676458724a5746683557363936485066713769cd03e8c408ab82b741e023a412a6736b796e6574c42212202c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7aea97465726d696e61746593a56563647361a9736563703338347231c461045936d631b849bb5760bcf62e0d1261b6b6e227dc0a3892cbeec91be069aaa25996f276b271c2c53cba4be96d67edcadd66b793456290609102d5401f413cd1b5f4130b9cfaa68d30d0d25c3704cb72734cd32064365ff7042f5a3eee09b06cc1c40a4f70617175654461746192929ad94030393765356635353263373964346636346531356638353361643139643031333937333334336165613535376435633134383264396365663731393135646238d92e516d56513965715a4d33686f5463597a4366365241585078715368583163396a4d48445659444875707862575232cd03e8c403000102a6736b796e6574c42212202c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7aea86d6574686f645f3193a56563647361a9736563703338347231c461044717583406373a9b47f564e6af4c28d9bc45b11da5de0fdfcd9928dab12eaacaedfabc7357565f2ecfa222f4b4e654a727397c3cad00a2af4c21defe5a0b403d3e62390b71633b203c268fd35ffe2e83fc7c602c2ae19274707a96f579e5439ec403000102c4221220bae7ad2ad1a246565d642930c241e7c390b159878cfa5a1a76e4fb91a00595ddc460c7e0cf6099d3cc1f6cd81fcf75c12af8a378c9433299938f15d3ebeee07a9756546420d9a63a83abe4d52dc41b2ab1487d22f54cc5a713daf9cde22341c5fecd24108a73ea2d77bca871e7e16cbe4f07b427db94d4b4ea0051c829b474402d8a929ad94030393765356635353263373964346636346531356638353361643139643031333937333334336165613535376435633134383264396365663731393135646238d92e516d63326d383963624d6d5956516156484c64336655365a6766646d46316d3775537538643246584c35697a745acd03e8c403000102a6736b796e6574c42212202c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7aea86d6574686f645f3293a56563647361a9736563703338347231c461048295bf9d82b141177ebc03002000573f556bf40bfbd9b70e20c92c45374ed87cdd099759a019dc8665114ab60c83052c37fa99ac6cd933dc635e690d616d42874114dce3b1f41f5fc9b563679e50b0cb5f9295ce8fbaaa812ef69fef6b9b6100c403000102c4221220bae7ad2ad1a246565d642930c241e7c390b159878cfa5a1a76e4fb91a00595ddc4605365838d6ea99075b7b08c9186ddd28656b18fa9e975acb5f1bc48b99f46848044a2ab506ebf5da5cdc9e9bd4525751cb537eb30d5d984aca6bd30c2416363b26ce25ca78c33091e7482d150777a69dd082a9b68656c4bc6b5fdd198e86ece53";
    const BULK_TRANSACTION_DATA_HASH_HEX: &str =
        "1220cb7525e6f80b116271e6fc4bbf99b3a10815b3380fc32be2c990a0b2c547bbad";

    const UNIT_TRANSACTION_HEX: &str = "93a7756e69745f747899d94064386166386635363366323565623036353635316363646430356239373236666432376666396463343065336239633862346432633535666139383139663336d92e516d59486e45514c64663568374b59626a4650754853526b325350676458724a5746683557363936485066713769cd03e8c408ab82b741e023a412a6736b796e6574c42212202c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7aea97465726d696e61746593a56563647361a9736563703338347231c461045936d631b849bb5760bcf62e0d1261b6b6e227dc0a3892cbeec91be069aaa25996f276b271c2c53cba4be96d67edcadd66b793456290609102d5401f413cd1b5f4130b9cfaa68d30d0d25c3704cb72734cd32064365ff7042f5a3eee09b06cc1c40a4f706171756544617461c4603b472dc456b2db807f13b60920ee0c663405441b3b5e46f93371e40ecbe1a7922034865a4be36812394e7f65b26e626737c125174889888d30a85e131b3a75416cfa361621731853325b8383afd283beaaf244ebd9f86b88d8b275376f428fdb";
    const UNIT_TRANSACTION_SIGN: &str = "3b472dc456b2db807f13b60920ee0c663405441b3b5e46f93371e40ecbe1a7922034865a4be36812394e7f65b26e626737c125174889888d30a85e131b3a75416cfa361621731853325b8383afd283beaaf244ebd9f86b88d8b275376f428fdb";

    const BULK_WITHOUT_NODES_TRANSACTION_HEX: &str = "93a762756c6b5f747892d94030656333343639653335303936383264373539393739376139643163356364663536623264396264343335663835336133623939396362623731376530333337929199d94030626363663564636534663235303336646531656630393165613965383632666133343865366465383265663136666263666338346331663133313462383665d92e516d59486e45514c64663568374b59626a4650754853526b325350676458724a5746683557363936485066713769cd03e8c408ab82b741e023a412a6736b796e6574c42212202c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7aea97465726d696e61746593a56563647361a9736563703338347231c461045936d631b849bb5760bcf62e0d1261b6b6e227dc0a3892cbeec91be069aaa25996f276b271c2c53cba4be96d67edcadd66b793456290609102d5401f413cd1b5f4130b9cfaa68d30d0d25c3704cb72734cd32064365ff7042f5a3eee09b06cc1c40a4f706171756544617461c0c46019f3a5d479c463569346078e52bc57d76201232eaaea083b54777086732e5f4a47bc3d8eee4e5af46eee211e40fac6502a1a0710161865a6abd13f1528ff0e4611d3af2d0b89e57ce3b2af0d283252aec2ecca5c5317cf7b98bdad96c9099299";
    const BULK_WITHOUT_NODES_TRANSACTION_SIGN: &str = "19f3a5d479c463569346078e52bc57d76201232eaaea083b54777086732e5f4a47bc3d8eee4e5af46eee211e40fac6502a1a0710161865a6abd13f1528ff0e4611d3af2d0b89e57ce3b2af0d283252aec2ecca5c5317cf7b98bdad96c9099299";
    const BULK_WITH_NODES_TRANSACTION_SIGN_ALT: &str = "c814893010201f45925d4118fdc5beabc7cb1d6cf58c9e44521a31f01d62ee445bf15729b304f9b32f4e6531c092f3b3fa3f893504dbd18c5f39c6ebb5a16a0584fd811dd43ca661dba909f0ee75965d8f6642a76b1c254514166f0cd4a78269";
    const BULK_WITH_NODES_TRANSACTION_SIGN: &str = "b0315a41eac7178b2b5a06b8faf9e19647086e34c789a0fbc87134350392b093942cf5de7a557a23c8397b60fb0a5c14a3970beac5db1c30bd97caa4e63c99861b5db79769f6e497d28b4cd1f862d7512f6f7702810f9e361386db6c91158d84";

    const RECEIPT_HEX: &str = "960309cd03e7c3c40a4f70617175654461746190";
    const RECEIPT_HASH_HEX: &str =
        "12202da9df047846a2c30866388c0650a1b126c421f4f3b55bea254edc1b4281cac3";

    const BLOCK_HEX: &str = "929893a56563647361a9736563703338347231c461045936d631b849bb5760bcf62e0d1261b6b6e227dc0a3892cbeec91be069aaa25996f276b271c2c53cba4be96d67edcadd66b793456290609102d5401f413cd1b5f4130b9cfaa68d30d0d25c3704cb72734cd32064365ff7042f5a3eee09b06cc10103c4221220648263253df78db6c2f1185e832c546f2f7a9becbdc21d3be41c80dc96b86011c4221220f937696c204cc4196d48f3fe7fc95c80be266d210b95397cc04cfc6b062799b8c4221220dec404bd222542402ffa6b32ebaa9998823b7bb0a628152601d1da11ec70b867c422122005db394ef154791eed2cb97e7befb2864a5702ecfd44fab7ef1c5ca215475c7d00c403000102";
    const BLOCK_HASH_HEX: &str =
        "122089d787c8ad06a874ef107dc811cd767d4d991a46f5adac5c934ea6d3dc575f39";

    const BLOCK_DATA_HEX: &str = "9893a56563647361a9736563703338347231c461045936d631b849bb5760bcf62e0d1261b6b6e227dc0a3892cbeec91be069aaa25996f276b271c2c53cba4be96d67edcadd66b793456290609102d5401f413cd1b5f4130b9cfaa68d30d0d25c3704cb72734cd32064365ff7042f5a3eee09b06cc10103c4221220648263253df78db6c2f1185e832c546f2f7a9becbdc21d3be41c80dc96b86011c4221220f937696c204cc4196d48f3fe7fc95c80be266d210b95397cc04cfc6b062799b8c4221220dec404bd222542402ffa6b32ebaa9998823b7bb0a628152601d1da11ec70b867c422122005db394ef154791eed2cb97e7befb2864a5702ecfd44fab7ef1c5ca215475c7d00";
    const BLOCK_DATA_HASH_HEX: &str =
        "122059c1f128b6e58f7d5ae040ca2f4a2c803ea60e574e0e1420e7945be513c5e7bf";

    const ACCOUNT_CONTRACT_HEX: &str = "94d92e516d4e4c656937387a576d7a556462655242334369556641697a5755726265655a68354b31726841514b4368353181a3534b59c40103c422122087b6239079719fc7e4349ec54baac9e04c20c48cf0c6a9d2b29b0ccf7c31c727c0";
    const ACCOUNT_NCONTRAC_HEX: &str = "94d92e516d4e4c656937387a576d7a556462655242334369556641697a5755726265655a68354b31726841514b4368353181a3534b59c40103c0c0";

    const CONTRACT_EVENT_HEX: &str = "95c42212202c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7aeae6f726967696e5f6163636f756e74c4221220a4cea0f0f6e4ac6865fd6092a319ccc6d2387cd8bb65e64bdc486f1a9a998569ab636f6f6c5f6d6574686f64c403010203";

    pub(crate) const FUEL_LIMIT: u64 = 1000;

    fn create_test_data_unit(fuel_limit: u64) -> TransactionData {
        // Opaque information returned by the smart contract.
        let args = hex::decode("4f706171756544617461").unwrap();
        let public_key = PublicKey::Ecdsa(ecdsa_secp384_test_public_key(0));
        let account = public_key.to_account_id();
        let contract =
            Hash::from_hex("12202c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae")
                .unwrap();

        TransactionData::V1(TransactionDataV1 {
            account,
            fuel_limit,
            nonce: [0xab, 0x82, 0xb7, 0x41, 0xe0, 0x23, 0xa4, 0x12].to_vec(),
            network: "skynet".to_string(),
            contract: Some(contract),
            method: "terminate".to_string(),
            caller: public_key,
            args,
        })
    }

    fn create_transactiondata_bulk_node_v1(
        pk: PublicKey,
        contract: Hash,
        method: String,
        root_hash: Hash,
    ) -> TransactionData {
        TransactionData::BulkNodeV1(TransactionDataBulkNodeV1 {
            account: pk.to_account_id(),
            fuel_limit: FUEL_LIMIT,
            nonce: vec![0, 1, 2],
            network: "skynet".to_string(),
            contract: Some(contract),
            method,
            caller: pk,
            args: vec![0, 1, 2],
            depends_on: root_hash,
        })
    }

    fn create_bulk_node_transaction_alt(
        root_hash: Hash,
        key: u8,
        method: String,
    ) -> SignedTransaction {
        let keypair = KeyPair::Ecdsa(ecdsa_secp384_test_keypair(key));
        let contract =
            Hash::from_hex("12202c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae")
                .unwrap();

        let data =
            create_transactiondata_bulk_node_v1(keypair.public_key(), contract, method, root_hash);

        let signature = match key{
            // This guarantees a fix signature for tests
            1 => hex::decode("c7e0cf6099d3cc1f6cd81fcf75c12af8a378c9433299938f15d3ebeee07a9756546420d9a63a83abe4d52dc41b2ab1487d22f54cc5a713daf9cde22341c5fecd24108a73ea2d77bca871e7e16cbe4f07b427db94d4b4ea0051c829b474402d8a").unwrap(),
            2 => hex::decode("5365838d6ea99075b7b08c9186ddd28656b18fa9e975acb5f1bc48b99f46848044a2ab506ebf5da5cdc9e9bd4525751cb537eb30d5d984aca6bd30c2416363b26ce25ca78c33091e7482d150777a69dd082a9b68656c4bc6b5fdd198e86ece53").unwrap(),
            _ => panic!()
        };

        SignedTransaction { data, signature }
    }

    fn create_bulk_node_transaction(root_hash: Hash, key: u8, method: String) -> SignedTransaction {
        let keypair = KeyPair::Ecdsa(ecdsa_secp384_test_keypair(key));
        let contract =
            Hash::from_hex("12202c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae")
                .unwrap();

        let data =
            create_transactiondata_bulk_node_v1(keypair.public_key(), contract, method, root_hash);

        let signature = data.sign(&keypair).unwrap();
        //let signature = match key{
        //    // This guarantees a fix signature for tests
        //    1 => hex::decode("c7e0cf6099d3cc1f6cd81fcf75c12af8a378c9433299938f15d3ebeee07a9756546420d9a63a83abe4d52dc41b2ab1487d22f54cc5a713daf9cde22341c5fecd24108a73ea2d77bca871e7e16cbe4f07b427db94d4b4ea0051c829b474402d8a").unwrap(),
        //    2 => hex::decode("5365838d6ea99075b7b08c9186ddd28656b18fa9e975acb5f1bc48b99f46848044a2ab506ebf5da5cdc9e9bd4525751cb537eb30d5d984aca6bd30c2416363b26ce25ca78c33091e7482d150777a69dd082a9b68656c4bc6b5fdd198e86ece53").unwrap(),
        //    _ => panic!()
        //};

        SignedTransaction { data, signature }
    }

    fn create_test_data_bulk(with_nodes: bool) -> TransactionData {
        // Opaque information returned by the smart contract.
        let args = hex::decode("4f706171756544617461").unwrap();
        let public_key = PublicKey::Ecdsa(ecdsa_secp384_test_public_key(0));
        let account = public_key.to_account_id();
        let contract =
            Hash::from_hex("12202c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae")
                .unwrap();

        let root_data = TransactionData::BulkRootV1(TransactionDataV1 {
            account,
            fuel_limit: FUEL_LIMIT,
            nonce: [0xab, 0x82, 0xb7, 0x41, 0xe0, 0x23, 0xa4, 0x12].to_vec(),
            network: "skynet".to_string(),
            contract: Some(contract),
            method: "terminate".to_string(),
            caller: public_key,
            args,
        });

        let root = UnsignedTransaction { data: root_data };

        let root_hash = root.data.primary_hash();

        let nodes = if with_nodes {
            let nodes = vec![
                create_bulk_node_transaction(root_hash, 1, String::from("method_1")),
                create_bulk_node_transaction(root_hash, 2, String::from("method_2")),
            ];

            Some(nodes)
        } else {
            None
        };

        TransactionData::BulkV1(TransactionDataBulkV1 {
            txs: BulkTransactions {
                root: Box::new(root),
                nodes,
            },
        })
    }

    fn create_test_data_bulk_alt(with_nodes: bool) -> TransactionData {
        // Opaque information returned by the smart contract.
        let args = hex::decode("4f706171756544617461").unwrap();
        let public_key = PublicKey::Ecdsa(ecdsa_secp384_test_public_key(0));
        let account = public_key.to_account_id();
        let contract =
            Hash::from_hex("12202c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae")
                .unwrap();

        let root_data = TransactionData::BulkRootV1(TransactionDataV1 {
            account,
            fuel_limit: FUEL_LIMIT,
            nonce: [0xab, 0x82, 0xb7, 0x41, 0xe0, 0x23, 0xa4, 0x12].to_vec(),
            network: "skynet".to_string(),
            contract: Some(contract),
            method: "terminate".to_string(),
            caller: public_key,
            args,
        });

        let root = UnsignedTransaction { data: root_data };

        let root_hash = root.data.primary_hash();

        let nodes = if with_nodes {
            let nodes = vec![
                create_bulk_node_transaction_alt(root_hash, 1, String::from("method_1")),
                create_bulk_node_transaction_alt(root_hash, 2, String::from("method_2")),
            ];

            Some(nodes)
        } else {
            None
        };

        TransactionData::BulkV1(TransactionDataBulkV1 {
            txs: BulkTransactions {
                root: Box::new(root),
                nodes,
            },
        })
    }

    pub fn create_test_unit_tx(fuel_limit: u64) -> Transaction {
        // UNCOMMENT THIS to create a new signature
        //let keypair = crate::crypto::sign::tests::create_test_keypair();
        //let data = create_test_data_unit();
        //let data = crate::base::serialize::rmp_serialize(&data).unwrap();
        //let signature = keypair.sign(&data).unwrap();
        //println!("unit_sign: {}", hex::encode(&signature));

        let signature = hex::decode(UNIT_TRANSACTION_SIGN).unwrap();

        Transaction::UnitTransaction(SignedTransaction {
            data: create_test_data_unit(fuel_limit),
            signature,
        })
    }

    pub fn create_test_bulk_tx(with_nodes: bool) -> Transaction {
        // UNCOMMENT THIS to create a new signature
        //let keypair = crate::crypto::sign::tests::create_test_keypair();
        //let data = create_test_data_bulk(with_nodes);
        //let data = crate::base::serialize::rmp_serialize(&data).unwrap();
        //let signature = keypair.sign(&data).unwrap();
        //println!("bulk_sign: {}", hex::encode(&signature));

        let signature = if with_nodes {
            hex::decode(BULK_WITH_NODES_TRANSACTION_SIGN).unwrap()
        } else {
            hex::decode(BULK_WITHOUT_NODES_TRANSACTION_SIGN).unwrap()
        };
        Transaction::BulkTransaction(BulkTransaction {
            data: create_test_data_bulk(with_nodes),
            signature,
        })
    }

    // fixed sign in sub-tx
    pub fn create_test_bulk_tx_alt(with_nodes: bool) -> Transaction {
        // UNCOMMENT THIS to create a new signature
        //let keypair = crate::crypto::sign::tests::create_test_keypair();
        //let data = create_test_data_bulk_alt(with_nodes);
        //let data = crate::base::serialize::rmp_serialize(&data).unwrap();
        //let signature = keypair.sign(&data).unwrap();
        //println!("bulk_sign: {}", hex::encode(&signature));

        let signature = if with_nodes {
            hex::decode(BULK_WITH_NODES_TRANSACTION_SIGN_ALT).unwrap()
        } else {
            hex::decode(BULK_WITHOUT_NODES_TRANSACTION_SIGN).unwrap()
        };
        Transaction::BulkTransaction(BulkTransaction {
            data: create_test_data_bulk_alt(with_nodes),
            signature,
        })
    }

    pub fn create_test_contract_event() -> SmartContractEvent {
        SmartContractEvent {
            event_tx: Hash::from_hex(
                "12202c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
            )
            .unwrap(),
            emitter_account: "origin_account".to_string(),
            emitter_smart_contract: Hash::from_hex(
                "1220a4cea0f0f6e4ac6865fd6092a319ccc6d2387cd8bb65e64bdc486f1a9a998569",
            )
            .unwrap(),
            event_name: "cool_method".to_string(),
            event_data: vec![1, 2, 3],
        }
    }

    pub fn create_test_receipt() -> Receipt {
        // Opaque information returned by the smart contract.
        let returns = hex::decode("4f706171756544617461").unwrap();
        Receipt {
            height: 3,
            index: 9,
            burned_fuel: 999,
            success: true,
            returns,
            events: Some(Vec::new()),
        }
    }

    pub fn create_test_account() -> Account {
        let hash =
            Hash::from_hex("122087b6239079719fc7e4349ec54baac9e04c20c48cf0c6a9d2b29b0ccf7c31c727")
                .unwrap();
        let mut account = Account::new(ACCOUNT_ID, Some(hash));
        account
            .assets
            .insert("SKY".to_string(), ByteBuf::from([3u8].to_vec()));
        account
    }

    pub fn create_test_block_data() -> BlockData {
        let prev_hash =
            Hash::from_hex("1220648263253df78db6c2f1185e832c546f2f7a9becbdc21d3be41c80dc96b86011")
                .unwrap();
        let txs_hash =
            Hash::from_hex("1220f937696c204cc4196d48f3fe7fc95c80be266d210b95397cc04cfc6b062799b8")
                .unwrap();
        let res_hash =
            Hash::from_hex("1220dec404bd222542402ffa6b32ebaa9998823b7bb0a628152601d1da11ec70b867")
                .unwrap();
        let state_hash =
            Hash::from_hex("122005db394ef154791eed2cb97e7befb2864a5702ecfd44fab7ef1c5ca215475c7d")
                .unwrap();
        let keypair = crate::crypto::sign::tests::create_test_keypair();

        BlockData {
            validator: Some(keypair.public_key()),

            height: 1,
            size: 3,
            prev_hash,
            txs_hash,
            rxs_hash: res_hash,
            state_hash,
            timestamp: 0,
        }
    }

    pub fn create_test_block() -> Block {
        let data = create_test_block_data();

        Block {
            data,
            signature: vec![0, 1, 2],
        }
    }

    #[test]
    fn unit_transaction_data_serialize() {
        let data = create_test_data_unit(FUEL_LIMIT);

        let buf = data.serialize();

        assert_eq!(UNIT_TRANSACTION_DATA_HEX, hex::encode(buf));
    }

    #[test]
    fn unit_transaction_data_deserialize() {
        let expected = create_test_data_unit(FUEL_LIMIT);

        let buf = hex::decode(UNIT_TRANSACTION_DATA_HEX).unwrap();

        let data = TransactionData::deserialize(&buf).unwrap();

        assert_eq!(expected, data);
    }

    #[test]
    fn bulk_transaction_data_serialize() {
        let data = create_test_data_bulk(false);

        let buf = data.serialize();

        assert_eq!(BULK_TRANSACTION_DATA_HEX, hex::encode(buf));
    }

    #[test]
    fn bulk_transaction_data_deserialize() {
        let expected = create_test_data_bulk(false);

        let buf = hex::decode(BULK_TRANSACTION_DATA_HEX).unwrap();

        let data = TransactionData::deserialize(&buf).unwrap();

        assert_eq!(expected, data);
    }

    #[test]
    fn bulk_with_nodes_transaction_data_serialize() {
        let data = create_test_data_bulk_alt(true);

        let buf = data.serialize();

        assert_eq!(BULK_WITH_NODES_TRANSACTION_DATA_HEX, hex::encode(buf));
    }

    #[test]
    fn bulk_with_nodes_transaction_data_deserialize() {
        let expected = create_test_data_bulk_alt(true);

        let buf = hex::decode(BULK_WITH_NODES_TRANSACTION_DATA_HEX).unwrap();

        let data = TransactionData::deserialize(&buf).unwrap();

        assert_eq!(expected, data);
    }

    #[test]
    fn unit_transaction_data_deserialize_fail() {
        let mut buf = hex::decode(UNIT_TRANSACTION_DATA_HEX).unwrap();
        buf.pop(); // remove a byte to make it fail

        let error = TransactionData::deserialize(&buf).unwrap_err();

        assert_eq!(error.kind, ErrorKind::MalformedData);
    }

    #[test]
    fn bulk_transaction_data_deserialize_fail() {
        let mut buf = hex::decode(BULK_TRANSACTION_DATA_HEX).unwrap();
        buf.pop(); // remove a byte to make it fail

        let error = TransactionData::deserialize(&buf).unwrap_err();

        assert_eq!(error.kind, ErrorKind::MalformedData);
    }

    #[test]
    fn unit_transaction_serialize() {
        let tx = create_test_unit_tx(FUEL_LIMIT);

        let buf = tx.serialize();

        assert_eq!(UNIT_TRANSACTION_HEX, hex::encode(buf));
    }

    #[test]
    fn unit_transaction_deserialize() {
        let expected = create_test_unit_tx(FUEL_LIMIT);
        let buf = hex::decode(UNIT_TRANSACTION_HEX).unwrap();

        let tx = Transaction::deserialize(&buf).unwrap();

        assert_eq!(expected, tx);
    }

    #[test]
    fn bulk_transaction_serialize() {
        let tx = create_test_bulk_tx(false);

        let buf = tx.serialize();

        assert_eq!(BULK_WITHOUT_NODES_TRANSACTION_HEX, hex::encode(buf));
    }

    #[test]
    fn bulk_transaction_deserialize() {
        let expected = create_test_bulk_tx(false);
        let buf = hex::decode(BULK_WITHOUT_NODES_TRANSACTION_HEX).unwrap();

        let tx = Transaction::deserialize(&buf).unwrap();

        assert_eq!(expected, tx);
    }

    #[test]
    fn transaction_deserialize_fail() {
        let mut buf = hex::decode(UNIT_TRANSACTION_HEX).unwrap();
        buf.pop();

        let error = Transaction::deserialize(&buf).unwrap_err();

        assert_eq!(error.kind, ErrorKind::MalformedData);

        let mut buf = hex::decode(BULK_WITHOUT_NODES_TRANSACTION_HEX).unwrap();
        buf.pop();

        let error = Transaction::deserialize(&buf).unwrap_err();

        assert_eq!(error.kind, ErrorKind::MalformedData);
    }

    #[test]
    fn unit_transaction_data_hash() {
        let tx = create_test_unit_tx(FUEL_LIMIT);
        let hash = match tx {
            Transaction::UnitTransaction(tx) => tx.data.primary_hash(),
            Transaction::BulkTransaction(tx) => tx.data.primary_hash(),
        };
        assert_eq!(UNIT_TRANSACTION_DATA_HASH_HEX, hex::encode(hash));
    }

    #[test]
    fn bulk_transaction_data_hash() {
        let tx = create_test_bulk_tx(false);
        let hash = match tx {
            Transaction::BulkTransaction(tx) => tx.data.primary_hash(),
            _ => panic!(),
        };
        assert_eq!(BULK_TRANSACTION_DATA_HASH_HEX, hex::encode(hash));
    }

    #[test]
    fn bulk_with_nodes_transaction_data_hash() {
        let tx = create_test_bulk_tx_alt(false);
        let hash = match tx {
            Transaction::BulkTransaction(tx) => tx.data.primary_hash(),
            _ => panic!(),
        };
        assert_eq!(BULK_WITH_NODES_TRANSACTION_DATA_HASH_HEX, hex::encode(hash));
    }

    #[test]
    fn unit_transaction_data_verify() {
        let tx = create_test_unit_tx(FUEL_LIMIT);
        let result = tx.verify(tx.get_caller(), tx.get_signature());
        assert!(result.is_ok());
    }

    #[test]
    fn bulk_transaction_data_verify() {
        let tx = create_test_bulk_tx(false);
        let result = tx.verify(tx.get_caller(), tx.get_signature());
        assert!(result.is_ok());
    }

    #[test]
    fn bulk_with_nodes_transaction_data_verify() {
        let tx = create_test_bulk_tx_alt(true);
        let result = tx.verify(tx.get_caller(), tx.get_signature());
        assert!(result.is_ok());
    }

    #[test]
    fn unit_transaction_data_sign_verify() {
        let data = create_test_data_unit(FUEL_LIMIT);
        let keypair = KeyPair::Ecdsa(ecdsa_secp384_test_keypair(0));

        let signature = data.sign(&keypair).unwrap();
        let result = data.verify(&keypair.public_key(), &signature);

        assert!(result.is_ok());
    }

    #[test]
    fn bulk_transaction_data_sign_verify() {
        let data = create_test_data_bulk(false);
        let keypair = KeyPair::Ecdsa(ecdsa_secp384_test_keypair(0));

        let signature = data.sign(&keypair).unwrap();
        let result = data.verify(&keypair.public_key(), &signature);

        assert!(result.is_ok());
    }

    #[test]
    fn bulk_transaction_data_with_nodes_sign_verify() {
        let data = create_test_data_bulk(true);
        let keypair = KeyPair::Ecdsa(ecdsa_secp384_test_keypair(0));

        let signature = data.sign(&keypair).unwrap();
        let result = data.verify(&keypair.public_key(), &signature);

        assert!(result.is_ok());

        match data {
            TransactionData::BulkV1(tx_data) => {
                for node_tx in tx_data.txs.nodes.unwrap() {
                    match node_tx.data {
                        TransactionData::BulkNodeV1(tx_data) => {
                            tx_data.verify(&tx_data.caller, &node_tx.signature).unwrap();
                        }
                        _ => panic!(),
                    }
                }
            }
            _ => panic!(),
        }
    }

    #[test]
    fn bulk_transaction_data_check_integrity() {
        let data = create_test_data_bulk(true);

        assert!(data.check_integrity().is_ok());
    }

    #[test]
    fn bulk_transaction_data_with_nodes_check_integrity() {
        let data = create_test_data_bulk(true);

        assert!(data.check_integrity().is_ok());
    }

    #[test]
    fn receipt_serialize() {
        let receipt = create_test_receipt();

        let buf = receipt.serialize();

        assert_eq!(hex::encode(buf), RECEIPT_HEX);
    }

    #[test]
    fn receipt_deserialize() {
        let expected = create_test_receipt();
        let buf = hex::decode(RECEIPT_HEX).unwrap();

        let receipt = Receipt::deserialize(&buf).unwrap();

        assert_eq!(receipt, expected);
    }

    #[test]
    fn receipt_deserialize_fail() {
        let mut buf = hex::decode(RECEIPT_HEX).unwrap();
        buf.pop(); // remove a byte to make it fail

        let err = Receipt::deserialize(&buf).unwrap_err();

        assert_eq!(err.kind, ErrorKind::MalformedData);
    }

    #[test]
    fn receipt_hash() {
        let receipt = create_test_receipt();

        let hash = receipt.primary_hash();

        assert_eq!(RECEIPT_HASH_HEX, hex::encode(hash));
    }

    #[test]
    fn contract_event_serialize() {
        let event = create_test_contract_event();

        let buf = event.serialize();

        assert_eq!(hex::encode(buf), CONTRACT_EVENT_HEX);
    }

    #[test]
    fn contract_event_deserialize() {
        let expected = create_test_contract_event();
        let buf = hex::decode(CONTRACT_EVENT_HEX).unwrap();

        let event = SmartContractEvent::deserialize(&buf).unwrap();

        assert_eq!(event, expected);
    }

    #[test]
    fn block_serialize() {
        let block = create_test_block();

        let buf = block.serialize();

        assert_eq!(hex::encode(buf), BLOCK_HEX);
    }

    #[test]
    fn block_deserialize() {
        let expected = create_test_block();
        let buf = hex::decode(BLOCK_HEX).unwrap();

        let block = Block::deserialize(&buf).unwrap();

        assert_eq!(block, expected);
    }

    #[test]
    fn block_deserialize_fail() {
        let mut buf = hex::decode(BLOCK_HEX).unwrap();
        buf.pop(); // remove a byte to make it fail

        let error = Block::deserialize(&buf).unwrap_err();

        assert_eq!(error.kind, ErrorKind::MalformedData);
    }

    #[test]
    fn block_hash() {
        let block = create_test_block();

        let hash = block.primary_hash();

        assert_eq!(BLOCK_HASH_HEX, hex::encode(hash));
    }

    #[test]
    fn block_data_serialize() {
        let block_data = create_test_block_data();

        let buf = block_data.serialize();

        assert_eq!(hex::encode(buf), BLOCK_DATA_HEX);
    }

    #[test]
    fn block_data_deserialize() {
        let expected = create_test_block_data();
        let buf = hex::decode(BLOCK_DATA_HEX).unwrap();

        let block_data = BlockData::deserialize(&buf).unwrap();

        assert_eq!(block_data, expected);
    }

    #[test]
    fn block_data_deserialize_fail() {
        let mut buf = hex::decode(BLOCK_DATA_HEX).unwrap();
        buf.pop(); // remove a byte to make it fail

        let error = BlockData::deserialize(&buf).unwrap_err();

        assert_eq!(error.kind, ErrorKind::MalformedData);
    }

    #[test]
    fn block_data_hash() {
        let block_data = create_test_block_data();

        let hash = block_data.primary_hash();

        assert_eq!(BLOCK_DATA_HASH_HEX, hex::encode(hash));
    }

    #[test]
    fn account_serialize() {
        let account = create_test_account();

        let buf = account.serialize();

        assert_eq!(hex::encode(buf), ACCOUNT_CONTRACT_HEX);
    }

    #[test]
    fn account_deserialize() {
        let expected = create_test_account();
        let buf = hex::decode(ACCOUNT_CONTRACT_HEX).unwrap();

        let account = Account::deserialize(&buf).unwrap();

        assert_eq!(account, expected);
    }

    #[test]
    fn account_serialize_null_contract() {
        let mut account = create_test_account();
        account.contract = None;

        let buf = account.serialize();

        assert_eq!(hex::encode(buf), ACCOUNT_NCONTRAC_HEX);
    }

    #[test]
    fn account_deserialize_null_contract() {
        let mut expected = create_test_account();
        expected.contract = None;
        let buf = hex::decode(ACCOUNT_NCONTRAC_HEX).unwrap();

        let account = Account::deserialize(&buf).unwrap();

        assert_eq!(account, expected);
    }

    #[test]
    fn account_deserialize_fail() {
        let mut buf = hex::decode(ACCOUNT_CONTRACT_HEX).unwrap();
        buf.pop();

        let error = Account::deserialize(&buf).unwrap_err();

        assert_eq!(error.kind, ErrorKind::MalformedData);
    }

    #[test]
    fn account_store_asset() {
        let mut account = create_test_account();

        account.store_asset("BTC", &[3]);

        assert_eq!(account.load_asset("BTC"), [3]);
    }

    #[test]
    fn account_remove_asset() {
        let mut account = create_test_account();

        account.remove_asset("BTC");

        assert_eq!(account.load_asset("BTC"), Vec::<u8>::new());
    }

    #[test]
    fn account_load_asset() {
        let mut account = create_test_account();
        account.store_asset("BTC", &[3]);

        let value = account.load_asset("BTC");

        assert_eq!(value, [3]);
    }
}
