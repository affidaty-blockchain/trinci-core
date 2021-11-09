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
    crypto::{Hash, KeyPair, PublicKey},
    ErrorKind, Result,
};
use serde_bytes::ByteBuf;
use std::collections::BTreeMap;

/// Transaction payload.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct TransactionData {
    /// Transaction schema version.
    pub schema: String,
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

/// Signed transaction.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Transaction {
    /// Transaction payload.
    pub data: TransactionData,
    /// Data field signature verifiable using the `caller` within the `data`.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

impl TransactionData {
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

// TODO add more test on events
/// Events risen by the smart contract execution
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct SmartContractEvent {
    pub name: String,
    pub data: Option<Vec<u8>>, // FIXME Remove the option (empty data will be an empty vector)
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

    pub events: Option<Vec<SmartContractEvent>>,
}

/// Block structure.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Block {
    /// Index in the blockhain, which is also the number of ancestors blocks.
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
}

impl Block {
    /// Instance a new block structure.
    pub fn new(
        height: u64,
        size: u32,
        prev_hash: Hash,
        txs_hash: Hash,
        rxs_hash: Hash,
        state_hash: Hash,
    ) -> Self {
        Block {
            height,
            size,
            prev_hash,
            txs_hash,
            rxs_hash,
            state_hash,
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

    const TRANSACTION_DATA_HEX: &str = "99ae6d792d636f6f6c2d736368656d61d92e516d59486e45514c64663568374b59626a4650754853526b325350676458724a5746683557363936485066713769cd03e8c408ab82b741e023a412a6736b796e6574c42212202c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7aea97465726d696e61746593a56563647361a9736563703338347231c461045936d631b849bb5760bcf62e0d1261b6b6e227dc0a3892cbeec91be069aaa25996f276b271c2c53cba4be96d67edcadd66b793456290609102d5401f413cd1b5f4130b9cfaa68d30d0d25c3704cb72734cd32064365ff7042f5a3eee09b06cc1c40a4f706171756544617461";
    const TRANSACTION_DATA_HASH_HEX: &str =
        "1220a1626da0acb6d0ac8b6d10db846ae7c25cef0cb77c6355e7e128e91414364a4f";

    const TRANSACTION_HEX: &str = "9299ae6d792d636f6f6c2d736368656d61d92e516d59486e45514c64663568374b59626a4650754853526b325350676458724a5746683557363936485066713769cd03e8c408ab82b741e023a412a6736b796e6574c42212202c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7aea97465726d696e61746593a56563647361a9736563703338347231c461045936d631b849bb5760bcf62e0d1261b6b6e227dc0a3892cbeec91be069aaa25996f276b271c2c53cba4be96d67edcadd66b793456290609102d5401f413cd1b5f4130b9cfaa68d30d0d25c3704cb72734cd32064365ff7042f5a3eee09b06cc1c40a4f706171756544617461c460cf2665db3c17f94579404a7a87204960446f7d65a7962db22953721576bf125a72215bfdee464bf025d2359615550fa6660cc53fb729b02ef251c607dfc93dc441a783bb058c41e694fe99904969f69d0735a794dc85010e4156a6edcb55177e";
    const TRANSACTION_SIGN: &str = "cf2665db3c17f94579404a7a87204960446f7d65a7962db22953721576bf125a72215bfdee464bf025d2359615550fa6660cc53fb729b02ef251c607dfc93dc441a783bb058c41e694fe99904969f69d0735a794dc85010e4156a6edcb55177e";

    const RECEIPT_HEX: &str = "960309cd03e7c3c40a4f70617175654461746190";
    const RECEIPT_HASH_HEX: &str =
        "12202da9df047846a2c30866388c0650a1b126c421f4f3b55bea254edc1b4281cac3";

    const BLOCK_HEX: &str = "960103c4221220648263253df78db6c2f1185e832c546f2f7a9becbdc21d3be41c80dc96b86011c4221220f937696c204cc4196d48f3fe7fc95c80be266d210b95397cc04cfc6b062799b8c4221220dec404bd222542402ffa6b32ebaa9998823b7bb0a628152601d1da11ec70b867c422122005db394ef154791eed2cb97e7befb2864a5702ecfd44fab7ef1c5ca215475c7d";
    const BLOCK_HASH_HEX: &str =
        "12207967613f2ce65f93437c8da954ba4a32a795dc1235ff179cd27f92f330521ccb";

    const ACCOUNT_CONTRACT_HEX: &str = "94d92e516d4e4c656937387a576d7a556462655242334369556641697a5755726265655a68354b31726841514b4368353181a3534b59c40103c422122087b6239079719fc7e4349ec54baac9e04c20c48cf0c6a9d2b29b0ccf7c31c727c0";
    const ACCOUNT_NCONTRAC_HEX: &str = "94d92e516d4e4c656937387a576d7a556462655242334369556641697a5755726265655a68354b31726841514b4368353181a3534b59c40103c0c0";

    const TRANSACTION_SCHEMA: &str = "my-cool-schema";
    const FUEL_LIMIT: u64 = 1000;

    fn create_test_data() -> TransactionData {
        // Opaque information returned by the smart contract.
        let args = hex::decode("4f706171756544617461").unwrap();
        let public_key = PublicKey::Ecdsa(ecdsa_secp384_test_public_key());
        let account = public_key.to_account_id();
        let contract =
            Hash::from_hex("12202c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae")
                .unwrap();
        TransactionData {
            schema: TRANSACTION_SCHEMA.to_owned(),
            account,
            fuel_limit: FUEL_LIMIT,
            nonce: [0xab, 0x82, 0xb7, 0x41, 0xe0, 0x23, 0xa4, 0x12].to_vec(),
            network: "skynet".to_string(),
            contract: Some(contract),
            method: "terminate".to_string(),
            caller: public_key,
            args,
        }
    }

    pub fn create_test_tx() -> Transaction {
        let signature = hex::decode(TRANSACTION_SIGN).unwrap();
        Transaction {
            data: create_test_data(),
            signature,
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

    pub fn create_test_block() -> Block {
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
        Block {
            height: 1,
            size: 3,
            prev_hash,
            txs_hash,
            rxs_hash: res_hash,
            state_hash,
        }
    }

    #[test]
    fn transaction_data_serialize() {
        let data = create_test_data();

        let buf = data.serialize();

        assert_eq!(TRANSACTION_DATA_HEX, hex::encode(buf));
    }

    #[test]
    fn transaction_data_deserialize() {
        let expected = create_test_data();
        let buf = hex::decode(TRANSACTION_DATA_HEX).unwrap();

        let data = TransactionData::deserialize(&buf).unwrap();

        assert_eq!(expected, data);
    }

    #[test]
    fn transaction_data_deserialize_fail() {
        let mut buf = hex::decode(TRANSACTION_DATA_HEX).unwrap();
        buf.pop(); // remove a byte to make it fail

        let error = TransactionData::deserialize(&buf).unwrap_err();

        assert_eq!(error.kind, ErrorKind::MalformedData);
    }

    #[test]
    fn transaction_data_hash() {
        let tx = create_test_tx();

        let hash = tx.data.primary_hash();

        assert_eq!(TRANSACTION_DATA_HASH_HEX, hex::encode(hash));
    }

    #[test]
    fn transaction_data_verify() {
        let tx = create_test_tx();

        let result = tx.data.verify(&tx.data.caller, &tx.signature);

        assert!(result.is_ok());
    }

    #[test]
    fn transaction_data_sign_verify() {
        let data = create_test_data();
        let keypair = KeyPair::Ecdsa(ecdsa_secp384_test_keypair());

        let signature = data.sign(&keypair).unwrap();
        let result = data.verify(&keypair.public_key(), &signature);

        println!("SIGN: {}", hex::encode(&signature));
        assert!(result.is_ok());
    }

    #[test]
    fn transaction_serialize() {
        let tx = create_test_tx();

        let buf = tx.serialize();

        assert_eq!(TRANSACTION_HEX, hex::encode(buf));
    }

    #[test]
    fn transaction_deserialize() {
        let expected = create_test_tx();
        let buf = hex::decode(TRANSACTION_HEX).unwrap();

        let tx = Transaction::deserialize(&buf).unwrap();

        assert_eq!(expected, tx);
    }

    #[test]
    fn transaction_deserialize_fail() {
        let mut buf = hex::decode(TRANSACTION_HEX).unwrap();
        buf.pop();

        let error = Transaction::deserialize(&buf).unwrap_err();

        assert_eq!(error.kind, ErrorKind::MalformedData);
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
    fn account_load_asset() {
        let mut account = create_test_account();
        account.store_asset("BTC", &[3]);

        let value = account.load_asset("BTC");

        assert_eq!(value, [3]);
    }
}
