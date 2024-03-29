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

//! Message used to send notification to the blockchain service.
//! Message elements defined as "packed` are structures serialized in
//! "MessagePack" format.
use super::Event;
use crate::{
    base::{
        schema::{Block, SmartContractEvent},
        Account, Receipt, Transaction,
    },
    channel,
    crypto::Hash,
    Error,
};

/// Message types enumeration.
///
/// TODO
/// Enum variants are internally tagged as strings.
/// We will switch to integer tags as soon as
/// [this](https://github.com/serde-rs/serde/pull/2056) is merged.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
#[allow(clippy::large_enum_variant)]
pub enum Message {
    /// Exception response used for the full set of messages.
    #[serde(rename = "0")]
    Exception(Error),
    /// Subscribe to a set blockchain events.
    #[serde(rename = "1")]
    Subscribe {
        /// Subscriber identifier.
        id: String,
        /// Events set (bitflags).
        events: Event,
    },
    /// Unsubscribe from a set of blockchain events.
    #[serde(rename = "2")]
    Unsubscribe {
        /// Subscriber identifier.
        id: String,
        /// Events set (bitflags).
        events: Event,
    },
    /// Add transaction request. Boolean is true if we require confirmation.
    #[serde(rename = "3")]
    PutTransactionRequest {
        /// Request for confirmation.
        confirm: bool,
        /// `Transaction` structure.
        tx: Transaction,
    },
    /// Put transaction response.
    /// This message is sent only if `PutTransactionRequest` confirmation is requested.
    #[serde(rename = "4")]
    PutTransactionResponse {
        /// Transaction `data` hash.
        hash: Hash,
    },
    /// Get transaction request.
    #[serde(rename = "5")]
    GetTransactionRequest {
        /// `Transaction::data` hash.
        hash: Hash,
        /// Destination of the `Transaction`. `None` if local operations,
        /// or to gossip propagation. TODO: maybe Some("ALL") for gossip
        destination: Option<String>,
    },
    /// Get transaction response.
    #[serde(rename = "6")]
    GetTransactionResponse {
        tx: Transaction,
        /// Origin of the `Transaction`. `None` if local operations,
        /// and no chance to propagate outside the response.
        origin: Option<String>,
    },
    /// Get receipt request.
    #[serde(rename = "7")]
    GetReceiptRequest {
        /// `Transaction::data` hash.
        hash: Hash,
    },
    /// Get transaction receipt response.
    #[serde(rename = "8")]
    GetReceiptResponse {
        /// `Receipt` structure.
        rx: Receipt,
    },
    /// Get block request.
    #[serde(rename = "9")]
    GetBlockRequest {
        /// Block height.
        height: u64,
        /// Request for block transactions hashes.
        txs: bool,
        /// Destination of the `Block`. `None` if local operations,
        /// or to gossip propagation. TODO: maybe Some("ALL") for gossip
        destination: Option<String>,
    },
    /// Get block response.
    #[serde(rename = "10")]
    GetBlockResponse {
        /// `Block` structure.
        block: Block,
        /// Block transactions hashes. `None` if not requested.
        txs: Option<Vec<Hash>>,
        /// Origin of the `Block`. `None` if local operations,
        /// and no chance to propagate outside the response.
        origin: Option<String>,
    },
    /// Get account request.
    #[serde(rename = "11")]
    GetAccountRequest {
        /// Account identifier.
        id: String,
        /// Account data fields.
        data: Vec<String>,
    },
    /// Get account response.
    #[serde(rename = "12")]
    GetAccountResponse {
        /// Packed `Account` structure.
        acc: Account,
        /// Account data
        data: Vec<Option<Vec<u8>>>,
    },
    /// Get core stats request.
    #[serde(rename = "13")]
    GetCoreStatsRequest,
    /// Get core stats response.
    #[serde(rename = "14")]
    GetCoreStatsResponse((Hash, usize, Option<Block>)),
    /// Get the contracts events.
    #[serde(rename = "15")]
    GetContractEvent {
        /// `Event` structure.
        event: SmartContractEvent,
    },
    /// Get network ID request.
    #[serde(rename = "16")]
    GetNetworkIdRequest,
    /// Get network ID response.
    #[serde(rename = "17")]
    GetNetworkIdResponse(String),
    /// Get seed request.
    #[serde(rename = "18")]
    GetSeedRequest,
    /// Get seed response.
    #[serde(rename = "19")]
    GetSeedRespone(u64),
    /// Get seed response.
    #[serde(rename = "20")]
    GetP2pIdRequest,
    /// Get seed response.
    #[serde(rename = "21")]
    GetP2pIdResponse(String),
    /// Send block info to aligner
    #[serde(rename = "22")]
    AlignBlockInfo { peer_id: String, block: Block },
    /// Read only put tx
    #[serde(rename = "23")]
    ExecReadOnlyTransaction {
        /// Target account.
        target: String,
        /// Method.
        method: String,
        /// Method's args.
        args: Vec<u8>,
        /// Origin. (PublicKey)
        origin: String,
        /// Contract.
        contract: Option<Hash>,
        /// Max consumable fuel.
        max_fuel: u64,
        /// Network
        network: String,
    },
    /// Acknowledgment message for reqRes,
    /// it means that a req message
    /// has been received.
    #[serde(rename = "253")]
    Ack,
    /// Stop blockchain service.
    #[serde(rename = "254")]
    Stop,
    /// Packed message serialized using MessagePack.
    #[serde(rename = "255")]
    Packed {
        /// Serialized message bytes.
        #[serde(with = "serde_bytes")]
        buf: Vec<u8>,
    },
}

/// Helper structure to transparently deserialize both single and vector of
/// messages. Internally this is used by the blockchain listener to deserialize
/// the content of `Packed` message types.
#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum MultiMessage {
    /// Simple message.
    Simple(Message),
    /// Vector of messages.
    Sequence(Vec<Message>),
}

/// Blockchain request sender alias.
pub type BlockRequestSender = channel::RequestSender<Message, Message>;

/// Blockchain request receiver alias.
pub type BlockRequestReceiver = channel::RequestReceiver<Message, Message>;

/// Blockchain response sender alias.
pub type BlockResponseSender = channel::Sender<Message>;

/// Blockchain response receiver alias.
pub type BlockResponseReceiver = channel::Receiver<Message>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        base::{
            schema::{
                tests::{create_test_contract_event, create_test_unit_tx},
                FUEL_LIMIT,
            },
            serialize::{rmp_deserialize, rmp_serialize},
        },
        error::ErrorKind,
    };

    const HASH_HEX: &str = "12207787c3d2d765727ec290eaa4dfbad582112641aa98e1c2279e34873a529808d9";

    const EXCEPTION_HEX: &str = "93a130ab626164206e6574776f726bac6572726f7220736f75726365";
    const STOP_HEX: &str = "91a3323534";
    const SUBSCRIBE_HEX: &str = "93a131a44a6f686e03";
    const UNSUBSCRIBE_HEX: &str = "93a132a44a6f686e03";
    const PUT_TRANSACTION_REQ_HEX: &str = "93a133c393a7756e69745f747899d94064386166386635363366323565623036353635316363646430356239373236666432376666396463343065336239633862346432633535666139383139663336d92e516d59486e45514c64663568374b59626a4650754853526b325350676458724a5746683557363936485066713769cd03e8c408ab82b741e023a412a6736b796e6574c42212202c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7aea97465726d696e61746593a56563647361a9736563703338347231c461045936d631b849bb5760bcf62e0d1261b6b6e227dc0a3892cbeec91be069aaa25996f276b271c2c53cba4be96d67edcadd66b793456290609102d5401f413cd1b5f4130b9cfaa68d30d0d25c3704cb72734cd32064365ff7042f5a3eee09b06cc1c40a4f706171756544617461c4603b472dc456b2db807f13b60920ee0c663405441b3b5e46f93371e40ecbe1a7922034865a4be36812394e7f65b26e626737c125174889888d30a85e131b3a75416cfa361621731853325b8383afd283beaaf244ebd9f86b88d8b275376f428fdb";
    const PUT_TRANSACTION_RES_HEX: &str =
        "92a134c42212207787c3d2d765727ec290eaa4dfbad582112641aa98e1c2279e34873a529808d9";
    const GET_TRANSACTION_REQ_HEX: &str =
        "93a135c42212207787c3d2d765727ec290eaa4dfbad582112641aa98e1c2279e34873a529808d9c0";
    const GET_TRANSACTION_RES_HEX: &str = "93a13693a7756e69745f747899d94064386166386635363366323565623036353635316363646430356239373236666432376666396463343065336239633862346432633535666139383139663336d92e516d59486e45514c64663568374b59626a4650754853526b325350676458724a5746683557363936485066713769cd03e8c408ab82b741e023a412a6736b796e6574c42212202c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7aea97465726d696e61746593a56563647361a9736563703338347231c461045936d631b849bb5760bcf62e0d1261b6b6e227dc0a3892cbeec91be069aaa25996f276b271c2c53cba4be96d67edcadd66b793456290609102d5401f413cd1b5f4130b9cfaa68d30d0d25c3704cb72734cd32064365ff7042f5a3eee09b06cc1c40a4f706171756544617461c4603b472dc456b2db807f13b60920ee0c663405441b3b5e46f93371e40ecbe1a7922034865a4be36812394e7f65b26e626737c125174889888d30a85e131b3a75416cfa361621731853325b8383afd283beaaf244ebd9f86b88d8b275376f428fdbc0";
    const GET_CONTRACTS_EVENTS_HEX: &str = "92a2313595c42212202c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7aeae6f726967696e5f6163636f756e74c4221220a4cea0f0f6e4ac6865fd6092a319ccc6d2387cd8bb65e64bdc486f1a9a998569ab636f6f6c5f6d6574686f64c403010203";

    const PACKED_HEX: &str = "92a3323535c42893a135c42212207787c3d2d765727ec290eaa4dfbad582112641aa98e1c2279e34873a529808d9c0";

    fn exception_msg() -> Message {
        Message::Exception(Error::new_ext(ErrorKind::BadNetwork, "error source"))
    }

    fn subscribe_msg() -> Message {
        Message::Subscribe {
            id: "John".to_owned(),
            events: Event::BLOCK | Event::TRANSACTION,
        }
    }

    fn unsubscribe_msg() -> Message {
        Message::Unsubscribe {
            id: "John".to_owned(),
            events: Event::BLOCK | Event::TRANSACTION,
        }
    }

    fn put_transaction_req_msg() -> Message {
        Message::PutTransactionRequest {
            confirm: true,
            tx: create_test_unit_tx(FUEL_LIMIT),
        }
    }

    fn put_transaction_res_msg() -> Message {
        Message::PutTransactionResponse {
            hash: Hash::from_hex(HASH_HEX).unwrap(),
        }
    }

    fn get_transaction_req_msg() -> Message {
        Message::GetTransactionRequest {
            hash: Hash::from_hex(HASH_HEX).unwrap(),
            destination: None,
        }
    }

    fn get_transaction_res_msg() -> Message {
        Message::GetTransactionResponse {
            tx: create_test_unit_tx(FUEL_LIMIT),
            origin: None,
        }
    }

    fn get_contract_events_msg() -> Message {
        Message::GetContractEvent {
            event: create_test_contract_event(),
        }
    }

    #[test]
    fn exception_serialize() {
        let msg = exception_msg();

        let buf = rmp_serialize(&msg).unwrap();

        assert_eq!(hex::encode(&buf), EXCEPTION_HEX);
    }

    #[test]
    fn exception_deserialize() {
        let buf = hex::decode(EXCEPTION_HEX).unwrap();

        let msg: Message = rmp_deserialize(&buf).unwrap();

        assert_eq!(msg, exception_msg());
    }

    #[test]
    fn stop_serialize() {
        let msg = Message::Stop;

        let buf = rmp_serialize(&msg).unwrap();

        assert_eq!(hex::encode(&buf), STOP_HEX);
    }

    #[test]
    fn stop_deserialize() {
        let buf = hex::decode(STOP_HEX).unwrap();

        let msg: Message = rmp_deserialize(&buf).unwrap();

        assert_eq!(msg, Message::Stop);
    }

    #[test]
    fn subscribe_serialize() {
        let msg = subscribe_msg();

        let buf = rmp_serialize(&msg).unwrap();

        assert_eq!(hex::encode(&buf), SUBSCRIBE_HEX);
    }

    #[test]
    fn subscribe_deserialize() {
        let buf = hex::decode(SUBSCRIBE_HEX).unwrap();

        let msg: Message = rmp_deserialize(&buf).unwrap();

        assert_eq!(msg, subscribe_msg());
    }

    #[test]
    fn unsubscribe_serialize() {
        let msg = unsubscribe_msg();

        let buf = rmp_serialize(&msg).unwrap();

        assert_eq!(hex::encode(&buf), UNSUBSCRIBE_HEX);
    }

    #[test]
    fn unsubscribe_deserialize() {
        let buf = hex::decode(UNSUBSCRIBE_HEX).unwrap();

        let msg: Message = rmp_deserialize(&buf).unwrap();

        assert_eq!(msg, unsubscribe_msg());
    }

    #[test]
    fn put_transaction_req_serialize() {
        let msg = put_transaction_req_msg();

        let buf = rmp_serialize(&msg).unwrap();

        assert_eq!(hex::encode(&buf), PUT_TRANSACTION_REQ_HEX);
    }

    #[test]
    fn put_transaction_req_deserialize() {
        let buf = hex::decode(PUT_TRANSACTION_REQ_HEX).unwrap();

        let msg: Message = rmp_deserialize(&buf).unwrap();

        assert_eq!(msg, put_transaction_req_msg());
    }

    #[test]
    fn put_transaction_res_serialize() {
        let msg = put_transaction_res_msg();

        let buf = rmp_serialize(&msg).unwrap();

        assert_eq!(hex::encode(&buf), PUT_TRANSACTION_RES_HEX);
    }

    #[test]
    fn put_transaction_res_deserialize() {
        let buf = hex::decode(PUT_TRANSACTION_RES_HEX).unwrap();

        let msg: Message = rmp_deserialize(&buf).unwrap();

        assert_eq!(msg, put_transaction_res_msg());
    }

    #[test]
    fn get_transaction_req_serialize() {
        let msg = get_transaction_req_msg();

        let buf = rmp_serialize(&msg).unwrap();

        //println!("{}", hex::encode(&buf));

        assert_eq!(hex::encode(&buf), GET_TRANSACTION_REQ_HEX);
    }

    #[test]
    fn get_transaction_req_deserialize() {
        let buf = hex::decode(GET_TRANSACTION_REQ_HEX).unwrap();

        let msg: Message = rmp_deserialize(&buf).unwrap();

        assert_eq!(msg, get_transaction_req_msg());
    }

    #[test]
    fn get_transaction_res_serialize() {
        let msg = get_transaction_res_msg();

        let buf = rmp_serialize(&msg).unwrap();

        assert_eq!(hex::encode(&buf), GET_TRANSACTION_RES_HEX);
    }

    #[test]
    fn get_transaction_res_deserialize() {
        let buf = hex::decode(GET_TRANSACTION_RES_HEX).unwrap();

        let msg: Message = rmp_deserialize(&buf).unwrap();

        assert_eq!(msg, get_transaction_res_msg());
    }

    #[test]
    fn get_contracts_events_serialize() {
        let msg = get_contract_events_msg();

        let buf = rmp_serialize(&msg).unwrap();

        assert_eq!(hex::encode(&buf), GET_CONTRACTS_EVENTS_HEX);
    }

    #[test]
    fn get_contracts_events_deserialize() {
        let buf = hex::decode(GET_CONTRACTS_EVENTS_HEX).unwrap();

        let msg: Message = rmp_deserialize(&buf).unwrap();

        assert_eq!(msg, get_contract_events_msg());
    }

    #[test]
    fn packed_message_serialize() {
        let inner_msg = get_transaction_req_msg();
        let inner_buf = rmp_serialize(&inner_msg).unwrap();
        let msg = Message::Packed { buf: inner_buf };

        let buf = rmp_serialize(&msg).unwrap();

        assert_eq!(hex::encode(&buf), PACKED_HEX);
    }

    #[test]
    fn packed_message_deserialize() {
        let buf = hex::decode(PACKED_HEX).unwrap();

        if let Message::Packed { buf } = rmp_deserialize(&buf).unwrap() {
            let inner_msg: Message = rmp_deserialize(&buf).unwrap();
            assert_eq!(inner_msg, get_transaction_req_msg());
        } else {
            panic!("unexpected");
        }
    }

    #[test]
    fn multi_message_sequence_deserialize() {
        let org_msgs = vec![
            Message::GetBlockRequest {
                height: 0,
                txs: true,
                destination: None,
            },
            Message::Exception(Error::new_ext(ErrorKind::WasmMachineFault, "fatality")),
            Message::Packed { buf: vec![1, 2, 3] },
        ];
        let buf = rmp_serialize(&org_msgs).unwrap();

        let mm: MultiMessage = rmp_deserialize(&buf).unwrap();

        match mm {
            MultiMessage::Sequence(msgs) => assert_eq!(msgs, org_msgs),
            _ => panic!("unexpected"),
        }
    }

    #[test]
    fn multi_message_simple_deserialize() {
        let org_msg = Message::GetBlockRequest {
            height: 0,
            txs: true,
            destination: None,
        };
        let buf = rmp_serialize(&org_msg).unwrap();

        let mm: MultiMessage = rmp_deserialize(&buf).unwrap();

        match mm {
            MultiMessage::Simple(msg) => assert_eq!(msg, org_msg),
            _ => panic!("unexpected"),
        }
    }
}
