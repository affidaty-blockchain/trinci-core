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

//! Blockchain component in charge of handling messages submitted via the
//! message queue exposed by the blockchain service.
//!
//! Messages can come from both internal and external components.
//! When a message is coming from an external component (e.g. received from a
//! network interface) its validation is typically left to the dispatcher and
//! the message payload is passed "as-is" using a dedicated message type (`Packed`).
//! In this case the message is assumed to be packed using MessagePack format.
//!
//! When the message is submitted as a `Packed` message:
//! - the payload can be a single packed `Message` or a vector of `Message`s.
//! - one incoming Packed message generates one outgoing Packed message, this
//!   behavior is performed **for all** message types, even for the ones that
//!   normally do not send out a response. This is to avoid starvation of
//!   submitters that are not commonly aware of the actual content of the packed payload.
//!   In case of messages that are not supposed to send out a real response

use crate::{
    base::{
        schema::Block,
        serialize::{rmp_deserialize, rmp_serialize},
        BlockchainSettings, Mutex, RwLock,
    },
    blockchain::{
        message::*,
        pool::{BlockInfo, Pool},
        pubsub::{Event, PubSub},
        BlockConfig,
    },
    crypto::{drand::SeedSource, Hash, HashAlgorithm, Hashable},
    db::Db,
    Error, ErrorKind, Result, Transaction,    
};
use std::sync::{Arc, Condvar, Mutex as StdMutex};

/// Dispatcher context data.
pub(crate) struct Dispatcher<D: Db> {
    /// Blockchain configuration.
    config: Arc<Mutex<BlockConfig>>,
    /// Outstanding blocks and transactions.
    pool: Arc<RwLock<Pool>>,
    /// Instance of a type implementing Database trait.
    db: Arc<RwLock<D>>,
    /// PubSub subsystem to publish blockchain events.
    pubsub: Arc<Mutex<PubSub>>,
    /// Seed
    seed: Arc<SeedSource>,
    /// P2P ID
    p2p_id: String,
    /// Aligner
    aligner: (
        Arc<Mutex<BlockRequestSender>>,
        Arc<(StdMutex<bool>, Condvar)>,
    ),
}

impl<D: Db> Clone for Dispatcher<D> {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            pool: self.pool.clone(),
            db: self.db.clone(),
            pubsub: self.pubsub.clone(),
            seed: self.seed.clone(),
            p2p_id: self.p2p_id.clone(),
            aligner: (self.aligner.0.clone(), self.aligner.1.clone()),
        }
    }
}

impl<D: Db> Dispatcher<D> {
    /// Constructs a new dispatcher.
    pub fn new(
        config: Arc<Mutex<BlockConfig>>,
        pool: Arc<RwLock<Pool>>,
        db: Arc<RwLock<D>>,
        pubsub: Arc<Mutex<PubSub>>,
        seed: Arc<SeedSource>,
        p2p_id: String,
        aligner: (
            Arc<Mutex<BlockRequestSender>>,
            Arc<(StdMutex<bool>, Condvar)>,
        ),
    ) -> Self {
        Dispatcher {
            config,
            pool,
            db,
            pubsub,
            seed,
            p2p_id,
            aligner,
        }
    }

    /// Set the block timeout
    pub fn set_block_timeout(&mut self, block_timeout: u16) {
        self.config.clone().lock().timeout = block_timeout;
    }

    fn put_transaction_internal(&self, tx: Transaction) -> Result<Hash> {
        tx.verify(tx.get_caller(), tx.get_signature())?;
        tx.check_integrity()?;
        let hash = tx.get_primary_hash();

        debug!("Received transaction: {}", hex::encode(hash));

        // Check the network.
        if self.config.lock().network != tx.get_network() {
            return Err(ErrorKind::BadNetwork.into());
        }

        // Check if already present in db.
        if self.db.read().contains_transaction(&hash) {
            return Err(ErrorKind::DuplicatedConfirmedTx.into());
        }

        let mut pool = self.pool.write();
        match pool.txs.get_mut(&hash) {
            None => {
                pool.txs.insert(hash, Some(tx));
                pool.unconfirmed.push(hash);
            }
            Some(tx_ref @ None) => {
                *tx_ref = Some(tx);
            }
            Some(Some(_)) => {
                return if pool.unconfirmed.contains(&hash) {
                    Err(ErrorKind::DuplicatedUnconfirmedTx.into())
                } else {
                    Err(ErrorKind::DuplicatedConfirmedTx.into())
                };
            }
        }
        Ok(hash)
    }

    #[inline]
    fn broadcast_attempt(&self, tx: Transaction) {
        let mut sub = self.pubsub.lock();
        debug!("### NEW TX -> BROADCAST ATTEMPT ###");
        if sub.has_subscribers(Event::TRANSACTION) {
            sub.publish(
                Event::TRANSACTION,
                Message::GetTransactionResponse { tx, origin: None },
            );
        }
    }

    fn put_transaction_handler(&self, tx: Transaction) -> Message {
        let result = self.put_transaction_internal(tx.clone());
        match result {
            Ok(hash) => {
                self.broadcast_attempt(tx);
                Message::PutTransactionResponse { hash }
            }
            Err(err) => {
                debug!("Error: {}", err.to_string());
                Message::Exception(err)
            }
        }
    }

    fn get_transaction_handler(&self, hash: Hash, _destination: Option<String>) -> Message {
        let mut opt = self.db.read().load_transaction(&hash);
        if opt.is_none() {
            opt = match self.pool.read().txs.get(&hash) {
                Some(Some(tx)) => Some(tx.clone()),
                _ => None,
            }
        }
        match opt {
            Some(tx) => Message::GetTransactionResponse {
                tx,
                origin: Some(self.p2p_id.clone()),
            },
            None => Message::Exception(ErrorKind::ResourceNotFound.into()),
        }
    }

    fn get_receipt_handler(&self, hash: Hash) -> Message {
        let opt = self.db.read().load_receipt(&hash);
        match opt {
            Some(rx) => Message::GetReceiptResponse { rx },
            None => Message::Exception(ErrorKind::ResourceNotFound.into()),
        }
    }

    fn get_block_handler(&self, height: u64, txs: bool) -> Message {
        let opt = self.db.read().load_block(height);
        debug!("GETBLOCKREQ\theight: {}\ttxs: {}", height, txs);
        match opt {
            Some(block) => {
                let blk_txs = if txs {
                    self.db.read().load_transactions_hashes(block.data.height)
                } else {
                    None
                };
                debug!("GETBLOCKREQ response send\ttxs: {}", blk_txs.is_some());
                Message::GetBlockResponse {
                    block,
                    txs: blk_txs,
                    origin: Some(self.p2p_id.clone()),
                }
            }
            None => Message::Exception(Error::new(ErrorKind::ResourceNotFound)),
        }
    }

    fn get_account_handler(&self, id: String, data_names: Vec<String>) -> Message {
        let opt = self.db.read().load_account(&id);
        match opt {
            Some(acc) => {
                let mut data = vec![];
                for name in data_names.iter() {
                    let val = if name == "*" {
                        let keys = self.db.read().load_account_keys(&id);
                        Some(rmp_serialize(&keys).unwrap())
                    } else {
                        self.db.read().load_account_data(&id, name)
                    };
                    data.push(val);
                }
                Message::GetAccountResponse { acc, data }
            }
            None => Message::Exception(Error::new(ErrorKind::ResourceNotFound)),
        }
    }

    fn get_transaction_res_handler(&self, transaction: Transaction, origin: Option<String>) {
        let res = self.put_transaction_internal(transaction.clone());
        debug!("PUT TX INTERNAL: {}", res.is_ok());
        // if in alignment just send
        // an ACK to aligner, so that
        // it can ask for next TX
        let aligner_status = self.aligner.1.clone();
        if !*aligner_status.0.lock().unwrap() {
            let req = Message::GetTransactionResponse {
                tx: transaction,
                origin,
            };
            self.aligner.0.lock().send_sync(req).unwrap();
        }
    }

    fn get_block_res_handler(
        &mut self,
        block: &Block,
        txs_hashes: &Option<Vec<Hash>>,
        origin: &Option<String>,
        _req: Message,
    ) {
        //debug!("Aligner: {:?}", self.aligner.1);

        // get local last block
        let opt = self.db.read().load_block(u64::MAX);

        // collect missing blocks by heights
        let mut missing_headers = match opt {
            Some(last) => last.data.height + 1..block.data.height,
            None => 0..block.data.height,
        };
        if txs_hashes.is_none() {
            missing_headers.end += 1;
        }

        // Check if wether or not there are missing blocks.
        // In case the recieved block is the "next block", it means the behaviour
        // is the one expected, the node is aligned.
        // Note: this happens only if the node is not in a
        // "alignment" status, shown by the status of the aligner (false -> alignment)
        let aligner_status = self.aligner.1.clone();
        if missing_headers.end == block.data.height && *aligner_status.0.lock().unwrap() {
            // if recieved block contains txs
            //  . remove those from unconfirmed pool
            //  . add txs to pool.txs if not present
            // push new block into pool.confirmed
            let mut pool = self.pool.write();
            if let Some(ref hashes) = txs_hashes {
                for hash in hashes {
                    if pool.unconfirmed.contains(hash) {
                        pool.unconfirmed.remove(hash);
                    }
                    if !pool.txs.contains_key(hash) {
                        pool.txs.insert(*hash, None);
                    }
                }
            }
            let blk_info = BlockInfo {
                hash: Some(block.data.primary_hash()),
                validator: block.data.validator.to_owned(),
                signature: Some(block.signature.clone()),
                txs_hashes: txs_hashes.to_owned(),
            };
            pool.confirmed.insert(block.data.height, blk_info);
        } else if missing_headers.start <= block.data.height {
            // in this case the node miss some block
            // it needes to be re-aligned

            // start aligner if not already running
            if *aligner_status.0.lock().unwrap() {
                debug!("[dispatcher] node is misaligned, launching aligner service");

                *aligner_status.0.lock().unwrap() = false;
                aligner_status.1.notify_one();
            } else {
                // send block message to aligner
                debug!(
                    "[dispatcher] sending GetBlockResponse to the aligner (height: {}) (txs: {})",
                    block.clone().data.height,
                    txs_hashes.is_some(),
                );
                let req = Message::GetBlockResponse {
                    block: block.to_owned(),
                    txs: txs_hashes.to_owned(),
                    origin: origin.to_owned(),
                };
                self.aligner.0.lock().send_sync(req).unwrap();
            }
        }
    }

    fn get_stats_handler(&self) -> Message {
        // the turbofish (<Vec<_>>) thanks to _ makes te compiler infre the type
        let hash_pool = self
            .pool
            .read()
            .unconfirmed
            .iter()
            .collect::<Vec<_>>()
            .hash(HashAlgorithm::Sha256);
        let len_pool = self.pool.read().unconfirmed.len();
        let last_block = self.db.read().load_block(u64::MAX);
        Message::GetCoreStatsResponse((hash_pool, len_pool, last_block))
    }

    fn get_network_id_handler(&self) -> Message {
        let buf = self
            .db
            .read()
            .load_configuration("blockchain:settings")
            .unwrap(); // If this fails is at the very beginning
        let config = rmp_deserialize::<BlockchainSettings>(&buf).unwrap(); // If this fails is at the very beginning

        let network_name = config.network_name.unwrap(); // If this fails is at the very beginning
        Message::GetNetworkIdResponse(network_name)
    }

    fn get_seed_handler(&self) -> Message {
        let seed = self.seed.get_seed();
        Message::GetSeedRespone(seed)
    }

    fn get_p2p_id_handler(&self) -> Message {
        let id = self.p2p_id.clone();
        //let id = self.config.lock().keypair.public_key().to_account_id();
        Message::GetP2pIdResponse(id)
    }

    fn packed_message_handler(
        &mut self,
        buf: Vec<u8>,
        res_chan: &BlockResponseSender,
        pack_level: usize,
    ) -> Option<Message> {
        trace!("RX ({}): {}", buf.len(), hex::encode(&buf));
        const ARRAY_HIGH_NIBBLE: u8 = 0x90;
        const MAX_PACK_LEVEL: usize = 32;

        if pack_level >= MAX_PACK_LEVEL {
            return None;
        }

        // Be sure that the client is using anonymous serialization format.
        let tag = buf.get(0).cloned().unwrap_or_default();
        if (tag & ARRAY_HIGH_NIBBLE) != ARRAY_HIGH_NIBBLE {
            let err = Error::new_ext(
                ErrorKind::MalformedData,
                "expected anonymous serialization format",
            );
            return Some(Message::Exception(err));
        }

        let res = match rmp_deserialize(&buf) {
            Ok(MultiMessage::Simple(req)) => self
                .message_handler(req, res_chan, pack_level)
                .map(MultiMessage::Simple),
            Ok(MultiMessage::Sequence(requests)) => {
                let mut responses = Vec::with_capacity(requests.len());
                for req in requests.into_iter() {
                    if let Some(res) = self.message_handler(req, res_chan, pack_level) {
                        responses.push(res);
                    };
                }
                match responses.is_empty() {
                    true => None,
                    false => Some(MultiMessage::Sequence(responses)),
                }
            }
            Err(_err) => {
                let res = Message::Exception(ErrorKind::MalformedData.into());
                Some(MultiMessage::Simple(res))
            }
        };
        res.map(|res| {
            let buf = rmp_serialize(&res).unwrap_or_default();
            trace!("TX ({}): {}", buf.len(), hex::encode(&buf));
            Message::Packed { buf }
        })
    }

    pub fn message_handler(
        &mut self,
        req: Message,
        res_chan: &BlockResponseSender,
        pack_level: usize,
    ) -> Option<Message> {
        match req {
            Message::PutTransactionRequest { confirm, tx } => {
                let res = self.put_transaction_handler(tx);
                confirm.then(|| res)
            }
            Message::GetTransactionRequest { hash, destination } => {
                let res = self.get_transaction_handler(hash, destination);
                Some(res)
            }
            Message::GetReceiptRequest { hash } => {
                let res = self.get_receipt_handler(hash);
                Some(res)
            }
            Message::GetBlockRequest {
                height,
                txs,
                destination: _,
            } => {
                let res = self.get_block_handler(height, txs);
                Some(res)
            }
            Message::GetAccountRequest { id, data } => {
                let res = self.get_account_handler(id, data);
                Some(res)
            }
            Message::GetCoreStatsRequest => {
                let res = self.get_stats_handler();
                Some(res)
            }
            Message::GetNetworkIdRequest => {
                let res = self.get_network_id_handler();
                Some(res)
            }
            Message::GetSeedRequest => {
                let res = self.get_seed_handler();
                Some(res)
            }
            Message::Subscribe { id, events } => {
                self.pubsub
                    .lock()
                    .subscribe(id, events, pack_level, res_chan.clone());
                None
            }
            Message::Unsubscribe { id, events } => {
                self.pubsub.lock().unsubscribe(id, events);
                None
            }
            Message::GetBlockResponse {
                ref block,
                ref txs,
                ref origin,
            } => {
                debug!(
                    "GETBLOCKRES\theight: {}\ttxs: {}",
                    block.data.height,
                    txs.clone().is_some()
                );
                self.get_block_res_handler(block, txs, origin, req.clone());
                None
            }
            Message::GetTransactionResponse { tx, origin } => {
                self.get_transaction_res_handler(tx, origin);
                None
            }
            Message::GetP2pIdRequest => Some(self.get_p2p_id_handler()),
            Message::Packed { buf } => self.packed_message_handler(buf, res_chan, pack_level + 1),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        base::schema::tests::{
            create_test_account, create_test_block, create_test_bulk_tx, create_test_bulk_tx_alt,
            create_test_unit_tx, FUEL_LIMIT,
        },
        channel::simple_channel,
        db::*,
        Error, ErrorKind,
        blockchain::aligner::Aligner
    };

    const ACCOUNT_ID: &str = "AccountId";
    const BULK_TX_DATA_HASH_HEX: &str =
        "1220cb7525e6f80b116271e6fc4bbf99b3a10815b3380fc32be2c990a0b2c547bbad";
    const BULK_WITH_NODES_TX_DATA_HASH_HEX: &str =
        "1220656ec5443f3eb0cb47507a858ab0e0e025c9d0d99b167c012d95886c2aa9c508";
    const TX_DATA_HASH_HEX: &str =
        "12207cfff11a272ad3f5cb60606717adc9984d1cd4dc4c491fdf4c56661ee40caaad";
    fn create_dispatcher(fail_condition: bool) -> Dispatcher<MockDb> {
        let pool = Arc::new(RwLock::new(Pool::default()));
        let db = Arc::new(RwLock::new(create_db_mock(fail_condition)));
        let pubsub = Arc::new(Mutex::new(PubSub::default()));
        let config = Arc::new(Mutex::new(BlockConfig {
            threshold: 42,
            timeout: 3,
            network: "skynet".to_string(),
            keypair: Arc::new(crate::crypto::sign::tests::create_test_keypair()),
        }));

        // seed init
        let nw_name = String::from("skynet");
        let nonce: Vec<u8> = vec![0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56];
        let prev_hash =
            Hash::from_hex("1220a4cea0f0f6eddc6865fd6092a319ccc6d2387cd8bb65e64bdc486f1a9a998569")
                .unwrap();
        let txs_hash =
            Hash::from_hex("1220a4cea0f1f6eddc6865fd6092a319ccc6d2387cf8bb63e64b4c48601a9a998569")
                .unwrap();
        let rxs_hash =
            Hash::from_hex("1220a4cea0f0f6edd46865fd6092a319ccc6d5387cd8bb65e64bdc486f1a9a998569")
                .unwrap();

        let seed = SeedSource::new(
            nw_name,
            nonce,
            prev_hash.clone(),
            txs_hash.clone(),
            rxs_hash.clone(),
        );
        let seed = Arc::new(seed);

        let aligner = Aligner::new(pubsub.clone(), db.clone(), pool.clone());

        Dispatcher::new(
            config,
            pool,
            db,
            pubsub,
            seed,
            "TEST".to_string(),
            (aligner.request_channel(), aligner.status.clone()),
        )
    }

    fn create_db_mock(fail_condition: bool) -> MockDb {
        let mut db = MockDb::new();
        db.expect_load_block().returning(|height| match height {
            0 => Some(create_test_block()),
            _ => None,
        });
        db.expect_load_transaction().returning(|hash| {
            match *hash == Hash::from_hex(TX_DATA_HASH_HEX).unwrap() {
                true => Some(create_test_unit_tx(FUEL_LIMIT)),
                false => None,
            }
        });
        db.expect_load_account()
            .returning(|id| match id == ACCOUNT_ID {
                true => Some(create_test_account()),
                false => None,
            });
        db.expect_contains_transaction()
            .returning(move |_| fail_condition);
        db
    }

    impl Dispatcher<MockDb> {
        fn message_handler_wrap(&mut self, req: Message) -> Option<Message> {
            let (tx_chan, _rx_chan) = simple_channel::<Message>();
            self.message_handler(req, &tx_chan, 0)
        }
    }

    #[test]
    fn put_unit_transaction() {
        let mut dispatcher = create_dispatcher(false);
        let req = Message::PutTransactionRequest {
            confirm: true,
            tx: create_test_unit_tx(FUEL_LIMIT),
        };

        let res = dispatcher.message_handler_wrap(req).unwrap();

        // Uncomment if hash update needed
        //match res {
        //    Message::PutTransactionResponse { hash } => {
        //        println!("{}", hex::encode(hash));
        //    }
        //    _ => (),
        //}

        let exp_res = Message::PutTransactionResponse {
            hash: Hash::from_hex(TX_DATA_HASH_HEX).unwrap(),
        };
        assert_eq!(res, exp_res);
    }

    #[test]
    fn put_bulk_transaction() {
        let mut dispatcher = create_dispatcher(false);
        let req = Message::PutTransactionRequest {
            confirm: true,
            tx: create_test_bulk_tx(false),
        };

        let res = dispatcher.message_handler_wrap(req).unwrap();

        // Uncomment if hash update needed
        //match res {
        //    Message::PutTransactionResponse { hash } => {
        //        println!("{}", hex::encode(hash));
        //    }
        //    _ => (),
        //}

        let exp_res = Message::PutTransactionResponse {
            hash: Hash::from_hex(BULK_TX_DATA_HASH_HEX).unwrap(),
        };
        assert_eq!(res, exp_res);
    }

    #[test]
    fn put_bulk_transaction_with_nodes() {
        let mut dispatcher = create_dispatcher(false);
        let req = Message::PutTransactionRequest {
            confirm: true,
            tx: create_test_bulk_tx_alt(true),
        };

        let res = dispatcher.message_handler_wrap(req).unwrap();

        // Uncomment if hash update needed
        //match res {
        //    Message::PutTransactionResponse { hash } => {
        //        println!("{}", hex::encode(hash));
        //    }
        //    _ => (),
        //}

        let exp_res = Message::PutTransactionResponse {
            hash: Hash::from_hex(BULK_WITH_NODES_TX_DATA_HASH_HEX).unwrap(),
        };
        assert_eq!(res, exp_res);
    }

    #[test]
    fn put_bad_signature_transaction() {
        let mut dispatcher = create_dispatcher(false);
        let mut tx = create_test_unit_tx(FUEL_LIMIT);

        match tx {
            Transaction::UnitTransaction(ref mut tx) => tx.signature[0] += 1,
            _ => panic!(),
        }

        let req = Message::PutTransactionRequest { confirm: true, tx };

        let res = dispatcher.message_handler_wrap(req).unwrap();

        match res {
            Message::Exception(err) => {
                assert_eq!(err.kind, ErrorKind::InvalidSignature)
            }
            _ => panic!("Unexpected response"),
        }
    }

    #[test]
    fn put_bad_signature_bulk_transaction() {
        let mut dispatcher = create_dispatcher(false);
        let mut tx = create_test_bulk_tx(false);

        match tx {
            Transaction::BulkTransaction(ref mut tx) => tx.signature[0] += 1,
            _ => panic!(),
        }

        let req = Message::PutTransactionRequest { confirm: true, tx };

        let res = dispatcher.message_handler_wrap(req).unwrap();

        match res {
            Message::Exception(err) => {
                assert_eq!(err.kind, ErrorKind::InvalidSignature)
            }
            _ => panic!("Unexpected response"),
        }
    }

    #[test]
    fn put_duplicated_unconfirmed_transaction() {
        let mut dispatcher = create_dispatcher(false);
        let req = Message::PutTransactionRequest {
            confirm: true,
            tx: create_test_unit_tx(FUEL_LIMIT),
        };
        dispatcher.message_handler_wrap(req.clone()).unwrap();

        let res = dispatcher.message_handler_wrap(req).unwrap();

        let exp_res = Message::Exception(Error::new(ErrorKind::DuplicatedUnconfirmedTx));
        assert_eq!(res, exp_res);
    }

    #[test]
    fn put_duplicated_confirmed_transaction() {
        let mut dispatcher = create_dispatcher(true);
        let req = Message::PutTransactionRequest {
            confirm: true,
            tx: create_test_unit_tx(FUEL_LIMIT),
        };

        let res = dispatcher.message_handler_wrap(req).unwrap();

        let exp_res = Message::Exception(Error::new(ErrorKind::DuplicatedConfirmedTx));
        assert_eq!(res, exp_res);
    }

    #[test]
    fn get_transaction() {
        let mut dispatcher = create_dispatcher(false);
        let req = Message::GetTransactionRequest {
            hash: Hash::from_hex(TX_DATA_HASH_HEX).unwrap(),
            destination: None,
        };

        let res = dispatcher.message_handler_wrap(req).unwrap();

        let exp_res = Message::GetTransactionResponse {
            tx: create_test_unit_tx(FUEL_LIMIT),
            origin: None,
        };
        assert_eq!(res, exp_res);
    }

    #[test]
    fn get_block() {
        let mut dispatcher = create_dispatcher(false);
        let req = Message::GetBlockRequest {
            height: 0,
            txs: false,
            destination: None,
        };

        let res = dispatcher.message_handler_wrap(req).unwrap();

        let exp_res = Message::GetBlockResponse {
            block: create_test_block(),
            txs: None,
            origin: None,
        };
        assert_eq!(res, exp_res);
    }

    #[test]
    fn get_account() {
        let mut dispatcher = create_dispatcher(false);
        let req = Message::GetAccountRequest {
            id: ACCOUNT_ID.to_owned(),
            data: vec![],
        };

        let res = dispatcher.message_handler_wrap(req).unwrap();

        let exp_res = Message::GetAccountResponse {
            acc: create_test_account(),
            data: vec![],
        };
        assert_eq!(res, exp_res);
    }

    #[test]
    fn submit_packed() {
        let get_block_packed = hex::decode("93a13900c2").unwrap();
        let mut dispatcher = create_dispatcher(false);
        let req = Message::Packed {
            buf: get_block_packed,
        };

        let res = dispatcher.message_handler_wrap(req).unwrap();

        match res {
            Message::Packed { buf: _ } => (),
            _ => panic!("Unexepcted response"),
        }
    }

    #[test]
    fn submit_packed_named() {
        let get_block_packed = hex::decode("83a474797065a139a668656967687400a3747873c2").unwrap();
        let mut dispatcher = create_dispatcher(false);
        let req = Message::Packed {
            buf: get_block_packed,
        };

        let res = dispatcher.message_handler_wrap(req).unwrap();

        let err = Error::new_ext(
            ErrorKind::MalformedData,
            "expected anonymous serialization format",
        );
        assert_eq!(res, Message::Exception(err));
    }

    #[test]
    fn test_get_core_stats() {
        let mut dispatcher = create_dispatcher(false);
        let req = Message::GetCoreStatsRequest;

        let res = dispatcher.message_handler_wrap(req).unwrap();

        match res {
            Message::GetCoreStatsResponse(info) => println!("{:?}", info),
            _ => panic!("Unexpected response"),
        }
    }
}
