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

use super::KafkaConfig;
use crate::base::serialize::rmp_serialize;
use crate::blockchain::{pubsub::Event, BlockRequestSender, Message};

use futures::{future, StreamExt};
use kafka::producer::{Producer, Record, RequiredAcks};
use std::task::{Context, Poll};
use std::time::Duration;

const SMARTCONTRACT_EVENT: &str = "trinci_messages_transaction_event";
const BLOCK_EVENT: &str = "trinci_messages_get_block_response";

pub struct KafkaWorker {
    config: KafkaConfig,
    bc_chan: BlockRequestSender,
}

impl KafkaWorker {
    pub fn new(config: KafkaConfig, bc_chan: BlockRequestSender) -> Self {
        KafkaWorker { config, bc_chan }
    }

    fn handle_msg(&self, msg: Message) {
        match msg {
            Message::GetContractEvent { .. } => self.send_to_kafka(
                &format!("{}:{}", self.config.addr, self.config.port),
                SMARTCONTRACT_EVENT,
                msg,
            ),
            Message::GetBlockResponse { .. } => self.send_to_kafka(
                &format!("{}:{}", self.config.addr, self.config.port),
                BLOCK_EVENT,
                msg,
            ),
            _ => (),
        }
    }

    fn send_to_kafka(&self, host: &str, topic: &str, payload: Message) {
        // TODO: Put it outside.
        let mut producer = Producer::from_hosts(vec![host.to_owned()])
            .with_ack_timeout(Duration::from_secs(1))
            .with_required_acks(RequiredAcks::One)
            .create()
            .unwrap();

        let buf = rmp_serialize(&payload).unwrap();
        let hex = hex::encode(buf);

        producer.send(&Record::from_value(topic, hex)).unwrap();
    }

    async fn run(&mut self) {
        let res_chan = self.bc_chan.send_sync(Message::Subscribe {
            id: "kafka".to_owned(),
            events: Event::BLOCK | Event::CONTRACT_EVENTS,
        });

        match res_chan {
            Ok(mut res_chan) => {
                let future = future::poll_fn(move |cx: &mut Context<'_>| -> Poll<()> {
                    loop {
                        match res_chan.poll_next_unpin(cx) {
                            Poll::Ready(Some(msg)) => {
                                debug!("[kafka] {:?}", msg);
                                self.handle_msg(msg)
                            }
                            Poll::Ready(None) => {
                                warn!("[kafka] blockchain channel has been closed, exiting");
                                return Poll::Ready(());
                            }
                            Poll::Pending => {
                                break;
                            }
                        }
                    }

                    Poll::Pending
                });

                future.await;
            }
            Err(_) => warn!("blockchain channel error"),
        }
    }

    /// Bridge worker synchronous task.
    pub fn run_sync(&mut self) {
        async_std::task::block_on(self.run());
    }
}
