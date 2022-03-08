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

//! Implementation of publish/subscriber protocol for blockchain events.
//!
//! Events are propagated using the channel that the subscriber has received
//! when sent the `Subscribe` message.
//!
//! If the subscriber closes the receiving side of the channel then this is
//! interpreted as an implicit unsubscribe.

use super::{BlockResponseSender, Message};
use crate::base::serialize::rmp_serialize;
use serde::de::Error as SerdeError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

bitflags::bitflags! {
    /// Blockchain event kinds.
    pub struct Event: u8 {
        /// New unconfirmed transaction.
        const TRANSACTION = 1 << 0;
        /// New block has been executed.
        const BLOCK = 1 << 1;
        /// Any unsolicited gossip request from the blockchain.
        const GOSSIP_REQUEST = 1 << 2;
        /// Any unsolicited unicast request from the blockchain.
        const UNICAST_REQUEST = 1 << 3;
        /// Contracts events
        const CONTRACT_EVENTS = 1 << 4;
    }
}

const EVENTS_NUM: usize = 4;

impl Serialize for Event {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u8(self.bits)
    }
}

impl<'de> Deserialize<'de> for Event {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct EventVisitor;

        impl<'de> serde::de::Visitor<'de> for EventVisitor {
            type Value = u8;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("u8")
            }

            fn visit_u8<R>(self, value: u8) -> std::result::Result<u8, R> {
                Ok(value)
            }
        }

        let bits = deserializer.deserialize_u8(EventVisitor)?;
        let event = Event::from_bits(bits).ok_or_else(|| SerdeError::custom("invalid bits"))?;
        Ok(event)
    }
}

#[derive(Clone)]
struct SubscriberInfo {
    pack_level: usize,
    chan: BlockResponseSender,
}

/// Blockchain events subscribers.
pub(crate) struct PubSub {
    events_sub: HashMap<Event, HashMap<String, SubscriberInfo>>,
}

/// Default trait implementation.
impl Default for PubSub {
    fn default() -> Self {
        PubSub {
            events_sub: HashMap::new(),
        }
    }
}

impl PubSub {
    /// Instance a new subscribers map for blockchain events.
    /// Actually this just invokes the `default` constructor.
    pub fn new() -> Self {
        PubSub::default()
    }

    /// Check if the `event` kind has subscribers.
    pub fn has_subscribers(&self, event: Event) -> bool {
        match self.events_sub.get(&event) {
            Some(subs) => !subs.is_empty(),
            None => false,
        }
    }

    /// Subscribe to blockchain events.
    /// The `events` parameter is a bitflag, thus it is not limited to one
    /// single event and multiple kinds can be OR-ed together.
    /// An identifier can be passed to track the subscriber behavior.
    /// Events will be received from the receiver end of `chan`.
    pub fn subscribe(
        &mut self,
        id: String,
        events: Event,
        pack_level: usize,
        chan: BlockResponseSender,
    ) {
        for i in 0..EVENTS_NUM {
            if let Some(event) = Event::from_bits((1 << i) & events.bits) {
                if event.is_empty() {
                    continue;
                }
                debug!(
                    "[sub] '{}' subscribed to '{:?}' event (pack-level = {})",
                    id, event, pack_level
                );
                let subscriber_info = SubscriberInfo {
                    pack_level,
                    chan: chan.clone(),
                };
                match self.events_sub.get_mut(&event) {
                    Some(event_subs) => {
                        event_subs.insert(id.clone(), subscriber_info);
                    }
                    None => {
                        let mut event_subs = HashMap::new();
                        event_subs.insert(id.clone(), subscriber_info);
                        self.events_sub.insert(event, event_subs);
                    }
                }
            }
        }
    }

    /// Unsubscribe from blockchain events.
    /// The `events` parameter is a bitflag, thus it is not limited to one
    /// single event and multiple kinds can be OR-ed together.
    pub fn unsubscribe(&mut self, id: String, events: Event) {
        for i in 0..EVENTS_NUM {
            if let Some(event) = Event::from_bits((1 << i) & events.bits) {
                if event.is_empty() {
                    continue;
                }
                debug!("[sub] '{}' unsubscribed from '{:?}' event", id, event);
                if let Some(event_subs) = self.events_sub.get_mut(&event) {
                    event_subs.remove(&id);
                    if event_subs.is_empty() {
                        self.events_sub.remove(&event);
                    }
                }
            }
        }
    }

    /// Publish blockchain event to subscribers.
    pub fn publish(&mut self, event: Event, msg: Message) {
        if let Some(event_subs) = self.events_sub.get_mut(&event) {
            let mut closed_chans = vec![];
            for (id, info) in event_subs.iter() {
                if info.chan.is_closed() {
                    closed_chans.push(id.clone());
                    continue;
                }
                let id_clone = id.clone();
                let info_clone = info.clone();
                let mut msg_clone = msg.clone();
                async_std::task::spawn(async move {
                    debug!("[sub] '{}' notified about '{:?}' event", id_clone, event);
                    let mut pack_level = info_clone.pack_level;
                    while pack_level > 0 {
                        let buf = rmp_serialize(&msg_clone).unwrap_or_default();
                        msg_clone = Message::Packed { buf };
                        pack_level -= 1;
                    }
                    let res = info_clone.chan.send(msg_clone).await;
                    if res.is_err() {
                        debug!("[sub] error publishing to '{}', closing channel", id_clone);
                        info_clone.chan.close();
                    }
                });
            }
            closed_chans.iter().for_each(|id| {
                debug!(
                    "[sub] detected closed channel for '{}', removing it from {:?} events",
                    id, event
                );
                event_subs.remove(id);
            });
            if event_subs.is_empty() {
                self.events_sub.remove(&event);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        base::schema::tests::create_test_block, blockchain::BlockResponseReceiver, channel,
    };

    #[test]
    fn events_subscribe() {
        let mut pubsub = PubSub::default();
        let (sender, _) = channel::simple_channel();

        pubsub.subscribe(
            "foo".to_string(),
            Event::BLOCK | Event::TRANSACTION | Event::CONTRACT_EVENTS,
            0,
            sender,
        );

        assert!(pubsub.has_subscribers(Event::BLOCK));
        assert!(pubsub.has_subscribers(Event::TRANSACTION));
        assert!(pubsub.has_subscribers(Event::CONTRACT_EVENTS));
    }

    #[test]
    fn events_unsubscribe() {
        let mut pubsub = PubSub::default();
        let (sender, _) = channel::simple_channel();
        pubsub.subscribe(
            "foo".to_string(),
            Event::BLOCK | Event::TRANSACTION | Event::CONTRACT_EVENTS,
            0,
            sender,
        );

        pubsub.unsubscribe("foo".to_string(), Event::BLOCK);

        assert!(!pubsub.has_subscribers(Event::BLOCK));
        assert!(pubsub.has_subscribers(Event::TRANSACTION));
        assert!(pubsub.has_subscribers(Event::CONTRACT_EVENTS));
    }

    fn receiver_mock(chan: BlockResponseReceiver) {
        while let Ok(msg) = chan.recv_sync() {
            match msg {
                Message::GetBlockResponse { .. } => break,
                _ => panic!("unexpected"),
            }
        }
    }

    #[test]
    fn broadcast() {
        let mut pubsub = PubSub::default();
        let (sender, receiver) = channel::simple_channel();
        let handle = std::thread::spawn(move || receiver_mock(receiver));
        pubsub.subscribe(
            "foo".to_string(),
            Event::BLOCK | Event::TRANSACTION,
            0,
            sender,
        );
        let msg = Message::GetBlockResponse {
            block: create_test_block(),
            txs: None,
            origin: None,
        };

        // This also forces the thread termination so that we can join it below...
        pubsub.publish(Event::BLOCK, msg.clone());

        handle.join().unwrap();
        // The subscriber is still in the subscriber list.
        // Removal is lazy and is eventually performed on the next broadcast invocation.
        assert!(pubsub.has_subscribers(Event::BLOCK));
        pubsub.publish(Event::BLOCK, msg);
        assert!(!pubsub.has_subscribers(Event::BLOCK));
    }

    #[test]
    fn broadcast_remove_closed_channels() {
        let mut pubsub = PubSub::default();
        let (sender, _) = channel::simple_channel();
        pubsub.subscribe(
            "foo".to_string(),
            Event::BLOCK | Event::TRANSACTION,
            0,
            sender,
        );
        let msg = Message::GetBlockResponse {
            block: create_test_block(),
            txs: None,
            origin: None,
        };

        pubsub.publish(Event::BLOCK, msg);

        assert!(!pubsub.has_subscribers(Event::BLOCK));
    }
}
