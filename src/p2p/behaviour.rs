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
    base::serialize::rmp_serialize,
    blockchain::{BlockRequestSender, Message},
    Error, ErrorKind, Result,
};
use async_std::task;
use libp2p::{
    gossipsub::{
        error::PublishError, Gossipsub, GossipsubConfigBuilder, GossipsubEvent, IdentTopic,
        MessageAuthenticity, ValidationMode,
    },
    mdns::{Mdns, MdnsConfig, MdnsEvent},
    swarm::NetworkBehaviourEventProcess,
    NetworkBehaviour, PeerId,
};

/// Network behavior for application level message processing.
#[derive(NetworkBehaviour)]
pub(crate) struct Behavior {
    /// Gossip-sub as sub/sub protocol.
    pub gossip: Gossipsub,
    /// mDNS for peer discovery.
    pub mdns: Mdns,
    /// To forward incoming messages to blockchain service.
    #[behaviour(ignore)]
    pub bc_chan: BlockRequestSender,
}

const MAX_TRANSMIT_SIZE: usize = 524288;

impl Behavior {
    pub fn new(peer_id: PeerId, topic: IdentTopic, bc_chan: BlockRequestSender) -> Result<Self> {
        let mdns_fut = Mdns::new(MdnsConfig::default());
        let mdns = task::block_on(mdns_fut).map_err(|err| Error::new_ext(ErrorKind::Other, err))?;

        let config = GossipsubConfigBuilder::default()
            .validation_mode(ValidationMode::Permissive)
            .max_transmit_size(MAX_TRANSMIT_SIZE)
            .build()
            .map_err(|err| Error::new_ext(ErrorKind::Other, err))?;
        //let privacy = MessageAuthenticity::Anonymous;
        let privacy = MessageAuthenticity::Author(peer_id);
        let mut gossip =
            Gossipsub::new(privacy, config).map_err(|err| Error::new_ext(ErrorKind::Other, err))?;

        gossip
            .subscribe(&topic)
            .map_err(|err| Error::new_ext(ErrorKind::Other, format!("{:?}", err)))?;

        Ok(Behavior {
            gossip,
            mdns,
            bc_chan,
        })
    }
}

impl NetworkBehaviourEventProcess<MdnsEvent> for Behavior {
    fn inject_event(&mut self, event: MdnsEvent) {
        match event {
            MdnsEvent::Discovered(nodes) => {
                for (peer, addr) in nodes {
                    debug!("discovered: {} @ {}", peer, addr);
                    self.gossip.add_explicit_peer(&peer);
                }
            }
            MdnsEvent::Expired(nodes) => {
                for (peer, addr) in nodes {
                    debug!("expired: {} @ {}", peer, addr);
                    self.gossip.remove_explicit_peer(&peer);
                }
            }
        }
    }
}

impl NetworkBehaviourEventProcess<GossipsubEvent> for Behavior {
    fn inject_event(&mut self, event: GossipsubEvent) {
        match event {
            GossipsubEvent::Message {
                propagation_source: _,
                message,
                message_id: _,
            } => {
                match self
                    .bc_chan
                    .send_sync(Message::Packed { buf: message.data })
                {
                    Ok(res_chan) => {
                        // Check if the blockchain has a response of if has dropped the response channel.
                        if let Ok(Message::Packed { buf }) = res_chan.recv_sync() {
                            let topic = IdentTopic::new(message.topic.as_str());
                            if let Err(err) = self.gossip.publish(topic, buf) {
                                if !matches!(err, PublishError::InsufficientPeers) {
                                    error!("publish error: {:?}", err);
                                }
                            }
                        }
                    }
                    Err(_err) => {
                        warn!("blockchain service seems down");
                    }
                }
            }
            GossipsubEvent::Subscribed { peer_id, topic } => {
                debug!("SUBSCRIBED peer-id: {}, topic: {}", peer_id, topic);
                if self.gossip.all_peers().count() == 1 {
                    let msg = Message::GetBlockRequest {
                        height: u64::MAX,
                        txs: false,
                    };
                    let topic = IdentTopic::new(topic.as_str());
                    let buf = rmp_serialize(&msg).unwrap_or_default();
                    if let Err(err) = self.gossip.publish(topic, buf) {
                        error!("publishing announcement message {:?}", err);
                    }
                }
            }
            GossipsubEvent::Unsubscribed { peer_id, topic } => {
                debug!("UNSUBSCRIBED peer-id: {}, topic: {}", peer_id, topic);
            }
        }
    }
}
