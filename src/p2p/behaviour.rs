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

//! KADEMLIA examples:
//! https://github.com/libp2p/rust-libp2p/blob/master/examples/ipfs-kad.rs
//! https://github.com/libp2p/rust-libp2p/discussions/2177
//! https://github.com/whereistejas/rust-libp2p/blob/4be8fcaf1f954599ff4c4428ab89ac79a9ccd0b9/examples/kademlia-example.rs

use crate::{
    base::serialize::rmp_serialize,
    blockchain::{BlockRequestSender, Message},
    Error, ErrorKind, Result,
};
use async_std::task;
use libp2p::{
    core::PublicKey,
    gossipsub::{
        error::PublishError, Gossipsub, GossipsubConfigBuilder, GossipsubEvent, IdentTopic,
        MessageAuthenticity, ValidationMode,
    },
    identify::{Identify, IdentifyConfig, IdentifyEvent},
    kad::{
        record::store::MemoryStore, GetClosestPeersError, Kademlia, KademliaConfig, KademliaEvent,
        QueryResult,
    },
    mdns::{Mdns, MdnsConfig, MdnsEvent},
    swarm::NetworkBehaviourEventProcess,
    Multiaddr, NetworkBehaviour, PeerId,
};
use std::str::FromStr;

/// Network behavior for application level message processing.
#[derive(NetworkBehaviour)]
pub(crate) struct Behavior {
    /// Peer identification protocol.
    pub identify: Identify,
    /// Gossip-sub as sub/sub protocol.
    pub gossip: Gossipsub,
    /// mDNS for peer discovery.
    pub mdns: Mdns,
    /// Kademlia for peer discovery.
    pub kad: Kademlia<MemoryStore>,
    /// To forward incoming messages to blockchain service.
    #[behaviour(ignore)]
    pub bc_chan: BlockRequestSender,
}

const MAX_TRANSMIT_SIZE: usize = 524288;

impl Behavior {
    fn identify_new(public_key: PublicKey) -> Result<Identify> {
        debug!("[p2p] identify start");
        let mut config = IdentifyConfig::new("trinci/1.0.0".to_owned(), public_key);
        config.push_listen_addr_updates = true;
        let identify = Identify::new(config);

        Ok(identify)
    }

    fn mdns_new() -> Result<Mdns> {
        debug!("[p2p] mdns start");
        let fut = Mdns::new(MdnsConfig::default());
        let mdns = task::block_on(fut).map_err(|err| Error::new_ext(ErrorKind::Other, err))?;

        Ok(mdns)
    }

    // TODO: random walk
    // let rand_peer: PeerId = identity::Keypair::generate_ed25519().public().into();
    // kad.get_closest_peers(rand_peer);
    fn kad_new(peer_id: PeerId, bootaddr: Option<String>) -> Result<Kademlia<MemoryStore>> {
        debug!("[p2p] kad start");
        let store = MemoryStore::new(peer_id);
        let config = KademliaConfig::default();
        let mut kad = Kademlia::with_config(peer_id, store, config);

        if let Some(bootaddr) = bootaddr {
            let (boot_peer, boot_addr) = match bootaddr.split_once('@') {
                Some((peer, addr)) => (peer, addr),
                None => {
                    return Err(Error::new_ext(
                        ErrorKind::MalformedData,
                        "address format should be <peer@multiaddr>",
                    ));
                }
            };
            let boot_peer = PeerId::from_str(boot_peer)
                .map_err(|err| Error::new_ext(ErrorKind::MalformedData, err))?;
            let boot_addr = Multiaddr::from_str(boot_addr)
                .map_err(|err| Error::new_ext(ErrorKind::MalformedData, err))?;
            kad.add_address(&boot_peer, boot_addr);

            //kad.bootstrap().unwrap();
            let peer: PeerId = libp2p::identity::Keypair::generate_ed25519()
                .public()
                .into();
            kad.get_closest_peers(peer);
        }

        Ok(kad)
    }

    fn gossip_new(peer_id: PeerId, topic: IdentTopic) -> Result<Gossipsub> {
        debug!("[p2p] gossip start");
        let privacy = MessageAuthenticity::Author(peer_id);
        let gossip_config = GossipsubConfigBuilder::default()
            .validation_mode(ValidationMode::Permissive)
            .max_transmit_size(MAX_TRANSMIT_SIZE)
            .build()
            .map_err(|err| Error::new_ext(ErrorKind::Other, err))?;
        let mut gossip = Gossipsub::new(privacy, gossip_config)
            .map_err(|err| Error::new_ext(ErrorKind::Other, err))?;

        gossip
            .subscribe(&topic)
            .map_err(|err| Error::new_ext(ErrorKind::Other, format!("{:?}", err)))?;

        Ok(gossip)
    }

    pub fn new(
        peer_id: PeerId,
        public_key: PublicKey,
        topic: IdentTopic,
        bootaddr: Option<String>,
        bc_chan: BlockRequestSender,
    ) -> Result<Self> {
        let identify = Self::identify_new(public_key)?;
        let gossip = Self::gossip_new(peer_id, topic)?;
        let mdns = Self::mdns_new()?;
        let kad = Self::kad_new(peer_id, bootaddr)?;

        Ok(Behavior {
            identify,
            gossip,
            mdns,
            kad,
            bc_chan,
        })
    }
}

// Received {
//     peer_id: PeerId("12D3KooWFmmKJ7jXhTfoYDvKkPqe7s9pHH42iZdf2xRdM5ykma1p"),
//     info: IdentifyInfo {
//         public_key: Ed25519(PublicKey(compressed): 587b8d516e965a6ee57a19e2734f1ab3bb8b45e6062801dff3e648d8594063),
//         protocol_version: "trinci/1.0.0",
//         agent_version: "rust-libp2p/0.30.0",
//         listen_addrs: [
//             "/ip4/127.0.0.1/tcp/41907",
//             "/ip4/192.168.1.125/tcp/41907",
//             "/ip4/172.18.0.1/tcp/41907",
//             "/ip4/172.17.0.1/tcp/41907"
//         ],
//         protocols: [
//             "/ipfs/id/1.0.0",
//             "/ipfs/id/push/1.0.0",
//             "/meshsub/1.1.0",
//             "/meshsub/1.0.0",
//             "/ipfs/kad/1.0.0"
//         ],
//         observed_addr: "/ip4/192.168.1.116/tcp/54612"
//     }
// }
impl NetworkBehaviourEventProcess<IdentifyEvent> for Behavior {
    fn inject_event(&mut self, event: IdentifyEvent) {
        match event {
            IdentifyEvent::Received { peer_id, info } => {
                // TODO: may be a good idea to eventually discard peers not supporting pubsub or kad protocols.
                self.gossip.add_explicit_peer(&peer_id);
                for addr in info.listen_addrs {
                    warn!("[kad] adding {} to routing table @ {}", peer_id, addr);
                    self.kad.add_address(&peer_id, addr);
                }
            }
            _ => warn!("[ident event] {:?}", event),
        }
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

impl NetworkBehaviourEventProcess<KademliaEvent> for Behavior {
    fn inject_event(&mut self, event: KademliaEvent) {
        #[allow(clippy::match_single_binding)]
        match event {
            KademliaEvent::RoutingUpdated {
                peer, addresses, ..
            } => {
                for addr in addresses.iter() {
                    debug!("kad discovered: {} @ {}", peer, addr);
                }
                self.gossip.add_explicit_peer(&peer);
            }
            KademliaEvent::OutboundQueryCompleted {
                result: QueryResult::GetClosestPeers(result),
                ..
            } => {
                match result {
                    Ok(ok) => {
                        if !ok.peers.is_empty() {
                            warn!("Query finished with closest peers: {:#?}", ok.peers)
                        } else {
                            // The example is considered failed as there
                            // should always be at least 1 reachable peer.
                            warn!("Query finished with no closest peers.")
                        }
                    }
                    Err(GetClosestPeersError::Timeout { peers, .. }) => {
                        if !peers.is_empty() {
                            warn!("Query timed out with closest peers: {:#?}", peers)
                        } else {
                            // The example is considered failed as there
                            // should always be at least 1 reachable peer.
                            warn!("Query timed out with no closest peers.");
                        }
                    }
                }
            }
            _ => {
                warn!("Kad event: {:?}", event);
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
