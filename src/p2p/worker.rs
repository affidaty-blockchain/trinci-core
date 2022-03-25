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

use super::{behaviour::Behavior, service::PeerConfig};
use crate::{
    base::serialize::{rmp_deserialize, rmp_serialize},
    blockchain::{pubsub::Event, BlockRequestSender, Message},
    p2p::behaviour::ReqUnicastMessage,
};
use futures::{future, prelude::*};
use libp2p::{
    core::{muxing::StreamMuxerBox, transport::Boxed},
    gossipsub::{error::PublishError, IdentTopic},
    identity::Keypair,
    mplex::MplexConfig,
    plaintext::PlainText2Config,
    swarm::Swarm,
    tcp::TcpConfig,
    Multiaddr, PeerId, Transport,
};
use std::task::{Context, Poll};
use std::{str::FromStr, sync::Arc};

const NODE_TOPIC: &str = "node";

fn build_transport(keypair: &Keypair) -> Boxed<(PeerId, StreamMuxerBox)> {
    let tcp_config = TcpConfig::new();

    // TODO: use NOISE protocol for encrypted traffic.
    // Currently is left as cleartext to allow traffic monitoring.
    // let noise_keys = libp2p::noise::Keypair::<libp2p::noise::X25519Spec>::new()
    //     .into_authentic(&keypair)
    //     .unwrap();
    // let sec_config = libp2p::noise::NoiseConfig::xx(noise_keys).into_authenticated();

    let sec_config = PlainText2Config {
        local_public_key: keypair.public(),
    };

    let mplex_config = MplexConfig::new();

    tcp_config
        .upgrade(libp2p::core::upgrade::Version::V1)
        .authenticate(sec_config)
        .multiplex(mplex_config)
        .boxed()
}

pub async fn run_async(config: Arc<PeerConfig>, block_tx: BlockRequestSender) {
    let keypair = match &config.p2p_keypair {
        Some(keypair) => {
            info!("[p2p] Using given keypair from Node");
            let mut bytes = keypair.to_bytes();
            let ed25519_keypair = libp2p::identity::ed25519::Keypair::decode(&mut bytes).unwrap();
            libp2p::identity::Keypair::Ed25519(ed25519_keypair)
        }
        None => {
            info!("[p2p] Generating random keypair");
            libp2p::identity::Keypair::generate_ed25519()
        }
    };

    let public_key = keypair.public();
    let peer_id = public_key.clone().to_peer_id();
    info!("P2P PeerId: {}", peer_id);

    // Subscribe to blockchain events of interest.
    let req = Message::Subscribe {
        id: "p2p".to_owned(),
        events: Event::BLOCK | Event::TRANSACTION | Event::GOSSIP_REQUEST | Event::UNICAST_REQUEST,
    };
    // We like to receive the payloads already in packed form...
    let buf = rmp_serialize(&req).unwrap();
    let req = Message::Packed { buf };
    let mut block_rx = match block_tx.send(req).await {
        Ok(chan) => chan,
        Err(_err) => {
            error!("Starting p2p worker. Blockchain channel is closed");
            return;
        }
    };

    let topic: String = NODE_TOPIC.to_string();
    let topic = IdentTopic::new(topic);

    let nw_name: String = config.network.lock().clone();

    let transport = build_transport(&keypair);
    let behaviour = Behavior::new(
        peer_id,
        public_key,
        topic.clone(),
        nw_name.clone(),
        config.bootstrap_addr.clone(),
        block_tx,
    )
    .unwrap();
    let mut swarm = Swarm::new(transport, behaviour, peer_id);

    let addr = format!("/ip4/{}/tcp/{}", config.addr, config.port);
    let addr = addr.parse::<Multiaddr>().unwrap();
    let res = Swarm::listen_on(&mut swarm, addr);
    if res.is_err() {
        error!("Error listening {}", res.unwrap_err());
    }

    let mut listening = false;

    let future = future::poll_fn(move |cx: &mut Context<'_>| -> Poll<()> {
        loop {
            match block_rx.poll_next_unpin(cx) {
                Poll::Ready(Some(msg)) => match msg {
                    Message::Packed { buf } => {
                        let behavior = swarm.behaviour_mut();

                        for peer in behavior.gossip.all_peers() {
                            trace!("ALL-PEER: {:?}", peer);
                        }
                        for peer in behavior.gossip.all_mesh_peers() {
                            trace!("MESH-PEER: {:?}", peer);
                        }

                        let msg: Message = rmp_deserialize(&buf).unwrap();

                        match msg {
                            Message::GetBlockRequest {
                                height: _,
                                txs: _,
                                ref destination,
                            } => {
                                match destination {
                                    Some(destination) => {
                                        // send to peer in unicast
                                        let behavior = swarm.behaviour_mut();
                                        let peer = PeerId::from_str(&destination.clone()).unwrap();
                                        let buf = rmp_serialize(&msg).unwrap();
                                        let request = ReqUnicastMessage(buf);
                                        debug!("[p2p] recieved an internal pubsub request, sended in unicast to {}", destination);
                                        behavior.reqres.send_request(&peer, request);
                                    }
                                    None => {
                                        // send in broadcast (gossip)
                                        let behavior = swarm.behaviour_mut();
                                        let buf = rmp_serialize(&msg).unwrap();
                                        if let Err(err) =
                                            behavior.gossip.publish(topic.clone(), buf)
                                        {
                                            if !matches!(err, PublishError::InsufficientPeers) {
                                                error!("publish error: {:?}", err);
                                            }
                                        }
                                    }
                                }
                            }
                            Message::GetTransactionRequest {
                                hash: _,
                                ref destination,
                            } => {
                                match destination {
                                    Some(destination) => {
                                        // send to peer in unicast
                                        let behavior = swarm.behaviour_mut();
                                        let peer = PeerId::from_str(&destination).unwrap();
                                        let buf = rmp_serialize(&msg).unwrap();
                                        let request = ReqUnicastMessage(buf);
                                        behavior.reqres.send_request(&peer, request);
                                    }
                                    None => {
                                        // send in broadcast (gossip)
                                        let behavior = swarm.behaviour_mut();
                                        let buf = rmp_serialize(&msg).unwrap();
                                        if let Err(err) =
                                            behavior.gossip.publish(topic.clone(), buf)
                                        {
                                            if !matches!(err, PublishError::InsufficientPeers) {
                                                error!("publish error: {:?}", err);
                                            }
                                        }
                                    }
                                }
                            }
                            Message::GetTransactionResponse { ref origin, .. } => {
                                if origin.is_none() {
                                    let buf = rmp_serialize(&msg).unwrap();
                                    if let Err(err) = behavior.gossip.publish(topic.clone(), buf) {
                                        if !matches!(err, PublishError::InsufficientPeers) {
                                            error!("publish error: {:?}", err);
                                        }
                                    }
                                }
                            }
                            Message::GetBlockResponse { ref origin, .. } => {
                                // check if is a message to propagate in gossip
                                if origin.is_none() {
                                    let buf = rmp_serialize(&msg).unwrap();
                                    if let Err(err) = behavior.gossip.publish(topic.clone(), buf) {
                                        if !matches!(err, PublishError::InsufficientPeers) {
                                            error!("publish error: {:?}", err);
                                        }
                                    }
                                }
                            }
                            Message::GetContractEvent { .. } => {}
                            _ => warn!("unexpected message from blockchain: {:?}", msg),
                        }
                    }
                    _ => warn!("unexpected message from blockchain"),
                },
                Poll::Ready(None) => {
                    warn!("blockchain channel has been closed, exiting");
                    return Poll::Ready(());
                }
                Poll::Pending => {
                    break;
                }
            }
        }

        loop {
            match swarm.poll_next_unpin(cx) {
                Poll::Ready(Some(event)) => {
                    trace!("[p2p] event: {:?}", event);
                    match event {
                        libp2p::swarm::SwarmEvent::Behaviour(event) => match event {
                            crate::p2p::behaviour::ComposedEvent::Identify(event) => {
                                swarm.behaviour_mut().identify_event_handler(event)
                            }
                            crate::p2p::behaviour::ComposedEvent::Kademlia(event) => {
                                swarm.behaviour_mut().kad_event_handler(event)
                            }
                            crate::p2p::behaviour::ComposedEvent::Gossip(event) => {
                                swarm.behaviour_mut().gossip_event_handler(event)
                            }
                            crate::p2p::behaviour::ComposedEvent::Mdns(event) => {
                                swarm.behaviour_mut().mdsn_event_handler(event)
                            }
                            crate::p2p::behaviour::ComposedEvent::ReqRes(event) => {
                                swarm.behaviour_mut().reqres_event_handler(event)
                            }
                        },
                        _ => (),
                    }
                }
                Poll::Ready(None) => {
                    warn!("swarm channel has been closed, exiting");
                    return Poll::Ready(());
                }
                Poll::Pending => {
                    if !listening {
                        for addr in Swarm::listeners(&swarm) {
                            debug!("[p2p] listening on {}", addr);
                            listening = true;
                        }
                    }
                    break;
                }
            }
        }

        Poll::Pending
    });

    future.await;
}

pub fn run(config: Arc<PeerConfig>, block_tx: BlockRequestSender) {
    let fut = run_async(config, block_tx);
    async_std::task::block_on(fut);
}
