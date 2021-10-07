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
    base::serialize::rmp_serialize,
    blockchain::{pubsub::Event, BlockRequestSender, Message},
    crypto,
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
use std::sync::Arc;
use std::task::{Context, Poll};

const NODE_TOPIC: &str = "node";

fn build_transport(keypair: &Keypair) -> Boxed<(PeerId, StreamMuxerBox)> {
    let tcp_config = TcpConfig::new();

    // TODO: use NOISE protocol for production usage.
    //
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
    let keypair = match &config.keypair {
        Some(crypto::KeyPair::Ed25519(keypair)) => {
            let mut bytes = keypair.to_bytes();
            let ed25519_keypair = libp2p::identity::ed25519::Keypair::decode(&mut bytes).unwrap();
            libp2p::identity::Keypair::Ed25519(ed25519_keypair)
        }
        None => {
            info!("[p2p] Generating random keypair");
            libp2p::identity::Keypair::generate_ed25519()
        }
        _ => panic!("Node supports only ed25519 keypairs"),
    };
    let peer_id = keypair.public().into_peer_id();
    info!("P2P PeerId: {}", peer_id);

    // Subscribe to blockchain events of interest.
    let req = Message::Subscribe {
        id: "p2p".to_owned(),
        events: Event::BLOCK | Event::TRANSACTION | Event::REQUEST,
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

    let topic = config.network.to_owned() + "-" + NODE_TOPIC;
    let topic = IdentTopic::new(topic);

    let transport = build_transport(&keypair);
    let behaviour = Behavior::new(peer_id, topic.clone(), block_tx).unwrap();
    let mut swarm: Swarm<Behavior> = Swarm::new(transport, behaviour, peer_id);

    let addr = format!("/ip4/{}/tcp/0", config.addr);
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
                        if let Err(err) = behavior.gossip.publish(topic.clone(), buf) {
                            if !matches!(err, PublishError::InsufficientPeers) {
                                error!("publish error: {:?}", err);
                            }
                        }
                    }
                    _ => warn!("unexpected message from blockchain: {:?}", msg),
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
                Poll::Ready(Some(event)) => trace!("[p2p] event: {:?}", event),
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
