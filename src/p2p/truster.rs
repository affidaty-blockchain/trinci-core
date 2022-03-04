use crate::p2p::worker;
use libp2p::PeerId;
pub struct trusted {
    pub peers: Vec<PeerId>,
}

impl trusted {
    /// Returns one of the trusted peers
    // should it handles the TO expulsion?
    pub fn get_trusted_peer() -> PeerId {
        todo!()
    }

    /// Remove peer from array
    pub fn remove_trusted_peer(peer: PeerId) {
        todo!()
    }

    /// Push peer to array
    pub fn add_trusted_peer(peer: PeerId) {
        todo!()
    }
}
