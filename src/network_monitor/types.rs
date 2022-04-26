#[derive(Serialize)]
pub enum Action {
    BlockProduced,
    BlockRecieved,
    TransactionProduced,
    TransactionRecieved,
}

#[derive(Serialize)]
pub struct Event {
    /// PeerId of the node that recieved the event.
    pub(crate) peer_id: String,
    /// Event recieved.
    pub(crate) action: Action,
    /// Payload of the event.
    pub(crate) payload: String,
    /// Network.
    pub(crate) network: String,
}

#[derive(Serialize)]
pub struct NodeTopology {
    /// PeerId of the node that recieved the event.
    pub(crate) peer_id: String,
    /// Node neighbours.
    pub(crate) neighbours: Vec<String>,
    /// Network.
    pub(crate) network: String,
}
