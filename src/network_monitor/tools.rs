use super::types::{Event, NodeTopology};

#[cfg(feature = "rt-monitor")]
use isahc::{self, Request, RequestExt};

const ADDRESS_ACTION: &str = "https://monitor.affidaty.net/api/v1/nodesMonitor/sendAction";
const ADDRESS_TOPOLOGY: &str = "https://monitor.affidaty.net/api/v1/nodesMonitor/sendTopology";

/// Sends the event
pub fn send_update(message: Event) {
    let request = match serde_json::to_string(&message) {
        Ok(request) => request,
        Err(_error) => {
            warn!("[monitor] error in serializing monitor structure");
            return;
        }
    };

    debug!("{}", request);

    let response = match Request::post(ADDRESS_ACTION)
        .header("content-type", "application/json")
        .body(request)
    {
        Ok(response) => response,
        Err(_error) => {
            warn!("[monitor] error in sending POST");
            return;
        }
    };

    match response.send() {
        Ok(_response) => debug!("[monitor] update sended"),
        Err(error) => warn!("[monitor] {:?}", error),
    }
}

/// Sends the event
pub fn send_topology(message: NodeTopology) {
    let request = match serde_json::to_string(&message) {
        Ok(request) => request,
        Err(_error) => {
            warn!("[monitor] error in serializing monitor structure");
            return;
        }
    };

    debug!("{}", request);

    let response = match Request::post(ADDRESS_TOPOLOGY)
        .header("content-type", "application/json")
        .body(request)
    {
        Ok(response) => response,
        Err(_error) => {
            warn!("[monitor] error in sending POST");
            return;
        }
    };

    match response.send() {
        Ok(_response) => debug!("[monitor] update sended"),
        Err(error) => warn!("[monitor] {:?}", error),
    }
}
