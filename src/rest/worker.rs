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
    base::serialize::{rmp_deserialize, rmp_serialize},
    blockchain::{BlockRequestSender, Message},
    crypto::Hash,
    Error, ErrorKind, Result, VERSION,
};
use tide::{http::mime, Request, Response, StatusCode};

/// Conversion from "core" errors to HTTP errors.
impl From<ErrorKind> for StatusCode {
    fn from(err: ErrorKind) -> StatusCode {
        use crate::error::ErrorKind::*;
        match err {
            MalformedData => StatusCode::BadRequest,
            BadNetwork => StatusCode::NotFound,
            InvalidSignature => StatusCode::Unauthorized,
            DuplicatedUnconfirmedTx | DuplicatedConfirmedTx => StatusCode::Conflict,
            ResourceNotFound => StatusCode::NotFound,
            WasmMachineFault | DatabaseFault | FuelError => StatusCode::InternalServerError,
            SmartContractFault => StatusCode::BadRequest,
            NotImplemented => StatusCode::NotImplemented,
            Tpm2Error => StatusCode::InternalServerError,
            WrongTxType => StatusCode::Conflict,
            BrokenIntegrity => StatusCode::Unauthorized,
            Other => StatusCode::ImATeapot,
        }
    }
}

impl From<Error> for Response {
    fn from(err: Error) -> Self {
        let status: StatusCode = err.kind.into();
        Response::builder(status)
            .content_type(mime::BYTE_STREAM)
            .build()
    }
}

// WARNING: Every message that we are sending is a CONFIRMED message (i.e. a response is expected).
// There is the strong assumption that the blockchain service is going to reply to our requests.
// A missing reply from the blockchain is going to block the receiver "forever".
// Maybe in the future is better to use the `recv_timeout` function?.
async fn send_recv(chan: &BlockRequestSender, request: Message) -> Result<Message> {
    let chan = chan.clone();

    let receiver = chan
        .send(request)
        .await
        .map_err(|_err| Error::new_ext(ErrorKind::Other, "blockchain service seems down"))?;

    receiver
        .recv()
        .await
        .map_err(|_err| Error::new_ext(ErrorKind::Other, "blockchain service seems down"))
}

fn tide_result(result: Result<Vec<u8>>) -> tide::Result {
    let (body, status) = match result {
        Ok(buf) => (buf, StatusCode::Ok),
        Err(err) => {
            let buf = err.to_string_full().as_bytes().to_vec();
            (buf, err.kind.into())
        }
    };
    let response = Response::builder(status)
        .body(body)
        .content_type(mime::BYTE_STREAM)
        .build();
    Ok(response)
}

async fn message_handler(mut req: Request<BlockRequestSender>) -> tide::Result {
    let body = req.body_bytes().await?;
    let res = match send_recv(req.state(), Message::Packed { buf: body }).await? {
        Message::Packed { buf } => Ok(buf),
        _ => Err(Error::new_ext(
            ErrorKind::Other,
            "unexpected response from block service",
        )),
    };
    tide_result(res)
}

async fn put_transaction(mut req: Request<BlockRequestSender>) -> tide::Result {
    let body = req.body_bytes().await?;
    let tx = rmp_deserialize(&body)?;
    let bc_req = Message::PutTransactionRequest { confirm: true, tx };
    let bc_res = match send_recv(req.state(), bc_req).await? {
        Message::PutTransactionResponse { hash } => Ok(hash.to_bytes()),
        Message::Exception(err) => Err(err),
        _ => Err(Error::new_ext(
            ErrorKind::Other,
            "unexpected response from block service",
        )),
    };
    tide_result(bc_res)
}

async fn get_transaction(req: Request<BlockRequestSender>) -> tide::Result {
    let ticket = req.param("0").unwrap_or_default();
    let hash = Hash::from_hex(ticket).unwrap_or_default();
    let bc_req = Message::GetTransactionRequest {
        hash,
        destination: None,
    };
    let res = match send_recv(req.state(), bc_req).await? {
        Message::GetTransactionResponse { tx, .. } => rmp_serialize(&tx),
        Message::Exception(err) => Err(err),
        _ => Err(Error::new_ext(
            ErrorKind::Other,
            "unexpected response from block service",
        )),
    };
    tide_result(res)
}

async fn get_receipt(req: Request<BlockRequestSender>) -> tide::Result {
    let ticket = req.param("0").unwrap_or_default();
    let hash = Hash::from_hex(ticket).unwrap_or_default();
    let bc_req = Message::GetReceiptRequest { hash };
    let res = match send_recv(req.state(), bc_req).await? {
        Message::GetReceiptResponse { rx } => rmp_serialize(&rx),
        Message::Exception(err) => Err(err),
        _ => Err(Error::new_ext(
            ErrorKind::Other,
            "unexpected response from block service",
        )),
    };
    tide_result(res)
}

async fn get_block(req: Request<BlockRequestSender>) -> tide::Result {
    let height = req.param("0").unwrap_or_default();
    let height = height.parse::<u64>().unwrap_or_default();
    let bc_req = Message::GetBlockRequest {
        height,
        txs: false,
        destination: None, // TODO: check but it should be for internal use
    };
    let res = match send_recv(req.state(), bc_req).await? {
        Message::GetBlockResponse { block, .. } => rmp_serialize(&block),
        Message::Exception(err) => Err(err),
        _ => Err(Error::new_ext(
            ErrorKind::Other,
            "unexpected response from block service",
        )),
    };
    tide_result(res)
}

async fn get_account(req: Request<BlockRequestSender>) -> tide::Result {
    let id = req.param("0").unwrap_or_default().to_owned();
    let bc_req = Message::GetAccountRequest { id, data: vec![] };
    let res = match send_recv(req.state(), bc_req).await? {
        Message::GetAccountResponse { acc, .. } => rmp_serialize(&acc),
        Message::Exception(err) => Err(err),
        _ => Err(Error::new_ext(
            ErrorKind::Other,
            "unexpected response from block service",
        )),
    };
    tide_result(res)
}

async fn get_p2p_id(req: Request<BlockRequestSender>) -> tide::Result {
    let bc_req = Message::GetP2pIdRequest;
    let res = match send_recv(req.state(), bc_req).await? {
        Message::GetP2pIdResponse(id) => id,
        Message::Exception(_err) => "ERR".to_string(),
        _ => "ERR".to_string(),
    };
    Ok(res.into())
}

async fn get_index(_req: Request<BlockRequestSender>) -> tide::Result {
    Ok(format!("TRINCI v{}", VERSION).into())
}

pub fn run(addr: String, port: u16, block_chan: BlockRequestSender) {
    let mut app = tide::with_state(block_chan);

    app.at("/api/v1/message").post(message_handler);
    app.at("/api/v1/submit").post(put_transaction);
    app.at("/api/v1/account/:0").get(get_account);
    app.at("/api/v1/transaction/:0").get(get_transaction);
    app.at("/api/v1/receipt/:0").get(get_receipt);
    app.at("/api/v1/block/:0").get(get_block);
    app.at("/api/v1/p2p/id").get(get_p2p_id);
    app.at("/").get(get_index);

    let fut = app.listen((addr, port));
    async_std::task::block_on(fut).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        base::{
            schema::tests::{
                create_test_account, create_test_block, create_test_receipt, create_test_unit_tx,
                FUEL_LIMIT,
            },
            serialize::{rmp_deserialize, rmp_serialize},
        },
        blockchain::BlockRequestReceiver,
        channel,
    };
    use std::{
        io::Read,
        sync::atomic::{AtomicU16, Ordering},
        thread,
    };
    use ureq::Response;

    const HASH_HEX: &str = "1220ceb09a4dda3d8c0f900c75a6d826ae3296e31918e7b155b5dbe41d3d4f766aac";
    const ACCOUNT_ID: &str = "QmYHnEQLdf5h7KYbjFPuHSRk2SPgdXrJWFh5W696HPfq7i";

    fn msg_handler(req: Message) -> Message {
        match req {
            Message::PutTransactionRequest { confirm, tx } if confirm => {
                if tx.verify(tx.get_caller(), &tx.get_signature()).is_err() {
                    Message::Exception(Error::new(ErrorKind::InvalidSignature))
                } else {
                    Message::PutTransactionResponse {
                        hash: Hash::from_hex(HASH_HEX).unwrap(),
                    }
                }
            }
            Message::GetTransactionRequest { hash, .. } => {
                match hash == Hash::from_hex(HASH_HEX).unwrap() {
                    true => Message::GetTransactionResponse {
                        tx: create_test_unit_tx(FUEL_LIMIT),
                        origin: None,
                    },
                    false => Message::Exception(ErrorKind::ResourceNotFound.into()),
                }
            }
            Message::GetReceiptRequest { hash } => {
                match hash == Hash::from_hex(HASH_HEX).unwrap() {
                    true => Message::GetReceiptResponse {
                        rx: create_test_receipt(),
                    },
                    false => Message::Exception(ErrorKind::ResourceNotFound.into()),
                }
            }
            Message::GetAccountRequest { id, data: _ } => match id == ACCOUNT_ID {
                true => Message::GetAccountResponse {
                    acc: create_test_account(),
                    data: vec![],
                },
                false => Message::Exception(ErrorKind::ResourceNotFound.into()),
            },
            Message::GetBlockRequest {
                height,
                txs: _,
                destination: _,
            } => match height {
                0 => Message::GetBlockResponse {
                    block: create_test_block(),
                    txs: None,
                    origin: None, // TODO: check but it should be local
                },
                _ => Message::Exception(ErrorKind::ResourceNotFound.into()),
            },
            Message::Packed { buf } => {
                let buf = match rmp_deserialize(&buf) {
                    Ok(req) => {
                        let res = msg_handler(req);
                        rmp_serialize(&res).unwrap()
                    }
                    _ => vec![],
                };
                Message::Packed { buf }
            }
            _ => Message::Stop, // Unexpected message
        }
    }

    fn block_svc_mock_start(req_chan: BlockRequestReceiver) {
        let fut = async move {
            while let Ok((req, res_chan)) = req_chan.recv().await {
                let res = msg_handler(req);
                if let Err(err) = res_chan.send(res).await {
                    warn!("block service mock response send error: {}", err);
                }
            }
        };
        std::thread::spawn(|| async_std::task::block_on(fut));
    }

    fn start_listener() -> String {
        static PORT: AtomicU16 = AtomicU16::new(9000);
        let port = PORT.fetch_add(1, Ordering::SeqCst);
        let addr = format!("http://localhost:{}", port);

        let (tx_chan, rx_chan) = channel::confirmed_channel();

        block_svc_mock_start(rx_chan);

        thread::spawn(move || {
            run("localhost".to_string(), port, tx_chan);
        });

        let mut trials = 3;
        loop {
            match ureq::get(&addr).call() {
                Ok(_) => break,
                Err(_) if trials > 0 => {
                    trials -= 1;
                    std::thread::sleep(std::time::Duration::from_secs(1));
                }
                _ => panic!("connection refused"),
            }
        }
        addr
    }

    fn fetch_response_body(response: Response) -> Vec<u8> {
        let mut body = vec![];
        response.into_reader().read_to_end(&mut body).unwrap();
        body
    }

    fn fetch_response_message(response: Response) -> Message {
        let buf = fetch_response_body(response);
        rmp_deserialize(&buf).unwrap()
    }

    fn fetch_error_response(err: ureq::Error) -> Response {
        match err {
            ureq::Error::Status(_code, response) => response,
            result => panic!("Unexpected result: {:?}", result),
        }
    }

    #[test]
    fn index_test() {
        let addr = start_listener();

        let response: ureq::Response = ureq::get(&addr).call().unwrap();

        assert_eq!(response.content_type(), "text/plain");
        assert_eq!(
            response.into_string().unwrap(),
            format!("TRINCI v{}", VERSION)
        );
    }

    #[test]
    fn message_get_transaction() {
        let tx = create_test_unit_tx(FUEL_LIMIT);
        let msg = Message::GetTransactionRequest {
            hash: Hash::from_hex(HASH_HEX).unwrap(),
            destination: None,
        };
        let buf = rmp_serialize(&msg).unwrap();

        let mut addr = start_listener();
        addr.push_str("/api/v1/message");

        let response = ureq::post(&addr).send_bytes(&buf).unwrap();

        assert_eq!(response.status_text(), "OK");
        assert_eq!(response.content_type(), "application/octet-stream");
        assert_eq!(
            fetch_response_message(response),
            Message::GetTransactionResponse { tx, origin: None },
        );
    }

    #[test]
    fn message_put_transaction() {
        let tx = create_test_unit_tx(FUEL_LIMIT);
        let msg = Message::PutTransactionRequest { confirm: true, tx };
        let buf = rmp_serialize(&msg).unwrap();

        let mut addr = start_listener();
        addr.push_str("/api/v1/message");

        let response = ureq::post(&addr).send_bytes(&buf).unwrap();

        assert_eq!(response.status_text(), "OK");
        assert_eq!(response.content_type(), "application/octet-stream");
        assert_eq!(
            fetch_response_message(response),
            Message::PutTransactionResponse {
                hash: Hash::from_hex(HASH_HEX).unwrap()
            }
        );
    }

    #[test]
    fn message_error() {
        let mut addr = start_listener();
        addr.push_str("/api/v1/message");

        let response = ureq::post(&addr).send_bytes(&[]).unwrap();

        assert_eq!(response.status_text(), "OK");
        assert_eq!(response.content_type(), "application/octet-stream");
        assert!(fetch_response_body(response).is_empty())
    }

    #[test]
    fn put_transaction() {
        let mut addr = start_listener();
        addr.push_str("/api/v1/submit");
        let tx = create_test_unit_tx(FUEL_LIMIT);
        let body = rmp_serialize(&tx).unwrap();

        let response = ureq::post(&addr).send_bytes(&body).unwrap();

        assert_eq!(response.status_text(), "OK");
        assert_eq!(response.content_type(), "application/octet-stream");
        let body = fetch_response_body(response);
        assert_eq!(hex::encode(body), HASH_HEX);
    }

    #[test]
    fn put_transaction_error() {
        let mut addr = start_listener();
        addr.push_str("/api/v1/submit");
        let mut tx = create_test_unit_tx(FUEL_LIMIT);

        match tx {
            crate::Transaction::UnitTransaction(ref mut tx) => tx.signature[0] += 1,
            crate::Transaction::BulkTransaction(ref mut tx) => tx.signature[0] += 1,
        }

        let body = rmp_serialize(&tx).unwrap();

        let error = ureq::post(&addr).send_bytes(&body).unwrap_err();
        let response = fetch_error_response(error);

        assert_eq!(response.status_text(), "Unauthorized");
        assert_eq!(response.content_type(), "application/octet-stream");
        let body = fetch_response_body(response);
        assert_eq!(String::from_utf8_lossy(&body), "invalid signature");
    }

    #[test]
    fn get_transaction() {
        let mut addr = start_listener();
        addr.push_str("/api/v1/transaction/");
        addr.push_str(HASH_HEX);

        let response: ureq::Response = ureq::get(&addr).call().unwrap();

        assert_eq!(response.status_text(), "OK");
        assert_eq!(response.content_type(), "application/octet-stream");
        let exp = rmp_serialize(&create_test_unit_tx(FUEL_LIMIT)).unwrap();
        assert_eq!(fetch_response_body(response), exp);
    }

    #[test]
    fn get_receipt() {
        let mut addr = start_listener();
        addr.push_str("/api/v1/receipt/");
        addr.push_str(HASH_HEX);

        let response: ureq::Response = ureq::get(&addr).call().unwrap();

        assert_eq!(response.status_text(), "OK");
        assert_eq!(response.content_type(), "application/octet-stream");
        let exp = rmp_serialize(&create_test_receipt()).unwrap();
        assert_eq!(fetch_response_body(response), exp);
    }

    #[test]
    fn get_block() {
        let mut addr = start_listener();
        addr.push_str("/api/v1/block/0");

        let response: ureq::Response = ureq::get(&addr).call().unwrap();

        assert_eq!(response.status_text(), "OK");
        let exp = rmp_serialize(&create_test_block()).unwrap();
        assert_eq!(fetch_response_body(response), exp);
    }

    #[test]
    fn get_account() {
        let mut addr = start_listener();
        addr.push_str("/api/v1/account/");
        addr.push_str(ACCOUNT_ID);

        let response: ureq::Response = ureq::get(&addr).call().unwrap();

        assert_eq!(response.status_text(), "OK");
        assert_eq!(response.content_type(), "application/octet-stream");
        let exp = rmp_serialize(&create_test_account()).unwrap();
        assert_eq!(fetch_response_body(response), exp);
    }
}
