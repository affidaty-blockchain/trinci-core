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

use super::BridgeConfig;
use crate::{
    blockchain::{BlockRequestSender, BlockResponseReceiver, Message},
    Error, ErrorKind, Result,
};
use async_std::net::{TcpListener, TcpStream};
use futures::{stream::StreamExt, AsyncReadExt, AsyncWriteExt};

pub struct BridgeWorker {
    config: BridgeConfig,
    bc_chan: BlockRequestSender,
}

impl BridgeWorker {
    pub fn new(config: BridgeConfig, bc_chan: BlockRequestSender) -> Self {
        BridgeWorker { config, bc_chan }
    }

    // WARNING: Every message that we are sending is a CONFIRMED message (i.e. a response is expected).
    // There is the strong assumption that the blockchain service is going to reply to our requests.
    // A missing reply from the blockchain is going to block the receiver "forever".
    // Maybe in the future is better to use the `recv_timeout` function?.
    async fn send_recv(
        request: Message,
        sender: BlockRequestSender,
        stream: &mut TcpStream,
    ) -> Result<Message> {
        let receiver = sender
            .send(request)
            .await
            .map_err(|_err| Error::new_ext(ErrorKind::Other, "blockchain service seems down"))?;

        let response = receiver
            .recv()
            .await
            .map_err(|_err| Error::new_ext(ErrorKind::Other, "blockchain service seems down"))?;

        if !receiver.is_closed() {
            // Possible subscription
            async_std::task::spawn(Self::subscription_handler(receiver, stream.clone()));
        }

        Ok(response)
    }

    async fn subscription_handler(chan: BlockResponseReceiver, mut stream: TcpStream) {
        while let Ok(Message::Packed { buf }) = chan.recv().await {
            let len = buf.len() as u32;
            let head: [u8; 4] = len.to_be_bytes();
            if stream.write_all(&head).await.is_err() {
                break;
            }
            if stream.write_all(&buf).await.is_err() {
                break;
            }
        }
    }

    async fn read_datagram(
        stream: &mut TcpStream,
    ) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error>> {
        // Read the header
        let mut head = [0u8; 4];
        stream.read_exact(&mut head).await?;
        let len = u32::from_be_bytes(head);

        // Read the body
        let mut buf = vec![0u8; len as usize];
        stream.read_exact(&mut buf).await?;

        Ok(buf)
    }

    async fn write_datagram(
        stream: &mut TcpStream,
        buf: Vec<u8>,
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        // Write the header
        let len = buf.len() as u32;
        let head: [u8; 4] = len.to_be_bytes();
        stream.write_all(&head).await?;

        // Write the body
        stream.write_all(buf.as_ref()).await?;

        Ok(())
    }

    async fn connection_handler(
        mut stream: TcpStream,
        bc_chan: BlockRequestSender,
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        loop {
            let buf = Self::read_datagram(&mut stream).await?;
            let req = Message::Packed { buf };
            let res = Self::send_recv(req, bc_chan.clone(), &mut stream).await?;
            if let Message::Packed { buf } = res {
                Self::write_datagram(&mut stream, buf).await?;
            } else {
                warn!("Unexpected response from blockchain to bridge: {:?}", res);
            }
        }
    }

    pub async fn run(&mut self) {
        let listener = TcpListener::bind((self.config.addr.as_str(), self.config.port))
            .await
            .unwrap();
        listener
            .incoming()
            .for_each_concurrent(None, |stream| {
                let bc_chan = self.bc_chan.clone();
                let fut = async move {
                    if let Ok(stream) = stream {
                        debug!("New bridge connection");
                        let _ = Self::connection_handler(stream, bc_chan.clone()).await;
                        debug!("Dropping bridge connection");
                    } else {
                        debug!("Spurious bridge connection");
                    }
                };
                async_std::task::spawn(fut)
            })
            .await;
    }

    /// Bridge worker synchronous task.
    pub fn run_sync(&mut self) {
        async_std::task::block_on(self.run());
    }
}
