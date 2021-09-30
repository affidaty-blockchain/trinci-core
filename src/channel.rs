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

//! Channel is built on top of async-std channel but with the addition of the
//! consumer responding with a message to the producer.  Since the producer no
//! longer only produces and the consumer no longer only consumes, the Producer
//! is renamed to [RequestSender] and the Consumer is renamed to
//! [RequestReceiver].

use async_std::{
    channel::{
        self as async_channel, Receiver as AsyncReceiver, Sender as AsyncSender, TryRecvError,
    },
    task,
};
use std::{fmt::Display, pin::Pin, time::Duration};

/// Upper bound to outstanding channel elements.
const CHANNEL_BOUND: usize = 1000;

/// Errors which can be triggered by a channel.
#[derive(Debug, PartialEq)]
pub enum ChannelError {
    /// Error during send. Broken channel.
    SendError,
    /// Error during receive. Broken channel.
    RecvError,
    /// Timeout during receive.
    RecvTimeout,
}

impl std::error::Error for ChannelError {}

impl Display for ChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            ChannelError::SendError => "channel send error",
            ChannelError::RecvError => "channel recv error",
            ChannelError::RecvTimeout => "channel recv timeout",
        };
        write!(f, "{}", msg)
    }
}

/// Creates a simple mpmc channel.
pub fn simple_channel<T>() -> (Sender<T>, Receiver<T>) {
    let (sender, receiver) = async_channel::bounded::<T>(CHANNEL_BOUND);
    let request_sender = Sender(sender);
    let request_receiver = Receiver(receiver);
    (request_sender, request_receiver)
}

/// Channel sender side.
#[derive(Clone)]
pub struct Sender<T>(AsyncSender<T>);

impl<Res> Sender<Res> {
    /// Responds a request from the [RequestSender] which finishes the request
    pub async fn send(&self, response: Res) -> Result<(), ChannelError> {
        self.0
            .send(response)
            .await
            .map_err(|_| ChannelError::SendError)
    }

    /// Responds a request from the [RequestSender], synchronous wrapper.
    pub fn send_sync(&self, response: Res) -> Result<(), ChannelError> {
        task::block_on(self.send(response))
    }

    /// Closes the channel.
    /// Returns true if this call has closed the channel and it was not closed already.
    /// The remaining messages can still be received.
    pub fn close(&self) -> bool {
        self.0.close()
    }

    /// Returns true if the channel is closed.
    pub fn is_closed(&self) -> bool {
        self.0.is_closed()
    }
}

/// [ResponseReceiver] listens for a response from a [ResponseSender].
/// The response is received using the `recv` method.
#[derive(Clone)]
pub struct Receiver<Res>(AsyncReceiver<Res>);

impl<Res> Receiver<Res> {
    /// Collect the result.
    ///
    /// This call is blocking.
    pub async fn recv(&self) -> Result<Res, ChannelError> {
        self.0.recv().await.map_err(|_| ChannelError::RecvError)
    }

    /// Collect the result.
    pub async fn recv_timeout(&self, timeout: Duration) -> Result<Res, ChannelError> {
        let mut timeout = timeout;
        let sleep_time = Duration::from_millis(100);
        loop {
            match self.0.try_recv() {
                Ok(res) => return Ok(res),
                Err(TryRecvError::Empty) if timeout > Duration::from_millis(0) => {
                    task::sleep(sleep_time).await;
                    timeout = timeout
                        .checked_sub(sleep_time)
                        .unwrap_or_else(|| Duration::from_millis(0));
                }
                Err(TryRecvError::Empty) => return Err(ChannelError::RecvTimeout),
                _ => return Err(ChannelError::RecvError),
            }
        }
    }

    /// Collect the result, synchronous wrapper.
    pub fn recv_sync(&self) -> Result<Res, ChannelError> {
        task::block_on(self.recv())
    }

    /// Collect the result with timeout, synchronous wrapper.
    pub fn recv_timeout_sync(&self, timeout: Duration) -> Result<Res, ChannelError> {
        task::block_on(self.recv_timeout(timeout))
    }

    /// Closes the channel.
    /// Returns true if this call has closed the channel and it was not closed already.
    /// The remaining messages can still be received.
    pub fn close(&self) -> bool {
        self.0.close()
    }

    /// Returns true if the channel is closed.
    pub fn is_closed(&self) -> bool {
        self.0.is_closed()
    }
}

/// Create a [RequestSender] and a [RequestReceiver] with a channel between them.
///
/// The [RequestSender] can be cloned to be able to do requests to the same [RequestReceiver] from multiple
/// threads.
pub fn confirmed_channel<Req, Res>() -> (RequestSender<Req, Res>, RequestReceiver<Req, Res>) {
    let (request_sender, request_receiver) =
        async_channel::bounded::<(Req, Sender<Res>)>(CHANNEL_BOUND);
    let request_sender = RequestSender(request_sender);
    let request_receiver = RequestReceiver(request_receiver);
    (request_sender, request_receiver)
}

/// [RequestSender] has a connection to a [RequestReceiver] to which it can
/// send a requests to.
/// The request method is used to make a request and it returns a
/// [ResponseReceiver] which is used to receive the response.
#[derive(Clone)]
pub struct RequestSender<Req, Res>(AsyncSender<(Req, Sender<Res>)>);

impl<Req, Res> RequestSender<Req, Res> {
    /// Send request to the connected [RequestReceiver]
    /// Returns a [ResponseReceiver] which is used to receive the response.
    pub async fn send(&self, request: Req) -> Result<Receiver<Res>, ChannelError> {
        let (response_sender, response_receiver) = simple_channel();
        self.0
            .send((request, response_sender))
            .await
            .map_err(|_| ChannelError::SendError)
            .map(|_| response_receiver)
    }

    /// Send request, synchronous wrapper.
    pub fn send_sync(&self, request: Req) -> Result<Receiver<Res>, ChannelError> {
        task::block_on(self.send(request))
    }

    /// Closes the channel.
    /// Returns true if this call has closed the channel and it was not closed already.
    /// The remaining messages can still be received.
    pub fn close(&self) -> bool {
        self.0.close()
    }

    /// Returns true if the channel is closed.
    pub fn is_closed(&self) -> bool {
        self.0.is_closed()
    }
}

/// A [RequestReceiver] listens to requests. Requests are a tuple of a message
/// and a [ResponseSender] which is used to respond back to the [ResponseReceiver]
#[derive(Clone)]
pub struct RequestReceiver<Req, Res>(AsyncReceiver<(Req, Sender<Res>)>);

impl<Req, Res> RequestReceiver<Req, Res> {
    /// Poll if the [RequestReceiver] has received any requests.
    /// The poll returns a tuple of the request message and a [ResponseSender]
    /// which is used to respond back to the ResponseReceiver.
    ///
    /// This call is blocking.
    pub async fn recv(&self) -> Result<(Req, Sender<Res>), ChannelError> {
        self.0.recv().await.map_err(|_| ChannelError::RecvError)
    }

    /// Poll if the [RequestReceiver] has received any requests.
    /// The poll returns a tuple of the request message and a [ResponseSender]
    /// which is used to respond back to the ResponseReceiver.
    /// Returns after a given timeout.
    pub async fn recv_timeout(
        &self,
        timeout: Duration,
    ) -> Result<(Req, Sender<Res>), ChannelError> {
        let mut timeout = timeout;
        let sleep_time = Duration::from_millis(100);
        loop {
            match self.0.try_recv() {
                Ok(res) => return Ok(res),
                Err(TryRecvError::Empty) if timeout > Duration::from_millis(0) => {
                    task::sleep(sleep_time).await;
                    timeout = timeout
                        .checked_sub(sleep_time)
                        .unwrap_or_else(|| Duration::from_millis(0));
                }
                Err(TryRecvError::Empty) => return Err(ChannelError::RecvTimeout),
                _ => return Err(ChannelError::RecvError),
            }
        }
    }

    /// Poll if the [RequestReceiver] has received any requests, synchronous wrapper.
    pub fn recv_sync(&self) -> Result<(Req, Sender<Res>), ChannelError> {
        task::block_on(self.recv())
    }

    /// Poll if the [RequestReceiver] has received any requests, synchronous wrapper.
    /// Returns after a given timeout.
    pub fn recv_timeout_sync(&self, timeout: Duration) -> Result<(Req, Sender<Res>), ChannelError> {
        task::block_on(self.recv_timeout(timeout))
    }

    /// Closes the channel.
    /// Returns true if this call has closed the channel and it was not closed already.
    /// The remaining messages can still be received.
    pub fn close(&self) -> bool {
        self.0.close()
    }

    /// Returns true if the channel is closed.
    pub fn is_closed(&self) -> bool {
        self.0.is_closed()
    }
}

/// Type alias for simple sender.
/// This is sent by the [RequestSender] `request_send` along with the used data.
pub type ResponseSender<Res> = Sender<Res>;

/// Type alias for simple receiver.
/// This is returned by the [RequestSender] `request_send` method.
pub type ResponseReceiver<Res> = Receiver<Res>;

/// Stream implementation for [Receiver].
impl<T> futures::Stream for Receiver<T> {
    type Item = T;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let pin = Pin::new(&mut self.0);
        pin.poll_next(cx)
    }
}

/// Stream implementation for [RequestReceiver].
impl<Req, Res> futures::Stream for RequestReceiver<Req, Res> {
    type Item = (Req, ResponseSender<Res>);

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let pin = Pin::new(&mut self.0);
        pin.poll_next(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const TIMEOUT_DURATION: Duration = Duration::from_secs(1);

    #[test]
    fn send_recv() {
        let (tx_chan, rx_chan) = simple_channel::<u32>();

        tx_chan.send_sync(3).unwrap();
        let val = rx_chan.recv_sync().unwrap();

        assert_eq!(val, 3);
    }

    #[test]
    fn send_closed_receiver() {
        let (tx_chan, _) = simple_channel::<()>();

        let err = tx_chan.send_sync(()).unwrap_err();

        assert_eq!(err, ChannelError::SendError);
    }

    #[test]
    fn recv_closed_sender() {
        let (_, rx_chan) = simple_channel::<()>();

        let err = rx_chan.recv_sync().unwrap_err();

        assert_eq!(err, ChannelError::RecvError);
    }

    #[test]
    fn recv_with_timeout() {
        let (_tx_chan, rx_chan) = simple_channel::<()>();

        let err = rx_chan.recv_timeout_sync(TIMEOUT_DURATION).unwrap_err();

        assert_eq!(err, ChannelError::RecvTimeout);
    }

    #[test]
    fn send_confirmed_request() {
        let (req_tx_chan, req_rx_chan) = confirmed_channel::<u32, u8>();

        let res_rx_chan = req_tx_chan.send_sync(3).unwrap();
        let (req, res_tx_chan) = req_rx_chan.recv_sync().unwrap();

        res_tx_chan.send_sync(9).unwrap();
        let res = res_rx_chan.recv_sync().unwrap();

        assert_eq!(req, 3);
        assert_eq!(res, 9);
    }

    #[test]
    fn send_confirmed_request_closed_sender() {
        let (req_tx_chan, req_rx_chan) = confirmed_channel::<u32, u8>();

        let res_rx_chan = req_tx_chan.send_sync(3).unwrap();
        let (req, _) = req_rx_chan.recv_sync().unwrap();

        let err = res_rx_chan.recv_sync().unwrap_err();

        assert_eq!(req, 3);
        assert_eq!(err, ChannelError::RecvError);
    }
}
