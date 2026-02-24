use std::fmt::Debug;
use std::net::SocketAddr;

use futures_util::FutureExt;
use futures_util::future::LocalBoxFuture;
use hickory_proto::op::Message;
use hickory_proto::xfer::DnsResponse;

mod https;
mod udp;

pub trait Backend: Debug {
    async fn send_request(&self, message: Message, src: SocketAddr) -> anyhow::Result<DnsResponse>;
}

pub trait DynBackend {
    fn dyn_send_request(
        &self,
        message: Message,
        src: SocketAddr,
    ) -> LocalBoxFuture<'_, anyhow::Result<DnsResponse>>;
}

impl<T: Backend> DynBackend for T {
    fn dyn_send_request(
        &self,
        message: Message,
        src: SocketAddr,
    ) -> LocalBoxFuture<'_, anyhow::Result<DnsResponse>> {
        self.send_request(message, src).boxed_local()
    }
}
