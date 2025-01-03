use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use hickory_proto::op::Message;
use hickory_proto::xfer::DnsResponse;

mod h3;
mod https;
mod quic;
mod tls;
mod udp;

pub use h3::H3Backend;
pub use https::HttpsBackend;
pub use quic::QuicBackend;
pub use tls::TlsBackend;
pub use udp::UdpBackend;

#[async_trait]
pub trait Backend: Debug {
    async fn send_request(&self, message: Message, src: SocketAddr) -> anyhow::Result<DnsResponse>;
}

#[async_trait]
impl Backend for Arc<dyn Backend + Send + Sync> {
    async fn send_request(&self, message: Message, src: SocketAddr) -> anyhow::Result<DnsResponse> {
        (**self).send_request(message, src).await
    }
}

#[async_trait]
impl<B: Backend + Sync> Backend for &B {
    async fn send_request(&self, message: Message, src: SocketAddr) -> anyhow::Result<DnsResponse> {
        (*self).send_request(message, src).await
    }
}
