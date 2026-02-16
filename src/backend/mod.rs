use std::fmt::Debug;
use std::net::SocketAddr;

use async_trait::async_trait;
use hickory_proto::op::Message;
use hickory_proto::xfer::DnsResponse;

mod adaptor_backend;
mod group;
mod h3;
mod https;
mod quic;
mod tls;
mod udp;

pub use adaptor_backend::AdaptorBackend;
pub use group::Group;
pub use h3::H3Builder;
pub use https::HttpsBuilder;
pub use quic::QuicBuilder;
pub use tls::TlsBuilder;
pub use udp::UdpBuilder;

pub type DynBackend = Box<dyn Backend + Send + Sync>;

#[async_trait]
pub trait Backend: Debug {
    async fn send_request(&self, message: Message, src: SocketAddr) -> anyhow::Result<DnsResponse>;
    fn to_dyn_clone(&self) -> DynBackend;
}

impl Clone for DynBackend {
    fn clone(&self) -> Self {
        self.to_dyn_clone()
    }
}

#[async_trait]
impl<B: Backend + Sync> Backend for &B {
    async fn send_request(&self, message: Message, src: SocketAddr) -> anyhow::Result<DnsResponse> {
        (*self).send_request(message, src).await
    }

    fn to_dyn_clone(&self) -> DynBackend {
        (*self).to_dyn_clone()
    }
}

#[async_trait]
impl<B: Backend + Sync + Send + ?Sized> Backend for Box<B> {
    async fn send_request(&self, message: Message, src: SocketAddr) -> anyhow::Result<DnsResponse> {
        (**self).send_request(message, src).await
    }

    fn to_dyn_clone(&self) -> DynBackend {
        (**self).to_dyn_clone()
    }
}
