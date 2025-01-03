use std::net::SocketAddr;

use enum_dispatch::enum_dispatch;
use hickory_proto::op::Message;
use hickory_proto::rr::rdata::opt::EdnsCode;
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

#[enum_dispatch]
pub trait Backend {
    async fn send_request(&self, message: Message, src: SocketAddr) -> anyhow::Result<DnsResponse>;
}

#[derive(Debug, Clone)]
pub struct ExtensionBackend {
    pub(crate) backend: Backends,
    clear_ecs: bool,
}

impl ExtensionBackend {
    pub fn new(backend: Backends, clear_ecs: bool) -> Self {
        Self { backend, clear_ecs }
    }
}

impl Backend for ExtensionBackend {
    #[inline]
    async fn send_request(
        &self,
        mut message: Message,
        src: SocketAddr,
    ) -> anyhow::Result<DnsResponse> {
        if self.clear_ecs {
            if let Some(edns) = message.extensions_mut() {
                edns.options_mut().remove(EdnsCode::Subnet);
            }
        }

        self.backend.send_request(message, src).await
    }
}

#[enum_dispatch(Backend)]
#[derive(Debug, Clone)]
pub enum Backends {
    Tls(TlsBackend),
    Udp(UdpBackend),
    Https(HttpsBackend),
    Quic(QuicBackend),
    H3(H3Backend),
    #[cfg(test)]
    Test(TestBackend),
}

#[cfg(test)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct TestBackend(pub usize);

#[cfg(test)]
impl Backend for TestBackend {
    async fn send_request(&self, _: Message, _: SocketAddr) -> anyhow::Result<DnsResponse> {
        panic!("just for test")
    }
}
