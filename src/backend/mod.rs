use std::net::SocketAddr;

use enum_dispatch::enum_dispatch;
use hickory_proto::op::Message;
use hickory_proto::xfer::DnsResponse;

mod https;
mod tls;
mod udp;

pub use https::HttpsBackend;
pub use tls::TlsBackend;
pub use udp::UdpBackend;

#[enum_dispatch]
pub trait Backend {
    async fn send_request(&self, message: Message, src: SocketAddr) -> anyhow::Result<DnsResponse>;
}

#[enum_dispatch(Backend)]
#[derive(Debug, Clone)]
pub enum Backends {
    Tls(TlsBackend),
    Https(HttpsBackend),
    Udp(UdpBackend),
}
