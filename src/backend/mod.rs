use std::net::SocketAddr;

use enum_dispatch::enum_dispatch;
use hickory_proto::op::Message;
use hickory_proto::xfer::DnsResponse;

pub mod tls;
pub use tls::TlsBackend;

#[enum_dispatch]
pub trait Backend {
    async fn send_request(&self, message: Message, src: SocketAddr) -> anyhow::Result<DnsResponse>;
}

#[enum_dispatch(Backend)]
pub enum Backends {
    TlsBackend,
}
