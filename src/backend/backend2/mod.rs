use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use hickory_proto::op::Message;
use hickory_proto::xfer::DnsResponse;

mod udp;

pub type DynBackend = Arc<dyn Backend + Send + Sync>;

#[async_trait(?Send)]
pub trait Backend: Debug {
    async fn send_request(&self, message: Message, src: SocketAddr) -> anyhow::Result<DnsResponse>;
}

#[async_trait(?Send)]
impl Backend for DynBackend {
    async fn send_request(&self, message: Message, src: SocketAddr) -> anyhow::Result<DnsResponse> {
        (**self).send_request(message, src).await
    }
}
