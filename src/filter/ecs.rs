use std::net::{IpAddr, SocketAddr};

use async_trait::async_trait;
use hickory_proto::op::{Edns, Message};
use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};
use hickory_proto::xfer::DnsResponse;
use tower::Layer;

use crate::backend::Backend;

#[derive(Debug, Copy, Clone, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct EcsFilterLayer {
    ipv4_prefix: Option<u8>,
    ipv6_prefix: Option<u8>,
}

impl EcsFilterLayer {
    pub fn new(ipv4_prefix: Option<u8>, ipv6_prefix: Option<u8>) -> Self {
        EcsFilterLayer {
            ipv4_prefix,
            ipv6_prefix,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct EcsFilter<B> {
    ipv4_prefix: Option<u8>,
    ipv6_prefix: Option<u8>,
    backend: B,
}

impl<B> Layer<B> for EcsFilterLayer {
    type Service = EcsFilter<B>;

    fn layer(&self, inner: B) -> Self::Service {
        EcsFilter {
            ipv4_prefix: self.ipv4_prefix,
            ipv6_prefix: self.ipv6_prefix,
            backend: inner,
        }
    }
}

#[async_trait]
impl<B: Backend + Sync + Send + 'static> Backend for EcsFilter<B> {
    async fn send_request(
        &self,
        mut message: Message,
        src: SocketAddr,
    ) -> anyhow::Result<DnsResponse> {
        let extensions = message.extensions_mut();
        let opt = extensions.get_or_insert_with(Edns::new).options_mut();
        if opt.get(EdnsCode::Subnet).is_none() {
            let src_ip = src.ip();
            let prefix = match src_ip {
                IpAddr::V4(_) => self.ipv4_prefix,
                IpAddr::V6(_) => self.ipv6_prefix,
            };

            if let Some(prefix) = prefix {
                opt.insert(EdnsOption::Subnet(ClientSubnet::new(src_ip, prefix, 0)));
            }
        }

        self.backend.send_request(message, src).await
    }
}
