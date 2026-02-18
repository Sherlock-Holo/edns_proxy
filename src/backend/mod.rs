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
mod static_file;
mod tls;
mod udp;
// mod tracing_dns_exchange;

pub use adaptor_backend::AdaptorBackend;
pub use group::Group;
pub use h3::H3Builder;
pub use https::HttpsBuilder;
pub use quic::QuicBuilder;
pub use static_file::StaticFileBuilder;
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

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Once;

    use hickory_proto::op::{Message, Query};
    use hickory_proto::rr::{Name, RData, RecordType};
    use hickory_proto::xfer::DnsResponse;

    pub fn create_query_message() -> Message {
        let mut message = Message::new();
        message.add_query(Query::query(
            Name::from_utf8("www.example.com").unwrap(),
            RecordType::A,
        ));
        message.set_recursion_desired(true);

        message
    }

    #[track_caller]
    pub fn check_dns_response(dns_response: &DnsResponse) {
        let answers = dns_response.answers();
        dbg!(answers);

        assert!(answers.iter().any(|record| {
            let data = record.data();
            match data {
                RData::A(ip) => ip.0 == Ipv4Addr::new(104, 18, 26, 120),
                _ => false,
            }
        }));
    }

    pub fn init_tls_provider() {
        static INSTALL_ONCE: Once = Once::new();

        INSTALL_ONCE.call_once(|| {
            let provider = rustls::crypto::aws_lc_rs::default_provider();

            provider
                .install_default()
                .expect("install crypto provider should succeed");
        })
    }
}
