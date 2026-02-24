use std::net::SocketAddr;

use futures_util::FutureExt;
use futures_util::future::LocalBoxFuture;
use hickory_proto26::op::{DnsResponse, Message};

mod https;
mod quic;
mod tls;
mod udp;

pub trait Backend {
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

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use hickory_proto26::op::{DnsResponse, Message, Query};
    use hickory_proto26::rr::{Name, RData, RecordType};

    pub use super::super::tests::init_tls_provider;

    pub fn create_query_message() -> Message {
        let mut message = Message::query();
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
}
