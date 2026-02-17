use std::io::{BufRead, BufReader, Read};

use hickory_proto::rr::Name;
use tracing::instrument;

use crate::backend::Backend;
use crate::route::Route;

pub trait DnsmasqExt {
    fn import_from_dnsmasq<R, B>(&mut self, reader: R, backend: B) -> anyhow::Result<()>
    where
        R: Read,
        B: Backend + Clone + Send + Sync + 'static;
}

impl DnsmasqExt for Route {
    #[instrument(err, skip(reader))]
    fn import_from_dnsmasq<R, B>(&mut self, reader: R, backend: B) -> anyhow::Result<()>
    where
        R: Read,
        B: Backend + Clone + Send + Sync + 'static,
    {
        let lines = BufReader::new(reader).lines();

        for line in lines {
            let line = line?;
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if line.starts_with('#') {
                continue;
            }
            if !line.starts_with("server=") {
                return Err(anyhow::anyhow!("invalid dnsmasq rule: {line}"));
            }

            let domain = line
                .split('/')
                .nth(1)
                .ok_or_else(|| anyhow::anyhow!("invalid dnsmasq rule: {line}"))?;
            Name::from_utf8(domain)?;

            self.insert(domain.to_string(), backend.clone());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::net::SocketAddr;

    use async_trait::async_trait;
    use hickory_proto::op::Message;
    use hickory_proto::xfer::DnsResponse;

    use super::*;
    use crate::backend::DynBackend;

    #[derive(Debug, Copy, Clone, Eq, PartialEq)]
    struct TestBackend;

    #[async_trait]
    impl Backend for TestBackend {
        async fn send_request(&self, _: Message, _: SocketAddr) -> anyhow::Result<DnsResponse> {
            panic!("just for test")
        }

        fn to_dyn_clone(&self) -> DynBackend {
            Box::new(*self)
        }
    }

    #[test]
    fn test_import_from_dnsmasq() {
        const CONTENT: &str = r#"
        # comment
        server=/example.com/1.0.0.1
        server=/example.io/1.0.0.1
        "#;

        let reader = Cursor::new(CONTENT.as_bytes());
        let mut route = Route::default();

        route.import_from_dnsmasq(reader, TestBackend).unwrap();

        assert!(route.get_backend(&"example.com".parse().unwrap()).is_some());
    }
}
