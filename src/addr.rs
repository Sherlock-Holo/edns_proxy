use std::net::SocketAddr;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};

#[derive(Debug, Eq, PartialEq)]
pub enum BindAddr {
    Udp(SocketAddr),
    Tcp {
        addr: SocketAddr,
        timeout: Option<Duration>,
    },
    Https {
        addr: SocketAddr,
        certificate: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
        domain: Option<String>,
        path: Option<String>,
        timeout: Option<Duration>,
    },
    Tls {
        addr: SocketAddr,
        certificate: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
        timeout: Option<Duration>,
    },
    Quic {
        addr: SocketAddr,
        certificate: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
        timeout: Option<Duration>,
    },
    H3 {
        addr: SocketAddr,
        certificate: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
        // path: Option<String>,
        timeout: Option<Duration>,
    },
}
