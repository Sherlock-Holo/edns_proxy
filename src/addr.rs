use std::net::SocketAddr;
use std::time::Duration;

use educe::Educe;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

#[derive(Educe, Eq, PartialEq)]
#[educe(Debug)]
pub enum BindAddr {
    Udp(SocketAddr),

    Tcp {
        addr: SocketAddr,
        timeout: Option<Duration>,
    },

    Https {
        addr: SocketAddr,
        #[educe(Debug(ignore))]
        certificate: Vec<CertificateDer<'static>>,
        #[educe(Debug(ignore))]
        private_key: PrivateKeyDer<'static>,
        domain: Option<String>,
        path: String,
        timeout: Option<Duration>,
    },

    Tls {
        addr: SocketAddr,
        #[educe(Debug(ignore))]
        certificate: Vec<CertificateDer<'static>>,
        #[educe(Debug(ignore))]
        private_key: PrivateKeyDer<'static>,
        timeout: Option<Duration>,
    },

    Quic {
        addr: SocketAddr,
        #[educe(Debug(ignore))]
        certificate: Vec<CertificateDer<'static>>,
        #[educe(Debug(ignore))]
        private_key: PrivateKeyDer<'static>,
        timeout: Option<Duration>,
    },

    H3 {
        addr: SocketAddr,
        #[educe(Debug(ignore))]
        certificate: Vec<CertificateDer<'static>>,
        #[educe(Debug(ignore))]
        private_key: PrivateKeyDer<'static>,
        // path: Option<String>,
        timeout: Option<Duration>,
    },
}
