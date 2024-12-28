use std::net::SocketAddr;
use std::time::Duration;

use rustls::{Certificate, PrivateKey};

#[derive(Debug, Eq, PartialEq)]
pub enum BindAddr {
    Udp(SocketAddr),
    Tcp {
        addr: SocketAddr,
        timeout: Option<Duration>,
    },
    Https {
        addr: SocketAddr,
        certificate: Vec<Certificate>,
        private_key: PrivateKey,
        timeout: Option<Duration>,
    },
    Tls {
        addr: SocketAddr,
        certificate: Vec<Certificate>,
        private_key: PrivateKey,
        timeout: Option<Duration>,
    },
    Quic {
        addr: SocketAddr,
        certificate: Vec<Certificate>,
        private_key: PrivateKey,
        timeout: Option<Duration>,
    },
    H3 {
        addr: SocketAddr,
        certificate: Vec<Certificate>,
        private_key: PrivateKey,
        timeout: Option<Duration>,
    },
}
