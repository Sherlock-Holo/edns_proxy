use std::collections::HashSet;
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::time::Duration;

use humantime_serde::Serde;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub proxy: Vec<Proxy>,
}

impl Config {
    pub fn read(path: &str) -> anyhow::Result<Self> {
        let file = File::open(path)?;

        Ok(serde_yaml::from_reader(file)?)
    }
}

#[derive(Debug, Deserialize)]
pub struct Proxy {
    pub ipv4_prefix: u8,
    pub ipv6_prefix: u8,
    pub r#type: BindAddrType,
    pub bind_addr: SocketAddr,
    pub timeout: Option<Serde<Duration>>,
    pub private_key: Option<String>,
    pub certificate: Option<String>,
    pub backend: Backend,
}

#[derive(Debug, Deserialize, Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Hash)]
#[serde(rename_all = "snake_case")]
pub enum BindAddrType {
    Udp,
    Tcp,
    Https,
    Tls,
    Quic,
    H3,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Hash, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Backend {
    Tls(TlsBackend),
    Https(HttpsBackend),
    Udp(UdpBackend),
}

#[derive(Debug, Deserialize, Clone)]
pub struct TlsBackend {
    pub tls_name: String,
    pub port: Option<u16>,
    pub bootstrap: HashSet<SocketAddr>,
}

impl TlsBackend {
    pub const DEFAULT_PORT: u16 = 853;
}

impl PartialEq for TlsBackend {
    fn eq(&self, other: &Self) -> bool {
        self.tls_name == other.tls_name && self.port == other.port
    }
}

impl Eq for TlsBackend {}

impl Hash for TlsBackend {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.tls_name.hash(state);
        self.port.hash(state);
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct HttpsBackend {
    pub host: String,
    pub port: Option<u16>,
    pub bootstrap: HashSet<SocketAddr>,
}

impl HttpsBackend {
    pub const DEFAULT_PORT: u16 = 443;
}

impl PartialEq for HttpsBackend {
    fn eq(&self, other: &Self) -> bool {
        self.host == other.host && self.port == other.port
    }
}

impl Eq for HttpsBackend {}

impl Hash for HttpsBackend {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.host.hash(state);
        self.port.hash(state);
    }
}

#[derive(Debug, Deserialize, Clone, Eq, PartialEq, Hash)]
pub struct UdpBackend {
    pub addr: Vec<SocketAddr>,
}
