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
    #[serde(flatten)]
    pub bind: Bind,
    pub backend: Backend,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Bind {
    Udp(UdpBind),
    Tcp(TcpBind),
    Tls(TlsBasedBind),
    Quic(TlsBasedBind),
    Https(HttpsBasedBind),
    H3(HttpsBasedBind),
}

#[derive(Debug, Deserialize)]
pub struct UdpBind {
    pub bind_addr: SocketAddr,
}

#[derive(Debug, Deserialize)]
pub struct TcpBind {
    pub bind_addr: SocketAddr,
    pub timeout: Option<Serde<Duration>>,
}

#[derive(Debug, Deserialize)]
pub struct HttpsBasedBind {
    pub bind_addr: SocketAddr,
    pub bind_domain: Option<String>,
    pub bind_path: Option<String>,
    pub timeout: Option<Serde<Duration>>,
    pub private_key: String,
    pub certificate: String,
}

#[derive(Debug, Deserialize)]
pub struct TlsBasedBind {
    pub bind_addr: SocketAddr,
    pub bind_tls_name: Option<String>,
    pub timeout: Option<Serde<Duration>>,
    pub private_key: String,
    pub certificate: String,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Hash, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Backend {
    Tls(TlsBackend),
    Udp(UdpBackend),
    Https(HttpsBasedBackend),
    H3(HttpsBasedBackend),
    Quic(TlsBackend),
}

#[derive(Debug, Deserialize, Clone)]
pub struct TlsBackend {
    pub tls_name: String,
    #[serde(default = "TlsBackend::default_port")]
    pub port: u16,
    pub bootstrap: HashSet<SocketAddr>,
}

impl TlsBackend {
    const fn default_port() -> u16 {
        853
    }
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
pub struct HttpsBasedBackend {
    pub host: String,
    #[serde(default = "HttpsBasedBackend::default_path")]
    pub path: String,
    #[serde(default = "HttpsBasedBackend::default_port")]
    pub port: u16,
    pub bootstrap: HashSet<SocketAddr>,
}

impl HttpsBasedBackend {
    const fn default_port() -> u16 {
        443
    }

    fn default_path() -> String {
        "/dns-query".to_string()
    }
}

impl PartialEq for HttpsBasedBackend {
    fn eq(&self, other: &Self) -> bool {
        self.host == other.host && self.port == other.port
    }
}

impl Eq for HttpsBasedBackend {}

impl Hash for HttpsBasedBackend {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.host.hash(state);
        self.port.hash(state);
    }
}

#[derive(Debug, Deserialize, Clone, Eq, PartialEq, Hash)]
pub struct UdpBackend {
    pub addr: Vec<SocketAddr>,
    pub timeout: Option<Serde<Duration>>,
}
