use std::collections::HashSet;
use std::fs::File;
use std::net::SocketAddr;
use std::time::Duration;

use humantime_serde::Serde;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub proxy: Vec<Proxy>,
    pub backend: Vec<Backend>,
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
    pub backend: String,
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

#[derive(Debug, Deserialize)]
pub struct Backend {
    pub name: String,
    #[serde(flatten)]
    pub backend_detail: BackendDetail,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BackendDetail {
    Tls(TlsBackend),
    Udp(UdpBackend),
    Https(HttpsBasedBackend),
    H3(HttpsBasedBackend),
    Quic(TlsBackend),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapOrAddrs {
    Bootstrap(HashSet<SocketAddr>),
    Addrs(HashSet<SocketAddr>),
}

#[derive(Debug, Deserialize)]
pub struct TlsBackend {
    pub tls_name: String,
    #[serde(default = "TlsBackend::default_port")]
    pub port: u16,
    #[serde(flatten)]
    pub bootstrap_or_addrs: BootstrapOrAddrs,
}

impl TlsBackend {
    const fn default_port() -> u16 {
        853
    }
}

#[derive(Debug, Deserialize)]
pub struct HttpsBasedBackend {
    pub host: String,
    #[serde(default = "HttpsBasedBackend::default_path")]
    pub path: String,
    #[serde(default = "HttpsBasedBackend::default_port")]
    pub port: u16,
    #[serde(flatten)]
    pub bootstrap_or_addrs: BootstrapOrAddrs,
}

impl HttpsBasedBackend {
    const fn default_port() -> u16 {
        443
    }

    fn default_path() -> String {
        "/dns-query".to_string()
    }
}

#[derive(Debug, Deserialize, Clone, Eq, PartialEq, Hash)]
pub struct UdpBackend {
    pub addr: Vec<SocketAddr>,
    pub timeout: Option<Serde<Duration>>,
}
