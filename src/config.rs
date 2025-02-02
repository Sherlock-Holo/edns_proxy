use std::collections::HashSet;
use std::fs::File;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroUsize;
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
    #[serde(flatten)]
    pub bind: Bind,
    pub backend: String,
    #[serde(default)]
    pub filter: Vec<Filter>,
    pub cache: Option<Cache>,
    #[serde(default)]
    pub route: Vec<Route>,
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
    #[serde(default = "HttpsBasedBind::default_bind_path")]
    pub bind_path: String,
    pub timeout: Option<Serde<Duration>>,
    pub private_key: String,
    pub certificate: String,
}

impl HttpsBasedBind {
    fn default_bind_path() -> String {
        "/dns-query".to_string()
    }
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

    Group(GroupBackend),
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapOrAddrs {
    Bootstrap(HashSet<SocketAddr>),
    Addr(HashSet<SocketAddr>),
}

#[derive(Debug, Deserialize, Clone, Eq, PartialEq, Hash)]
pub struct UdpBackend {
    pub addr: Vec<SocketAddr>,
    pub timeout: Option<Serde<Duration>>,
}

#[derive(Debug, Deserialize, Clone, Eq, PartialEq, Hash)]
pub struct GroupBackend {
    pub backends: Vec<GroupBackendInfo>,
}

#[derive(Debug, Deserialize, Clone, Eq, PartialEq, Hash)]
pub struct GroupBackendInfo {
    pub name: String,
    pub weight: usize,
}

#[derive(Debug, Deserialize)]
pub struct Route {
    #[serde(flatten)]
    pub route_type: RouteType,
    pub backend: String,
    #[serde(default)]
    pub filter: Vec<Filter>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RouteType {
    Normal { path: String },
    Dnsmasq { path: String },
}

#[derive(Debug, Deserialize)]
pub struct Cache {
    #[serde(default = "Cache::default_capacity")]
    pub capacity: NonZeroUsize,
    #[serde(default = "Cache::default_ipv4_fuzz_prefix")]
    pub ipv4_fuzz_prefix: u8,
    #[serde(default = "Cache::default_ipv6_fuzz_prefix")]
    pub ipv6_fuzz_prefix: u8,
}

impl Cache {
    const fn default_capacity() -> NonZeroUsize {
        NonZeroUsize::new(100).unwrap()
    }

    const fn default_ipv4_fuzz_prefix() -> u8 {
        16
    }

    const fn default_ipv6_fuzz_prefix() -> u8 {
        64
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Filter {
    EdnsClientSubnet {
        ipv4_prefix: Option<u8>,
        ipv6_prefix: Option<u8>,
    },

    StaticEdnsClientSubnet {
        ipv4: Option<StaticEdnsClientSubnetIpv4>,
        ipv6: Option<StaticEdnsClientSubnetIpv6>,
    },
}

#[derive(Debug, Deserialize)]
pub struct StaticEdnsClientSubnetIpv4 {
    pub ip: Ipv4Addr,
    pub prefix: u8,
}

#[derive(Debug, Deserialize)]
pub struct StaticEdnsClientSubnetIpv6 {
    pub ip: Ipv6Addr,
    pub prefix: u8,
}
