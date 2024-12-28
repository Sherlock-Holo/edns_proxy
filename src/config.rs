use std::fs::File;
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
pub enum BindAddrType {
    Udp,
    Tcp,
    Https,
    Tls,
    Quic,
    H3,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Hash, Clone)]
pub struct Backend {
    pub r#type: BackendType,
    pub addr: Vec<SocketAddr>,
    pub tls_name: Option<String>,
}

#[derive(Debug, Deserialize, Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Hash)]
pub enum BackendType {
    // Udp,
    // Tcp,
    // Https,
    Tls,
    // Quic,
    // H3,
}
