use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io;
use std::io::BufReader;
use std::net::SocketAddr;

use clap::Parser;
use clap::builder::styling;
use futures_util::{FutureExt, select};
use hickory_resolver::AsyncResolver;
use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use hickory_resolver::error::ResolveErrorKind;
use itertools::Itertools;
use rustls::{Certificate, PrivateKey};
use tokio::signal::unix;
use tokio::signal::unix::SignalKind;
use tracing::level_filters::LevelFilter;
use tracing::{error, instrument, subscriber};
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{Registry, fmt};

use crate::addr::BindAddr;
use crate::backend::{Backends, TlsBackend};
use crate::config::{BindAddrType, Config, Proxy};

mod addr;
mod backend;
mod config;
mod proxy;

const STYLES: styling::Styles = styling::Styles::styled()
    .header(styling::AnsiColor::Green.on_default().bold())
    .usage(styling::AnsiColor::Green.on_default().bold())
    .literal(styling::AnsiColor::Blue.on_default().bold())
    .placeholder(styling::AnsiColor::Cyan.on_default());

#[derive(Debug, Parser)]
#[command(styles = STYLES)]
pub struct Args {
    #[clap(short, long)]
    /// config path
    config: String,

    #[clap(short, long)]
    /// enable debug log
    debug: bool,
}

pub async fn run() -> anyhow::Result<()> {
    let args = Args::parse();

    init_log(args.debug);

    let config = Config::read(&args.config)?;

    let proxies = config
        .proxy
        .into_iter()
        .map(|proxy| (proxy.backend.clone(), proxy))
        .fold(
            HashMap::<_, Vec<_>>::new(),
            |mut proxies, (backend, proxy)| {
                proxies.entry(backend).or_default().push(proxy);

                proxies
            },
        );

    let mut tasks = Vec::with_capacity(proxies.len());
    for (backend, proxies) in proxies {
        let backend = match backend {
            config::Backend::Tls(config::TlsBackend {
                tls_name,
                port,
                bootstrap,
            }) => {
                let addrs = bootstrap_domain(
                    &bootstrap,
                    &tls_name,
                    port.unwrap_or(config::TlsBackend::DEFAULT_PORT),
                )
                .await?;
                let tls_backend = TlsBackend::new(addrs, tls_name)?;

                Backends::from(tls_backend)
            }
        };

        let first_proxy = &proxies[0];
        let ipv4_prefix = first_proxy.ipv4_prefix;
        let ipv6_prefix = first_proxy.ipv6_prefix;

        let bind_addrs = proxies
            .into_iter()
            .map(create_bind_addr)
            .try_collect::<_, Vec<_>, _>()?;

        let task = proxy::start_proxy(bind_addrs, ipv4_prefix, ipv6_prefix, backend).await?;
        tasks.push(task);
    }

    signal_stop().await?;

    for mut task in tasks {
        if let Err(err) = task.stop().await {
            error!(%err, "stop proxy failed");
        }
    }

    Ok(())
}

#[instrument(ret, err)]
async fn bootstrap_domain(
    bootstrap_addr: &HashSet<SocketAddr>,
    domain: &str,
    port: u16,
) -> anyhow::Result<HashSet<SocketAddr>> {
    let mut resolver_config = ResolverConfig::new();
    for addr in bootstrap_addr {
        resolver_config.add_name_server(NameServerConfig::new(*addr, Protocol::Udp));
    }
    let async_resolver = AsyncResolver::tokio(resolver_config, ResolverOpts::default());

    let mut addrs = match async_resolver.ipv4_lookup(domain).await {
        Err(err) if matches!(err.kind(), ResolveErrorKind::NoRecordsFound { .. }) => HashSet::new(),
        Err(err) => return Err(err.into()),

        Ok(ipv4_lookup) => ipv4_lookup
            .into_iter()
            .map(|ip| SocketAddr::new(ip.0.into(), port))
            .collect(),
    };

    match async_resolver.ipv6_lookup(domain).await {
        Err(err) if matches!(err.kind(), ResolveErrorKind::NoRecordsFound { .. }) => Ok(addrs),
        Err(err) => Err(err.into()),

        Ok(ipv6_lookup) => {
            addrs.extend(
                ipv6_lookup
                    .into_iter()
                    .map(|ip| SocketAddr::new(ip.0.into(), port)),
            );

            Ok(addrs)
        }
    }
}

fn create_bind_addr(proxy: Proxy) -> anyhow::Result<BindAddr> {
    let bind_addr = match proxy.r#type {
        BindAddrType::Udp => BindAddr::Udp(proxy.bind_addr),

        BindAddrType::Tcp => BindAddr::Tcp {
            addr: proxy.bind_addr,
            timeout: proxy.timeout.map(|timeout| timeout.into_inner()),
        },

        BindAddrType::Https => {
            let cert = proxy
                .certificate
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("https bind type must set certificate path"))?;
            let private_key = proxy
                .private_key
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("https bind type must set private key path"))?;
            let certs = load_certificates_from_pem(cert)?;
            let private_key = load_private_key_from_file(private_key)?;
            BindAddr::Https {
                addr: proxy.bind_addr,
                certificate: certs,
                private_key,
                timeout: proxy.timeout.map(|timeout| timeout.into_inner()),
            }
        }

        BindAddrType::Tls => {
            let cert = proxy
                .certificate
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("tls bind type must set certificate path"))?;
            let private_key = proxy
                .private_key
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("tls bind type must set private key path"))?;
            let certs = load_certificates_from_pem(cert)?;
            let private_key = load_private_key_from_file(private_key)?;
            BindAddr::Tls {
                addr: proxy.bind_addr,
                certificate: certs,
                private_key,
                timeout: proxy.timeout.map(|timeout| timeout.into_inner()),
            }
        }

        BindAddrType::Quic => {
            let cert = proxy
                .certificate
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("quic bind type must set certificate path"))?;
            let private_key = proxy
                .private_key
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("quic bind type must set private key path"))?;
            let certs = load_certificates_from_pem(cert)?;
            let private_key = load_private_key_from_file(private_key)?;
            BindAddr::Quic {
                addr: proxy.bind_addr,
                certificate: certs,
                private_key,
                timeout: proxy.timeout.map(|timeout| timeout.into_inner()),
            }
        }

        BindAddrType::H3 => {
            let cert = proxy
                .certificate
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("h3 bind type must set certificate path"))?;
            let private_key = proxy
                .private_key
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("h3 bind type must set private key path"))?;
            let certs = load_certificates_from_pem(cert)?;
            let private_key = load_private_key_from_file(private_key)?;
            BindAddr::H3 {
                addr: proxy.bind_addr,
                certificate: certs,
                private_key,
                timeout: proxy.timeout.map(|timeout| timeout.into_inner()),
            }
        }
    };

    Ok(bind_addr)
}

async fn signal_stop() -> anyhow::Result<()> {
    let mut term = unix::signal(SignalKind::terminate())?;
    let mut interrupt = unix::signal(SignalKind::interrupt())?;

    select! {
        _ = term.recv().fuse() => {}
        _ = interrupt.recv().fuse() => {}
    }

    Ok(())
}

fn init_log(debug: bool) {
    let layer = fmt::layer()
        .pretty()
        .with_target(true)
        .with_writer(io::stderr);

    let level = if debug {
        LevelFilter::DEBUG
    } else {
        LevelFilter::INFO
    };

    let targets = Targets::new().with_default(LevelFilter::DEBUG);
    let layered = Registry::default().with(targets).with(layer).with(level);

    subscriber::set_global_default(layered).unwrap();
}

fn load_certificates_from_pem(path: &str) -> anyhow::Result<Vec<Certificate>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)?;

    Ok(certs.into_iter().map(Certificate).collect())
}

fn load_private_key_from_file(path: &str) -> anyhow::Result<PrivateKey> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut keys = rustls_pemfile::pkcs8_private_keys(&mut reader)?;

    let key = keys
        .pop()
        .ok_or_else(|| anyhow::anyhow!("no PKCS8-encoded private key found in {path}"))?;

    Ok(PrivateKey(key))
}
