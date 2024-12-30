use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io;
use std::io::BufReader;
use std::net::SocketAddr;

use clap::Parser;
use clap::builder::styling;
use futures_util::{FutureExt, select};
use hickory_proto::xfer::Protocol;
use hickory_resolver::Resolver;
use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use itertools::Itertools;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::signal::unix;
use tokio::signal::unix::SignalKind;
use tracing::level_filters::LevelFilter;
use tracing::{error, instrument, subscriber};
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{Registry, fmt};

use crate::addr::BindAddr;
use crate::backend::{Backends, H3Backend, HttpsBackend, QuicBackend, TlsBackend, UdpBackend};
use crate::config::{Bind, Config, HttpsBasedBind, Proxy, TcpBind, TlsBasedBind, UdpBind};

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
    init_tls_provider();

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
                let addrs = bootstrap_domain(&bootstrap, &tls_name, port).await?;
                let tls_backend = TlsBackend::new(addrs, tls_name)?;

                Backends::from(tls_backend)
            }

            config::Backend::Udp(config::UdpBackend { addr, timeout }) => {
                Backends::from(UdpBackend::new(
                    addr.into_iter().collect(),
                    timeout.map(|timeout| timeout.into_inner()),
                ))
            }

            config::Backend::Https(config::HttpsBasedBackend {
                host,
                path,
                port,
                bootstrap,
            }) => {
                let addrs = bootstrap_domain(&bootstrap, &host, port).await?;
                let https_backend = HttpsBackend::new(addrs, host, path)?;

                Backends::from(https_backend)
            }

            config::Backend::Quic(config::TlsBackend {
                tls_name,
                port,
                bootstrap,
            }) => {
                let addrs = bootstrap_domain(&bootstrap, &tls_name, port).await?;
                let quic_backend = QuicBackend::new(addrs, tls_name)?;

                Backends::from(quic_backend)
            }

            config::Backend::H3(config::HttpsBasedBackend {
                host,
                path,
                port,
                bootstrap,
            }) => {
                let addrs = bootstrap_domain(&bootstrap, &host, port).await?;
                let h3_backend = H3Backend::new(addrs, host, path)?;

                Backends::from(h3_backend)
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
    let async_resolver = Resolver::tokio(resolver_config, ResolverOpts::default());

    let mut addrs = match async_resolver.ipv4_lookup(domain).await {
        Err(err) if err.is_no_records_found() => HashSet::new(),
        Err(err) => return Err(err.into()),

        Ok(ipv4_lookup) => ipv4_lookup
            .into_iter()
            .map(|ip| SocketAddr::new(ip.0.into(), port))
            .collect(),
    };

    match async_resolver.ipv6_lookup(domain).await {
        Err(err) if err.is_no_records_found() => Ok(addrs),
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
    let bind_addr = match proxy.bind {
        Bind::Udp(UdpBind { bind_addr }) => BindAddr::Udp(bind_addr),

        Bind::Tcp(TcpBind { bind_addr, timeout }) => BindAddr::Tcp {
            addr: bind_addr,
            timeout: timeout.map(|timeout| timeout.into_inner()),
        },

        Bind::Https(HttpsBasedBind {
            bind_addr,
            bind_domain,
            bind_path,
            timeout,
            private_key,
            certificate,
        }) => {
            let certs = load_certificates_from_pem(&certificate)?;
            let private_key = load_private_key_from_file(&private_key)?;
            BindAddr::Https {
                addr: bind_addr,
                certificate: certs,
                private_key,
                domain: bind_domain,
                path: bind_path,
                timeout: timeout.map(|timeout| timeout.into_inner()),
            }
        }

        Bind::Tls(TlsBasedBind {
            bind_addr,
            bind_tls_name: _bind_tls_name,
            timeout,
            private_key,
            certificate,
        }) => {
            let certs = load_certificates_from_pem(&certificate)?;
            let private_key = load_private_key_from_file(&private_key)?;
            BindAddr::Tls {
                addr: bind_addr,
                certificate: certs,
                private_key,
                timeout: timeout.map(|timeout| timeout.into_inner()),
            }
        }

        Bind::Quic(TlsBasedBind {
            bind_addr,
            bind_tls_name: _bind_tls_name,
            timeout,
            private_key,
            certificate,
        }) => {
            let certs = load_certificates_from_pem(&certificate)?;
            let private_key = load_private_key_from_file(&private_key)?;
            BindAddr::Quic {
                addr: bind_addr,
                certificate: certs,
                private_key,
                timeout: timeout.map(|timeout| timeout.into_inner()),
            }
        }

        Bind::H3(HttpsBasedBind {
            bind_addr,
            bind_domain: _bind_domain,
            bind_path: _bind_path,
            timeout,
            private_key,
            certificate,
        }) => {
            let certs = load_certificates_from_pem(&certificate)?;
            let private_key = load_private_key_from_file(&private_key)?;
            BindAddr::H3 {
                addr: bind_addr,
                certificate: certs,
                private_key,
                timeout: timeout.map(|timeout| timeout.into_inner()),
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

fn init_tls_provider() {
    let provider = rustls::crypto::aws_lc_rs::default_provider();

    provider
        .install_default()
        .expect("install crypto provider should succeed");
}

fn load_certificates_from_pem(path: &str) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    rustls_pemfile::certs(&mut reader)
        .map(|res| res.map_err(anyhow::Error::from))
        .try_collect()
}

fn load_private_key_from_file(path: &str) -> anyhow::Result<PrivateKeyDer<'static>> {
    Ok(PrivateKeyDer::from_pem_file(path)?)
}
