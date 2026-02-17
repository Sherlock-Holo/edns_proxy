use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io;
use std::io::{BufReader, IsTerminal};
use std::net::SocketAddr;

use clap::builder::styling;
use clap::{Parser, ValueEnum};
use futures_util::{FutureExt, select};
use hickory_proto::xfer::Protocol;
use hickory_resolver::Resolver;
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::name_server::TokioConnectionProvider;
use itertools::Itertools;
use opentelemetry::trace::TracerProvider;
use opentelemetry_sdk::trace::SdkTracerProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::signal::unix;
use tokio::signal::unix::SignalKind;
use tower::Layer;
use tower::layer::layer_fn;
use tracing::level_filters::LevelFilter;
use tracing::{error, instrument};
use tracing_log::LogTracer;
use tracing_subscriber::Registry;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::addr::BindAddr;
use crate::backend::{
    AdaptorBackend, Backend, DynBackend, Group, H3Builder, HttpsBuilder, QuicBuilder,
    StaticFileBuilder, TlsBuilder, UdpBuilder,
};
use crate::cache::Cache;
use crate::config::{
    BackendDetail, Bind, BootstrapOrAddrs, Config, Filter, HttpsBasedBind, RouteType, TcpBind,
    TlsBasedBind, UdpBind,
};
use crate::filter::ecs::EcsFilterLayer;
use crate::filter::static_ecs::StaticEcsFilterLayer;
use crate::layer::LayerBuilder;
use crate::route::{Route, dnsmasq::DnsmasqExt};

mod addr;
mod backend;
mod cache;
mod config;
mod filter;
mod layer;
mod proxy;
mod route;
mod utils;
mod wrr;

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

    #[clap(short, long, default_value = "info")]
    /// log level
    log_level: LogLevel,
}

#[derive(Debug, ValueEnum, Eq, PartialEq, Copy, Clone, Default)]
enum LogLevel {
    Off,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
}

impl From<LogLevel> for LevelFilter {
    fn from(value: LogLevel) -> Self {
        match value {
            LogLevel::Off => LevelFilter::OFF,
            LogLevel::Debug => LevelFilter::DEBUG,
            LogLevel::Info => LevelFilter::INFO,
            LogLevel::Warn => LevelFilter::WARN,
            LogLevel::Error => LevelFilter::ERROR,
        }
    }
}

pub async fn run() -> anyhow::Result<()> {
    let args = Args::parse();

    init_log(args.log_level);
    init_tls_provider();

    let config = Config::read(&args.config)?;

    let backends = collect_backends(config.backend).await?;

    let mut tasks = Vec::with_capacity(config.proxy.len());
    for proxy in config.proxy {
        let default_backend = backends
            .get(&proxy.backend)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("backend '{}' not found", proxy.backend))?;
        let default_backend = filter_backend(proxy.filter, default_backend);
        let bind_addr = create_bind_addr(proxy.bind)?;

        let mut route = Route::default();
        for route_config in proxy.route {
            let backend = backends
                .get(&route_config.backend)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("backend '{}' not found", route_config.backend))?;
            let backend = filter_backend(route_config.filter, backend);

            match route_config.route_type {
                RouteType::Normal { path } => {
                    let file = File::open(path)
                        .inspect_err(|err| error!(%err, "open normal file failed"))?;
                    route.import(file, backend)?;
                }

                RouteType::Dnsmasq { path } => {
                    let file = File::open(path)
                        .inspect_err(|err| error!(%err, "open dnsmasq file failed"))?;
                    route.import_from_dnsmasq(file, backend)?;
                }
            }
        }

        let task = proxy::start_proxy(
            bind_addr,
            route,
            default_backend,
            proxy.cache.map(|cache| {
                Cache::new(
                    cache.capacity,
                    cache.ipv4_fuzz_prefix,
                    cache.ipv6_fuzz_prefix,
                )
            }),
        )
        .await?;
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

async fn collect_backends(
    cfg_backends: Vec<config::Backend>,
) -> anyhow::Result<HashMap<String, DynBackend>> {
    let mut backend_groups = HashMap::new();
    let mut backends = HashMap::with_capacity(cfg_backends.len());
    for backend in cfg_backends {
        let attempts = backend.attempts();
        let name = backend.name;
        if backends.contains_key(&name) {
            return Err(anyhow::anyhow!("backend '{}' already exists", name));
        }

        let backend: DynBackend = match backend.backend_detail {
            BackendDetail::Tls(config::TlsBackend {
                tls_name,
                port,
                bootstrap_or_addrs,
            }) => {
                let addrs = match bootstrap_or_addrs {
                    BootstrapOrAddrs::Bootstrap(bootstrap) => {
                        bootstrap_domain(&bootstrap, &tls_name, port).await?
                    }
                    BootstrapOrAddrs::Addr(addrs) => addrs,
                };

                let tls_backend =
                    AdaptorBackend::new(TlsBuilder::new(addrs, tls_name)?, attempts).await?;

                Box::new(tls_backend)
            }

            BackendDetail::Udp(config::UdpBackend { addr, timeout }) => Box::new(
                AdaptorBackend::new(
                    UdpBuilder::new(
                        addr.into_iter().collect(),
                        timeout.map(|timeout| timeout.into_inner()),
                    ),
                    attempts,
                )
                .await?,
            ),

            BackendDetail::Https(config::HttpsBasedBackend {
                host,
                path,
                port,
                bootstrap_or_addrs,
            }) => {
                let addrs = match bootstrap_or_addrs {
                    BootstrapOrAddrs::Bootstrap(bootstrap) => {
                        bootstrap_domain(&bootstrap, &host, port).await?
                    }
                    BootstrapOrAddrs::Addr(addrs) => addrs,
                };

                let https_backend =
                    AdaptorBackend::new(HttpsBuilder::new(addrs, host, path)?, attempts).await?;

                Box::new(https_backend)
            }

            BackendDetail::Quic(config::TlsBackend {
                tls_name,
                port,
                bootstrap_or_addrs,
            }) => {
                let addrs = match bootstrap_or_addrs {
                    BootstrapOrAddrs::Bootstrap(bootstrap) => {
                        bootstrap_domain(&bootstrap, &tls_name, port).await?
                    }
                    BootstrapOrAddrs::Addr(addrs) => addrs,
                };
                let quic_backend =
                    AdaptorBackend::new(QuicBuilder::new(addrs, tls_name)?, attempts).await?;

                Box::new(quic_backend)
            }

            BackendDetail::H3(config::HttpsBasedBackend {
                host,
                path,
                port,
                bootstrap_or_addrs,
            }) => {
                let addrs = match bootstrap_or_addrs {
                    BootstrapOrAddrs::Bootstrap(bootstrap) => {
                        bootstrap_domain(&bootstrap, &host, port).await?
                    }
                    BootstrapOrAddrs::Addr(addrs) => addrs,
                };
                let h3_backend =
                    AdaptorBackend::new(H3Builder::new(addrs, host, path)?, attempts).await?;

                Box::new(h3_backend)
            }

            BackendDetail::StaticFile(static_config) => {
                let static_file_backend_config = static_config.load()?;
                let static_backend = AdaptorBackend::new(
                    StaticFileBuilder::new(static_file_backend_config)?,
                    attempts,
                )
                .await?;

                Box::new(static_backend)
            }

            BackendDetail::Group(backend_info_list) => {
                backend_groups.insert(name, backend_info_list);

                continue;
            }
        };

        backends.insert(name, backend);
    }

    for (name, group_backend) in backend_groups {
        let grouped_backends = group_backend
            .backends
            .into_iter()
            .map(|info| {
                backends
                    .get(&info.name)
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!("backend '{}' not found", info.name))
                    .map(|backend| (info.weight, backend))
            })
            .try_collect::<_, Vec<_>, _>()?;

        let group = Group::new(grouped_backends);

        backends.insert(name, Box::new(group));
    }

    Ok(backends)
}

fn filter_backend<B: Backend + Send + Sync + 'static>(
    filter: Vec<Filter>,
    backend: B,
) -> DynBackend {
    let mut layer_builder = LayerBuilder::new();
    for filter in filter {
        match filter {
            Filter::EdnsClientSubnet {
                ipv4_prefix,
                ipv6_prefix,
            } => {
                let layer = EcsFilterLayer::new(ipv4_prefix, ipv6_prefix);

                layer_builder = layer_builder.layer(layer_fn(move |backend| {
                    Box::new(layer.layer(backend)) as DynBackend
                }));
            }

            Filter::StaticEdnsClientSubnet { ipv4, ipv6 } => {
                let layer = StaticEcsFilterLayer::new(
                    ipv4.map(|cfg| (cfg.ip, cfg.prefix)),
                    ipv6.map(|cfg| (cfg.ip, cfg.prefix)),
                );

                layer_builder = layer_builder.layer(layer_fn(move |backend| {
                    Box::new(layer.layer(backend)) as DynBackend
                }));
            }
        }
    }

    layer_builder.build(backend)
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

    let async_resolver =
        Resolver::builder_with_config(resolver_config, TokioConnectionProvider::default()).build();

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

fn create_bind_addr(bind: Bind) -> anyhow::Result<BindAddr> {
    let bind_addr = match bind {
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

fn init_log(level: LogLevel) {
    if io::stderr().is_terminal() {
        init_console_log(level);
    } else {
        init_json_log(level);
    }

    let _ = LogTracer::init();
}

fn init_console_log(level: LogLevel) {
    let layer = tracing_subscriber::fmt::layer()
        .pretty()
        .with_line_number(true)
        .with_writer(io::stderr)
        .with_target(true);

    let targets = Targets::new().with_default(LevelFilter::TRACE);

    Registry::default()
        .with(targets)
        .with(layer)
        .with(LevelFilter::from(level))
        .init();
}

fn init_json_log(level: LogLevel) {
    let tracer = SdkTracerProvider::builder().build().tracer("edns_proxy");
    let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);

    let json = json_subscriber::layer()
        .with_writer(io::stderr)
        .with_current_span(false)
        .with_span_list(false)
        .with_line_number(true)
        .with_file(true)
        .with_target(true)
        .with_opentelemetry_ids(true);

    let targets = Targets::new().with_default(LevelFilter::TRACE);

    Registry::default()
        .with(targets)
        .with(telemetry)
        .with(LevelFilter::from(level))
        .with(json)
        .init();
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
