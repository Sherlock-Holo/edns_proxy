use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufReader, IsTerminal};
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::thread;
use std::{env, io};

use async_notify::Notify;
use clap::builder::styling;
use clap::{Parser, ValueEnum};
use futures_util::{FutureExt, select};
use hickory_proto::xfer::Protocol;
use hickory_resolver::Resolver;
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::name_server::TokioConnectionProvider;
use itertools::Itertools;
use opentelemetry::KeyValue;
use opentelemetry::global;
use opentelemetry::trace::TracerProvider;
use opentelemetry_otlp::tonic_types::transport::ClientTlsConfig;
use opentelemetry_otlp::{SpanExporter, WithExportConfig, WithTonicConfig};
use opentelemetry_sdk::resource::Resource;
use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::runtime::Builder;
use tokio::signal::unix;
use tokio::signal::unix::SignalKind;
use tower::Layer;
use tower::layer::layer_fn;
use tracing::level_filters::LevelFilter;
use tracing::{Level, error, instrument};
use tracing_appender::non_blocking::{NonBlockingBuilder, WorkerGuard};
use tracing_log::LogTracer;
use tracing_subscriber::Registry;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::fmt::writer::MakeWriterExt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::addr::BindAddr;
use crate::backend::{
    AdaptorBackend, Backend, DynBackend, Group, H3Builder, HttpsBuilder, QuicBuilder,
    StaticFileBuilder, TlsBuilder, UdpBuilder,
};
use crate::cache::Cache;
use crate::config::{
    BackendDetail, Bind, BootstrapOrAddrs, Config, Filter, HttpsBasedBind, Proxy, RouteType,
    TcpBind, TlsBasedBind, UdpBind,
};
use crate::filter::ecs::EcsFilterLayer;
use crate::filter::static_ecs::StaticEcsFilterLayer;
use crate::layer::LayerBuilder;
use crate::proxy::{
    BindSocket, SocketType, create_tcp_listener_reuse_port, create_udp_socket_reuse_port,
    socket_type_for_bind, start_proxy_with_socket,
};
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
    #[clap(short, long, env)]
    /// Config path
    config: String,

    #[clap(short, long, env, default_value = "info")]
    /// Log level
    log_level: LogLevel,

    #[clap(long, env)]
    /// OpenTelemetry OTLP gRPC endpoint (e.g. http://apm.example.com:4317 for insecure, https://apm.example.com:443 for TLS)
    otel_endpoint: Option<String>,

    #[clap(long, env)]
    /// OpenTelemetry auth token (will be sent as Bearer token if not already prefixed)
    otel_token: Option<String>,

    #[clap(long, env, default_value = "0.01")]
    /// OpenTelemetry trace sampling rate (0.0-1.0, e.g. 0.01 for 1%)
    otel_sampling_rate: f64,
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

impl From<LogLevel> for Level {
    fn from(value: LogLevel) -> Self {
        match value {
            LogLevel::Off => Level::ERROR,
            LogLevel::Debug => Level::DEBUG,
            LogLevel::Info => Level::INFO,
            LogLevel::Warn => Level::WARN,
            LogLevel::Error => Level::ERROR,
        }
    }
}

pub async fn run() -> anyhow::Result<()> {
    let args = Args::parse();

    let _guard = init_log(
        args.log_level,
        args.otel_endpoint,
        args.otel_token,
        args.otel_sampling_rate,
    )?;
    init_tls_provider();

    let config = Config::read(&args.config)?;
    let backends = collect_backends(config.backend).await?;
    let (join_handles, shutdown_notify, threads) = spawn_proxy_workers(config.proxy, backends)?;

    signal_stop().await?;

    shutdown_notify.notify_n(NonZeroUsize::new(threads).unwrap());
    for handle in join_handles {
        if let Ok(Err(err)) = handle.join() {
            error!(%err, "worker thread failed");
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

type SpawnResult = (
    Vec<thread::JoinHandle<anyhow::Result<()>>>,
    Arc<Notify>,
    usize,
);

fn spawn_proxy_workers(
    proxy_configs: Vec<Proxy>,
    backends: HashMap<String, DynBackend>,
) -> anyhow::Result<SpawnResult> {
    let mut join_handles = Vec::new();
    let shutdown_notify = Arc::new(Notify::new());

    let mut threads = 0;
    for proxy in proxy_configs {
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

        let n = proxy.workers.count();
        threads += n;

        let route = Arc::new(route);
        let bind_addr = Arc::new(bind_addr);
        let cache_config = proxy
            .cache
            .map(|c| (c.capacity, c.ipv4_fuzz_prefix, c.ipv6_fuzz_prefix));
        let backend_clones: Vec<_> = (0..n).map(|_| default_backend.clone()).collect();

        for backend in backend_clones {
            let shutdown = Arc::clone(&shutdown_notify);
            let route = Arc::clone(&route);
            let bind_addr = Arc::clone(&bind_addr);

            let handle = thread::spawn(move || {
                let rt = Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap_or_else(|err| panic!("build runtime failed: {err}"));

                rt.block_on(async move {
                    let socket = match socket_type_for_bind(&bind_addr) {
                        SocketType::Udp => {
                            BindSocket::Udp(create_udp_socket_reuse_port(bind_addr.addr())?)
                        }
                        SocketType::Tcp => {
                            BindSocket::Tcp(create_tcp_listener_reuse_port(bind_addr.addr())?)
                        }
                    };

                    let cache = cache_config.map(|(cap, v4, v6)| Cache::new(cap, v4, v6));

                    let task =
                        start_proxy_with_socket(bind_addr, socket, route, backend, cache).await?;

                    task.run_until_shutdown(shutdown).await
                })
            });

            join_handles.push(handle);
        }
    }

    Ok((join_handles, shutdown_notify, threads))
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

struct LogShutdownGuard {
    _non_blocking_writer_guard: WorkerGuard,
}

impl Drop for LogShutdownGuard {
    fn drop(&mut self) {}
}

fn init_log(
    level: LogLevel,
    otel_endpoint: Option<String>,
    otel_token: Option<String>,
    otel_sampling_rate: f64,
) -> anyhow::Result<LogShutdownGuard> {
    let (writer, guard) = NonBlockingBuilder::default()
        .lossy(false)
        .buffered_lines_limit(512_000)
        .finish(io::stderr());

    let writer = writer.with_max_level(level.into());
    let otel_layer = match (otel_endpoint, otel_token) {
        (Some(endpoint), Some(token)) => {
            Some(make_otel_layer(endpoint, token, otel_sampling_rate)?)
        }
        _ => None,
    };

    if io::stderr().is_terminal() {
        init_console_log(writer, otel_layer);
    } else {
        init_json_log(writer, otel_layer);
    }

    let _ = LogTracer::init();

    Ok(LogShutdownGuard {
        _non_blocking_writer_guard: guard,
    })
}

fn init_console_log<L, W>(writer: W, otel_layer: L)
where
    L: tracing_subscriber::layer::Layer<Registry> + Send + Sync + 'static,
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    let layer = tracing_subscriber::fmt::layer()
        .pretty()
        .with_line_number(true)
        .with_writer(writer)
        .with_target(true);

    let targets = Targets::new().with_default(LevelFilter::TRACE);

    Registry::default()
        .with(otel_layer)
        .with(targets)
        .with(layer)
        .init();
}

fn init_json_log<L, W>(writer: W, otel_layer: L)
where
    L: tracing_subscriber::layer::Layer<Registry> + Send + Sync + 'static,
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    let json = json_subscriber::layer()
        .with_writer(writer)
        .with_current_span(false)
        .with_span_list(false)
        .with_line_number(true)
        .with_file(true)
        .with_target(true)
        .with_opentelemetry_ids(true);

    let targets = Targets::new().with_default(LevelFilter::TRACE);

    Registry::default()
        .with(otel_layer)
        .with(targets)
        .with(json)
        .init();
}

fn make_otel_layer(
    otel_endpoint: String,
    otel_token: String,
    sampling_rate: f64,
) -> anyhow::Result<impl tracing_subscriber::layer::Layer<Registry>> {
    let use_tls = otel_endpoint.starts_with("https://");

    let mut exporter_builder = SpanExporter::builder()
        .with_tonic()
        .with_endpoint(otel_endpoint);

    if use_tls {
        exporter_builder =
            exporter_builder.with_tls_config(ClientTlsConfig::new().with_enabled_roots());
    }

    let exporter = exporter_builder.build()?;

    let host_name = env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string());
    let resource = Resource::builder()
        .with_attributes([
            KeyValue::new("token", otel_token),
            KeyValue::new("service.name", "edns_proxy"),
            KeyValue::new("host.name", host_name),
        ])
        .build();

    let sampler = Sampler::TraceIdRatioBased(sampling_rate.clamp(0.0, 1.0));
    let tracer_provider = SdkTracerProvider::builder()
        .with_sampler(sampler)
        .with_batch_exporter(exporter)
        .with_resource(resource)
        .build();

    let tracer = tracer_provider.tracer("edns_proxy");
    global::set_tracer_provider(tracer_provider);

    Ok(tracing_opentelemetry::layer()
        .with_level(true)
        .with_tracer(tracer))
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
