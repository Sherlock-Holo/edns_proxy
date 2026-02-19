use std::io::IsTerminal;
use std::{env, io};

use clap::ValueEnum;
use opentelemetry::KeyValue;
use opentelemetry::global;
use opentelemetry::trace::TracerProvider;
use opentelemetry_otlp::tonic_types::transport::ClientTlsConfig;
use opentelemetry_otlp::{SpanExporter, WithExportConfig, WithTonicConfig};
use opentelemetry_sdk::resource::Resource;
use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider};
use tracing::Event;
use tracing::level_filters::LevelFilter;
use tracing_appender::non_blocking::{NonBlockingBuilder, WorkerGuard};
use tracing_log::LogTracer;
use tracing_subscriber::Registry;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::fmt::FmtContext;
use tracing_subscriber::fmt::format::{Compact, Format, FormatEvent, FormatFields, Pretty, Writer};
use tracing_subscriber::fmt::time::SystemTime;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Debug, ValueEnum, Eq, PartialEq, Copy, Clone, Default)]
#[value(rename_all = "lower")]
pub enum LogLevel {
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

impl From<LogLevel> for tracing::Level {
    fn from(value: LogLevel) -> Self {
        match value {
            LogLevel::Off => tracing::Level::ERROR,
            LogLevel::Debug => tracing::Level::DEBUG,
            LogLevel::Info => tracing::Level::INFO,
            LogLevel::Warn => tracing::Level::WARN,
            LogLevel::Error => tracing::Level::ERROR,
        }
    }
}

pub struct LogShutdownGuard {
    _non_blocking_writer_guard: WorkerGuard,
}

impl Drop for LogShutdownGuard {
    fn drop(&mut self) {}
}

/// Wraps a FormatEvent to prefix each log line with OpenTelemetry trace_id and span_id when valid.
struct OtelTraceIdFormat<F> {
    inner: F,
}

impl<F> OtelTraceIdFormat<F> {
    fn new(inner: F) -> Self {
        Self { inner }
    }
}

impl<S, N, F> FormatEvent<S, N> for OtelTraceIdFormat<F>
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
    F: FormatEvent<S, N>,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> std::fmt::Result {
        use opentelemetry::trace::TraceContextExt;
        let otel_ctx = opentelemetry::Context::current();
        let span_ref = otel_ctx.span();
        let span_context = span_ref.span_context();
        if span_context.is_valid() {
            write!(
                &mut writer,
                "[trace_id={} span_id={}] ",
                span_context.trace_id(),
                span_context.span_id()
            )?;
        }
        self.inner.format_event(ctx, writer, event)
    }
}

/// Unifies Format<Pretty, _> and Format<Compact, _> into one type for conditional selection.
enum PrettyOrCompact {
    Pretty(Format<Pretty, SystemTime>),
    Compact(Format<Compact, SystemTime>),
}

impl<S, N> FormatEvent<S, N> for PrettyOrCompact
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    #[inline]
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        writer: Writer<'_>,
        event: &Event<'_>,
    ) -> std::fmt::Result {
        match self {
            PrettyOrCompact::Pretty(f) => f.format_event(ctx, writer, event),
            PrettyOrCompact::Compact(f) => f.format_event(ctx, writer, event),
        }
    }
}

pub fn init_log(
    level: LogLevel,
    otel_endpoint: Option<String>,
    otel_token: Option<String>,
    otel_sampling_rate: f64,
) -> anyhow::Result<LogShutdownGuard> {
    let (writer, guard) = NonBlockingBuilder::default()
        .lossy(false)
        .buffered_lines_limit(512_000)
        .finish(io::stderr());

    let otel_layer = match (otel_endpoint, otel_token) {
        (Some(endpoint), Some(token)) => {
            Some(make_otel_layer(endpoint, token, otel_sampling_rate)?)
        }
        _ => None,
    };

    let formatter: PrettyOrCompact = if io::stderr().is_terminal() {
        PrettyOrCompact::Pretty(
            tracing_subscriber::fmt::format()
                .pretty()
                .with_line_number(true)
                .with_target(true),
        )
    } else {
        PrettyOrCompact::Compact(
            tracing_subscriber::fmt::format()
                .compact()
                .with_line_number(true)
                .with_target(true),
        )
    };

    let fmt_layer = tracing_subscriber::fmt::layer()
        .event_format(OtelTraceIdFormat::new(formatter))
        .with_writer(writer);

    let targets = Targets::new().with_default(LevelFilter::TRACE);

    Registry::default()
        .with(otel_layer)
        .with(LevelFilter::from(level))
        .with(targets)
        .with(fmt_layer)
        .init();

    let _ = LogTracer::init();

    Ok(LogShutdownGuard {
        _non_blocking_writer_guard: guard,
    })
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
