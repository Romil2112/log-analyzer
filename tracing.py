"""
Optional OpenTelemetry distributed tracing for the log-analyzer pipeline.

OTEL_AVAILABLE is True when opentelemetry-sdk and the OTLP gRPC exporter are
installed.  All public helpers are safe to call when OTEL_AVAILABLE is False —
get_tracer() returns a no-op that accepts the same call patterns as a real tracer.

Activate by installing:
    pip install opentelemetry-api opentelemetry-sdk opentelemetry-exporter-otlp-proto-grpc

Point at a Jaeger (or any OTLP) collector via:
    OTEL_EXPORTER_OTLP_ENDPOINT=localhost:4317   # gRPC, no TLS
"""
from __future__ import annotations

import logging
import os

try:
    from opentelemetry import trace
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter  # type: ignore[import]
    from opentelemetry.propagate import inject, set_global_textmap
    from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
    OTEL_AVAILABLE = True
except ImportError:
    OTEL_AVAILABLE = False

logger = logging.getLogger(__name__)
_SERVICE_NAME = "log-analyzer"


def init_tracer(endpoint: str | None = None) -> None:
    """Configure the global OTel TracerProvider.  No-op when OTel is not installed."""
    if not OTEL_AVAILABLE:
        return
    otlp = endpoint or os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")
    exporter = OTLPSpanExporter(endpoint=otlp, insecure=True)  # type: ignore[call-arg]
    provider = TracerProvider(resource=Resource.create({"service.name": _SERVICE_NAME}))
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    set_global_textmap(TraceContextTextMapPropagator())
    logger.debug("OTel tracer initialised — exporting to %s", otlp)


def get_tracer():
    """Return the log-analyzer tracer (or a no-op when OTel is absent)."""
    if not OTEL_AVAILABLE:
        return _NoOpTracer()
    return trace.get_tracer(_SERVICE_NAME)


def inject_http_headers(headers: dict) -> dict:
    """Inject W3C TraceContext into *headers* in place, then return it."""
    if OTEL_AVAILABLE:
        inject(headers)
    return headers


def inject_grpc_metadata(metadata: list) -> list:
    """Return *metadata* extended with W3C TraceContext key-value pairs."""
    if not OTEL_AVAILABLE:
        return metadata
    carrier: dict[str, str] = {}
    inject(carrier)
    return metadata + list(carrier.items())


class _NoOpSpan:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def set_attribute(self, key: str, value) -> None:
        pass

    def record_exception(self, exc: Exception) -> None:
        pass


class _NoOpTracer:
    def start_as_current_span(self, name: str, **kwargs):
        return _NoOpSpan()
