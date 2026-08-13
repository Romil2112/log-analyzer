"""Tests for the optional OpenTelemetry tracing module.

All tests run regardless of whether OTel packages are installed:
init_tracer / get_tracer / inject_* are each expected to be no-ops when
OTEL_AVAILABLE is False.
"""
from __future__ import annotations

import unittest.mock as mock

import pytest
import tracing
from tracing import (
    OTEL_AVAILABLE,
    get_tracer,
    inject_grpc_metadata,
    inject_http_headers,
    init_tracer,
)


def test_otel_available_is_bool():
    assert isinstance(OTEL_AVAILABLE, bool)


def test_module_exposes_expected_names():
    for name in ("OTEL_AVAILABLE", "init_tracer", "get_tracer",
                 "inject_http_headers", "inject_grpc_metadata"):
        assert hasattr(tracing, name)


def test_init_tracer_does_not_raise_with_unreachable_endpoint():
    init_tracer(endpoint="localhost:19999")


def test_init_tracer_does_not_raise_without_endpoint(monkeypatch):
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    init_tracer()


def test_get_tracer_returns_usable_object():
    t = get_tracer()
    assert hasattr(t, "start_as_current_span")


def test_get_tracer_span_context_manager():
    t = get_tracer()
    with t.start_as_current_span("test.span") as span:
        span.set_attribute("key", "value")


def test_inject_http_headers_returns_dict():
    headers: dict = {"Content-Type": "application/json"}
    result = inject_http_headers(headers)
    assert isinstance(result, dict)
    assert result is headers


def test_inject_http_headers_noop_when_unavailable(monkeypatch):
    monkeypatch.setattr(tracing, "OTEL_AVAILABLE", False)
    headers: dict = {}
    inject_http_headers(headers)
    assert headers == {}


def test_inject_grpc_metadata_returns_list():
    metadata = [("x-api-key", "test")]
    result = inject_grpc_metadata(metadata)
    assert isinstance(result, list)
    assert ("x-api-key", "test") in result


def test_inject_grpc_metadata_noop_when_unavailable(monkeypatch):
    monkeypatch.setattr(tracing, "OTEL_AVAILABLE", False)
    metadata = [("x-api-key", "test")]
    result = inject_grpc_metadata(metadata)
    assert result == metadata


def test_init_tracer_skips_exporter_when_sdk_disabled(monkeypatch):
    """init_tracer() must return before constructing any OTel objects when OTEL_SDK_DISABLED=true."""
    if not tracing.OTEL_AVAILABLE:
        pytest.skip("OTel not installed — early-return guard not exercisable")
    monkeypatch.setenv("OTEL_SDK_DISABLED", "true")
    with mock.patch.object(tracing, "OTLPSpanExporter") as mock_exporter:
        init_tracer()
        mock_exporter.assert_not_called()


def test_init_tracer_skips_exporter_case_insensitive(monkeypatch):
    """The OTEL_SDK_DISABLED guard must match regardless of case or surrounding whitespace."""
    if not tracing.OTEL_AVAILABLE:
        pytest.skip("OTel not installed")
    for value in ("TRUE", "True", " true ", "TRUE "):
        monkeypatch.setenv("OTEL_SDK_DISABLED", value)
        with mock.patch.object(tracing, "OTLPSpanExporter") as mock_exporter:
            init_tracer()
            mock_exporter.assert_not_called(), f"exporter constructed for OTEL_SDK_DISABLED={value!r}"
