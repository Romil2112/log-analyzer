"""Unit tests for Redis-backed suppress-repeats (redis.Redis mocked)."""
import os
import sys
from unittest.mock import MagicMock, call, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import argparse

from log_analyzer import _apply_suppress_repeats, _redis_suppress_repeats


def _incidents(*types_and_ips):
    return [
        {"incident_type": t, "source_ip": ip}
        for t, ip in types_and_ips
    ]


def _mock_redis_client(existing_keys=()):
    """Return a mocked redis.Redis client where existing_keys are 'already set'."""
    client = MagicMock()
    client.exists.side_effect = lambda key: key in existing_keys
    client.setex.return_value = True
    return client


# ---------------------------------------------------------------------------
# No-op paths
# ---------------------------------------------------------------------------

def test_empty_incidents_returns_zero_no_errors():
    ok, suppressed = _redis_suppress_repeats([], window_minutes=5, redis_url="redis://localhost")
    assert ok == []
    assert suppressed == 0


def test_zero_window_returns_all_through():
    incs = _incidents(("brute_force", "1.2.3.4"))
    ok, suppressed = _redis_suppress_repeats(incs, window_minutes=0, redis_url="redis://localhost")
    assert ok == incs
    assert suppressed == 0


# ---------------------------------------------------------------------------
# Happy path — new incidents pass through and get written to Redis
# ---------------------------------------------------------------------------

def test_new_incident_passes_through_and_sets_key():
    client = _mock_redis_client(existing_keys=set())
    with patch("redis.from_url", return_value=client):
        remaining, suppressed = _redis_suppress_repeats(
            _incidents(("brute_force", "10.0.0.1")),
            window_minutes=10,
            redis_url="redis://localhost",
        )
    assert len(remaining) == 1
    assert suppressed == 0
    client.setex.assert_called_once()
    key_used = client.setex.call_args[0][0]
    assert "brute_force" in key_used
    assert "10.0.0.1" in key_used


def test_setex_ttl_equals_window_minutes_times_sixty():
    client = _mock_redis_client()
    with patch("redis.from_url", return_value=client):
        _redis_suppress_repeats(
            _incidents(("port_scan", "5.5.5.5")),
            window_minutes=15,
            redis_url="redis://localhost",
        )
    _, ttl_arg, _ = client.setex.call_args[0]
    assert ttl_arg == 900  # 15 * 60


# ---------------------------------------------------------------------------
# Duplicate suppression
# ---------------------------------------------------------------------------

def test_duplicate_incident_is_suppressed():
    key = "log-analyzer:suppress:brute_force:10.0.0.1"
    client = _mock_redis_client(existing_keys={key})
    with patch("redis.from_url", return_value=client):
        remaining, suppressed = _redis_suppress_repeats(
            _incidents(("brute_force", "10.0.0.1")),
            window_minutes=5,
            redis_url="redis://localhost",
        )
    assert remaining == []
    assert suppressed == 1
    client.setex.assert_not_called()


def test_mixed_new_and_duplicate():
    key = "log-analyzer:suppress:brute_force:1.1.1.1"
    client = _mock_redis_client(existing_keys={key})
    with patch("redis.from_url", return_value=client):
        remaining, suppressed = _redis_suppress_repeats(
            _incidents(("brute_force", "1.1.1.1"), ("port_scan", "2.2.2.2")),
            window_minutes=5,
            redis_url="redis://localhost",
        )
    assert len(remaining) == 1
    assert remaining[0]["incident_type"] == "port_scan"
    assert suppressed == 1


# ---------------------------------------------------------------------------
# Safe fallback on errors
# ---------------------------------------------------------------------------

def test_redis_connection_error_passes_all_through():
    client = MagicMock()
    client.exists.side_effect = Exception("connection refused")
    with patch("redis.from_url", return_value=client):
        incs = _incidents(("brute_force", "1.2.3.4"))
        remaining, suppressed = _redis_suppress_repeats(incs, 5, "redis://localhost")
    assert remaining == incs
    assert suppressed == 0


def test_redis_import_error_passes_all_through():
    incs = _incidents(("brute_force", "1.2.3.4"))
    with patch.dict("sys.modules", {"redis": None}):
        remaining, suppressed = _redis_suppress_repeats(incs, 5, "redis://localhost")
    assert remaining == incs
    assert suppressed == 0


def test_client_close_called_after_run():
    client = _mock_redis_client()
    with patch("redis.from_url", return_value=client):
        _redis_suppress_repeats(
            _incidents(("brute_force", "1.2.3.4")), 5, "redis://localhost"
        )
    client.close.assert_called_once()


# ---------------------------------------------------------------------------
# _apply_suppress_repeats routing
# ---------------------------------------------------------------------------

def _args(suppress_repeats=5, no_db=False, dsn="postgresql://localhost/test"):
    ns = argparse.Namespace()
    ns.suppress_repeats = suppress_repeats
    ns.no_db = no_db
    ns.dsn = dsn
    return ns


def test_apply_no_db_no_redis_skips_with_warning(capsys):
    """Old behavior preserved: --no-db + REDIS_URL unset → skip, print warning."""
    incs = _incidents(("brute_force", "1.2.3.4"))
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("REDIS_URL", None)
        remaining, suppressed = _apply_suppress_repeats(incs, _args(no_db=True), None)
    assert remaining == incs
    assert suppressed == 0


def test_apply_no_db_with_redis_runs_redis_path():
    """New behavior: --no-db + REDIS_URL set → Redis path runs (no DB needed)."""
    client = _mock_redis_client(existing_keys=set())
    incs = _incidents(("port_scan", "10.0.0.2"))
    with patch("redis.from_url", return_value=client):
        with patch.dict(os.environ, {"REDIS_URL": "redis://localhost"}):
            remaining, suppressed = _apply_suppress_repeats(
                incs, _args(no_db=True), None
            )
    assert len(remaining) == 1
    assert suppressed == 0
    client.setex.assert_called_once()
