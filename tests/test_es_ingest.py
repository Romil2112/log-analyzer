"""Tests for Elasticsearch incident indexing (es_ingest.py)."""
import os
import sys
from unittest.mock import MagicMock, patch, call

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import es_ingest

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_SAMPLE_INCIDENTS = [
    {
        "incident_type": "brute_force",
        "source_ip": "198.51.100.5",
        "country": "CN",
        "severity": "HIGH",
        "event_count": 42,
        "known_bad": True,
        "mitre": {"id": "T1110.001", "name": "Brute Force: Password Guessing", "tactic": "Credential Access"},
    },
    {
        "incident_type": "port_scan",
        "source_ip": "203.0.113.10",
        "country": "RU",
        "severity": "MEDIUM",
        "event_count": 300,
        "known_bad": False,
        "mitre": {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
    },
]


def _make_client():
    """Return a mock ES client whose info() succeeds."""
    client = MagicMock()
    client.info.return_value = {"version": {"number": "8.17.2"}}
    client.indices.exists.return_value = False
    return client


# ---------------------------------------------------------------------------
# connect()
# ---------------------------------------------------------------------------

def test_connect_returns_none_when_package_missing(monkeypatch):
    """connect() must return None when elasticsearch is not installed."""
    import builtins
    real_import = builtins.__import__

    def _block(name, *args, **kwargs):
        if name == "elasticsearch":
            raise ImportError("no module")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _block)
    assert es_ingest.connect("http://localhost:9200") is None


def test_connect_returns_none_when_unreachable():
    """connect() must return None when the cluster is not reachable."""
    with patch("elasticsearch.Elasticsearch") as MockES:
        instance = MockES.return_value
        instance.info.side_effect = Exception("Connection refused")
        result = es_ingest.connect("http://localhost:9200")
    assert result is None


def test_connect_returns_client_on_success():
    """connect() returns the ES client when info() succeeds."""
    with patch("elasticsearch.Elasticsearch") as MockES:
        instance = MockES.return_value
        instance.info.return_value = {"version": {"number": "8.17.2"}}
        result = es_ingest.connect("http://localhost:9200")
    assert result is instance


# ---------------------------------------------------------------------------
# ensure_index()
# ---------------------------------------------------------------------------

def test_ensure_index_creates_when_absent():
    client = _make_client()
    client.indices.exists.return_value = False
    es_ingest.ensure_index(client, "test_idx")
    client.indices.create.assert_called_once()
    args, kwargs = client.indices.create.call_args
    assert kwargs.get("index") == "test_idx" or args[0] == "test_idx" or kwargs.get("index") == "test_idx"


def test_ensure_index_skips_when_exists():
    client = _make_client()
    client.indices.exists.return_value = True
    es_ingest.ensure_index(client, "test_idx")
    client.indices.create.assert_not_called()


def test_ensure_index_noop_on_none_client():
    es_ingest.ensure_index(None)  # must not raise


def test_ensure_index_tolerates_exception():
    client = _make_client()
    client.indices.exists.side_effect = Exception("cluster error")
    es_ingest.ensure_index(client)  # must not raise


# ---------------------------------------------------------------------------
# index_incidents()
# ---------------------------------------------------------------------------

def test_index_incidents_returns_zero_for_empty_list():
    client = _make_client()
    count = es_ingest.index_incidents(client, [], log_file="auth.log")
    assert count == 0


def test_index_incidents_returns_zero_for_none_client():
    count = es_ingest.index_incidents(None, _SAMPLE_INCIDENTS)
    assert count == 0


def test_index_incidents_indexes_all_on_success():
    with patch("elasticsearch.helpers.bulk") as mock_bulk:
        mock_bulk.return_value = (2, [])
        client = _make_client()
        count = es_ingest.index_incidents(client, _SAMPLE_INCIDENTS, log_file="auth.log")
    assert count == 2


def test_index_incidents_document_fields():
    """Verify the generated document contains all expected fields."""
    captured_docs = []

    def fake_bulk(client, actions, **kwargs):
        for doc in actions:
            captured_docs.append(doc)
        return (len(captured_docs), [])

    with patch("elasticsearch.helpers.bulk", side_effect=fake_bulk):
        client = _make_client()
        es_ingest.index_incidents(client, _SAMPLE_INCIDENTS[:1], log_file="/var/log/auth.log")

    assert len(captured_docs) == 1
    src = captured_docs[0]["_source"]
    assert src["incident_type"] == "brute_force"
    assert src["source_ip"] == "198.51.100.5"
    assert src["technique_id"] == "T1110.001"
    assert src["severity"] == "HIGH"
    assert src["known_bad"] is True
    assert src["log_file"] == "/var/log/auth.log"
    assert "indexed_at" in src


def test_index_incidents_handles_bulk_error_gracefully():
    from elasticsearch.helpers import BulkIndexError
    with patch("elasticsearch.helpers.bulk") as mock_bulk:
        mock_bulk.side_effect = BulkIndexError("1 document(s) failed", [{"index": {"error": "bad"}}])
        client = _make_client()
        count = es_ingest.index_incidents(client, _SAMPLE_INCIDENTS)
    assert count >= 0  # must not raise


def test_index_incidents_handles_generic_exception():
    with patch("elasticsearch.helpers.bulk", side_effect=Exception("network down")):
        client = _make_client()
        count = es_ingest.index_incidents(client, _SAMPLE_INCIDENTS)
    assert count == 0


# ---------------------------------------------------------------------------
# CLI flag wiring (build_parser sanity check)
# ---------------------------------------------------------------------------

def test_cli_flag_es_host_parsed():
    """--es-host must be a recognized argument in the log-analyzer CLI."""
    import log_analyzer
    parser = log_analyzer.build_parser()
    args = parser.parse_args(["dummy.log", "--es-host", "http://localhost:9200"])
    assert args.es_host == "http://localhost:9200"


def test_cli_flag_es_host_defaults_to_none():
    import log_analyzer
    parser = log_analyzer.build_parser()
    args = parser.parse_args(["dummy.log"])
    assert args.es_host is None
