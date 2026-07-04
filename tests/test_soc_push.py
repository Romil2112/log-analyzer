"""Tests for pushing incidents to the SOC-Dashboard ingestion endpoint."""
import json
import os
import sys
from contextlib import contextmanager

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import soc_push


def test_incident_to_alert_maps_fields():
    inc = {
        "incident_type": "brute_force",
        "source_ip": "10.1.2.3",
        "event_count": 120,
        "severity": "HIGH",
        "mitre": {"id": "T1110.001", "tactic": "Credential Access"},
    }
    alert = soc_push.incident_to_alert(inc)
    assert alert["category"] == "brute_force"
    assert alert["severity"] == "HIGH"
    assert alert["source_ip"] == "10.1.2.3"
    assert "10.1.2.3" in alert["title"]
    assert "T1110.001" in alert["description"]


def test_incident_to_alert_maps_flood_to_anomaly_category():
    alert = soc_push.incident_to_alert(
        {"incident_type": "flood_404", "source_ip": "203.0.113.66", "event_count": 40}
    )
    assert alert["category"] == "anomaly"
    assert alert["severity"] == "LOW"  # default when not provided


def test_push_incidents_posts_each_and_counts_success(monkeypatch):
    posted = []

    class _Resp:
        status = 201
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def fake_urlopen(req, timeout=None):
        posted.append(json.loads(req.data.decode()))
        return _Resp()

    monkeypatch.setattr(soc_push.urllib.request, "urlopen", fake_urlopen)

    incidents = [
        {"incident_type": "brute_force", "source_ip": "10.0.0.1", "event_count": 50, "severity": "HIGH"},
        {"incident_type": "port_scan", "source_ip": "10.0.0.2", "event_count": 200, "severity": "MEDIUM"},
    ]
    ok, errors = soc_push.push_incidents(incidents, "http://localhost:8000/api/alerts")
    assert ok == 2
    assert errors == []
    assert len(posted) == 2
    assert posted[0]["category"] == "brute_force"
    assert posted[1]["category"] == "port_scan"  # port_scan maps to itself


def test_push_incidents_sends_api_key_header(monkeypatch):
    captured = []

    class _Resp:
        status = 201
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def fake_urlopen(req, timeout=None):
        # urllib normalises header names to Title-Case (X-api-key)
        captured.append(req.headers)
        return _Resp()

    monkeypatch.setattr(soc_push.urllib.request, "urlopen", fake_urlopen)
    inc = [{"incident_type": "brute_force", "source_ip": "1.2.3.4",
            "event_count": 5, "severity": "HIGH"}]

    soc_push.push_incidents(inc, "http://localhost:8000/api/alerts", api_key="s3cret")
    assert captured[0].get("X-api-key") == "s3cret"

    captured.clear()
    soc_push.push_incidents(inc, "http://localhost:8000/api/alerts")
    assert "X-api-key" not in captured[0]


def test_push_incidents_records_errors(monkeypatch):
    import urllib.error

    def boom(req, timeout=None):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(soc_push.urllib.request, "urlopen", boom)
    ok, errors = soc_push.push_incidents(
        [{"incident_type": "brute_force", "source_ip": "1.2.3.4", "event_count": 5}],
        "http://localhost:9/api/alerts",
    )
    assert ok == 0
    assert len(errors) == 1
