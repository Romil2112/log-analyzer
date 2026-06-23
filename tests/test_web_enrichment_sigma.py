"""Tests for the web-access-log parser, IP enrichment, and Sigma export."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import enrichment
import log_analyzer as la
import sigma_export

WEB_LOG = os.path.join(os.path.dirname(__file__), "..", "test_web_access.log")


# ── Web access-log parser → activates 404-flood detection ─────────────────────

def test_detect_log_format_recognizes_web():
    assert la.detect_log_format(WEB_LOG) == "web"


def test_parse_web_log_emits_http_404_events():
    events = la.parse_web_log(WEB_LOG)
    assert events, "parser returned no events"
    assert any(e["event_type"] == "http_404" for e in events)
    assert all(e["log_type"] == "apache_nginx" for e in events)
    # timestamps must be timezone-aware for downstream window math
    assert all(e["event_time"].tzinfo is not None for e in events)


def test_web_log_triggers_404_flood_detection():
    events = la.parse_web_log(WEB_LOG)
    incidents = la.detect_404_flood(events)
    assert len(incidents) >= 1
    assert incidents[0]["incident_type"] == "flood_404"
    assert incidents[0]["source_ip"] == "203.0.113.66"


# ── Threat-intel + GeoIP enrichment ───────────────────────────────────────────

def test_load_threat_intel_bundled_is_nonempty():
    nets = enrichment.load_threat_intel()
    assert len(nets) > 0


def test_is_known_bad_matches_listed_cidr_and_rejects_clean_ip():
    nets = enrichment.load_threat_intel()
    assert enrichment.is_known_bad("203.0.113.66", nets) is True   # in 203.0.113.0/24
    assert enrichment.is_known_bad("8.8.8.8", nets) is False
    assert enrichment.is_known_bad("not-an-ip", nets) is False


def test_geoip_degrades_gracefully_without_db():
    geo = enrichment.GeoIP(db_path=None)
    assert geo.enabled is False
    assert geo.country("8.8.8.8") == "Unknown"


def test_enrich_incidents_attaches_country_and_reputation():
    nets = enrichment.load_threat_intel()
    incidents = [{"incident_type": "flood_404", "source_ip": "203.0.113.66", "event_count": 40}]
    enrichment.enrich_incidents(incidents, nets, enrichment.GeoIP(None))
    assert incidents[0]["known_bad"] is True
    assert incidents[0]["country"] == "Unknown"


# ── Sigma export (detection-as-code) ──────────────────────────────────────────

def test_incident_to_sigma_has_required_fields():
    rule = sigma_export.incident_to_sigma("brute_force")
    assert rule is not None
    for key in ("title", "id", "logsource", "detection", "level", "tags"):
        assert key in rule
    assert any(t.startswith("attack.t") for t in rule["tags"])


def test_incident_to_sigma_unknown_type_returns_none():
    assert sigma_export.incident_to_sigma("nonsense") is None


def test_export_sigma_writes_one_file_per_type(tmp_path):
    incidents = [
        {"incident_type": "brute_force", "source_ip": "10.0.0.1", "event_count": 50},
        {"incident_type": "brute_force", "source_ip": "10.0.0.2", "event_count": 9},
        {"incident_type": "flood_404", "source_ip": "203.0.113.66", "event_count": 40},
    ]
    paths = sigma_export.export_sigma(incidents, str(tmp_path))
    assert len(paths) == 2  # deduped by type
    import yaml
    for p in paths:
        with open(p) as fh:
            loaded = yaml.safe_load(fh)
        assert "detection" in loaded and "title" in loaded
