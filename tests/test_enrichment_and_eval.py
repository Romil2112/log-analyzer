"""Coverage-focused tests for IP enrichment (enrichment.py) and the
evaluation harness's reporting / CLI paths (eval/eval_harness.py).

Hermetic: the GeoIP reader is a fake (no MaxMind DB or geoip2 package needed),
and every corpus is written to a temp dir, so nothing touches the network or a
database.
"""
from __future__ import annotations

import os
import sys
from types import SimpleNamespace

import pytest

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "eval"))

import eval_harness as eh  # noqa: E402

import enrichment  # noqa: E402

# ── enrichment: threat intel ──────────────────────────────────────────────────

def test_load_threat_intel_missing_file_returns_empty(tmp_path):
    assert enrichment.load_threat_intel(str(tmp_path / "nope.txt")) == []


def test_load_threat_intel_parses_and_skips_bad_lines(tmp_path):
    feed = tmp_path / "ti.txt"
    feed.write_text(
        "# comment only\n"
        "\n"
        "185.220.101.0/24   # tor exit range\n"
        "not-an-ip-at-all\n"
        "203.0.113.5\n",
        encoding="utf-8",
    )
    nets = enrichment.load_threat_intel(str(feed))
    assert len(nets) == 2  # the CIDR and the single host; bad line skipped
    assert enrichment.is_known_bad("185.220.101.10", nets)
    assert enrichment.is_known_bad("203.0.113.5", nets)
    assert not enrichment.is_known_bad("8.8.8.8", nets)
    assert not enrichment.is_known_bad("garbage", nets)


# ── enrichment: GeoIP (faked reader) ──────────────────────────────────────────

class _FakeReader:
    def __init__(self, path):
        self.path = path
        self.closed = False

    def country(self, ip):
        if ip == "boom":
            raise ValueError("lookup failed")
        iso = None if ip == "0.0.0.0" else "US"
        return SimpleNamespace(country=SimpleNamespace(iso_code=iso))

    def close(self):
        self.closed = True


def test_geoip_disabled_without_db():
    geo = enrichment.GeoIP(db_path=None)
    assert geo.enabled is False
    assert geo.country("8.8.8.8") == "Unknown"
    geo.close()  # no reader -> no-op, must not raise


def test_geoip_enabled_with_fake_reader(tmp_path, monkeypatch):
    db = tmp_path / "GeoLite2-Country.mmdb"
    db.write_text("stub", encoding="utf-8")
    monkeypatch.setattr(enrichment, "_GEOIP_LIB", True)
    monkeypatch.setattr(
        enrichment, "geoip2",
        SimpleNamespace(database=SimpleNamespace(Reader=_FakeReader)),
        raising=False,
    )
    geo = enrichment.GeoIP(db_path=str(db))
    assert geo.enabled is True
    assert geo.country("8.8.8.8") == "US"
    assert geo.country("0.0.0.0") == "Unknown"   # iso_code None -> Unknown
    assert geo.country("boom") == "Unknown"      # exception -> Unknown
    geo.close()
    assert geo._reader.closed is True


def test_geoip_reader_construction_failure_degrades(tmp_path, monkeypatch):
    db = tmp_path / "bad.mmdb"
    db.write_text("stub", encoding="utf-8")

    def _boom(_path):
        raise OSError("corrupt db")

    monkeypatch.setattr(enrichment, "_GEOIP_LIB", True)
    monkeypatch.setattr(
        enrichment, "geoip2",
        SimpleNamespace(database=SimpleNamespace(Reader=_boom)),
        raising=False,
    )
    geo = enrichment.GeoIP(db_path=str(db))
    assert geo.enabled is False  # construction failed -> reader stays None


def test_enrich_incidents_attaches_country_and_flag(tmp_path):
    feed = tmp_path / "ti.txt"
    feed.write_text("45.33.32.0/24\n", encoding="utf-8")
    nets = enrichment.load_threat_intel(str(feed))
    incidents = [
        {"source_ip": "45.33.32.156"},
        {"source_ip": "8.8.8.8"},
        {"source_ip": None},
    ]
    out = enrichment.enrich_incidents(incidents, nets, geo=None)
    assert out[0]["known_bad"] is True and out[0]["country"] == "Unknown"
    assert out[1]["known_bad"] is False
    assert out[2]["known_bad"] is False  # missing IP -> not bad, no crash


# ── eval_harness: format dispatch, evidence, config guard ─────────────────────

def test_load_events_web_and_windows(tmp_path):
    web = tmp_path / "access.log"
    web.write_text(
        '1.2.3.4 - - [01/Jan/2024:12:00:00 +0000] "GET /x HTTP/1.1" 404 1\n',
        encoding="utf-8",
    )
    assert eh.load_events(str(web))  # web branch

    csv_path = tmp_path / "win.csv"
    csv_path.write_text(
        "TimeCreated,EventID,IpAddress,TargetUserName,IpPort\n"
        "2024-01-01T12:00:00,4625,7.7.7.7,admin,4444\n",
        encoding="utf-8",
    )
    assert eh.load_events(str(csv_path))  # windows (else) branch


def test_per_ip_evidence_skips_events_without_ip():
    ev = eh._per_ip_evidence([
        {"source_ip": None, "event_type": "failed_login"},
        {"source_ip": "1.1.1.1", "event_type": "failed_login",
         "username": "root", "raw_line": "Failed password for invalid user root"},
        {"source_ip": "1.1.1.1", "event_type": "successful_login"},
    ])
    assert set(ev) == {"1.1.1.1"}
    assert ev["1.1.1.1"]["invalid_fails"] == 1
    assert ev["1.1.1.1"]["has_success"] is True


def test_predict_rejects_unknown_config():
    with pytest.raises(ValueError):
        eh.predict([], {}, "definitely-not-a-config")


# ── eval_harness: full evaluate -> report -> CLI, on a tiny inline corpus ─────

def _write_corpus(tmp_path):
    """A minimal SSH corpus: one brute-forcer (malicious, labeled) plus one
    benign IP that succeeds and is left unlabeled (exercises benign_default)."""
    lines = [
        f"Jan 01 12:{m:02d}:00 host sshd[{m}]: Failed password for user{m} "
        f"from 45.33.32.156 port 22 ssh2"
        for m in range(6)
    ]
    lines.append("Jan 01 12:10:00 host sshd[9]: Accepted password for bob "
                 "from 10.0.0.5 port 22 ssh2")
    log = tmp_path / "c.log"
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    labels = tmp_path / "c.labels.json"
    labels.write_text(
        '{"unit": "source_ip", "benign_default": true, "allowlist": [], '
        '"labels": {"45.33.32.156": {"class": "brute_force", "malicious": true}}}',
        encoding="utf-8",
    )
    return str(log), str(labels)


def test_ground_truth_uses_benign_default(tmp_path):
    log, labels = _write_corpus(tmp_path)
    events = eh.load_events(log)
    gt = eh.ground_truth(events, eh.load_labels(labels))
    assert gt["45.33.32.156"] is True     # labeled malicious
    assert gt["10.0.0.5"] is False        # unlabeled -> benign_default


def test_report_prints_all_sections(tmp_path, capsys):
    log, labels = _write_corpus(tmp_path)
    result = eh.evaluate(log, labels)
    assert result["n_malicious"] == 1
    eh.report(result)
    out = capsys.readouterr().out
    assert "LABELED EVALUATION" in out
    assert "CONFUSION MATRIX" in out
    assert "NET EFFECT" in out          # multi-config block shown when only=None
    assert "FALSE POSITIVES" in out and "FALSE NEGATIVES" in out


def test_report_single_config_omits_net_effect(tmp_path, capsys):
    log, labels = _write_corpus(tmp_path)
    result = eh.evaluate(log, labels)
    eh.report(result, only="rules")
    out = capsys.readouterr().out
    assert "CONFUSION MATRIX" in out
    assert "NET EFFECT" not in out      # net-effect block skipped for a single config


def test_main_text_output(tmp_path, monkeypatch, capsys):
    log, labels = _write_corpus(tmp_path)
    monkeypatch.setattr(sys, "argv",
                        ["eval_harness", log, "--labels", labels, "--config", "rules"])
    eh.main()
    assert "LABELED EVALUATION" in capsys.readouterr().out


def test_main_json_output(tmp_path, monkeypatch, capsys):
    log, labels = _write_corpus(tmp_path)
    monkeypatch.setattr(sys, "argv",
                        ["eval_harness", log, "--labels", labels, "--json"])
    eh.main()
    import json
    parsed = json.loads(capsys.readouterr().out)
    assert parsed["n_malicious"] == 1 and "configs" in parsed
