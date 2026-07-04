"""Coverage-focused tests for the refactored helpers, parsers, detection,
privacy, the AI layer, and the ``main`` orchestration (both --no-db and a
mocked-DB path). Hermetic: no real network or database.
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest import mock

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import ai_scale
import ai_summary
import benchmark_ai
import log_analyzer as la

BASE = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _evt(ip, etype="failed_login", minutes=0, port=None, user="root"):
    return {
        "log_type": "ssh",
        "event_type": etype,
        "event_time": BASE + timedelta(minutes=minutes),
        "source_ip": ip,
        "username": user,
        "port": port,
        "raw_line": f"line from {ip}",
    }


def _brute_incident(ip="10.0.0.1", n=8):
    return {
        "incident_type": "brute_force",
        "source_ip": ip,
        "first_seen": BASE,
        "last_seen": BASE + timedelta(minutes=5),
        "event_count": n,
        "severity": "HIGH",
        "details": {"window_minutes": 10, "threshold": 5},
        "mitre": {"id": "T1110", "tactic": "Credential Access",
                  "name": "Brute Force", "url": "http://x"},
    }


# ── Pure report / chart helpers ───────────────────────────────────────────────

def test_report_pure_helpers():
    events = [_evt("1.1.1.1", minutes=0), _evt("1.1.1.1", minutes=1),
              _evt("2.2.2.2", "successful_login", minutes=2)]
    counts = la._count_event_types(events)
    assert counts["failed_login"] == 2
    top = la._top_failed_login_ips(events)
    assert top[0] == ("1.1.1.1", 2)

    incs = [_brute_incident("1.1.1.1")]
    hours = la._timeline_hours(incs)
    assert hours and la._bucket_count(incs, hours[0]) >= 1
    assert la._timeline_hours([]) == []

    assert isinstance(la._mitre_coverage_cards(incs), list)
    assert la._count_mitre_ids(incs)["T1110"] == 1

    bf, ps, f4 = la._split_incidents_by_type(
        [_brute_incident(), {"incident_type": "port_scan", "source_ip": "9.9.9.9",
                             "first_seen": BASE, "last_seen": BASE, "event_count": 20,
                             "severity": "HIGH", "details": {"unique_ports": [1, 2, 3]}}])
    assert len(bf) == 1 and len(ps) == 1 and f4 == []


def test_score_and_label_helpers():
    assert la._score_color(0.9) != la._score_color(0.1)
    assert "red" in la._ml_score_markup(0.9)
    assert "cyan" in la._ml_score_markup(0.0)
    assert "ef4444" in la._score_color(0.9)
    assert la._detection_labels(True)[0] == "Rule + ML"
    assert la._detection_labels(False)[0] == "ML Only"


def test_ml_and_incident_rows():
    scores = {"1.1.1.1": 0.9, "2.2.2.2": 0.1}
    rows = la._ml_anomaly_rows(scores, [{"source_ip": "1.1.1.1", "failed_logins": 5}],
                               rule_ips={"1.1.1.1"})
    assert rows and rows[0]["source_ip"] == "1.1.1.1"
    assert la._ml_chart_data({"a": 0.5}.items() and [("a", 0.5)])["ml_chart_labels"] == ["a"]
    vol = la._volume_chart_data({"failed_login": 2}, [("1.1.1.1", 2)], [], [], [])
    assert vol["event_type_labels"] == ["failed_login"]
    enriched = la._enrich_incident(_brute_incident(), scores)
    assert enriched["mitre_id"] == "T1110"
    assert la._duration_incident_rows([_brute_incident()], scores)[0]["duration"]
    ps = {"incident_type": "port_scan", "source_ip": "9.9.9.9", "first_seen": BASE,
          "last_seen": BASE + timedelta(minutes=1), "event_count": 20, "severity": "HIGH",
          "details": {"unique_ports": list(range(20))}}
    assert "..." in la._port_scan_rows([ps], scores)[0]["sample_ports"]


def test_generate_report_writes_file(tmp_path):
    report = tmp_path / "r.html"
    la.generate_report([_evt("1.1.1.1")], [_brute_incident()], "src.log", str(report),
                       anomaly_scores={"1.1.1.1": 0.9},
                       feature_rows=[{"source_ip": "1.1.1.1", "failed_logins": 5}])
    assert report.exists() and "Incident Report" in report.read_text()


# ── Parsers ───────────────────────────────────────────────────────────────────

def test_parse_ssh_and_web_and_format(tmp_path):
    ssh = tmp_path / "auth.log"
    ssh.write_text(
        "Jan 01 12:00:00 h sshd[1]: Failed password for root from 5.5.5.5 port 22 ssh2\n"
        "Jan 01 12:00:01 h sshd[2]: Accepted password for bob from 6.6.6.6 port 22 ssh2\n")
    events = la.parse_ssh_log(str(ssh))
    assert any(e["source_ip"] == "5.5.5.5" for e in events)
    assert la.detect_log_format(str(ssh)) == "ssh"

    web = tmp_path / "access.log"
    web.write_text('1.2.3.4 - - [01/Jan/2024:12:00:00 +0000] "GET /x HTTP/1.1" 404 1\n')
    wev = la.parse_web_log(str(web))
    assert wev[0]["event_type"] == "http_404"
    assert la.detect_log_format(str(web)) == "web"


def test_parse_windows_csv(tmp_path):
    csv_path = tmp_path / "win.csv"
    csv_path.write_text(
        "TimeCreated,EventID,IpAddress,TargetUserName,IpPort\n"
        "2024-01-01T12:00:00,4625,7.7.7.7,admin,4444\n"
        "2024-01-01T12:00:01,4624,8.8.8.8,bob,\n")
    events = la.parse_windows_csv(str(csv_path))
    assert events[0]["event_type"] == "failed_login"
    assert events[0]["port"] == 4444
    assert events[1]["port"] is None
    assert la.detect_log_format(str(csv_path)) == "windows"


def test_windows_row_helpers():
    cols = la._resolve_windows_columns(["TimeCreated", "EventID", "IpAddress"])
    assert cols["time"] == "TimeCreated"
    assert la._col_value({"a": " x "}, "a") == "x"
    assert la._col_value({}, None) is None
    assert la._parse_port("22") == 22
    assert la._parse_port("nope") is None
    assert la._parse_windows_row({"TimeCreated": ""}, cols) is None


# ── Detection ─────────────────────────────────────────────────────────────────

def test_detectors():
    bf_events = [_evt("3.3.3.3", minutes=m) for m in range(6)]
    assert la.detect_brute_force(bf_events)
    ps_events = [_evt("4.4.4.4", "connection", minutes=0, port=p) for p in range(25)]
    assert la.detect_port_scan(ps_events)
    f4_events = [_evt("5.5.5.5", "http_404", minutes=0) for _ in range(35)]
    assert la.detect_404_flood(f4_events)
    assert la._first_time_window([], timedelta(minutes=10), 5) is None


@given(st.integers(min_value=0, max_value=99999))
def test_parse_port_property(n):
    assert la._parse_port(str(n)) == n


@given(st.lists(st.integers(min_value=0, max_value=120), min_size=0, max_size=40))
@settings(max_examples=50)
def test_first_time_window_property(offsets):
    times = sorted(BASE + timedelta(minutes=o) for o in offsets)
    out = la._first_time_window(times, timedelta(minutes=10), 5)
    assert out is None or len(out) >= 5


# ── AnomalyDetector ───────────────────────────────────────────────────────────

@pytest.mark.skipif(not la.ML_AVAILABLE, reason="sklearn not installed")
def test_anomaly_detector():
    events = []
    for i in range(5):
        for m in range(10):
            events.append(_evt(f"10.0.0.{i}", minutes=m, port=1000 + m))
    det = la.AnomalyDetector()
    scores = det.fit_score(events)
    assert scores and all(0.0 <= s <= 1.0 for s in scores.values())
    rows = det.feature_rows(events)
    assert rows and "source_ip" in rows[0]
    assert la.AnomalyDetector._count_features(events[:10])[0] == 10
    assert la.AnomalyDetector._burst_score([BASE], 1) == 1.0


# ── Privacy transforms ────────────────────────────────────────────────────────

def test_privacy_transforms():
    events = [_evt("1.1.1.1", user="alice")]
    incs = [_brute_incident("1.1.1.1")]
    args = SimpleNamespace(pseudonymize=True, scrub_usernames=True, no_raw_lines=True)
    banners = la.apply_privacy_transforms(events, incs, args)
    assert len(banners) == 3
    assert events[0]["raw_line"] is None
    assert events[0]["source_ip"] != "1.1.1.1"
    assert events[0]["username"] != "alice"
    # no-op path
    assert la.apply_privacy_transforms([], [], SimpleNamespace(
        pseudonymize=False, scrub_usernames=False, no_raw_lines=False)) == []


# ── AI layer ──────────────────────────────────────────────────────────────────

def test_benchmark_ai_smoke(capsys):
    benchmark_ai.run(n=4, latency=0.001, concurrency=2)
    assert "benchmark" in capsys.readouterr().out


def test_ai_summary(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert ai_summary.ai_summary([], {}) is None

    fake_msg = SimpleNamespace(content=[SimpleNamespace(text="3-sentence summary")])
    fake_client = mock.MagicMock()
    fake_client.messages.create.return_value = fake_msg
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test")
    monkeypatch.setattr(ai_summary, "Anthropic", lambda api_key: fake_client)
    out = ai_summary.ai_summary([_brute_incident()], {})
    assert out == "3-sentence summary"


def test_ai_scale_metrics():
    results, metrics = ai_scale.summarize_batch(
        ["p1", "p2"], client=benchmark_ai.LatencyStub(0.001), max_concurrency=2)
    assert metrics.succeeded == 2 and metrics.cost_usd > 0
    assert metrics.p95_ms >= 0 and metrics.throughput_per_s >= 0
    assert ai_scale.looks_valid("a" * 30) and not ai_scale.looks_valid("")


# ── main() orchestration ──────────────────────────────────────────────────────

def _write_fixture(tmp_path):
    log = tmp_path / "auth.log"
    lines = []
    for i in range(4):
        for m in range(8):
            lines.append(
                f"Jan 01 12:{m:02d}:00 h sshd[{i}]: Failed password for root "
                f"from 10.0.0.{i} port {2000 + m} ssh2")
    log.write_text("\n".join(lines) + "\n")
    return log


def test_main_no_db(tmp_path, monkeypatch):
    log = _write_fixture(tmp_path)
    report = tmp_path / "out.html"
    monkeypatch.setattr(sys, "argv", ["log-analyzer", str(log), "--no-db",
                                      "--report", str(report)])
    la.main()
    assert report.exists()


def test_main_with_exports_and_mocked_db(tmp_path, monkeypatch):
    log = _write_fixture(tmp_path)
    report = tmp_path / "out.html"
    sigma_dir = tmp_path / "sigma"
    monkeypatch.setattr(la, "get_connection", lambda dsn: mock.MagicMock())
    monkeypatch.setattr(la.psycopg2.extras, "execute_batch", lambda *a, **k: None)
    monkeypatch.setattr(la, "init_schema", lambda conn: None)
    monkeypatch.setattr(la, "AI_SUMMARY_AVAILABLE", True)
    monkeypatch.setattr(la, "_ai_summary", lambda incs, scores: "exec summary")
    monkeypatch.setattr(la.soc_push, "push_incidents", lambda *a, **k: (1, []))
    monkeypatch.setattr(sys, "argv", [
        "log-analyzer", str(log), "--report", str(report),
        "--export-sigma", str(sigma_dir), "--no-enrich",
        "--push-soc", "http://localhost:8000/api/alerts", "--soc-api-key", "k",
        "--ai-summary", "--scrub-usernames",
    ])
    la.main()
    assert report.exists() and sigma_dir.exists()


def test_main_bad_file(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "argv", ["log-analyzer", str(tmp_path / "nope.log")])
    with pytest.raises(SystemExit):
        la.main()


def test_main_init_schema(monkeypatch):
    monkeypatch.setattr(la, "get_connection", lambda dsn: mock.MagicMock())
    monkeypatch.setattr(la, "init_schema", lambda conn: None)
    monkeypatch.setattr(sys, "argv", ["log-analyzer", "ignored", "--init-schema"])
    la.main()  # returns after schema init


# ── DB store helpers (mocked connection) ──────────────────────────────────────

def test_store_helpers_mocked(monkeypatch):
    monkeypatch.setattr(la.psycopg2.extras, "execute_batch", lambda *a, **k: None)
    conn = mock.MagicMock()
    la.store_events(conn, [_evt("1.1.1.1")], "src.log", fernet=None)
    la.store_incidents(conn, [_brute_incident()], fernet=None)
    conn.cursor.return_value.__enter__.return_value.rowcount = 3
    assert la.purge_old_records(conn, 30) == (3, 3)
    assert la.purge_old_records(conn, 0) == (0, 0)


# ── print tables (smoke) ──────────────────────────────────────────────────────

def test_print_tables_smoke():
    incs = [_brute_incident()]
    la.print_incident_table(incs)
    la.print_mitre_summary(incs)
    la.print_enrichment_summary(incs)
    la.print_ml_table({"10.0.0.1": 0.9}, {"10.0.0.1"}, 0.6)
