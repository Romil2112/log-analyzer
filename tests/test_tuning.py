"""Tests for detection tuning features: allowlist YAML, config thresholds,
suppress-repeats, evaluate mode, replay-compare, and detection versioning."""
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import log_analyzer as la  # noqa: E402

# ── Helpers ───────────────────────────────────────────────────────────────────

def _events(rows):
    """Build a minimal event list from (ip, username, event_type) tuples."""
    base_time = datetime(2026, 7, 18, 10, 0, 0, tzinfo=timezone.utc)
    events = []
    for i, (ip, username, etype) in enumerate(rows):
        events.append({
            "log_type": "ssh",
            "event_type": etype,
            "event_time": base_time + timedelta(seconds=i),
            "source_ip": ip,
            "username": username,
            "port": 22,
            "raw_line": f"test line {i}",
        })
    return events


# ── Allowlist YAML ────────────────────────────────────────────────────────────

def test_allowlist_yaml_suppresses_exact_ip():
    events = _events([
        ("10.0.0.1", "admin", "failed_login"),
        ("10.0.0.2", "admin", "failed_login"),
    ])
    cfg = {"ips": ["10.0.0.1"], "usernames": [], "hostnames": []}
    filtered, suppressed = la.filter_events_allowlist_yaml(events, cfg)
    assert suppressed == 1
    assert all(e["source_ip"] != "10.0.0.1" for e in filtered)


def test_allowlist_yaml_suppresses_cidr():
    events = _events([
        ("192.168.1.100", "admin", "failed_login"),
        ("192.168.2.1",   "admin", "failed_login"),
        ("10.0.0.1",      "admin", "failed_login"),
    ])
    cfg = {"ips": ["192.168.0.0/16"], "usernames": [], "hostnames": []}
    filtered, suppressed = la.filter_events_allowlist_yaml(events, cfg)
    assert suppressed == 2
    assert len(filtered) == 1
    assert filtered[0]["source_ip"] == "10.0.0.1"


def test_allowlist_yaml_suppresses_username():
    events = _events([
        ("10.0.0.1", "monitoring",   "failed_login"),
        ("10.0.0.2", "realattacker", "failed_login"),
    ])
    cfg = {"ips": [], "usernames": ["monitoring"], "hostnames": []}
    filtered, suppressed = la.filter_events_allowlist_yaml(events, cfg)
    assert suppressed == 1
    assert all(e.get("username") != "monitoring" for e in filtered)


def test_allowlist_yaml_suppresses_hostname():
    events = [
        {
            "log_type": "ssh", "event_type": "failed_login",
            "event_time": datetime.now(timezone.utc),
            "source_ip": "1.2.3.4", "username": "a", "port": 22,
            "raw_line": "", "hostname": "scanner.corp",
        },
        {
            "log_type": "ssh", "event_type": "failed_login",
            "event_time": datetime.now(timezone.utc),
            "source_ip": "5.6.7.8", "username": "b", "port": 22,
            "raw_line": "",
        },
    ]
    cfg = {"ips": [], "usernames": [], "hostnames": ["scanner.corp"]}
    filtered, suppressed = la.filter_events_allowlist_yaml(events, cfg)
    assert suppressed == 1
    assert filtered[0]["source_ip"] == "5.6.7.8"


def test_allowlist_yaml_no_matches_changes_nothing():
    events = _events([
        ("10.0.0.1", "admin", "failed_login"),
        ("10.0.0.2", "admin", "failed_login"),
    ])
    cfg = {"ips": ["192.168.0.0/16"], "usernames": ["nobody"], "hostnames": []}
    filtered, suppressed = la.filter_events_allowlist_yaml(events, cfg)
    assert suppressed == 0
    assert len(filtered) == len(events)


def test_load_allowlist_yaml_reads_file(tmp_path):
    p = tmp_path / "al.yaml"
    p.write_text("ips: [10.0.0.1]\nusernames: [admin]\nhostnames: [host.example]\n")
    cfg = la.load_allowlist_yaml(str(p))
    assert cfg["ips"] == ["10.0.0.1"]
    assert cfg["usernames"] == ["admin"]
    assert cfg["hostnames"] == ["host.example"]


def test_load_allowlist_yaml_missing_file_exits(tmp_path):
    with pytest.raises(SystemExit):
        la.load_allowlist_yaml(str(tmp_path / "nonexistent.yaml"))


def test_allowlist_yaml_empty_file_returns_empty_lists(tmp_path):
    p = tmp_path / "empty.yaml"
    p.write_text("")
    cfg = la.load_allowlist_yaml(str(p))
    assert cfg == {"ips": [], "usernames": [], "hostnames": []}


# ── Per-rule threshold overrides ──────────────────────────────────────────────

def test_config_threshold_override_changes_detection_sensitivity():
    """A lower brute_force count threshold should trigger on fewer events."""
    events = _events([("10.0.0.1", "admin", "failed_login")] * 2)
    # With default threshold (5): no incident.
    incidents_default = la.detect_brute_force(events)
    assert len(incidents_default) == 0

    # Override threshold to 2 via config.
    cfg = {"thresholds": {"brute_force": {"count": 2, "window_seconds": 600}}}
    overrides = la.config_to_argparse_defaults(cfg)
    saved = la.BRUTE_FORCE_THRESHOLD
    try:
        la.BRUTE_FORCE_THRESHOLD = overrides["brute_force_threshold"]
        incidents_lowered = la.detect_brute_force(events)
        assert len(incidents_lowered) == 1
    finally:
        la.BRUTE_FORCE_THRESHOLD = saved


def test_config_to_argparse_defaults_correct_keys():
    cfg = {
        "thresholds": {
            "brute_force": {"count": 3, "window_seconds": 300},
            "port_scan":   {"count": 10, "window_seconds": 120},
            "flood_404":   {"count": 15, "window_seconds": 180},
        }
    }
    defaults = la.config_to_argparse_defaults(cfg)
    assert defaults["brute_force_threshold"] == 3
    assert defaults["brute_force_window"] == 5    # 300s / 60
    assert defaults["port_scan_threshold"] == 10
    assert defaults["port_scan_window"] == 2      # 120s / 60
    assert defaults["flood_404_threshold"] == 15
    assert defaults["flood_404_window"] == 3      # 180s / 60


def test_invalid_threshold_zero_exits():
    cfg = {"thresholds": {"brute_force": {"count": 0, "window_seconds": 300}}}
    with pytest.raises(SystemExit):
        la.config_to_argparse_defaults(cfg)


def test_invalid_threshold_non_integer_exits():
    cfg = {"thresholds": {"brute_force": {"count": "notanumber"}}}
    with pytest.raises(SystemExit):
        la.config_to_argparse_defaults(cfg)


def test_empty_thresholds_section_returns_empty_dict():
    assert la.config_to_argparse_defaults({}) == {}


def test_partial_thresholds_only_overrides_provided():
    cfg = {"thresholds": {"brute_force": {"count": 3}}}
    defaults = la.config_to_argparse_defaults(cfg)
    assert "brute_force_threshold" in defaults
    assert "port_scan_threshold" not in defaults


# ── Suppress-repeats (unit, no real DB) ──────────────────────────────────────

def test_suppress_recent_incidents_noop_when_window_zero():
    incidents = [{"incident_type": "brute_force", "source_ip": "1.2.3.4"}]
    remaining, count = la.suppress_recent_incidents(None, incidents, 0)
    assert remaining == incidents
    assert count == 0


def test_suppress_recent_incidents_noop_when_empty():
    remaining, count = la.suppress_recent_incidents(None, [], 5)
    assert remaining == []
    assert count == 0


# ── Evaluate mode ─────────────────────────────────────────────────────────────

def _make_incidents(ip_list):
    base = datetime(2026, 7, 18, 10, 0, 0, tzinfo=timezone.utc)
    return [
        {
            "incident_type": "brute_force",
            "source_ip": ip,
            "first_seen": base,
            "last_seen": base + timedelta(minutes=5),
            "event_count": 10,
            "severity": "HIGH",
            "mitre": {},
        }
        for ip in ip_list
    ]


def test_evaluate_detection_tp_fp_fn_tn():
    base = datetime(2026, 7, 18, 10, 0, 0, tzinfo=timezone.utc)
    incidents = _make_incidents(["1.1.1.1", "2.2.2.2"])
    ground_truth = [
        {"timestamp": base, "source_ip": "1.1.1.1", "label": "malicious"},  # TP
        {"timestamp": base, "source_ip": "2.2.2.2", "label": "benign"},     # FP
        {"timestamp": base, "source_ip": "3.3.3.3", "label": "malicious"},  # FN
        {"timestamp": base, "source_ip": "4.4.4.4", "label": "benign"},     # TN
    ]
    metrics = la.evaluate_detection(incidents, ground_truth, tolerance_minutes=5)
    assert metrics["true_positives"] == 1
    assert metrics["false_positives"] == 1
    assert metrics["false_negatives"] == 1
    assert metrics["true_negatives"] == 1
    assert metrics["precision"] == 0.5
    assert metrics["recall"] == 0.5
    assert "2.2.2.2" in metrics["fp_source_ips"]
    assert "3.3.3.3" in metrics["fn_source_ips"]


def test_evaluate_detection_perfect_precision_recall():
    base = datetime(2026, 7, 18, 10, 0, 0, tzinfo=timezone.utc)
    incidents = _make_incidents(["1.1.1.1", "2.2.2.2"])
    ground_truth = [
        {"timestamp": base, "source_ip": "1.1.1.1", "label": "malicious"},
        {"timestamp": base, "source_ip": "2.2.2.2", "label": "malicious"},
    ]
    metrics = la.evaluate_detection(incidents, ground_truth, tolerance_minutes=5)
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["f1"] == 1.0


def test_evaluate_detection_includes_detection_version():
    metrics = la.evaluate_detection([], [], 5)
    assert "detection_version" in metrics
    assert metrics["detection_version"] == la.DETECTION_RULES_VERSION


def test_evaluate_detection_empty_inputs_zero_metrics():
    metrics = la.evaluate_detection([], [], 5)
    assert metrics["true_positives"] == 0
    assert metrics["precision"] == 0.0
    assert metrics["f1"] == 0.0


def test_load_ground_truth_reads_csv(tmp_path):
    p = tmp_path / "gt.csv"
    p.write_text(
        "timestamp,source_ip,label\n"
        "2026-07-18T10:00:00Z,10.0.0.1,malicious\n"
        "2026-07-18T10:05:00Z,10.0.0.2,benign\n"
    )
    rows = la.load_ground_truth(str(p))
    assert len(rows) == 2
    assert rows[0]["label"] == "malicious"
    assert rows[1]["label"] == "benign"


def test_load_ground_truth_skips_invalid_label(tmp_path):
    p = tmp_path / "gt.csv"
    p.write_text(
        "timestamp,source_ip,label\n"
        "2026-07-18T10:00:00Z,10.0.0.1,unknown\n"
        "2026-07-18T10:05:00Z,10.0.0.2,benign\n"
    )
    rows = la.load_ground_truth(str(p))
    assert len(rows) == 1
    assert rows[0]["source_ip"] == "10.0.0.2"


def test_load_ground_truth_missing_file_exits(tmp_path):
    with pytest.raises(SystemExit):
        la.load_ground_truth(str(tmp_path / "nope.csv"))


# ── Replay compare ────────────────────────────────────────────────────────────

def test_replay_compare_runs_without_error(tmp_path, capsys):
    """Both configs with same thresholds should show 0 diff."""
    events = _events([("10.0.0.1", "admin", "failed_login")] * 10)

    config_a = tmp_path / "a.yaml"
    config_b = tmp_path / "b.yaml"
    config_a.write_text("thresholds:\n  brute_force:\n    count: 5\n    window_seconds: 600\n")
    config_b.write_text("thresholds:\n  brute_force:\n    count: 5\n    window_seconds: 600\n")

    # Should not raise.
    la.run_replay_compare(events, str(config_a), str(config_b))


def test_replay_incidents_key_set():
    incidents = [
        {"incident_type": "brute_force", "source_ip": "1.1.1.1"},
        {"incident_type": "port_scan",   "source_ip": "2.2.2.2"},
    ]
    keys = la._incidents_key_set(incidents)
    assert ("brute_force", "1.1.1.1") in keys
    assert ("port_scan",   "2.2.2.2") in keys


def test_replay_missing_config_exits(tmp_path):
    events = _events([("1.1.1.1", "x", "failed_login")])
    with pytest.raises(SystemExit):
        la.run_replay_compare(events, str(tmp_path / "a.yaml"), str(tmp_path / "b.yaml"))


# ── Detection version ─────────────────────────────────────────────────────────

def test_detection_version_constant_exists():
    assert hasattr(la, "DETECTION_RULES_VERSION")
    assert isinstance(la.DETECTION_RULES_VERSION, str)
    assert la.DETECTION_RULES_VERSION  # non-empty


def test_detection_version_in_soc_push_payload():
    import soc_push
    incident = {
        "incident_type": "brute_force",
        "source_ip": "1.2.3.4",
        "severity": "HIGH",
        "event_count": 10,
        "mitre": {},
    }
    payload = soc_push.incident_to_alert(incident, detection_version="1.1.0")
    assert payload.get("detection_version") == "1.1.0"


def test_detection_version_absent_when_not_passed():
    import soc_push
    incident = {
        "incident_type": "brute_force",
        "source_ip": "1.2.3.4",
        "severity": "HIGH",
        "event_count": 10,
        "mitre": {},
    }
    payload = soc_push.incident_to_alert(incident)
    assert "detection_version" not in payload


def test_detection_version_in_html_report(tmp_path):
    """The HTML report footer must contain the detection version string."""
    events = []
    incidents = []
    report_path = str(tmp_path / "report.html")
    la.generate_report(events, incidents, "test.log", report_path)
    content = Path(report_path).read_text()
    assert la.DETECTION_RULES_VERSION in content
