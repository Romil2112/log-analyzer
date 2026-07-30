"""Tests for PyTorchAnomalyDetector.

All tests that exercise the autoencoder itself are skipped when torch is not
installed (PYTORCH_AVAILABLE is False), matching the graceful-degradation
pattern used across this codebase.
"""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

import pytorch_detector
from pytorch_detector import PYTORCH_AVAILABLE, PyTorchAnomalyDetector


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_events(n_ips: int = 5, events_per_ip: int = 20) -> list[dict]:
    """Generate synthetic log events with predictable per-IP behaviour."""
    base = datetime(2024, 1, 1, 10, 0, 0)
    events = []
    for ip_idx in range(n_ips):
        ip = f"10.0.0.{ip_idx + 1}"
        for j in range(events_per_ip):
            events.append({
                "source_ip": ip,
                "event_type": "failed_login" if j % 3 == 0 else "ssh_connection",
                "event_time": base + timedelta(seconds=j * 30 + ip_idx * 600),
                "port": 22 + (j % 3),
                "username": f"user{j % 4}",
            })
    return events


def _make_outlier_events(base_events: list[dict]) -> list[dict]:
    """Add a clearly anomalous IP: extreme port diversity, all failures, high rate."""
    base = datetime(2024, 1, 1, 10, 0, 0)
    outlier = []
    for j in range(200):
        outlier.append({
            "source_ip": "192.168.1.99",
            "event_type": "failed_login",
            "event_time": base + timedelta(seconds=j),
            "port": 1000 + j,
            "username": f"root{j}",
        })
    return base_events + outlier


# ---------------------------------------------------------------------------
# Flag / availability tests (always run)
# ---------------------------------------------------------------------------

def test_pytorch_available_flag_is_bool():
    assert isinstance(PYTORCH_AVAILABLE, bool)


def test_module_has_expected_names():
    assert hasattr(pytorch_detector, "PYTORCH_AVAILABLE")
    assert hasattr(pytorch_detector, "PyTorchAnomalyDetector")
    assert hasattr(pytorch_detector, "FEATURES")


def test_features_list_has_eight_entries():
    assert len(pytorch_detector.FEATURES) == 8


def test_fit_score_returns_empty_when_unavailable(monkeypatch):
    monkeypatch.setattr(pytorch_detector, "PYTORCH_AVAILABLE", False)
    det = PyTorchAnomalyDetector()
    assert det.fit_score(_make_events()) == {}


def test_fit_score_returns_empty_for_too_few_ips():
    """< 3 unique IPs → empty dict (same guard as Isolation Forest)."""
    if not PYTORCH_AVAILABLE:
        pytest.skip("torch not installed")
    events = _make_events(n_ips=2)
    det = PyTorchAnomalyDetector()
    assert det.fit_score(events) == {}


# ---------------------------------------------------------------------------
# Functional tests (require torch)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not PYTORCH_AVAILABLE, reason="torch not installed")
def test_fit_score_returns_dict_with_all_ips():
    events = _make_events(n_ips=5)
    det = PyTorchAnomalyDetector()
    scores = det.fit_score(events)
    ips = {e["source_ip"] for e in events}
    assert set(scores.keys()) == ips


@pytest.mark.skipif(not PYTORCH_AVAILABLE, reason="torch not installed")
def test_fit_score_all_values_in_unit_interval():
    events = _make_events(n_ips=5)
    det = PyTorchAnomalyDetector()
    scores = det.fit_score(events)
    for ip, s in scores.items():
        assert 0.0 <= s <= 1.0, f"score for {ip} out of range: {s}"


@pytest.mark.skipif(not PYTORCH_AVAILABLE, reason="torch not installed")
def test_fit_score_outlier_scores_higher():
    """An IP with extreme behaviour should score higher than normal peers."""
    events = _make_events(n_ips=5)
    events_with_outlier = _make_outlier_events(events)
    det = PyTorchAnomalyDetector()
    scores = det.fit_score(events_with_outlier)
    outlier_score = scores["192.168.1.99"]
    normal_mean = sum(
        s for ip, s in scores.items() if ip != "192.168.1.99"
    ) / (len(scores) - 1)
    assert outlier_score > normal_mean, (
        f"Outlier score {outlier_score:.4f} should exceed normal mean {normal_mean:.4f}"
    )


@pytest.mark.skipif(not PYTORCH_AVAILABLE, reason="torch not installed")
def test_feature_rows_returns_correct_structure():
    events = _make_events(n_ips=3)
    det = PyTorchAnomalyDetector()
    rows = det.feature_rows(events)
    assert len(rows) == 3
    for row in rows:
        assert "source_ip" in row
        for feat in pytorch_detector.FEATURES:
            assert feat in row, f"feature '{feat}' missing from row"
        assert isinstance(row["failed_logins"], float)


@pytest.mark.skipif(not PYTORCH_AVAILABLE, reason="torch not installed")
def test_fit_score_ignores_events_without_source_ip():
    events = _make_events(n_ips=4)
    # Add events with no source_ip — should be silently ignored.
    events.append({"event_type": "ssh_connection", "event_time": datetime.now(), "port": 22})
    det = PyTorchAnomalyDetector()
    scores = det.fit_score(events)
    assert None not in scores
    assert "" not in scores
