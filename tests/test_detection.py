"""
Comprehensive pytest unit tests for log_analyzer detection and scoring logic.

Covers:
- detect_brute_force
- detect_port_scan
- detect_404_flood
- score_severity
- build_allowlist + filter_allowlist
"""

import sys
import os
from datetime import datetime, timedelta, timezone

import pytest

# ---------------------------------------------------------------------------
# Make sure the project root is on sys.path so we can import log_analyzer
# directly without installing it as a package.
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import log_analyzer as la

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

BASE_TIME = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def make_event(
    event_type: str,
    source_ip: str,
    minutes_offset: float = 0,
    port: int = None,
    log_type: str = "ssh",
) -> dict:
    """
    Build a minimal event dict compatible with log_analyzer detection functions.

    Parameters
    ----------
    event_type     : e.g. 'failed_login', 'connection', 'http_404'
    source_ip      : attacker IP string
    minutes_offset : how many minutes after BASE_TIME (2024-01-01 12:00 UTC)
    port           : optional port number
    log_type       : 'ssh', 'windows', or 'apache_nginx'
    """
    return {
        "event_type": event_type,
        "source_ip": source_ip,
        "event_time": BASE_TIME + timedelta(minutes=minutes_offset),
        "port": port,
        "log_type": log_type,
        "username": None,
        "raw_line": f"synthetic {event_type} from {source_ip}",
    }


# ===========================================================================
# detect_brute_force
# ===========================================================================

class TestDetectBruteForce:

    def _run(self, events, threshold=5, window=10):
        """Helper: temporarily patch globals, run detector, restore."""
        orig_t = la.BRUTE_FORCE_THRESHOLD
        orig_w = la.BRUTE_FORCE_WINDOW
        la.BRUTE_FORCE_THRESHOLD = threshold
        la.BRUTE_FORCE_WINDOW = window
        try:
            return la.detect_brute_force(events)
        finally:
            la.BRUTE_FORCE_THRESHOLD = orig_t
            la.BRUTE_FORCE_WINDOW = orig_w

    # ---- basic detection at threshold ----

    def test_detects_at_threshold(self):
        """Exactly threshold failures within window must trigger an incident."""
        events = [
            make_event("failed_login", "1.2.3.4", minutes_offset=i)
            for i in range(5)  # 5 logins at 0,1,2,3,4 minutes
        ]
        incidents = self._run(events, threshold=5, window=10)
        assert len(incidents) == 1
        inc = incidents[0]
        assert inc["incident_type"] == "brute_force"
        assert inc["source_ip"] == "1.2.3.4"
        assert inc["event_count"] == 5

    def test_detects_above_threshold(self):
        """More failures than threshold still produces exactly one incident per IP."""
        events = [
            make_event("failed_login", "1.2.3.4", minutes_offset=i * 0.5)
            for i in range(20)
        ]
        incidents = self._run(events, threshold=5, window=10)
        assert len(incidents) == 1
        assert incidents[0]["event_count"] >= 5

    def test_misses_below_threshold(self):
        """Fewer failures than threshold must produce no incidents."""
        events = [
            make_event("failed_login", "1.2.3.4", minutes_offset=i)
            for i in range(4)  # only 4, threshold=5
        ]
        incidents = self._run(events, threshold=5, window=10)
        assert incidents == []

    def test_respects_window(self):
        """Failures spread across multiple windows should not combine."""
        # 3 failures at t=0, 3 failures at t=30 — each group is below threshold=5
        events = (
            [make_event("failed_login", "1.2.3.4", minutes_offset=i) for i in range(3)]
            + [make_event("failed_login", "1.2.3.4", minutes_offset=30 + i) for i in range(3)]
        )
        incidents = self._run(events, threshold=5, window=10)
        assert incidents == []

    def test_handles_multiple_ips(self):
        """Each IP that breaches threshold gets its own incident."""
        events = []
        for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
            for i in range(6):
                events.append(make_event("failed_login", ip, minutes_offset=i))
        incidents = self._run(events, threshold=5, window=10)
        incident_ips = {inc["source_ip"] for inc in incidents}
        assert incident_ips == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}

    def test_ignores_successful_logins(self):
        """Successful logins must NOT count toward brute force."""
        events = [
            make_event("successful_login", "1.2.3.4", minutes_offset=i)
            for i in range(10)
        ]
        incidents = self._run(events, threshold=5, window=10)
        assert incidents == []

    def test_one_incident_per_ip(self):
        """Even with many overlapping windows, only one incident is emitted per IP."""
        events = [
            make_event("failed_login", "5.5.5.5", minutes_offset=i * 0.1)
            for i in range(50)
        ]
        incidents = self._run(events, threshold=5, window=10)
        assert len(incidents) == 1

    def test_incident_fields_present(self):
        """Incident dict must contain all required keys."""
        events = [
            make_event("failed_login", "1.2.3.4", minutes_offset=i)
            for i in range(5)
        ]
        inc = self._run(events, threshold=5, window=10)[0]
        for key in ("incident_type", "source_ip", "first_seen", "last_seen", "event_count", "details"):
            assert key in inc, f"Missing key: {key}"

    def test_events_without_ip_are_ignored(self):
        """Events with source_ip=None must not cause errors or false positives."""
        events = [
            {**make_event("failed_login", "1.2.3.4", minutes_offset=i), "source_ip": None}
            for i in range(10)
        ]
        incidents = self._run(events, threshold=5, window=10)
        assert incidents == []


# ===========================================================================
# detect_port_scan
# ===========================================================================

class TestDetectPortScan:

    def _run(self, events, threshold=20, window=5):
        orig_t = la.PORT_SCAN_THRESHOLD
        orig_w = la.PORT_SCAN_WINDOW
        la.PORT_SCAN_THRESHOLD = threshold
        la.PORT_SCAN_WINDOW = window
        try:
            return la.detect_port_scan(events)
        finally:
            la.PORT_SCAN_THRESHOLD = orig_t
            la.PORT_SCAN_WINDOW = orig_w

    def test_detects_at_threshold(self):
        """Exactly threshold unique ports in window triggers incident."""
        events = [
            make_event("connection", "2.3.4.5", minutes_offset=i * 0.1, port=1000 + i)
            for i in range(20)
        ]
        incidents = self._run(events, threshold=20, window=5)
        assert len(incidents) == 1
        assert incidents[0]["incident_type"] == "port_scan"
        assert incidents[0]["source_ip"] == "2.3.4.5"
        assert incidents[0]["event_count"] >= 20

    def test_detects_above_threshold(self):
        events = [
            make_event("connection", "2.3.4.5", minutes_offset=i * 0.05, port=2000 + i)
            for i in range(50)
        ]
        incidents = self._run(events, threshold=20, window=5)
        assert len(incidents) == 1

    def test_misses_below_threshold(self):
        """Fewer unique ports than threshold must produce no incidents."""
        events = [
            make_event("connection", "2.3.4.5", minutes_offset=i * 0.1, port=1000 + i)
            for i in range(19)  # only 19 unique ports, threshold=20
        ]
        incidents = self._run(events, threshold=20, window=5)
        assert incidents == []

    def test_counts_unique_ports_only(self):
        """Repeated connections to the same port count as one unique port."""
        # 5 unique ports, each seen 4 times → only 5 unique ports, below threshold=20
        events = []
        for port in range(5):
            for repeat in range(4):
                events.append(
                    make_event("connection", "2.3.4.5", minutes_offset=repeat * 0.1, port=8000 + port)
                )
        incidents = self._run(events, threshold=20, window=5)
        assert incidents == []

    def test_counts_unique_ports_above_threshold(self):
        """20 unique ports each seen 3 times must still produce one incident."""
        events = []
        for port in range(20):
            for repeat in range(3):
                events.append(
                    make_event("connection", "2.3.4.5", minutes_offset=repeat * 0.1, port=9000 + port)
                )
        incidents = self._run(events, threshold=20, window=5)
        assert len(incidents) == 1
        assert incidents[0]["event_count"] == 20

    def test_respects_window(self):
        """Ports spread across two non-overlapping windows must not combine."""
        # 15 ports in window 1, 15 ports in window 2, threshold=20
        events = (
            [make_event("connection", "2.3.4.5", minutes_offset=i * 0.1, port=100 + i) for i in range(15)]
            + [make_event("connection", "2.3.4.5", minutes_offset=20 + i * 0.1, port=200 + i) for i in range(15)]
        )
        incidents = self._run(events, threshold=20, window=5)
        assert incidents == []

    def test_multiple_ips(self):
        """Two IPs each crossing threshold each get their own incident."""
        events = []
        for ip in ("3.3.3.3", "4.4.4.4"):
            for i in range(25):
                events.append(
                    make_event("connection", ip, minutes_offset=i * 0.1, port=3000 + i)
                )
        incidents = self._run(events, threshold=20, window=5)
        ips = {inc["source_ip"] for inc in incidents}
        assert ips == {"3.3.3.3", "4.4.4.4"}


# ===========================================================================
# detect_404_flood
# ===========================================================================

class TestDetect404Flood:

    def _run(self, events, threshold=30, window=5):
        orig_t = la.FLOOD_404_THRESHOLD
        orig_w = la.FLOOD_404_WINDOW
        la.FLOOD_404_THRESHOLD = threshold
        la.FLOOD_404_WINDOW = window
        try:
            return la.detect_404_flood(events)
        finally:
            la.FLOOD_404_THRESHOLD = orig_t
            la.FLOOD_404_WINDOW = orig_w

    def test_detects_at_threshold(self):
        events = [
            make_event("http_404", "6.6.6.6", minutes_offset=i * 0.1, log_type="apache_nginx")
            for i in range(30)
        ]
        incidents = self._run(events, threshold=30, window=5)
        assert len(incidents) == 1
        assert incidents[0]["incident_type"] == "flood_404"
        assert incidents[0]["source_ip"] == "6.6.6.6"
        assert incidents[0]["event_count"] >= 30

    def test_misses_below_threshold(self):
        events = [
            make_event("http_404", "6.6.6.6", minutes_offset=i * 0.1, log_type="apache_nginx")
            for i in range(29)
        ]
        incidents = self._run(events, threshold=30, window=5)
        assert incidents == []

    def test_respects_window(self):
        # 20 hits in window 1, 20 hits in window 2 (far apart), threshold=30
        events = (
            [make_event("http_404", "6.6.6.6", minutes_offset=i * 0.1, log_type="apache_nginx") for i in range(20)]
            + [make_event("http_404", "6.6.6.6", minutes_offset=30 + i * 0.1, log_type="apache_nginx") for i in range(20)]
        )
        incidents = self._run(events, threshold=30, window=5)
        assert incidents == []

    def test_ignores_non_404_events(self):
        """http_success or http_error events must not count toward flood."""
        events = [
            make_event("http_success", "6.6.6.6", minutes_offset=i * 0.1, log_type="apache_nginx")
            for i in range(50)
        ]
        incidents = self._run(events, threshold=30, window=5)
        assert incidents == []

    def test_multiple_ips_get_separate_incidents(self):
        events = []
        for ip in ("7.7.7.7", "8.8.8.8"):
            for i in range(35):
                events.append(
                    make_event("http_404", ip, minutes_offset=i * 0.1, log_type="apache_nginx")
                )
        incidents = self._run(events, threshold=30, window=5)
        ips = {inc["source_ip"] for inc in incidents}
        assert ips == {"7.7.7.7", "8.8.8.8"}

    def test_one_incident_per_ip(self):
        """Many 404s from one IP should produce exactly one incident."""
        events = [
            make_event("http_404", "9.9.9.9", minutes_offset=i * 0.05, log_type="apache_nginx")
            for i in range(200)
        ]
        incidents = self._run(events, threshold=30, window=5)
        assert len(incidents) == 1


# ===========================================================================
# score_severity
# ===========================================================================

class TestScoreSeverity:

    # ---- brute_force ----

    def test_brute_force_critical(self):
        inc = {"incident_type": "brute_force", "event_count": 100}
        assert la.score_severity(inc) == "CRITICAL"

    def test_brute_force_critical_above(self):
        inc = {"incident_type": "brute_force", "event_count": 500}
        assert la.score_severity(inc) == "CRITICAL"

    def test_brute_force_high(self):
        inc = {"incident_type": "brute_force", "event_count": 30}
        assert la.score_severity(inc) == "HIGH"

    def test_brute_force_high_boundary(self):
        inc = {"incident_type": "brute_force", "event_count": 99}
        assert la.score_severity(inc) == "HIGH"

    def test_brute_force_medium(self):
        inc = {"incident_type": "brute_force", "event_count": 10}
        assert la.score_severity(inc) == "MEDIUM"

    def test_brute_force_medium_boundary(self):
        inc = {"incident_type": "brute_force", "event_count": 29}
        assert la.score_severity(inc) == "MEDIUM"

    def test_brute_force_low(self):
        inc = {"incident_type": "brute_force", "event_count": 5}
        assert la.score_severity(inc) == "LOW"

    def test_brute_force_low_boundary(self):
        inc = {"incident_type": "brute_force", "event_count": 9}
        assert la.score_severity(inc) == "LOW"

    # ---- port_scan ----

    def test_port_scan_critical(self):
        inc = {"incident_type": "port_scan", "event_count": 500}
        assert la.score_severity(inc) == "CRITICAL"

    def test_port_scan_critical_above(self):
        inc = {"incident_type": "port_scan", "event_count": 1000}
        assert la.score_severity(inc) == "CRITICAL"

    def test_port_scan_high(self):
        inc = {"incident_type": "port_scan", "event_count": 100}
        assert la.score_severity(inc) == "HIGH"

    def test_port_scan_high_boundary(self):
        inc = {"incident_type": "port_scan", "event_count": 499}
        assert la.score_severity(inc) == "HIGH"

    def test_port_scan_medium(self):
        inc = {"incident_type": "port_scan", "event_count": 50}
        assert la.score_severity(inc) == "MEDIUM"

    def test_port_scan_medium_boundary(self):
        inc = {"incident_type": "port_scan", "event_count": 99}
        assert la.score_severity(inc) == "MEDIUM"

    def test_port_scan_low(self):
        inc = {"incident_type": "port_scan", "event_count": 20}
        assert la.score_severity(inc) == "LOW"

    def test_port_scan_low_boundary(self):
        inc = {"incident_type": "port_scan", "event_count": 49}
        assert la.score_severity(inc) == "LOW"

    # ---- flood_404 ----

    def test_flood_404_critical(self):
        inc = {"incident_type": "flood_404", "event_count": 200}
        assert la.score_severity(inc) == "CRITICAL"

    def test_flood_404_critical_above(self):
        inc = {"incident_type": "flood_404", "event_count": 999}
        assert la.score_severity(inc) == "CRITICAL"

    def test_flood_404_high(self):
        inc = {"incident_type": "flood_404", "event_count": 100}
        assert la.score_severity(inc) == "HIGH"

    def test_flood_404_high_boundary(self):
        inc = {"incident_type": "flood_404", "event_count": 199}
        assert la.score_severity(inc) == "HIGH"

    def test_flood_404_medium(self):
        inc = {"incident_type": "flood_404", "event_count": 50}
        assert la.score_severity(inc) == "MEDIUM"

    def test_flood_404_medium_boundary(self):
        inc = {"incident_type": "flood_404", "event_count": 99}
        assert la.score_severity(inc) == "MEDIUM"

    def test_flood_404_low(self):
        inc = {"incident_type": "flood_404", "event_count": 30}
        assert la.score_severity(inc) == "LOW"

    def test_flood_404_low_boundary(self):
        inc = {"incident_type": "flood_404", "event_count": 49}
        assert la.score_severity(inc) == "LOW"


# ===========================================================================
# build_allowlist + filter_allowlist
# ===========================================================================

class TestAllowlist:

    def test_build_allowlist_single_ip(self):
        al = la.build_allowlist(["127.0.0.1"])
        assert len(al) == 1

    def test_build_allowlist_ipv6(self):
        al = la.build_allowlist(["::1"])
        assert len(al) == 1

    def test_build_allowlist_cidr(self):
        al = la.build_allowlist(["192.168.1.0/24"])
        assert len(al) == 1

    def test_build_allowlist_multiple(self):
        al = la.build_allowlist(["127.0.0.1", "::1", "10.0.0.0/8"])
        assert len(al) == 3

    def test_build_allowlist_invalid_entry_skipped(self):
        """Invalid entries should be silently skipped, not crash."""
        al = la.build_allowlist(["not-an-ip", "127.0.0.1", "garbage/99"])
        # Only "127.0.0.1" is valid; "garbage/99" and "not-an-ip" are invalid
        # Exact count depends on implementation, but must not raise
        assert isinstance(al, list)
        # Valid entry should still be present
        import ipaddress
        valid_networks = [str(n) for n in al]
        assert any("127.0.0.1" in s for s in valid_networks)

    def test_build_allowlist_empty(self):
        al = la.build_allowlist([])
        assert al == []

    def test_is_allowed_exact_match(self):
        al = la.build_allowlist(["1.2.3.4"])
        assert la._is_allowed("1.2.3.4", al) is True

    def test_is_allowed_cidr_match(self):
        al = la.build_allowlist(["192.168.0.0/16"])
        assert la._is_allowed("192.168.50.10", al) is True

    def test_is_allowed_cidr_no_match(self):
        al = la.build_allowlist(["192.168.0.0/16"])
        assert la._is_allowed("10.0.0.1", al) is False

    def test_is_allowed_empty_allowlist(self):
        assert la._is_allowed("1.2.3.4", []) is False

    def test_filter_allowlist_removes_matching_events(self):
        al = la.build_allowlist(["1.2.3.4"])
        events = [
            make_event("failed_login", "1.2.3.4"),   # should be removed
            make_event("failed_login", "5.6.7.8"),   # should remain
            make_event("failed_login", "9.10.11.12"), # should remain
        ]
        filtered = la.filter_allowlist(events, al)
        ips = [e["source_ip"] for e in filtered]
        assert "1.2.3.4" not in ips
        assert "5.6.7.8" in ips
        assert "9.10.11.12" in ips

    def test_filter_allowlist_cidr(self):
        al = la.build_allowlist(["10.0.0.0/8"])
        events = [
            make_event("failed_login", "10.1.2.3"),   # inside CIDR → removed
            make_event("failed_login", "10.99.0.1"),  # inside CIDR → removed
            make_event("failed_login", "172.16.0.1"), # outside → kept
        ]
        filtered = la.filter_allowlist(events, al)
        ips = [e["source_ip"] for e in filtered]
        assert "10.1.2.3" not in ips
        assert "10.99.0.1" not in ips
        assert "172.16.0.1" in ips

    def test_filter_allowlist_empty_allowlist_keeps_all(self):
        al = la.build_allowlist([])
        events = [make_event("failed_login", ip) for ip in ("1.1.1.1", "2.2.2.2")]
        filtered = la.filter_allowlist(events, al)
        assert len(filtered) == len(events)

    def test_filter_allowlist_none_ip_events_kept(self):
        """Events with source_ip=None should pass through the filter unchanged."""
        al = la.build_allowlist(["1.2.3.4"])
        events = [
            {**make_event("failed_login", "1.2.3.4"), "source_ip": None},
        ]
        # Should not raise; event with None IP should be kept (not allowlisted)
        filtered = la.filter_allowlist(events, al)
        assert len(filtered) == 1

    def test_filter_allowlist_returns_list(self):
        al = la.build_allowlist(["127.0.0.1"])
        events = [make_event("failed_login", "8.8.8.8")]
        result = la.filter_allowlist(events, al)
        assert isinstance(result, list)
