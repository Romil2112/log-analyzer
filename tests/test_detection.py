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


# ===========================================================================
# Edge-case parsers (empty, single, malformed, IPv6, unicode)
# ===========================================================================

class TestEdgeCaseParsers:

    def test_empty_log_parse_returns_empty_list(self, tmp_path):
        """parse_ssh_log on empty file returns []."""
        p = tmp_path / "empty.log"
        p.write_text("")
        events = la.parse_ssh_log(str(p))
        assert events == []

    def test_empty_log_no_incidents(self, tmp_path):
        """No incidents when event list is empty."""
        p = tmp_path / "empty.log"
        p.write_text("")
        events = la.parse_ssh_log(str(p))
        assert la.detect_brute_force(events) == []
        assert la.detect_port_scan(events) == []
        assert la.detect_404_flood(events) == []

    def test_single_event_parsed(self, tmp_path):
        """Exactly one event parsed from single-line log."""
        p = tmp_path / "single.log"
        p.write_text(
            "Jun 15 02:00:00 server sshd[1234]: "
            "Failed password for root from 1.2.3.4 port 50000 ssh2\n"
        )
        events = la.parse_ssh_log(str(p))
        assert len(events) == 1
        assert events[0]["source_ip"] == "1.2.3.4"
        assert events[0]["event_type"] == "failed_login"

    def test_single_event_no_brute_force(self, tmp_path):
        """One event cannot trigger brute-force detection."""
        p = tmp_path / "single.log"
        p.write_text(
            "Jun 15 02:00:00 server sshd[1234]: "
            "Failed password for root from 1.2.3.4 port 50000 ssh2\n"
        )
        events = la.parse_ssh_log(str(p))
        assert la.detect_brute_force(events) == []

    def test_malformed_log_no_crash(self, tmp_path):
        """Malformed lines are silently skipped; valid lines parsed correctly."""
        lines = [
            "THIS IS NOT A LOG LINE",
            "Jun 15 02:00:00 server sshd[1]: Failed password for root from 9.9.9.9 port 22 ssh2",
            "%%% corrupted {entry",
            "",
            "Jun 15 02:00:05 server sshd[2]: Failed password for admin from 9.9.9.9 port 23 ssh2",
            "random garbage 123 !@#$",
        ]
        p = tmp_path / "malformed.log"
        p.write_text("\n".join(lines) + "\n")
        events = la.parse_ssh_log(str(p))
        # Only 2 valid lines
        assert len(events) == 2
        for e in events:
            assert e["source_ip"] == "9.9.9.9"

    def test_malformed_log_valid_events_correct(self, tmp_path):
        """Valid events in a malformed log have correct event_type and IP."""
        p = tmp_path / "malformed.log"
        p.write_text(
            "GARBAGE LINE ONE\n"
            "Jun 15 02:00:00 server sshd[1]: "
            "Failed password for root from 5.5.5.5 port 22 ssh2\n"
            "GARBAGE LINE TWO\n"
        )
        events = la.parse_ssh_log(str(p))
        assert len(events) == 1
        assert events[0]["event_type"] == "failed_login"
        assert events[0]["source_ip"] == "5.5.5.5"

    def test_ipv6_addresses_parsed_correctly(self, tmp_path):
        """IPv6 source addresses are captured in source_ip field."""
        lines = [
            "Jun 15 02:00:00 server sshd[1]: Failed password for root "
            "from ::ffff:192.168.1.1 port 22 ssh2",
            "Jun 15 02:00:05 server sshd[2]: Failed password for admin "
            "from 2001:db8::1 port 22 ssh2",
            "Jun 15 02:00:10 server sshd[3]: Connection from 2001:db8::cafe "
            "port 10000 on 0.0.0.0 port 22",
        ]
        p = tmp_path / "ipv6.log"
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        events = la.parse_ssh_log(str(p))
        assert len(events) == 3
        ips = [e["source_ip"] for e in events]
        assert "::ffff:192.168.1.1" in ips
        assert "2001:db8::1" in ips
        assert "2001:db8::cafe" in ips

    def test_ipv6_source_ip_not_none(self, tmp_path):
        """Parsed IPv6 source_ip must not be None."""
        p = tmp_path / "ipv6.log"
        p.write_text(
            "Jun 15 02:00:00 server sshd[1]: Failed password for root "
            "from 2001:db8::1 port 22 ssh2\n",
            encoding="utf-8",
        )
        events = la.parse_ssh_log(str(p))
        assert events[0]["source_ip"] is not None
        assert "2001" in events[0]["source_ip"]

    def test_unicode_usernames_no_crash(self, tmp_path):
        """Unicode usernames must not raise UnicodeDecodeError."""
        lines = [
            "Jun 15 02:00:00 server sshd[1]: Failed password for 用户 from 1.2.3.4 port 22 ssh2",
            "Jun 15 02:00:05 server sshd[2]: Failed password for Ümit from 1.2.3.4 port 23 ssh2",
            "Jun 15 02:00:10 server sshd[3]: Failed password for José from 1.2.3.4 port 24 ssh2",
            "Jun 15 02:00:15 server sshd[4]: Accepted password for Søren from 5.5.5.5 port 25 ssh2",
        ]
        p = tmp_path / "unicode.log"
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        events = la.parse_ssh_log(str(p))
        assert len(events) == 4

    def test_unicode_username_field_populated(self, tmp_path):
        """Username field is populated for unicode usernames."""
        p = tmp_path / "unicode.log"
        p.write_text(
            "Jun 15 02:00:00 server sshd[1]: Failed password for José "
            "from 1.2.3.4 port 22 ssh2\n",
            encoding="utf-8",
        )
        events = la.parse_ssh_log(str(p))
        assert events[0]["username"] is not None
        assert "Jos" in events[0]["username"]   # may be replaced on narrow encoding

    def test_unicode_log_file_parses_without_error(self):
        """test_unicode.log (if present) parses cleanly without UnicodeDecodeError."""
        import os
        if not os.path.exists("test_unicode.log"):
            pytest.skip("test_unicode.log not generated yet")
        events = la.parse_ssh_log("test_unicode.log")
        assert len(events) > 0   # at least valid ASCII events parsed


# ===========================================================================
# Large port scan — CRITICAL severity
# ===========================================================================

class TestLargePortScan:

    def test_large_port_scan_detected(self):
        """500 unique ports in 2 minutes triggers port_scan incident."""
        from datetime import timezone
        t0 = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        events = [
            {
                "event_type": "connection",
                "source_ip":  "203.0.113.200",
                "event_time": t0 + timedelta(seconds=i * 0.24),
                "port":       10000 + i,
                "log_type":   "ssh",
                "username":   None,
                "raw_line":   f"connection {i}",
            }
            for i in range(500)
        ]
        orig_t, orig_w = la.PORT_SCAN_THRESHOLD, la.PORT_SCAN_WINDOW
        la.PORT_SCAN_THRESHOLD, la.PORT_SCAN_WINDOW = 20, 5
        try:
            incidents = la.detect_port_scan(events)
        finally:
            la.PORT_SCAN_THRESHOLD, la.PORT_SCAN_WINDOW = orig_t, orig_w
        assert len(incidents) == 1
        assert incidents[0]["event_count"] == 500

    def test_large_port_scan_severity_critical(self):
        """500 unique-port incident scores CRITICAL."""
        inc = {"incident_type": "port_scan", "event_count": 500}
        assert la.score_severity(inc) == "CRITICAL"

    def test_large_port_scan_log_file(self):
        """test_large_scan.log produces a CRITICAL port-scan incident."""
        import os
        if not os.path.exists("test_large_scan.log"):
            pytest.skip("test_large_scan.log not generated yet")
        events = la.parse_ssh_log("test_large_scan.log")
        incidents = la.detect_port_scan(events)
        scanner_incidents = [i for i in incidents if i["source_ip"] == "203.0.113.200"]
        assert len(scanner_incidents) >= 1
        enriched = la.enrich_incidents(scanner_incidents)
        assert enriched[0]["severity"] == "CRITICAL"


# ===========================================================================
# Slow brute force — rule miss, ML hit
# ===========================================================================

class TestSlowBruteForceML:

    def test_slow_brute_force_rule_miss(self):
        """4 failures / 12 min must NOT trigger brute-force rule (threshold 5/10 min)."""
        from datetime import timezone
        t0 = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        events = []
        t = t0
        for _ in range(100):   # 100 groups of 4, each group in <10 min
            for _ in range(4):
                t += timedelta(seconds=90)   # 90s apart → 4 events in 6 min
                events.append({
                    "event_type": "failed_login",
                    "source_ip":  "185.100.87.202",
                    "event_time": t,
                    "port":       22,
                    "log_type":   "ssh",
                    "username":   "root",
                    "raw_line":   "test",
                })
            t += timedelta(minutes=12)   # 12-min gap between groups

        orig_t, orig_w = la.BRUTE_FORCE_THRESHOLD, la.BRUTE_FORCE_WINDOW
        la.BRUTE_FORCE_THRESHOLD, la.BRUTE_FORCE_WINDOW = 5, 10
        try:
            incidents = la.detect_brute_force(events)
        finally:
            la.BRUTE_FORCE_THRESHOLD, la.BRUTE_FORCE_WINDOW = orig_t, orig_w

        stuffer_hits = [i for i in incidents if i["source_ip"] == "185.100.87.202"]
        assert stuffer_hits == [], (
            f"Slow stuffer with 4/12-min rate should not trigger 5/10-min rule, "
            f"got {stuffer_hits}"
        )

    def test_slow_brute_force_ml_score(self):
        """test_slow_brute.log: stuffer IP should score > 0.5 in Isolation Forest."""
        import os
        if not os.path.exists("test_slow_brute.log"):
            pytest.skip("test_slow_brute.log not generated yet")
        if not la.ML_AVAILABLE:
            pytest.skip("scikit-learn not installed")
        events = la.parse_ssh_log("test_slow_brute.log")
        det    = la.AnomalyDetector()
        scores = det.fit_score(events)
        stuffer_score = scores.get("185.100.87.202", 0.0)
        assert stuffer_score > 0.5, (
            f"Slow stuffer 185.100.87.202 expected ML score > 0.5, got {stuffer_score:.4f}. "
            f"Top scores: {sorted(scores.items(), key=lambda x: -x[1])[:5]}"
        )


# ===========================================================================
# Mixed attack log — all 3 detectors fire
# ===========================================================================

class TestMixedAttackLog:

    def _flood_events(self, ip: str, count: int = 40):
        """Synthesise http_404 events (SSH parser can't produce these)."""
        return [
            make_event("http_404", ip, minutes_offset=i * 0.1, log_type="apache_nginx")
            for i in range(count)
        ]

    def test_mixed_brute_force_detected(self):
        """Mixed log: detect_brute_force returns >= 1 incident."""
        import os
        if not os.path.exists("test_mixed.log"):
            pytest.skip("test_mixed.log not generated yet")
        events = la.parse_ssh_log("test_mixed.log")
        bf = la.detect_brute_force(events)
        assert len(bf) >= 1, "Expected at least 1 brute-force incident from mixed log"

    def test_mixed_port_scan_detected(self):
        """Mixed log: detect_port_scan returns >= 1 incident."""
        import os
        if not os.path.exists("test_mixed.log"):
            pytest.skip("test_mixed.log not generated yet")
        events = la.parse_ssh_log("test_mixed.log")
        ps = la.detect_port_scan(events)
        assert len(ps) >= 1, "Expected at least 1 port-scan incident from mixed log"

    def test_mixed_404_flood_detected(self):
        """All 3 detectors fire when SSH events + synthesised 404 events combined."""
        import os
        if not os.path.exists("test_mixed.log"):
            pytest.skip("test_mixed.log not generated yet")
        ssh_events  = la.parse_ssh_log("test_mixed.log")
        flood_events = self._flood_events("9.8.7.6", count=40)
        all_events  = ssh_events + flood_events

        orig_t, orig_w = la.FLOOD_404_THRESHOLD, la.FLOOD_404_WINDOW
        la.FLOOD_404_THRESHOLD, la.FLOOD_404_WINDOW = 30, 5
        try:
            bf    = la.detect_brute_force(all_events)
            ps    = la.detect_port_scan(all_events)
            flood = la.detect_404_flood(all_events)
        finally:
            la.FLOOD_404_THRESHOLD, la.FLOOD_404_WINDOW = orig_t, orig_w

        assert len(bf) >= 1,    "Expected brute-force incident"
        assert len(ps) >= 1,    "Expected port-scan incident"
        assert len(flood) >= 1, "Expected 404-flood incident"


# ===========================================================================
# Allowlist interaction with detectors
# ===========================================================================

class TestAllowlistWithDetectors:

    def test_allowlist_suppresses_brute_force(self):
        """Filtering attacker IP before detection removes its incident."""
        events = [
            make_event("failed_login", "1.2.3.4", minutes_offset=i)
            for i in range(10)
        ]
        al       = la.build_allowlist(["1.2.3.4/32"])
        filtered = la.filter_allowlist(events, al)
        assert la.detect_brute_force(filtered) == []

    def test_allowlist_suppresses_port_scan(self):
        """Filtering scanner IP before detection removes its incident."""
        events = [
            make_event("connection", "2.3.4.5", minutes_offset=i * 0.1, port=1000 + i)
            for i in range(30)
        ]
        al       = la.build_allowlist(["2.3.4.5/32"])
        filtered = la.filter_allowlist(events, al)
        assert la.detect_port_scan(filtered) == []

    def test_allowlist_does_not_suppress_other_ip(self):
        """Allowlisting IP-A does not suppress incidents from IP-B."""
        events = [
            make_event("failed_login", "10.0.0.1", minutes_offset=i)
            for i in range(10)
        ]
        al       = la.build_allowlist(["9.9.9.9/32"])
        filtered = la.filter_allowlist(events, al)
        bf       = la.detect_brute_force(filtered)
        assert any(i["source_ip"] == "10.0.0.1" for i in bf)

    def test_build_allowlist_mixed_invalid_entries(self):
        """Invalid CIDR entries are skipped; valid ones accepted; no crash."""
        al = la.build_allowlist(["invalid!!!", "10.0.0.0/8", "999.999.999.999"])
        assert len(al) == 1
        assert la._is_allowed("10.5.5.5", al) is True
        assert la._is_allowed("172.16.0.1", al) is False

    def test_filter_allowlist_empty_returns_unchanged(self):
        """filter_allowlist with empty allowlist returns all events."""
        events = [make_event("failed_login", ip) for ip in ("1.2.3.4", "5.6.7.8")]
        filtered = la.filter_allowlist(events, [])
        assert len(filtered) == len(events)


# ===========================================================================
# Custom 404 flood threshold
# ===========================================================================

class TestFlood404CustomThreshold:

    def _run(self, events, threshold, window=5):
        orig_t, orig_w = la.FLOOD_404_THRESHOLD, la.FLOOD_404_WINDOW
        la.FLOOD_404_THRESHOLD, la.FLOOD_404_WINDOW = threshold, window
        try:
            return la.detect_404_flood(events)
        finally:
            la.FLOOD_404_THRESHOLD, la.FLOOD_404_WINDOW = orig_t, orig_w

    def test_threshold_10_triggers_on_11_events(self):
        """--flood-404-threshold 10 fires when 11 events are in window."""
        events = [
            make_event("http_404", "9.9.9.9", minutes_offset=i * 0.1,
                       log_type="apache_nginx")
            for i in range(11)
        ]
        incidents = self._run(events, threshold=10, window=5)
        assert len(incidents) == 1
        assert incidents[0]["event_count"] >= 10

    def test_threshold_10_does_not_trigger_on_10_events(self):
        """Exactly 10 events at threshold=10 still triggers (>= not >)."""
        events = [
            make_event("http_404", "9.9.9.9", minutes_offset=i * 0.1,
                       log_type="apache_nginx")
            for i in range(10)
        ]
        incidents = self._run(events, threshold=10, window=5)
        assert len(incidents) == 1   # >=10 triggers

    def test_threshold_10_misses_9_events(self):
        """9 events at threshold=10 produces no incident."""
        events = [
            make_event("http_404", "9.9.9.9", minutes_offset=i * 0.1,
                       log_type="apache_nginx")
            for i in range(9)
        ]
        incidents = self._run(events, threshold=10, window=5)
        assert incidents == []


# ===========================================================================
# generate_report HTML output
# ===========================================================================

class TestGenerateReport:

    def _make_incident(self, inc_type: str, ip: str, count: int) -> dict:
        from datetime import timezone as tz
        t0 = datetime(2024, 1, 1, 0, 0, 0, tzinfo=tz.utc)
        inc = {
            "incident_type": inc_type,
            "source_ip":     ip,
            "first_seen":    t0,
            "last_seen":     t0 + timedelta(minutes=5),
            "event_count":   count,
            "details":       {"unique_ports": list(range(min(count, 20)))}
                              if inc_type == "port_scan" else {},
        }
        return la.enrich_incidents([inc])[0]

    def test_zero_incidents_has_no_incidents_message(self, tmp_path):
        """Report with no incidents contains 'No incidents detected.' text."""
        out = str(tmp_path / "report_empty.html")
        la.generate_report([], [], "test.log", out)
        html = (tmp_path / "report_empty.html").read_text(encoding="utf-8")
        assert "No incidents detected." in html

    def test_zero_incidents_valid_html(self, tmp_path):
        """Report with no incidents is non-empty valid HTML."""
        out = str(tmp_path / "report_empty.html")
        la.generate_report([], [], "test.log", out)
        html = (tmp_path / "report_empty.html").read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in html
        assert "chart.js" in html.lower()   # CDN link: chart.js@4.4.0

    def test_all_three_incident_types_sections_present(self, tmp_path):
        """Report with all 3 types contains all 3 section headings."""
        incidents = [
            self._make_incident("brute_force", "1.1.1.1", 100),
            self._make_incident("port_scan",   "2.2.2.2", 50),
            self._make_incident("flood_404",   "3.3.3.3", 200),
        ]
        out = str(tmp_path / "report_all.html")
        la.generate_report([], incidents, "test.log", out)
        html = (tmp_path / "report_all.html").read_text(encoding="utf-8")
        assert "Brute Force Incidents" in html
        assert "Port Scan Incidents" in html
        assert "404 Flood Incidents" in html

    def test_report_contains_mitre_ids(self, tmp_path):
        """Incident report contains MITRE ATT&CK technique IDs."""
        incidents = [
            self._make_incident("brute_force", "1.1.1.1", 100),
            self._make_incident("port_scan",   "2.2.2.2", 50),
        ]
        out = str(tmp_path / "report_mitre.html")
        la.generate_report([], incidents, "test.log", out)
        html = (tmp_path / "report_mitre.html").read_text(encoding="utf-8")
        assert "T1110" in html
        assert "T1046" in html

    def test_report_from_10k_log_contains_key_strings(self, tmp_path):
        """HTML report from test_auth_10k.log contains Chart.js, MITRE IDs, severity labels."""
        import os
        if not os.path.exists("test_auth_10k.log"):
            pytest.skip("test_auth_10k.log not generated yet")
        events    = la.parse_ssh_log("test_auth_10k.log")
        bf        = la.detect_brute_force(events)
        ps        = la.detect_port_scan(events)
        incidents = la.enrich_incidents(bf + ps)
        out       = str(tmp_path / "r_10k_test.html")
        if la.ML_AVAILABLE and len({e["source_ip"] for e in events if e.get("source_ip")}) >= 3:
            det    = la.AnomalyDetector()
            scores = det.fit_score(events)
            feats  = det.feature_rows(events)
        else:
            scores, feats = None, None
        la.generate_report(events, incidents, "test_auth_10k.log", out, scores, feats)
        html = (tmp_path / "r_10k_test.html").read_text(encoding="utf-8")
        assert "chart.js" in html.lower(),     "Missing chart.js CDN link"
        assert "T1110" in html,                "Missing T1110 brute-force technique"
        assert "T1046" in html,                "Missing T1046 port-scan technique"
        assert ("CRITICAL" in html or "HIGH" in html), "Missing severity badge"
        if scores:
            assert "Isolation Forest" in html, "Missing Isolation Forest section"


# ===========================================================================
# AI summary — returns None when no key set
# ===========================================================================

class TestAISummary:

    def setup_method(self):
        """Ensure ANTHROPIC_API_KEY is not set during these tests."""
        import os
        self._saved = os.environ.pop("ANTHROPIC_API_KEY", None)

    def teardown_method(self):
        import os
        if self._saved is not None:
            os.environ["ANTHROPIC_API_KEY"] = self._saved

    def test_ai_summary_empty_no_key(self):
        """ai_summary([],{}) returns None when ANTHROPIC_API_KEY absent."""
        from ai_summary import ai_summary
        assert ai_summary([], {}) is None

    def test_ai_summary_with_incidents_no_key(self):
        """ai_summary with incident list returns None (not crash) when key absent."""
        from ai_summary import ai_summary
        result = ai_summary(
            [{"incident_type": "brute_force", "source_ip": "1.2.3.4",
              "event_count": 10, "mitre": {}}],
            {}
        )
        assert result is None

    def test_ai_summary_multiple_incidents_no_key(self):
        """ai_summary with multiple incidents doesn't crash when key absent."""
        from ai_summary import ai_summary
        incidents = [
            {"incident_type": t, "source_ip": f"1.1.1.{i}",
             "event_count": 5, "mitre": {"id": "T1046"}}
            for i, t in enumerate(["brute_force", "port_scan", "flood_404"])
        ]
        assert ai_summary(incidents, {"1.1.1.0": 0.9}) is None


# ===========================================================================
# score_severity extended edge cases
# ===========================================================================

class TestScoreSeverityExtended:

    def test_brute_force_200_is_critical(self):
        assert la.score_severity({"incident_type": "brute_force", "event_count": 200}) == "CRITICAL"

    def test_brute_force_5_is_low(self):
        assert la.score_severity({"incident_type": "brute_force", "event_count": 5}) == "LOW"

    def test_port_scan_500_is_critical(self):
        assert la.score_severity({"incident_type": "port_scan", "event_count": 500}) == "CRITICAL"

    def test_flood_404_250_is_critical(self):
        assert la.score_severity({"incident_type": "flood_404", "event_count": 250}) == "CRITICAL"

    def test_unknown_type_returns_low(self):
        assert la.score_severity({"incident_type": "unknown_type", "event_count": 9999}) == "LOW"


# ===========================================================================
# detect_log_format
# ===========================================================================

class TestDetectLogFormat:

    def test_csv_extension_returns_windows(self, tmp_path):
        p = tmp_path / "events.csv"
        p.write_text("TimeCreated,EventID\n")
        assert la.detect_log_format(str(p)) == "windows"

    def test_ssh_first_line_returns_ssh(self, tmp_path):
        p = tmp_path / "auth.log"
        p.write_text(
            "Jun 15 02:00:00 server sshd[1]: Failed password for root "
            "from 1.2.3.4 port 22 ssh2\n"
        )
        assert la.detect_log_format(str(p)) == "ssh"
