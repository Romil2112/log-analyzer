"""Tests for privacy controls: encryption, scrubbing, redaction,
pseudonymization, retention, and the plaintext-HTTP push warning."""
import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import crypto
import log_analyzer as la
import soc_push


# --------------------------------------------------------------------------- #
# Field-level encryption
# --------------------------------------------------------------------------- #
def test_encrypt_decrypt_round_trip(monkeypatch):
    monkeypatch.setenv("DB_ENCRYPTION_KEY", "unit-test-key")
    fernet = crypto.get_fernet()
    assert fernet is not None
    token = crypto.encrypt_field(fernet, "10.1.2.3")
    assert token != "10.1.2.3"
    assert crypto.decrypt_field(fernet, token) == "10.1.2.3"


def test_encryption_disabled_passthrough(monkeypatch):
    monkeypatch.delenv("DB_ENCRYPTION_KEY", raising=False)
    fernet = crypto.get_fernet()
    assert fernet is None
    assert crypto.encrypt_field(fernet, "secret") == "secret"
    assert crypto.decrypt_field(fernet, "secret") == "secret"
    assert crypto.encrypt_field(fernet, None) is None


# --------------------------------------------------------------------------- #
# Scrubbing / redaction / pseudonymization helpers
# --------------------------------------------------------------------------- #
def _args(**over):
    base = dict(scrub_usernames=False, no_raw_lines=False, pseudonymize=False)
    base.update(over)
    return argparse.Namespace(**base)


def test_scrub_usernames_hashes_and_is_stable():
    events = [{"username": "alice", "source_ip": "1.1.1.1", "raw_line": "x"},
              {"username": "alice", "source_ip": "1.1.1.1", "raw_line": "y"}]
    la.apply_privacy_transforms(events, [], _args(scrub_usernames=True))
    assert events[0]["username"].startswith("user_")
    assert events[0]["username"] != "alice"
    # same input -> same pseudonym
    assert events[0]["username"] == events[1]["username"]


def test_no_raw_lines_nulls_raw_line():
    events = [{"username": "bob", "source_ip": "2.2.2.2", "raw_line": "sensitive line"}]
    la.apply_privacy_transforms(events, [], _args(no_raw_lines=True))
    assert events[0]["raw_line"] is None


def test_pseudonymize_is_stable_within_run_and_covers_incidents():
    events = [{"source_ip": "3.3.3.3"}, {"source_ip": "3.3.3.3"}, {"source_ip": "4.4.4.4"}]
    incidents = [{"source_ip": "3.3.3.3", "details": {}}]
    la.apply_privacy_transforms(events, incidents, _args(pseudonymize=True))
    # original IP is gone, mapping is consistent for the same IP
    assert events[0]["source_ip"] != "3.3.3.3"
    assert events[0]["source_ip"] == events[1]["source_ip"]
    assert events[0]["source_ip"] != events[2]["source_ip"]
    # incidents share the same mapping as events within the run
    assert incidents[0]["source_ip"] == events[0]["source_ip"]


def test_pseudonymize_differs_across_runs():
    a = [{"source_ip": "5.5.5.5"}]
    b = [{"source_ip": "5.5.5.5"}]
    la.apply_privacy_transforms(a, [], _args(pseudonymize=True))
    la.apply_privacy_transforms(b, [], _args(pseudonymize=True))
    # different random session keys -> different pseudonyms
    assert a[0]["source_ip"] != b[0]["source_ip"]


# --------------------------------------------------------------------------- #
# Retention purge helper (mock connection — no live DB, matching repo style)
# --------------------------------------------------------------------------- #
class _FakeCursor:
    def __init__(self):
        self.executed = []
        self.rowcount = 7

    def execute(self, sql, params=None):
        self.executed.append((sql, params))

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _FakeConn:
    def __init__(self):
        self.cur = _FakeCursor()
        self.committed = False

    def cursor(self):
        return self.cur

    def commit(self):
        self.committed = True


def test_retention_purges_both_tables_with_day_threshold():
    conn = _FakeConn()
    ev, inc = la.purge_old_records(conn, 30)
    assert (ev, inc) == (7, 7)
    assert len(conn.cur.executed) == 2
    # both DELETEs are time-bounded and parameterized by the day count
    assert all("make_interval" in sql for sql, _ in conn.cur.executed)
    assert all(params == (30,) for _, params in conn.cur.executed)
    assert "log_events" in conn.cur.executed[0][0]
    assert "incidents" in conn.cur.executed[1][0]
    assert conn.committed


def test_retention_zero_is_noop():
    conn = _FakeConn()
    assert la.purge_old_records(conn, 0) == (0, 0)
    assert conn.cur.executed == []


# --------------------------------------------------------------------------- #
# Plaintext-HTTP push warning
# --------------------------------------------------------------------------- #
def _stub_urlopen(monkeypatch):
    class _Resp:
        status = 201
        def __enter__(self): return self
        def __exit__(self, *a): return False

    monkeypatch.setattr(soc_push.urllib.request, "urlopen",
                        lambda req, timeout=None: _Resp())


def test_http_push_emits_plaintext_warning(monkeypatch, capsys):
    _stub_urlopen(monkeypatch)
    soc_push.push_incidents(
        [{"incident_type": "brute_force", "source_ip": "1.2.3.4", "event_count": 5}],
        "http://localhost:8000/api/alerts",
    )
    assert "plaintext HTTP" in capsys.readouterr().err


def test_https_push_emits_no_warning(monkeypatch, capsys):
    _stub_urlopen(monkeypatch)
    soc_push.push_incidents(
        [{"incident_type": "brute_force", "source_ip": "1.2.3.4", "event_count": 5}],
        "https://soc.example.com/api/alerts",
    )
    assert "plaintext HTTP" not in capsys.readouterr().err
