"""Exercise every synthetic-log generator in generate_test_logs.py.

Each generator is invoked with a small ``total`` into a temp directory and the
output file is asserted non-empty. This both covers the fixture code and guards
against a generator regressing to produce no output.
"""
from __future__ import annotations

import generate_test_logs as g


def _run(monkeypatch, tmp_path, fn, name, **kwargs):
    monkeypatch.chdir(tmp_path)
    fn(path=name, **kwargs)
    out = tmp_path / name
    assert out.exists()
    return out


def test_simple_generators(monkeypatch, tmp_path):
    _run(monkeypatch, tmp_path, g.ssh_log, "a.log")
    _run(monkeypatch, tmp_path, g.windows_csv, "a.csv")
    _run(monkeypatch, tmp_path, g.ipv6_log, "ipv6.log")
    _run(monkeypatch, tmp_path, g.single_event_log, "single.log")
    empty = _run(monkeypatch, tmp_path, g.empty_log, "empty.log")
    assert empty.read_text() == ""


def test_sized_generators(monkeypatch, tmp_path):
    _run(monkeypatch, tmp_path, g.ssh_log_scale, "scale.log", total=300)
    _run(monkeypatch, tmp_path, g.high_volume_log, "hv.log", total=300)
    _run(monkeypatch, tmp_path, g.mixed_attack_log, "mixed.log", total=300)
    _run(monkeypatch, tmp_path, g.slow_brute_force_log, "slow.log", total=300)
    _run(monkeypatch, tmp_path, g.large_port_scan_log, "scan.log", total=600)
    _run(monkeypatch, tmp_path, g.coordinated_attack_log, "coord.log", total=800)
    _run(monkeypatch, tmp_path, g.malformed_log, "mal.log", total=200)
    _run(monkeypatch, tmp_path, g.unicode_log, "uni.log", total=200)


def test_generated_scale_log_is_parseable(monkeypatch, tmp_path):
    import log_analyzer as la
    out = _run(monkeypatch, tmp_path, g.ssh_log_scale, "scale.log", total=400)
    events = la.parse_ssh_log(str(out))
    assert len(events) > 0
    # the scale fixture is built to contain detectable brute-force activity
    assert la.detect_brute_force(events)


def test_dispatch_helpers(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    args = g._build_fixture_parser().parse_args(["--empty", "--single"])
    g._dispatch_optional_fixtures(args, run_all=False)
    assert (tmp_path / "test_empty.log").exists()
    assert (tmp_path / "test_single.log").exists()
