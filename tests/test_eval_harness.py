"""
Tests for the labeled-evaluation harness (eval/eval_harness.py).

These lock in the metrics story that the harness exists to demonstrate:
  - baseline rules produce the two known false positives (the FP traps) and
    miss the slow credential stuffer,
  - the false-positive levers remove both traps (precision -> 1.0),
  - the ML anomaly layer recovers the stuffer (recall -> 1.0).

The corpus is regenerated into a temp dir from the same builder the shipped
corpus uses, so ground truth and data can never drift apart.
"""

import json
import os
import sys

import pytest

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "eval"))

import eval_harness as eh  # noqa: E402
from generate_labeled_corpus import build  # noqa: E402

import log_analyzer as la  # noqa: E402

# Known IPs from the builder.
STUFFER = "91.108.4.200"
TRAP_FATFINGER = "172.16.9.9"
TRAP_INTERNAL = "10.0.0.9"
BRUTE_IPS = {"185.220.101.10", "45.33.32.156", "194.165.16.77"}
SCAN_IPS = {"203.0.113.42", "198.51.100.100"}


@pytest.fixture(scope="module")
def corpus(tmp_path_factory):
    d = tmp_path_factory.mktemp("labeled")
    lines, labels = build()
    log_path = d / "c.log"
    log_path.write_text("\n".join(line for _, line in lines) + "\n", encoding="utf-8")
    labels_doc = {
        "unit": "source_ip",
        "benign_default": True,
        "allowlist": [ip for ip, v in labels.items() if v.get("allowlist_candidate")],
        "labels": labels,
    }
    labels_path = d / "c.labels.json"
    labels_path.write_text(json.dumps(labels_doc), encoding="utf-8")
    return str(log_path), str(labels_path)


@pytest.fixture(scope="module")
def result(corpus):
    return eh.evaluate(*corpus)


def test_corpus_parses(result):
    assert result["n_events"] > 200
    assert result["n_malicious"] == 6


def test_baseline_rules_have_two_false_positives(result):
    m = result["configs"]["rules"]["metrics"]
    assert set(m["fp"]) == {TRAP_FATFINGER, TRAP_INTERNAL}
    # brute-force + port-scan attackers are all caught by rules
    assert set(m["tp"]) == BRUTE_IPS | SCAN_IPS
    # the slow stuffer is invisible to the rules
    assert STUFFER in m["fn"]


def test_fp_reduction_removes_both_traps(result):
    m = result["configs"]["rules+fp_reduction"]["metrics"]
    assert m["fp"] == []
    assert m["precision"] == 1.0
    detail = result["configs"]["rules+fp_reduction"]["detail"]
    assert set(detail["suppressed"]) == {TRAP_FATFINGER, TRAP_INTERNAL}


def test_full_system_recovers_the_stuffer(result):
    m = result["configs"]["full"]["metrics"]
    assert STUFFER not in m["fn"]
    assert m["recall"] == 1.0
    # ML recall gain should not undo the FP-reduction gains vs baseline
    assert m["precision"] >= result["configs"]["rules"]["metrics"]["precision"]


def test_precision_recall_are_monotone_story(result):
    rules = result["configs"]["rules"]["metrics"]
    reduced = result["configs"]["rules+fp_reduction"]["metrics"]
    full = result["configs"]["full"]["metrics"]
    assert reduced["precision"] > rules["precision"]   # levers help precision
    assert full["recall"] > reduced["recall"]          # ML helps recall


def test_suppression_reason_matches_lever():
    events = la.parse_ssh_log  # sanity: symbol exists
    assert callable(events)
    # fat-finger: single user + success -> suppressed
    ev = {TRAP_FATFINGER: {"failed_users": {"carol"}, "has_success": True}}
    assert eh.fp_suppress_reason(TRAP_FATFINGER, ev, set()) is not None
    # allowlist lever
    assert eh.fp_suppress_reason(TRAP_INTERNAL, {}, {TRAP_INTERNAL}) is not None
    # a genuine spray (many users, no success) is NOT suppressed
    ev2 = {"1.2.3.4": {"failed_users": {"root", "admin", "test"}, "has_success": False}}
    assert eh.fp_suppress_reason("1.2.3.4", ev2, set()) is None
