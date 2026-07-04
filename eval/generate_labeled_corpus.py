#!/usr/bin/env python3
"""
Generate a *labeled* SSH auth.log corpus for the evaluation harness.

Unlike generate_test_logs.py (which produces fixtures for functional tests),
this emits a log file **plus a companion ground-truth labels file** so that
eval_harness.py can compute precision / recall / F1 and a confusion matrix.

Ground truth is known *by construction*: every source IP is placed into the
log with a pre-declared class, and the same class is written to the labels
JSON. This is the most defensible kind of labeled benchmark — the labels
cannot drift from the data because both come from one source of truth.

The corpus deliberately includes two **false-positive traps** — benign IPs
that a naive 5-fails-in-10-min rule flags as brute force — so the harness can
demonstrate *measured* false-positive reduction, not just detection.

Usage
-----
    python eval/generate_labeled_corpus.py
    # writes eval/corpus/labeled_ssh.log
    #        eval/corpus/labeled_ssh.labels.json
"""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta
from pathlib import Path

BASE = datetime(2024, 6, 15, 2, 0, 0)
HERE = Path(__file__).resolve().parent
CORPUS_DIR = HERE / "corpus"

USERNAMES = ["root", "admin", "ubuntu", "pi", "deploy", "git", "postgres",
             "oracle", "user", "test", "dev", "ops", "service", "backup"]
LEGIT_USERS = ["alice", "bob", "charlie", "diana", "evan"]


def _ts(t: datetime) -> str:
    return t.strftime("%b %d %H:%M:%S")


def _failed(t: datetime, user: str, ip: str, invalid: bool = False) -> str:
    who = f"invalid user {user}" if invalid else user
    port = random.randint(40000, 65000)
    return (f"{_ts(t)} server sshd[{random.randint(1000,9999)}]: "
            f"Failed password for {who} from {ip} port {port} ssh2")


def _accepted(t: datetime, user: str, ip: str) -> str:
    port = random.randint(40000, 65000)
    return (f"{_ts(t)} server sshd[{random.randint(1000,9999)}]: "
            f"Accepted password for {user} from {ip} port {port} ssh2")


def _connection(t: datetime, ip: str, port: int) -> str:
    return (f"{_ts(t)} server sshd[{random.randint(1000,9999)}]: "
            f"Connection from {ip} port {port} on 0.0.0.0 port 22")


def build() -> tuple[list[tuple[datetime, str]], dict]:
    random.seed(42)
    lines: list[tuple[datetime, str]] = []
    labels: dict[str, dict] = {}

    def mark(ip, cls, malicious, **extra):
        labels[ip] = {"class": cls, "malicious": malicious, **extra}

    # ── Brute-force attackers (rule-detectable) ───────────────────────────────
    # Dense bursts, many distinct usernames sprayed, no successful login.
    for ip, n in [("185.220.101.10", 40), ("45.33.32.156", 25), ("194.165.16.77", 15)]:
        mark(ip, "brute_force", True, note="dense burst, many usernames, no success")
        t = BASE + timedelta(minutes=random.randint(0, 5))
        for _ in range(n):
            t += timedelta(seconds=random.randint(2, 18))
            lines.append((t, _failed(t, random.choice(USERNAMES), ip)))

    # ── Port scanners (rule-detectable) ───────────────────────────────────────
    for ip, n in [("203.0.113.42", 30), ("198.51.100.100", 25)]:
        mark(ip, "port_scan", True, note="many unique source ports, single burst")
        t = BASE + timedelta(minutes=random.randint(5, 20))
        for i in range(n):
            t += timedelta(seconds=random.randint(1, 8))
            lines.append((t, _connection(t, ip, 20000 + i * 73)))

    # ── Slow credential stuffer (RULE-INVISIBLE, ML-only) ─────────────────────
    # ~1 attempt every 5-8 min → never 5-in-10-min, but behaviourally anomalous
    # (all failures, all invalid users, many distinct usernames, spans hours).
    stuffer = "91.108.4.200"
    mark(stuffer, "anomaly", True, note="slow stuffer, below rule threshold, ML-only")
    t = BASE
    for _ in range(30):
        t += timedelta(minutes=random.randint(5, 8))
        lines.append((t, _failed(t, random.choice(USERNAMES), stuffer, invalid=True)))

    # ── Benign: corporate gateway with legitimate logins ──────────────────────
    gw = "172.16.0.10"
    mark(gw, "benign", False, note="corporate gateway, only successful logins")
    for user in LEGIT_USERS:
        for _ in range(random.randint(3, 8)):
            t = BASE + timedelta(minutes=random.randint(0, 120))
            lines.append((t, _accepted(t, user, gw)))

    # ── Benign: background noise IPs (below threshold) ────────────────────────
    for i in range(15):
        ip = f"10.10.{i}.5"
        mark(ip, "benign", False, note="occasional failed login, below threshold")
        for _ in range(random.randint(1, 4)):
            t = BASE + timedelta(minutes=random.randint(0, 120))
            lines.append((t, _failed(t, random.choice(USERNAMES), ip)))

    # ── FP TRAP A: fat-fingered legit user ────────────────────────────────────
    # 6 failures for ONE username in 3 min, then a successful login. Trips the
    # naive rule (>=5 fails/10min) but is obviously a human mistyping a password.
    # Lever: suppress when a single username fails then succeeds in-window.
    trap_a = "172.16.9.9"
    mark(trap_a, "benign", False, fp_trap=True,
         note="legit user 'carol' mistypes password 6x then logs in")
    t = BASE + timedelta(minutes=30)
    for _ in range(6):
        t += timedelta(seconds=random.randint(10, 25))
        lines.append((t, _failed(t, "carol", trap_a)))
    t += timedelta(seconds=20)
    lines.append((t, _accepted(t, "carol", trap_a)))

    # ── FP TRAP B: internal auth-monitoring service account ───────────────────
    # 8 failures for one service account, no success (it verifies auth is
    # enforced). Trips the rule; benign. Lever: allowlist known-internal IPs.
    trap_b = "10.0.0.9"
    mark(trap_b, "benign", False, fp_trap=True, allowlist_candidate=True,
         note="internal 'svc-monitor' health check, single account, no success")
    t = BASE + timedelta(minutes=45)
    for _ in range(8):
        t += timedelta(seconds=random.randint(15, 40))
        lines.append((t, _failed(t, "svc-monitor", trap_b)))

    lines.sort(key=lambda x: x[0])
    return lines, labels


def main() -> None:
    CORPUS_DIR.mkdir(parents=True, exist_ok=True)
    lines, labels = build()

    log_path = CORPUS_DIR / "labeled_ssh.log"
    with open(log_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(line for _, line in lines) + "\n")

    n_mal = sum(1 for v in labels.values() if v["malicious"])
    labels_doc = {
        "dataset": "synthetic-labeled-ssh-v1",
        "provenance": "generated by eval/generate_labeled_corpus.py "
                      "(ground truth known by construction)",
        "unit": "source_ip",
        "benign_default": True,
        "classes": ["brute_force", "port_scan", "anomaly", "benign"],
        "counts": {"total_ips": len(labels), "malicious": n_mal,
                   "benign": len(labels) - n_mal},
        "allowlist": [ip for ip, v in labels.items() if v.get("allowlist_candidate")],
        "labels": labels,
    }
    labels_path = CORPUS_DIR / "labeled_ssh.labels.json"
    with open(labels_path, "w", encoding="utf-8") as fh:
        json.dump(labels_doc, fh, indent=2)

    print(f"Written: {log_path}  ({len(lines)} lines)")
    print(f"Written: {labels_path}  ({len(labels)} labeled IPs: "
          f"{n_mal} malicious / {len(labels) - n_mal} benign, "
          f"{sum(1 for v in labels.values() if v.get('fp_trap'))} FP traps)")


if __name__ == "__main__":
    main()
