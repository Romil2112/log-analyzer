#!/usr/bin/env python3
"""
Labeled-evaluation harness for log-analyzer.

Runs the real detection pipeline (parse -> rule detectors -> Isolation Forest)
over a labeled corpus and reports a confusion matrix, precision / recall / F1,
and the explicit false-positive / false-negative lists. It evaluates three
configurations so the impact of each layer is measurable:

  1. rules              -- brute-force + port-scan rules as shipped
  2. rules+fp_reduction -- same rules with false-positive suppression levers
  3. full  (default)    -- rules+fp_reduction plus the ML anomaly layer

Evaluation unit is the **source IP** (that is the unit the detectors emit and
the unit ground truth is labeled at). An IP counts as a true positive when it
is genuinely malicious AND flagged by the configuration under test.

Labels file format (JSON)
-------------------------
    {
      "unit": "source_ip",
      "benign_default": true,          # IPs seen but unlabeled -> benign
      "allowlist": ["10.0.0.9"],       # known-good IPs (fp-reduction lever)
      "labels": {
        "185.220.101.10": {"class": "brute_force", "malicious": true},
        "172.16.9.9":     {"class": "benign", "malicious": false, "fp_trap": true}
      }
    }

This same format is used for the synthetic corpus AND for a hand-labeled real
corpus (e.g. a Loghub SSH slice) -- see eval/README.md.

Usage
-----
    python eval/eval_harness.py eval/corpus/labeled_ssh.log \
        --labels eval/corpus/labeled_ssh.labels.json
    python eval/eval_harness.py <log> --labels <json> --config rules
    python eval/eval_harness.py <log> --labels <json> --json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# log_analyzer.py lives one directory up (repo root).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import log_analyzer as la  # noqa: E402

CONFIGS = ("rules", "rules+fp_reduction", "full")


# ── Corpus / label loading ────────────────────────────────────────────────────

def load_events(log_path: str) -> list[dict]:
    fmt = la.detect_log_format(log_path)
    if fmt == "ssh":
        return la.parse_ssh_log(log_path)
    if fmt == "web":
        return la.parse_web_log(log_path)
    return la.parse_windows_csv(log_path)


def load_labels(labels_path: str) -> dict:
    with open(labels_path, encoding="utf-8") as fh:
        return json.load(fh)


def ground_truth(events: list[dict], labels_doc: dict) -> dict[str, bool]:
    """Map every IP present in the corpus to malicious(True)/benign(False)."""
    labels = labels_doc.get("labels", {})
    benign_default = labels_doc.get("benign_default", True)
    ips = {e["source_ip"] for e in events if e.get("source_ip")}
    gt: dict[str, bool] = {}
    for ip in ips:
        if ip in labels:
            gt[ip] = bool(labels[ip].get("malicious", False))
        elif benign_default:
            gt[ip] = False
        # else: leave unlabeled IPs out of scoring entirely
    return gt


# ── Per-IP evidence used by the false-positive levers ─────────────────────────

def _per_ip_evidence(events: list[dict]) -> dict[str, dict]:
    ev: dict[str, dict] = {}
    for e in events:
        ip = e.get("source_ip")
        if not ip:
            continue
        d = ev.setdefault(ip, {"failed_users": set(), "has_success": False,
                               "invalid_fails": 0, "total_fails": 0})
        if e["event_type"] == "failed_login":
            d["total_fails"] += 1
            if e.get("username"):
                d["failed_users"].add(e["username"])
            if "invalid user" in (e.get("raw_line") or ""):
                d["invalid_fails"] += 1
        elif e["event_type"] == "successful_login":
            d["has_success"] = True
    return ev


def fp_suppress_reason(ip: str, evidence: dict, allowlist: set[str]) -> str | None:
    """Return why a brute-force flag on `ip` is a likely false positive, else None."""
    if ip in allowlist:
        return "allowlisted (known-good internal IP)"
    d = evidence.get(ip, {})
    # A single username that fails a few times then succeeds is a human typo,
    # not a spray attack (attackers try many usernames and rarely succeed).
    if len(d.get("failed_users", ())) <= 1 and d.get("has_success"):
        return "single username failed then succeeded (fat-finger, not a spray)"
    return None


# ── Prediction sets ───────────────────────────────────────────────────────────

def predict(events: list[dict], labels_doc: dict, config: str) -> tuple[set[str], dict]:
    """Return (predicted_malicious_ips, detail) for a configuration."""
    if config not in CONFIGS:
        raise ValueError(f"config must be one of {CONFIGS}")

    bf = {i["source_ip"] for i in la.detect_brute_force(events)}
    scan = {i["source_ip"] for i in la.detect_port_scan(events)}
    rule_flagged = bf | scan

    detail: dict = {"brute_force": sorted(bf), "port_scan": sorted(scan),
                    "suppressed": {}, "ml_flagged": []}

    if config == "rules":
        return set(rule_flagged), detail

    # false-positive reduction: only brute-force flags are eligible for
    # suppression (port scans have no benign look-alike here).
    allowlist = set(labels_doc.get("allowlist", []))
    evidence = _per_ip_evidence(events)
    reduced = set(rule_flagged)
    for ip in bf:
        reason = fp_suppress_reason(ip, evidence, allowlist)
        if reason:
            reduced.discard(ip)
            detail["suppressed"][ip] = reason

    if config == "rules+fp_reduction":
        return reduced, detail

    # full system: add the ML anomaly layer (catches slow, rule-invisible IPs)
    scores = la.AnomalyDetector().fit_score(events)
    ml = {ip for ip, s in scores.items() if s >= la.ML_ANOMALY_THRESHOLD}
    detail["ml_flagged"] = sorted(ml)
    detail["ml_scores"] = {ip: scores[ip] for ip in sorted(scores)}
    return reduced | ml, detail


# ── Scoring ───────────────────────────────────────────────────────────────────

def score(gt: dict[str, bool], predicted: set[str]) -> dict:
    tp = sorted(ip for ip, m in gt.items() if m and ip in predicted)
    fn = sorted(ip for ip, m in gt.items() if m and ip not in predicted)
    fp = sorted(ip for ip, m in gt.items() if not m and ip in predicted)
    tn = sorted(ip for ip, m in gt.items() if not m and ip not in predicted)
    p = len(tp) / (len(tp) + len(fp)) if (tp or fp) else 1.0
    r = len(tp) / (len(tp) + len(fn)) if (tp or fn) else 1.0
    f1 = 2 * p * r / (p + r) if (p + r) else 0.0
    acc = (len(tp) + len(tn)) / len(gt) if gt else 1.0
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": round(p, 4), "recall": round(r, 4),
            "f1": round(f1, 4), "accuracy": round(acc, 4)}


def evaluate(log_path: str, labels_path: str) -> dict:
    """Run all three configurations. Returns a full result dict (used by tests)."""
    events = load_events(log_path)
    labels_doc = load_labels(labels_path)
    gt = ground_truth(events, labels_doc)
    results = {}
    for cfg in CONFIGS:
        predicted, detail = predict(events, labels_doc, cfg)
        results[cfg] = {"metrics": score(gt, predicted), "detail": detail}
    return {"log": log_path, "labels": labels_path,
            "n_events": len(events), "n_ips": len(gt),
            "n_malicious": sum(1 for m in gt.values() if m),
            "configs": results}


# ── Reporting ─────────────────────────────────────────────────────────────────

def _bar(title: str) -> None:
    print("\n" + title)
    print("─" * len(title))


def report(result: dict, only: str | None = None) -> None:
    print("═" * 68)
    print(f"  LABELED EVALUATION  —  {Path(result['log']).name}")
    print("═" * 68)
    print(f"  events parsed : {result['n_events']:,}")
    print(f"  IPs scored    : {result['n_ips']}  "
          f"({result['n_malicious']} malicious / "
          f"{result['n_ips'] - result['n_malicious']} benign)")

    rows = []
    for cfg, data in result["configs"].items():
        if only and cfg != only:
            continue
        m = data["metrics"]
        rows.append((cfg, m))

    _bar("CONFUSION MATRIX & METRICS (per source IP)")
    print(f"  {'configuration':<22}{'TP':>4}{'FP':>4}{'FN':>4}{'TN':>4}"
          f"{'precision':>11}{'recall':>9}{'F1':>8}")
    for cfg, m in rows:
        print(f"  {cfg:<22}{len(m['tp']):>4}{len(m['fp']):>4}"
              f"{len(m['fn']):>4}{len(m['tn']):>4}"
              f"{m['precision']:>11.3f}{m['recall']:>9.3f}{m['f1']:>8.3f}")

    # Detail for the last (most complete) shown config.
    cfg, data = (rows[-1][0], result["configs"][rows[-1][0]])
    m = data["metrics"]
    detail = data["detail"]

    if detail.get("suppressed"):
        _bar(f"FALSE-POSITIVE LEVERS APPLIED ({cfg})")
        for ip, reason in detail["suppressed"].items():
            print(f"  - {ip:<18} suppressed: {reason}")

    _bar(f"FALSE POSITIVES ({cfg}): {len(m['fp'])}")
    for ip in m["fp"]:
        print(f"  ! {ip}  (benign flagged as malicious)")
    if not m["fp"]:
        print("  (none)")

    _bar(f"FALSE NEGATIVES ({cfg}): {len(m['fn'])}")
    for ip in m["fn"]:
        print(f"  ? {ip}  (malicious, missed)")
    if not m["fn"]:
        print("  (none)")

    if len(result["configs"]) > 1 and not only:
        base = result["configs"]["rules"]["metrics"]
        full = result["configs"]["full"]["metrics"]
        _bar("NET EFFECT: rules  →  full system")
        print(f"  precision : {base['precision']:.3f}  →  {full['precision']:.3f}")
        print(f"  recall    : {base['recall']:.3f}  →  {full['recall']:.3f}")
        print(f"  F1        : {base['f1']:.3f}  →  {full['f1']:.3f}")
    print()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("logfile", help="Path to the labeled log file")
    ap.add_argument("--labels", required=True, help="Path to the labels JSON")
    ap.add_argument("--config", choices=CONFIGS, help="Show only one configuration")
    ap.add_argument("--json", action="store_true", help="Emit raw result JSON")
    args = ap.parse_args()

    result = evaluate(args.logfile, args.labels)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        report(result, only=args.config)


if __name__ == "__main__":
    main()
