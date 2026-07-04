#!/usr/bin/env python3
"""
Produce ground-truth labels for the Loghub OpenSSH sample (real data).

Source: logpai/loghub -> OpenSSH/OpenSSH_2k.log  (the public "LabSZ" capture,
an internet-facing OpenSSH server logged over ~2 days while under continuous
SSH brute-force from the internet). It is widely used as an attack dataset in
log-analysis research.

Labeling policy (domain knowledge — deliberately NOT the detector's rule, so
the evaluation is not circular):

  * Every source IP that presents failed credential attempts against this
    server is a remote attacker. The usernames are classic spray targets
    (webmaster, test, admin, oracle, ...) coming from foreign IPs, and the
    host is a public SSH server with no legitimate password-guessing users.
    -> class "brute_force", malicious = true.

  * The single successful interactive login (user 'fztu', which never appears
    in any failure) is the legitimate operator.
    -> class "benign", malicious = false.

Because the labels come from the data's nature and not from a "5 fails in
10 min" cutoff, the rule detector genuinely MISSES the low-volume attackers
(honest false negatives) — which is the point: it shows where thresholds fail
and where the ML layer earns its keep.

Usage:  python eval/label_loghub.py
Writes: eval/corpus/loghub_openssh_2k.labels.json
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import log_analyzer as la  # noqa: E402

LOG = HERE / "corpus" / "loghub_openssh_2k.log"
OUT = HERE / "corpus" / "loghub_openssh_2k.labels.json"


def main() -> None:
    events = la.parse_ssh_log(str(LOG))
    fails: Counter[str] = Counter()
    success: set[str] = set()
    for e in events:
        if e["event_type"] == "failed_login":
            fails[e["source_ip"]] += 1
        elif e["event_type"] == "successful_login":
            success.add(e["source_ip"])

    labels: dict[str, dict] = {}
    for ip in success:
        if fails.get(ip, 0) == 0:            # success-only -> legitimate operator
            labels[ip] = {"class": "benign", "malicious": False,
                          "note": "sole successful interactive login (operator)"}
    for ip, n in fails.items():
        labels[ip] = {"class": "brute_force", "malicious": True,
                      "failed_attempts": n,
                      "note": "remote credential attack against public SSH server"}

    n_mal = sum(1 for v in labels.values() if v["malicious"])
    doc = {
        "dataset": "loghub-OpenSSH_2k (LabSZ, real internet-facing SSH server)",
        "source": "https://github.com/logpai/loghub -> OpenSSH/OpenSSH_2k.log",
        "provenance": "hand-labeled by dataset domain knowledge (see label_loghub.py); "
                      "labels are independent of the detector threshold",
        "unit": "source_ip",
        "benign_default": True,
        "classes": ["brute_force", "benign"],
        "counts": {"total_ips": len(labels), "malicious": n_mal,
                   "benign": len(labels) - n_mal},
        "allowlist": [],
        "labels": labels,
    }
    OUT.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    print(f"Written: {OUT}")
    print(f"  {len(labels)} IPs labeled: {n_mal} malicious / {len(labels)-n_mal} benign")


if __name__ == "__main__":
    main()
