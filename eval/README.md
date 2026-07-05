# Labeled Evaluation Harness

Measures the detection pipeline against **ground-truth labels** and reports a
confusion matrix, precision / recall / F1, and the explicit false-positive and
false-negative lists — per source IP, the unit the detectors actually emit.

It exists to answer the two questions a reviewer asks about any detector:

1. **Does it work on real data?** — yes: it runs on a real Loghub SSH capture.
2. **How good is the classification, and can you reduce false positives with
   evidence?** — yes: metrics move measurably as each layer is added.

```
python eval/generate_labeled_corpus.py         # synthetic corpus + labels
python eval/eval_harness.py eval/corpus/labeled_ssh.log \
       --labels eval/corpus/labeled_ssh.labels.json
```

## What it evaluates

Three configurations, so the contribution of each layer is measurable:

| config | what it is |
|--------|------------|
| `rules` | brute-force + port-scan rules exactly as shipped (5 fails / 10 min; 20 ports / 5 min) |
| `rules+fp_reduction` | same rules with false-positive suppression levers applied |
| `full` (default) | `rules+fp_reduction` **plus** the Isolation Forest anomaly layer |

### False-positive levers (the "I measured FPs, then reduced them" story)

Applied to brute-force flags in `eval_harness.py`:

1. **Allowlist** — known-good internal IPs (e.g. an auth-monitoring service
   account) are never alerted on.
2. **Fat-finger suppression** — a *single* username that fails a few times then
   **succeeds** is a human typo, not a spray (attackers try many usernames and
   rarely succeed). Suppressed.

A third documented lever — treat `invalid user ...` failures as higher
confidence than a valid user's typo — is available in the parsed evidence
(`raw_line` carries the `invalid user` marker) and discussed below.

## Results

### Synthetic corpus — `labeled_ssh.log` (24 IPs: 6 malicious / 18 benign)

Ground truth is known **by construction** (the generator writes the log and the
labels from one source of truth). It deliberately contains two FP traps: a
fat-fingered legit user and an internal monitoring account.

| config | TP | FP | FN | precision | recall | F1 |
|--------|----|----|----|-----------|--------|----|
| rules | 5 | 2 | 1 | 0.714 | 0.833 | 0.769 |
| rules+fp_reduction | 5 | 0 | 1 | **1.000** | 0.833 | 0.909 |
| full | 6 | 1 | 0 | 0.857 | **1.000** | 0.923 |

Reading: the FP levers remove both traps (precision 0.71 → 1.00); the ML layer
then recovers the slow credential-stuffer that the rules structurally miss
(recall 0.83 → 1.00), at the cost of one honest false positive — the
high-volume corporate gateway, which the anomaly model finds statistically
unusual. That precision/recall trade is real and is the point; a rigged 1.0/1.0
would not be.

### Real data — `loghub_openssh_2k.log` (Loghub "LabSZ", 24 IPs: 23 malicious / 1 benign)

Public internet-facing OpenSSH server under continuous brute-force
(`logpai/loghub` → `OpenSSH/OpenSSH_2k.log`). Labeled by dataset domain
knowledge, **independent of the detector threshold** (see `label_loghub.py`), so
the eval is not circular.

| config | TP | FP | FN | precision | recall | F1 |
|--------|----|----|----|-----------|--------|----|
| rules | 9 | 0 | 14 | 1.000 | 0.391 | 0.562 |
| full | 9 | 0 | 14 | 1.000 | 0.391 | 0.562 |

Two honest findings this surfaces on real data:

* **The rule threshold has perfect precision but 39% recall** — it catches the 9
  high-volume attackers and misses 14 low-and-slow ones. That is the real cost
  of a fixed count threshold, quantified.
* **The ML layer adds nothing here**, unlike on the synthetic corpus. When ~96%
  of the population is already attacking, "anomalous vs the crowd" breaks down —
  Isolation Forest assumes attackers are rare outliers, and on a saturated log
  they are the baseline. It only re-flags the 4 most extreme IPs, which the
  rules already caught. Knowing *when* unsupervised anomaly detection helps
  (mostly-benign traffic) versus when it doesn't (saturated attack) is the
  takeaway.

> **Bug this harness caught and fixed.** `detect_port_scan` used to double-flag
> brute-forcers: SSH clients use random ephemeral **source** ports, and the parser
> stored that source port in the same `port` field, so a brute-forcer's many failed
> logins looked like many "unique ports." The fix is one predicate in
> `detect_port_scan`: count only `event_type == "connection"` events, since an auth
> event's port is the client's source port, not a scanned destination. Measured
> result across these corpora: port_scan false positives dropped 6 → 0 (synthetic 2,
> real Loghub 4), port_scan F1 rose 0.40 → 1.00, both genuine scanners were
> preserved, the per-IP metrics above are unchanged, and all 193 tests still pass.
> Fixed in commit `1662e4d`.

## Label file format

The same JSON drives both the synthetic and the real corpus:

```json
{
  "unit": "source_ip",
  "benign_default": true,            // IPs seen but unlabeled -> benign
  "allowlist": ["10.0.0.9"],         // fp-reduction lever
  "labels": {
    "185.220.101.10": {"class": "brute_force", "malicious": true},
    "172.16.9.9":     {"class": "benign", "malicious": false, "fp_trap": true}
  }
}
```

### Hand-labeling your own corpus (e.g. a bigger Loghub slice)

1. Get an SSH auth log the parser understands (syslog `Mon DD HH:MM:SS ...
   Failed/Accepted password for USER from IP port N`).
2. Decide, by **domain knowledge** (not the detector's rule), which source IPs
   are malicious. `label_loghub.py` shows a reproducible policy.
3. Write the labels JSON above and run `eval_harness.py`.

## Academic benchmarks (anomaly layer)

**CIC-IDS2017 / CSE-CIC-IDS2018** (UNB) are the standard labeled benchmarks to
validate the anomaly component against. Note they are **CICFlowMeter network-flow
CSVs** (columns like `Flow Duration`, `Total Fwd Packets`), *not* auth-log or
Windows-Event-CSV records — they are **not** parser input. To use them you write
a small flow→feature adapter feeding the Isolation Forest; cite them as the
benchmark for the anomaly model, not for the log parsers.

## Files

| file | purpose |
|------|---------|
| `eval_harness.py` | the evaluator (importable `evaluate()` + CLI) |
| `generate_labeled_corpus.py` | synthetic corpus + ground truth by construction |
| `label_loghub.py` | domain-knowledge labels for the real Loghub sample |
| `corpus/` | generated/downloaded logs + their `.labels.json` |
| `../tests/test_eval_harness.py` | locks in the metrics story |
```
