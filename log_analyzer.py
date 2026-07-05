#!/usr/bin/env python3
"""
log-analyzer: Detect brute force attacks and port scans from SSH auth.log
or Windows Event Log CSV files. Stores events in PostgreSQL, runs
Isolation Forest anomaly detection, maps findings to MITRE ATT&CK, and
generates an HTML incident report with Chart.js visualisations.
"""

import argparse
import csv
import hashlib
import hmac
import ipaddress as _ipaddress
import json
import os
import re
import secrets
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg2
import psycopg2.extras
from dateutil import parser as dateparser
from jinja2 import Template
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

try:
    from ai_summary import ai_summary as _ai_summary
    AI_SUMMARY_AVAILABLE = True
except ImportError:
    AI_SUMMARY_AVAILABLE = False

import contracts
import enrichment
import soc_push
from crypto import encrypt_field, get_fernet

try:
    import sigma_export
    SIGMA_AVAILABLE = True
except ImportError:
    SIGMA_AVAILABLE = False

try:
    import siem_export
    SIEM_AVAILABLE = True
except ImportError:
    SIEM_AVAILABLE = False

console = Console()

# ── Constants ─────────────────────────────────────────────────────────────────

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW    = 10
PORT_SCAN_THRESHOLD   = 20
PORT_SCAN_WINDOW      = 5
ML_ANOMALY_THRESHOLD  = 0.5

# ── MITRE ATT&CK technique definitions ───────────────────────────────────────

MITRE_TECHNIQUES: dict[str, dict] = {
    "brute_force": {
        "id":     "T1110.001",
        "parent": "T1110",
        "name":   "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "url":    "https://attack.mitre.org/techniques/T1110/001/",
    },
    "port_scan": {
        "id":     "T1046",
        "parent": "T1046",
        "name":   "Network Service Discovery",
        "tactic": "Discovery",
        "url":    "https://attack.mitre.org/techniques/T1046/",
    },
    "flood_404": {
        "id":     "T1595.002",
        "parent": "T1595",
        "name":   "Active Scanning: Vulnerability Scanning",
        "tactic": "Reconnaissance",
        "url":    "https://attack.mitre.org/techniques/T1595/002/",
    },
}

# ── Severity scoring ──────────────────────────────────────────────────────────

_SEVERITY_THRESHOLDS: dict[str, list[tuple[int, str]]] = {
    "brute_force": [(100, "CRITICAL"), (30, "HIGH"), (10, "MEDIUM")],
    "port_scan":   [(500, "CRITICAL"), (100, "HIGH"), (50, "MEDIUM")],
    "flood_404":   [(200, "CRITICAL"), (100, "HIGH"), (50, "MEDIUM")],
}

_SEV_RICH: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
}

_SEV_HTML_BG: dict[str, tuple[str, str]] = {
    "CRITICAL": ("#450a0a", "#fca5a5"),
    "HIGH":     ("#431407", "#fb923c"),
    "MEDIUM":   ("#422006", "#fde68a"),
    "LOW":      ("#172554", "#93c5fd"),
}


def get_severity(incident: dict) -> str:
    """Classify an incident's severity from its type and event_count. Returns
    one of "CRITICAL", "HIGH", "MEDIUM", or "LOW"."""
    for threshold, level in _SEVERITY_THRESHOLDS.get(incident["incident_type"], []):
        if incident["event_count"] >= threshold:
            return level
    return "LOW"


def enrich_incidents(incidents: list[dict]) -> list[dict]:
    """Attach severity + MITRE ATT&CK data to every incident in-place."""
    for inc in incidents:
        inc["severity"] = get_severity(inc)
        inc["mitre"]    = MITRE_TECHNIQUES.get(inc["incident_type"], {})
    return incidents


# ── SSH auth.log patterns ─────────────────────────────────────────────────────

_SSH_FAILED  = re.compile(
    r'^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+).*'
    r'Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) '
    r'from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)'
)
_SSH_ACCEPT  = re.compile(
    r'^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+).*'
    r'Accepted (?:password|publickey) for (?P<user>\S+) '
    r'from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)'
)
_SSH_CONNECT = re.compile(
    r'^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+).*'
    r'Connection from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)'
)

# ── Parsing ───────────────────────────────────────────────────────────────────

def _ssh_timestamp(month: str, day: str, time_str: str) -> datetime:
    year = datetime.now().year
    dt = dateparser.parse(f"{month} {day} {year} {time_str}")
    return dt.replace(tzinfo=timezone.utc)


def _line_count(path: str) -> int:
    """Count newlines in a file quickly (binary mode, no decoding overhead)."""
    with open(path, "rb") as fh:
        return sum(1 for _ in fh)


def parse_ssh_log(path: str, progress: Progress | None = None, task=None) -> list[dict]:
    """Parse an SSH auth.log into failed_login, successful_login, and connection
    event dicts. progress/task drive an optional Rich progress bar."""
    events = []
    with open(path, errors="replace") as fh:
        for raw in fh:
            raw = raw.rstrip("\n")
            for pattern, etype in (
                (_SSH_FAILED,  "failed_login"),
                (_SSH_ACCEPT,  "successful_login"),
                (_SSH_CONNECT, "connection"),
            ):
                m = pattern.search(raw)
                if m:
                    g = m.groupdict()
                    events.append({
                        "log_type":   "ssh",
                        "event_type": etype,
                        "event_time": _ssh_timestamp(g["month"], g["day"], g["time"]),
                        "source_ip":  g.get("ip"),
                        "username":   g.get("user"),
                        "port":       int(g["port"]) if g.get("port") else None,
                        "raw_line":   raw,
                    })
                    break
            if progress is not None and task is not None:
                progress.advance(task)
    return events


# Windows Event Log CSV columns (case-insensitive) -> accepted header aliases.
_WINDOWS_COLS = {
    "time": ("timecreated", "time created", "timestamp", "date/time"),
    "eid":  ("eventid", "event id", "id"),
    "ip":   ("ipaddress", "ip address", "source ip", "sourceip"),
    "user": ("targetusername", "username", "user name", "user"),
    "port": ("ipport", "port", "source port", "sourceport"),
}


def _resolve_windows_columns(fieldnames: list[str] | None) -> dict[str, str | None]:
    """Map each logical Windows column to the actual header present (or None)."""
    headers = {h.lower().strip(): h for h in (fieldnames or [])}
    return {
        key: next((headers[c] for c in candidates if c in headers), None)
        for key, candidates in _WINDOWS_COLS.items()
    }


def _col_value(row: dict, col: str | None) -> str | None:
    """Return the stripped value for ``col`` in ``row``, or None if absent."""
    return row.get(col, "").strip() if col else None


def _parse_port(port_raw: str | None) -> int | None:
    """Return the port as int if it is all digits, else None."""
    return int(port_raw) if port_raw and port_raw.isdigit() else None


def _parse_windows_row(row: dict, cols: dict[str, str | None]) -> dict | None:
    """Convert one Windows CSV row into an event dict, or None if it has no timestamp."""
    raw_time = _col_value(row, cols["time"])
    if not raw_time:
        return None
    event_time = dateparser.parse(raw_time)
    if event_time.tzinfo is None:
        event_time = event_time.replace(tzinfo=timezone.utc)
    eid_raw = _col_value(row, cols["eid"])
    eid     = int(eid_raw) if eid_raw else 0
    etype   = {4625: "failed_login", 4624: "successful_login"}.get(eid, f"event_{eid}")
    return {
        "log_type":   "windows",
        "event_type": etype,
        "event_time": event_time,
        "source_ip":  _col_value(row, cols["ip"]) or None,
        "username":   _col_value(row, cols["user"]) or None,
        "port":       _parse_port(_col_value(row, cols["port"])),
        "raw_line":   json.dumps(dict(row)),
    }


def parse_windows_csv(path: str, progress: Progress | None = None, task=None) -> list[dict]:
    """
    Expects columns (case-insensitive): TimeCreated, EventID, IpAddress,
    TargetUserName, IpPort. EventID 4625 = failed logon, 4624 = successful.
    """
    events = []
    with open(path, newline="", errors="replace") as fh:
        reader = csv.DictReader(fh)
        cols   = _resolve_windows_columns(reader.fieldnames)
        for row in reader:
            try:
                event = _parse_windows_row(row, cols)
            except (ValueError, TypeError):
                event = None
            if event is not None:
                events.append(event)
            if progress is not None and task is not None:
                progress.advance(task)
    return events


# ── Apache/Nginx access-log parsing ───────────────────────────────────────────

_WEB_LINE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" (?P<status>\d{3})'
)


def _web_timestamp(ts: str) -> datetime:
    try:
        return datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        dt = dateparser.parse(ts)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def parse_web_log(path: str, progress: Progress | None = None, task=None) -> list[dict]:
    """Parse Apache/Nginx combined/common access logs. HTTP 404s become
    ``http_404`` events, which feed the 404-flood / scanning detector."""
    events = []
    with open(path, errors="replace") as fh:
        for raw in fh:
            raw = raw.rstrip("\n")
            m = _WEB_LINE.search(raw)
            if m:
                g = m.groupdict()
                status = int(g["status"])
                events.append({
                    "log_type":   "apache_nginx",
                    "event_type": "http_404" if status == 404 else "http_request",
                    "event_time": _web_timestamp(g["ts"]),
                    "source_ip":  g["ip"],
                    "username":   None,
                    "port":       None,
                    "raw_line":   raw,
                })
            if progress is not None and task is not None:
                progress.advance(task)
    return events


def detect_log_format(path: str) -> str:
    """Guess a log file's format from its extension and first line — returns
    "windows", "web", or "ssh"."""
    ext = Path(path).suffix.lower()
    if ext == ".csv":
        return "windows"
    with open(path, errors="replace") as fh:
        first = fh.readline()
    if _WEB_LINE.search(first):
        return "web"
    if re.match(r'^\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}', first):
        return "ssh"
    return "windows"


# ── Rule-based detection ──────────────────────────────────────────────────────

def _first_time_window(
    times: list[datetime],
    window: timedelta,
    threshold: int,
) -> list[datetime] | None:
    """Return the first sliding time window containing >= ``threshold`` events."""
    for i in range(len(times)):
        window_times = [t for t in times[i:] if t - times[i] <= window]
        if len(window_times) >= threshold:
            return window_times
    return None


def detect_brute_force(events: list[dict]) -> list[dict]:
    """Flag brute-force attacks: many failed logins from one IP inside the sliding
    window. Returns one brute_force incident per offending source IP."""
    by_ip: dict[str, list[datetime]] = defaultdict(list)
    for e in events:
        if e["event_type"] == "failed_login" and e.get("source_ip"):
            by_ip[e["source_ip"]].append(e["event_time"])

    incidents = []
    window = timedelta(minutes=BRUTE_FORCE_WINDOW)
    for ip, times in by_ip.items():
        times.sort()
        window_times = _first_time_window(times, window, BRUTE_FORCE_THRESHOLD)
        if window_times:
            incidents.append({
                "incident_type": "brute_force",
                "source_ip":     ip,
                "first_seen":    window_times[0],
                "last_seen":     window_times[-1],
                "event_count":   len(window_times),
                "details":       {
                    "window_minutes": BRUTE_FORCE_WINDOW,
                    "threshold":      BRUTE_FORCE_THRESHOLD,
                },
            })
    return incidents


def _port_scan_window(
    pairs: list[tuple[datetime, int]],
    times: list[datetime],
    window: timedelta,
) -> tuple[datetime, datetime, set[int]] | tuple[None, None, None]:
    """Return (first_seen, last_seen, unique_ports) for the first window over threshold."""
    for i in range(len(pairs)):
        slice_ = [(t, p) for t, p in pairs[i:] if t - times[i] <= window]
        unique_ports = {p for _, p in slice_}
        if len(unique_ports) >= PORT_SCAN_THRESHOLD:
            slice_times = [t for t, _ in slice_]
            return min(slice_times), max(slice_times), unique_ports
    return None, None, None


def detect_port_scan(events: list[dict]) -> list[dict]:
    """Flag port scans: one IP hitting many distinct ports inside the window.
    Returns one port_scan incident per offending source IP."""
    by_ip: dict[str, list[tuple[datetime, int]]] = defaultdict(list)
    for e in events:
        # A port scan is evidenced by connection attempts. An auth event's `port`
        # is the client's ephemeral SOURCE port, not a scanned destination, so a
        # brute-forcer cycling through random source ports would otherwise look
        # like a scanner. Count connection events only.
        if e.get("event_type") == "connection" and e.get("source_ip") and e.get("port"):
            by_ip[e["source_ip"]].append((e["event_time"], e["port"]))

    incidents = []
    window = timedelta(minutes=PORT_SCAN_WINDOW)
    for ip, pairs in by_ip.items():
        pairs.sort()
        times = [p[0] for p in pairs]
        first_seen, last_seen, unique_ports = _port_scan_window(pairs, times, window)
        if unique_ports:
            incidents.append({
                "incident_type": "port_scan",
                "source_ip":     ip,
                "first_seen":    first_seen,
                "last_seen":     last_seen,
                "event_count":   len(unique_ports),
                "details":       {
                    "window_minutes": PORT_SCAN_WINDOW,
                    "threshold":      PORT_SCAN_THRESHOLD,
                    "unique_ports":   sorted(unique_ports),
                },
            })
    return incidents


# ── ML anomaly detection ──────────────────────────────────────────────────────

class AnomalyDetector:
    """
    Unsupervised anomaly detector using scikit-learn's Isolation Forest.

    Builds a behavioural feature vector for every unique source IP, then fits
    an IsolationForest on the full population.  IPs that deviate most from the
    crowd receive a high normalised anomaly score (0.0 = normal, 1.0 = most
    anomalous).  This catches slow/low-volume attackers that rule-based
    thresholds miss.

    Features (per source IP)
    ------------------------
    failed_logins      : total failed login events
    unique_ports       : number of distinct destination ports contacted
    unique_usernames   : number of distinct usernames tried
    events_per_minute  : overall event rate across the IP's active window
    active_minutes     : time span between first and last event
    night_ratio        : fraction of events occurring 00:00-06:00 UTC
    burst_score        : fraction of total events in the busiest 60-second window
    fail_ratio         : failed_logins / total_events
    """

    MIN_IPS  = 3
    FEATURES = [
        "failed_logins", "unique_ports", "unique_usernames",
        "events_per_minute", "active_minutes", "night_ratio",
        "burst_score", "fail_ratio",
    ]

    @staticmethod
    def _burst_score(times: list[datetime], total: int) -> float:
        # `times` is sorted ascending, so the busiest 60s window is found with a
        # forward two-pointer sweep in O(n) instead of the O(n^2) rescan-per-event
        # this used to do (which blew up to tens of millions of comparisons when a
        # single IP dominated a large log).
        if total <= 1:
            return 1.0
        w    = timedelta(seconds=60)
        n    = len(times)
        best = 0
        j    = 0
        for i in range(n):
            if j < i:
                j = i
            while j < n and times[j] - times[i] <= w:
                j += 1
            best = max(best, j - i)
        return best / total

    @staticmethod
    def _count_features(evts: list[dict]) -> tuple[int, int, int, int]:
        """Return (total_events, failed_logins, unique_ports, unique_usernames)."""
        total = len(evts)
        fails = sum(1 for e in evts if e["event_type"] == "failed_login")
        ports = {e["port"] for e in evts if e.get("port")}
        users = {e.get("username") for e in evts if e.get("username")}
        return total, fails, len(ports), len(users)

    @classmethod
    def _ip_feature_row(cls, evts: list[dict]) -> list[float]:
        """Compute the 8-feature vector for a single source IP's events."""
        times = sorted(e["event_time"] for e in evts)
        total, fails, n_ports, n_users = cls._count_features(evts)
        span_s     = (times[-1] - times[0]).total_seconds() if len(times) > 1 else 0
        active_min = span_s / 60.0
        rate       = total / max(active_min, 1.0)
        night      = sum(1 for t in times if t.hour < 6) / total
        burst      = cls._burst_score(times, total)
        return [
            float(fails), float(n_ports), float(n_users),
            float(rate), float(active_min), float(night),
            float(burst), float(fails / total),
        ]

    def _build_feature_matrix(self, events: list[dict]) -> tuple[list[str], list[list[float]]]:
        by_ip: dict[str, list[dict]] = defaultdict(list)
        for e in events:
            if e.get("source_ip"):
                by_ip[e["source_ip"]].append(e)

        ips, rows = [], []
        for ip, evts in by_ip.items():
            rows.append(self._ip_feature_row(evts))
            ips.append(ip)
        return ips, rows

    def fit_score(self, events: list[dict]) -> dict[str, float]:
        """Return per-IP anomaly scores: 0.0 = normal, 1.0 = most anomalous."""
        if not ML_AVAILABLE:
            return {}
        ips, rows = self._build_feature_matrix(events)
        if len(ips) < self.MIN_IPS:
            return {}
        features        = np.array(rows, dtype=float)
        features_scaled = StandardScaler().fit_transform(features)
        clf             = IsolationForest(n_estimators=200, contamination="auto", random_state=42)
        clf.fit(features_scaled)
        raw    = clf.score_samples(features_scaled)
        lo, hi = raw.min(), raw.max()
        norm   = 1.0 - (raw - lo) / (hi - lo) if hi > lo else np.zeros(len(raw))
        return {ip: float(round(s, 4)) for ip, s in zip(ips, norm, strict=False)}

    def feature_rows(self, events: list[dict]) -> list[dict]:
        """Return the per-IP feature vectors as dicts, each keyed by source_ip plus
        the eight feature names."""
        ips, rows = self._build_feature_matrix(events)
        return [
            {"source_ip": ip, **dict(zip(self.FEATURES, row, strict=False))}
            for ip, row in zip(ips, rows, strict=False)
        ]


# ── Rich terminal display ─────────────────────────────────────────────────────

def _print_header(log_path: str, fmt: str, n_lines: int) -> None:
    console.print(Panel(
        f"[bold cyan]Log Analyzer[/bold cyan]  [dim]|[/dim]  "
        f"[white]{Path(log_path).name}[/white]  [dim]|[/dim]  "
        f"[dim]format: {fmt}  |  {n_lines:,} lines[/dim]",
        border_style="blue",
        padding=(0, 2),
    ))


def _sev_markup(severity: str) -> str:
    style = _SEV_RICH.get(severity, "white")
    return f"[{style}]{severity}[/{style}]"


def print_incident_table(incidents: list[dict]) -> None:
    """Render a Rich table of all detected incidents with severity + MITRE ATT&CK."""
    if not incidents:
        console.print("  [green]No rule-based incidents detected.[/green]")
        return

    tbl = Table(
        title="Detected Incidents",
        box=box.ROUNDED,
        border_style="dim blue",
        show_lines=True,
        title_style="bold white",
        header_style="bold dim",
    )
    tbl.add_column("Type",          style="bold white",  no_wrap=True)
    tbl.add_column("Source IP",     style="cyan",        no_wrap=True)
    tbl.add_column("Count",         justify="right")
    tbl.add_column("Severity",      justify="center",    no_wrap=True)
    tbl.add_column("Duration",      style="dim")
    tbl.add_column("MITRE ID",      style="bold yellow", no_wrap=True)
    tbl.add_column("Tactic",        style="dim yellow",  no_wrap=True)
    tbl.add_column("Technique",     style="dim",         no_wrap=True)

    for inc in sorted(incidents, key=lambda x: -x["event_count"]):
        sev   = inc.get("severity", "LOW")
        mitre = inc.get("mitre", {})
        secs  = int((inc["last_seen"] - inc["first_seen"]).total_seconds())
        dur   = (f"{secs // 3600}h {(secs % 3600) // 60}m"
                 if secs >= 3600 else f"{secs // 60}m {secs % 60}s"
                 if secs >= 60 else f"{secs}s")

        tbl.add_row(
            inc["incident_type"].replace("_", " ").title(),
            inc["source_ip"] or "-",
            str(inc["event_count"]),
            _sev_markup(sev),
            dur,
            mitre.get("id", "-"),
            mitre.get("tactic", "-"),
            mitre.get("name", "-"),
        )

    console.print(tbl)


def _ml_score_markup(score: float) -> str:
    """Return a rich-markup string colouring an anomaly score by severity band."""
    if score >= 0.8:
        return f"[bold red]{score:.4f}[/bold red]"
    if score >= 0.65:
        return f"[red]{score:.4f}[/red]"
    if score >= 0.5:
        return f"[yellow]{score:.4f}[/yellow]"
    return f"[cyan]{score:.4f}[/cyan]"


def print_ml_table(
    anomaly_scores: dict[str, float],
    rule_ips: set[str],
    threshold: float,
) -> None:
    """Render Isolation Forest results; highlight IPs not caught by rules."""
    flagged = {ip: s for ip, s in anomaly_scores.items() if s >= threshold}
    if not flagged:
        return

    tbl = Table(
        title=f"ML Anomaly Scores — Isolation Forest  (threshold >= {threshold})",
        box=box.ROUNDED,
        border_style="dim green",
        show_lines=True,
        title_style="bold white",
        header_style="bold dim",
    )
    tbl.add_column("Source IP",     style="cyan",   no_wrap=True)
    tbl.add_column("Anomaly Score", justify="right")
    tbl.add_column("Detection",     justify="center")

    for ip, score in sorted(flagged.items(), key=lambda x: -x[1]):
        in_rules  = ip in rule_ips
        tag_style = "red" if in_rules else "magenta"
        tag_text  = "Rule + ML" if in_rules else "ML Only"
        tbl.add_row(ip, _ml_score_markup(score), f"[{tag_style}]{tag_text}[/{tag_style}]")

    console.print(tbl)


def _count_mitre_ids(incidents: list[dict]) -> dict[str, int]:
    """Count incidents grouped by their MITRE technique id (ignoring blanks)."""
    counts: dict[str, int] = defaultdict(int)
    for inc in incidents:
        mid = inc.get("mitre", {}).get("id", "")
        if mid:
            counts[mid] += 1
    return counts


def print_mitre_summary(incidents: list[dict]) -> None:
    """Print a compact MITRE ATT&CK coverage panel."""
    seen = _count_mitre_ids(incidents)
    if not seen:
        return

    lines = []
    for tech in MITRE_TECHNIQUES.values():
        count = seen.get(tech["id"], 0)
        if count:
            lines.append(
                f"  [bold yellow]{tech['id']}[/bold yellow]  "
                f"[white]{tech['name']}[/white]  "
                f"[dim]{tech['tactic']}[/dim]  "
                f"[cyan]({count} incident{'s' if count > 1 else ''})[/cyan]"
            )

    if lines:
        console.print(Panel(
            "\n".join(lines),
            title="[bold]MITRE ATT&CK Coverage[/bold]",
            border_style="yellow",
            padding=(0, 2),
        ))


def _first_incident_per_ip(incidents: list[dict]) -> dict[str, dict]:
    """Return the first incident seen for each distinct source IP."""
    by_ip: dict[str, dict] = {}
    for inc in incidents:
        ip = inc.get("source_ip")
        if ip and ip not in by_ip:
            by_ip[ip] = inc
    return by_ip


def _enrichment_line(ip: str, inc: dict) -> str:
    """Format one GeoIP + threat-intel summary line for an attacker IP."""
    intel = "[bold red]KNOWN-BAD[/bold red]" if inc.get("known_bad") else "[green]clean[/green]"
    geo   = inc.get("country", "Unknown")
    return f"  [cyan]{ip:<18}[/cyan] geo=[white]{geo:<8}[/white] intel={intel}"


def print_enrichment_summary(incidents: list[dict]) -> None:
    """Show GeoIP country + threat-intel reputation for each attacker IP."""
    by_ip = _first_incident_per_ip(incidents)
    if not by_ip:
        return

    top   = sorted(by_ip.items(), key=lambda kv: -kv[1]["event_count"])[:15]
    lines = [_enrichment_line(ip, inc) for ip, inc in top]
    bad   = sum(1 for inc in by_ip.values() if inc.get("known_bad"))
    console.print(Panel(
        "\n".join(lines),
        title=f"[bold]IP Enrichment — GeoIP + Threat Intel[/bold]  [dim]({bad} known-bad)[/dim]",
        border_style="magenta",
        padding=(0, 2),
    ))


# ── Database ──────────────────────────────────────────────────────────────────

def get_connection(dsn: str):
    """Open a psycopg2 PostgreSQL connection for the given DSN."""
    return psycopg2.connect(dsn)


def init_schema(conn):
    """Create the database schema by running schema.sql and committing."""
    schema_path = Path(__file__).parent / "schema.sql"
    with conn.cursor() as cur:
        cur.execute(schema_path.read_text())
    conn.commit()


def store_events(conn, events: list[dict], source_file: str, fernet=None):
    """Persist events. When DB_ENCRYPTION_KEY is set, the PII columns
    (source_ip, username, raw_line) are encrypted at rest. Encryption is applied
    to per-row copies so the in-memory events (used for the report) are
    untouched.
    """
    if fernet is None:
        fernet = get_fernet()
    sql = """
        INSERT INTO log_events
            (source_file, event_time, log_type, event_type, source_ip, username, port, raw_line)
        VALUES
            (%(source_file)s, %(event_time)s, %(log_type)s, %(event_type)s,
             %(source_ip)s, %(username)s, %(port)s, %(raw_line)s)
    """
    rows = []
    for e in events:
        row = {**e, "source_file": source_file}
        if fernet is not None:
            row["source_ip"] = encrypt_field(fernet, row.get("source_ip"))
            row["username"] = encrypt_field(fernet, row.get("username"))
            row["raw_line"] = encrypt_field(fernet, row.get("raw_line"))
        rows.append(row)
    with conn.cursor() as cur:
        psycopg2.extras.execute_batch(cur, sql, rows, page_size=500)
    conn.commit()


def store_incidents(conn, incidents: list[dict], fernet=None):
    """Persist incidents, encrypting source_ip at rest when a key is configured."""
    if fernet is None:
        fernet = get_fernet()
    sql = """
        INSERT INTO incidents
            (incident_type, source_ip, first_seen, last_seen, event_count, severity, details)
        VALUES
            (%(incident_type)s, %(source_ip)s, %(first_seen)s, %(last_seen)s,
             %(event_count)s, %(severity)s, %(details)s)
    """
    rows = []
    for i in incidents:
        row = {**i, "details": json.dumps(i["details"])}
        if fernet is not None:
            row["source_ip"] = encrypt_field(fernet, row.get("source_ip"))
        rows.append(row)
    with conn.cursor() as cur:
        psycopg2.extras.execute_batch(cur, sql, rows)
    conn.commit()


def purge_old_records(conn, days: int) -> tuple[int, int]:
    """Delete log_events (by event_time) and incidents (by first_seen) older than
    `days`. No-op when days <= 0. Returns (events_deleted, incidents_deleted).
    """
    if days <= 0:
        return (0, 0)
    with conn.cursor() as cur:
        cur.execute(
            "DELETE FROM log_events WHERE event_time < now() - make_interval(days => %s)",
            (days,),
        )
        events_deleted = cur.rowcount
        cur.execute(
            "DELETE FROM incidents WHERE first_seen < now() - make_interval(days => %s)",
            (days,),
        )
        incidents_deleted = cur.rowcount
    conn.commit()
    return (events_deleted, incidents_deleted)


# ── Privacy controls (scrubbing / redaction / pseudonymization) ─────────────────

def scrub_username(username):
    """Replace a username with a stable, non-reversible SHA-256 pseudonym."""
    if not username:
        return username
    return "user_" + hashlib.sha256(username.encode("utf-8")).hexdigest()[:8]


def make_ip_pseudonymizer():
    """Return an ip->pseudonym function using a random per-process HMAC key.

    The key and the mapping live in memory only and are never written to disk,
    so pseudonyms are stable within a run but not linkable across runs.
    """
    session_key = secrets.token_bytes(32)
    cache: dict = {}

    def pseudonymize(ip):
        """Map an IP to a stable per-run ip_<hmac> pseudonym. Falsy input (an empty
        IP) passes through unchanged."""
        if not ip:
            return ip
        if ip not in cache:
            digest = hmac.new(session_key, ip.encode("utf-8"), hashlib.sha256).hexdigest()
            cache[ip] = "ip_" + digest[:12]
        return cache[ip]

    return pseudonymize


def _apply_pseudonymize(events: list[dict], incidents: list[dict]) -> str:
    """Replace source IPs in events + incidents with per-run HMAC pseudonyms."""
    pseudonymize = make_ip_pseudonymizer()
    for e in events:
        if e.get("source_ip"):
            e["source_ip"] = pseudonymize(e["source_ip"])
    for i in incidents:
        if i.get("source_ip"):
            i["source_ip"] = pseudonymize(i["source_ip"])
    return (
        "IP pseudonymization ACTIVE — source IPs replaced with per-run HMAC "
        "pseudonyms (key in memory only)."
    )


def _apply_scrub_usernames(events: list[dict]) -> str:
    """Replace usernames in events with SHA-256 pseudonyms."""
    for e in events:
        if e.get("username"):
            e["username"] = scrub_username(e["username"])
    return "Username scrubbing ACTIVE — usernames replaced with SHA-256 pseudonyms."


def _apply_no_raw_lines(events: list[dict]) -> str:
    """Redact the raw log line from every event."""
    for e in events:
        e["raw_line"] = None
    return "Raw-line redaction ACTIVE — original log lines are not stored or reported."


def apply_privacy_transforms(
    events: list[dict],
    incidents: list[dict],
    args: argparse.Namespace,
) -> list[str]:
    """Apply opt-in privacy controls to in-memory events/incidents BEFORE they
    are displayed, reported, or stored. Detection and enrichment have already
    run on the original data, so detection logic is unaffected.

    Returns a list of human-readable banner strings describing what was applied.
    """
    banners: list[str] = []
    if getattr(args, "pseudonymize", False):
        banners.append(_apply_pseudonymize(events, incidents))
    if getattr(args, "scrub_usernames", False):
        banners.append(_apply_scrub_usernames(events))
    if getattr(args, "no_raw_lines", False):
        banners.append(_apply_no_raw_lines(events))
    return banners


# ── HTML Report ───────────────────────────────────────────────────────────────

REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Log Analyzer — Incident Report</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"
        integrity="sha384-e6nUZLBkQ86NJ6TVVKAeSaK8jWa3NhkYWZFomE39AvDbQWeie9PlQqM3pmYW5d1g"
        crossorigin="anonymous"></script>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
         background: #0f172a; color: #e2e8f0; }
  a { color: inherit; }
  header { background: #1e293b; padding: 1.5rem 2rem;
           border-bottom: 2px solid #3b82f6; }
  header h1 { font-size: 1.75rem; color: #60a5fa; }
  header p  { color: #94a3b8; margin-top: .3rem; font-size: .9rem; }
  main  { max-width: 1280px; margin: 2rem auto; padding: 0 1.25rem; }
  /* ── Summary cards ── */
  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
           gap: 1rem; margin-bottom: 2rem; }
  .stat-card { background: #1e293b; border-radius: 8px; padding: 1.25rem 1rem;
               border-left: 4px solid #3b82f6; }
  .stat-card .value { font-size: 1.9rem; font-weight: 700; color: #60a5fa; }
  .stat-card .label { font-size: .8rem; color: #94a3b8; margin-top: .2rem; }
  /* ── MITRE coverage cards ── */
  .mitre-grid { display: flex; flex-wrap: wrap; gap: 1rem; margin-top: .75rem; }
  .mitre-card { background: #1e293b; border: 1px solid #334155;
                border-left: 4px solid #f59e0b; border-radius: 8px;
                padding: .9rem 1.25rem; text-decoration: none; color: inherit;
                transition: border-color .2s, background .2s; min-width: 260px; }
  .mitre-card:hover { background: #263047; border-left-color: #fb923c; }
  .mitre-id   { font-family: monospace; font-size: 1.05rem; font-weight: 700; color: #fbbf24; }
  .mitre-name { color: #f1f5f9; margin-top: .2rem; font-size: .9rem; }
  .mitre-meta { font-size: .78rem; color: #64748b; margin-top: .3rem; }
  /* ── Sections ── */
  .section { margin-bottom: 2.5rem; }
  .section h2 { font-size: 1.2rem; color: #f1f5f9; margin-bottom: .75rem;
                padding-bottom: .4rem; border-bottom: 1px solid #334155; }
  .subtitle { font-size: .83rem; color: #64748b; margin-bottom: 1rem; }
  /* ── Charts ── */
  .chart-row  { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem;
                margin-bottom: 1.75rem; }
  .chart-solo { margin-bottom: 1.75rem; }
  .chart-box  { background: #1e293b; border-radius: 8px; padding: 1rem; }
  .chart-box canvas { max-height: 300px; }
  /* ── Tables ── */
  table { width: 100%; border-collapse: collapse; background: #1e293b;
          border-radius: 8px; overflow: hidden; font-size: .875rem; }
  th { background: #0f172a; padding: .7rem 1rem; text-align: left;
       color: #94a3b8; font-weight: 600; text-transform: uppercase;
       font-size: .72rem; letter-spacing: .05em; white-space: nowrap; }
  td { padding: .6rem 1rem; border-top: 1px solid #334155; vertical-align: middle; }
  tr:hover td { background: #263047; }
  /* ── Badges ── */
  .badge { display: inline-block; padding: .2rem .55rem; border-radius: 4px;
           font-size: .73rem; font-weight: 700; white-space: nowrap; }
  .mitre-badge { font-family: monospace; font-size: .82rem; font-weight: 700;
                 color: #fbbf24; text-decoration: none; }
  .mitre-badge:hover { text-decoration: underline; }
  /* ── Score bar ── */
  .score-wrap  { display: flex; align-items: center; gap: .6rem; }
  .score-label { font-family: monospace; font-size: .82rem; min-width: 3.5rem; }
  .bar-track   { flex: 1; background: #0f172a; border-radius: 3px;
                 height: 7px; min-width: 60px; }
  .bar-fill    { height: 7px; border-radius: 3px; }
  @media(max-width: 720px) { .chart-row { grid-template-columns: 1fr; } }
</style>
</head>
<body>
<header>
  <h1>&#x1F6E1; Log Analyzer — Incident Report</h1>
  <p>Generated {{ generated_at }}
     &nbsp;|&nbsp; Source: {{ source_file }}
     {% if ml_enabled %}&nbsp;|&nbsp; <span style="color:#34d399">Isolation Forest active</span>{% endif %}
  </p>
</header>
<main>

  <!-- ── Confidentiality notice ──────────────────────────────────────────── -->
  <div style="background:#422006;border:1px solid #b45309;border-radius:6px;
              padding:.8rem 1rem;margin-bottom:1.25rem;color:#fed7aa;font-size:.9rem;">
    &#x26A0;&#xFE0F; <strong>Confidential — contains potentially personal data.</strong>
    This report may include IP addresses, usernames, and incident details that can
    qualify as personal data under the GDPR, CCPA, and similar laws. Handle, store,
    and share it only in accordance with your organization's data-protection
    obligations.
  </div>

  <!-- ── Summary cards ───────────────────────────────────────────────────── -->
  <div class="stats">
    <div class="stat-card">
      <div class="value">{{ total_events }}</div>
      <div class="label">Events Parsed</div>
    </div>
    <div class="stat-card" style="border-color:#ef4444">
      <div class="value" style="color:#f87171">{{ brute_force_count }}</div>
      <div class="label">Brute Force Incidents</div>
    </div>
    <div class="stat-card" style="border-color:#f59e0b">
      <div class="value" style="color:#fbbf24">{{ port_scan_count }}</div>
      <div class="label">Port Scan Incidents</div>
    </div>
    <div class="stat-card" style="border-color:#06b6d4">
      <div class="value" style="color:#22d3ee">{{ flood_404_count }}</div>
      <div class="label">404 Flood Incidents</div>
    </div>
    <div class="stat-card" style="border-color:#8b5cf6">
      <div class="value" style="color:#a78bfa">{{ unique_ips }}</div>
      <div class="label">Attacker IPs</div>
    </div>
    {% if ml_enabled %}
    <div class="stat-card" style="border-color:#10b981">
      <div class="value" style="color:#34d399">{{ ml_anomaly_count }}</div>
      <div class="label">ML Anomalies</div>
    </div>
    {% endif %}
    <div class="stat-card" style="border-color:#f59e0b">
      <div class="value" style="color:#fbbf24">{{ mitre_coverage | length }}</div>
      <div class="label">MITRE Techniques</div>
    </div>
  </div>

  <!-- ── MITRE ATT&CK coverage ────────────────────────────────────────────── -->
  {% if mitre_coverage %}
  <div class="section">
    <h2>&#x1F3AF; MITRE ATT&CK Coverage</h2>
    <p class="subtitle">Techniques observed in this session, mapped to the ATT&CK framework.
       Click a card to view the full technique description.</p>
    <div class="mitre-grid">
      {% for tech in mitre_coverage %}
      <a href="{{ tech.url }}" target="_blank" rel="noopener" class="mitre-card">
        <div class="mitre-id">{{ tech.id }}</div>
        <div class="mitre-name">{{ tech.name }}</div>
        <div class="mitre-meta">{{ tech.tactic }}&nbsp;&bull;&nbsp;{{ tech.count }} incident{{ 's' if tech.count > 1 else '' }}</div>
      </a>
      {% endfor %}
    </div>
  </div>
  {% endif %}

  <!-- ── Charts ──────────────────────────────────────────────────────────── -->
  <div class="section">
    <h2>Attack Overview</h2>
    <div class="chart-row">
      <div class="chart-box"><canvas id="eventTypeChart"></canvas></div>
      <div class="chart-box"><canvas id="incidentTimelineChart"></canvas></div>
    </div>
    <div class="chart-row">
      <div class="chart-box"><canvas id="topIpChart"></canvas></div>
      <div class="chart-box"><canvas id="incidentTypePie"></canvas></div>
    </div>
    {% if ml_enabled and ml_chart_labels %}
    <div class="chart-solo">
      <div class="chart-box"><canvas id="mlAnomalyChart"></canvas></div>
    </div>
    {% endif %}
  </div>

  <!-- ── ML Anomaly Detection ─────────────────────────────────────────────── -->
  {% if ml_enabled %}
  <div class="section">
    <h2>&#x1F9E0; ML Anomaly Detection — Isolation Forest</h2>
    <p class="subtitle">
      8 behavioural features per source IP (failure rate, port diversity, event velocity,
      burst pattern, night-time ratio) fed into an Isolation Forest (200 trees).
      Score 1.0 = maximally anomalous. Threshold for display: &ge; {{ ml_threshold }}.
    </p>
    {% if ml_anomalies %}
    <table>
      <thead>
        <tr>
          <th>Source IP</th><th>Anomaly Score</th><th>Detection</th>
          <th>Failed Logins</th><th>Unique Ports</th>
          <th>Events / Min</th><th>Burst Score</th><th>Night %</th>
        </tr>
      </thead>
      <tbody>
        {% for a in ml_anomalies %}
        <tr>
          <td><code>{{ a.source_ip }}</code></td>
          <td>
            <div class="score-wrap">
              <span class="score-label">{{ "%.3f"|format(a.anomaly_score) }}</span>
              <div class="bar-track">
                <div class="bar-fill" style="width:{{ (a.anomaly_score*100)|int }}%;background:{{ a.bar_color }};"></div>
              </div>
            </div>
          </td>
          <td>
            <span class="badge" style="background:{{ a.badge_bg }};color:{{ a.badge_fg }};">
              {{ a.detection_type }}
            </span>
          </td>
          <td>{{ a.failed_logins|int }}</td>
          <td>{{ a.unique_ports|int }}</td>
          <td>{{ "%.1f"|format(a.events_per_minute) }}</td>
          <td>{{ "%.2f"|format(a.burst_score) }}</td>
          <td>{{ "%.0f"|format(a.night_ratio * 100) }}%</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
    {% else %}
    <p style="color:#4ade80;">&#x2705; No anomalies above threshold {{ ml_threshold }}.</p>
    {% endif %}
  </div>
  {% endif %}

  <!-- ── Brute Force Incidents ────────────────────────────────────────────── -->
  {% if brute_force_incidents %}
  <div class="section">
    <h2>&#x1F525; Brute Force Incidents</h2>
    <table>
      <thead>
        <tr>
          <th>Source IP</th><th>Severity</th><th>Failed Attempts</th>
          <th>First Seen</th><th>Last Seen</th><th>Duration</th>
          <th>MITRE ATT&CK</th>
          {% if ml_enabled %}<th>Anomaly Score</th>{% endif %}
        </tr>
      </thead>
      <tbody>
        {% for inc in brute_force_incidents %}
        <tr>
          <td><code>{{ inc.source_ip }}</code></td>
          <td>
            <span class="badge"
                  style="background:{{ inc.sev_bg }};color:{{ inc.sev_fg }};">
              {{ inc.severity }}
            </span>
          </td>
          <td>{{ inc.event_count }}</td>
          <td>{{ inc.first_seen }}</td>
          <td>{{ inc.last_seen }}</td>
          <td>{{ inc.duration }}</td>
          <td>
            <a href="{{ inc.mitre_url }}" target="_blank" rel="noopener"
               class="mitre-badge">{{ inc.mitre_id }}</a>
            <div style="font-size:.72rem;color:#64748b;margin-top:.15rem;">
              {{ inc.mitre_tactic }}
            </div>
          </td>
          {% if ml_enabled %}
          <td>
            <div class="score-wrap">
              <span class="score-label">{{ "%.3f"|format(inc.anomaly_score) }}</span>
              <div class="bar-track">
                <div class="bar-fill" style="width:{{ (inc.anomaly_score*100)|int }}%;background:{{ inc.bar_color }};"></div>
              </div>
            </div>
          </td>
          {% endif %}
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% endif %}

  <!-- ── Port Scan Incidents ──────────────────────────────────────────────── -->
  {% if port_scan_incidents %}
  <div class="section">
    <h2>&#x1F50D; Port Scan Incidents</h2>
    <table>
      <thead>
        <tr>
          <th>Source IP</th><th>Severity</th><th>Unique Ports</th>
          <th>First Seen</th><th>Last Seen</th><th>Sample Ports</th>
          <th>MITRE ATT&CK</th>
          {% if ml_enabled %}<th>Anomaly Score</th>{% endif %}
        </tr>
      </thead>
      <tbody>
        {% for inc in port_scan_incidents %}
        <tr>
          <td><code>{{ inc.source_ip }}</code></td>
          <td>
            <span class="badge"
                  style="background:{{ inc.sev_bg }};color:{{ inc.sev_fg }};">
              {{ inc.severity }}
            </span>
          </td>
          <td>{{ inc.event_count }}</td>
          <td>{{ inc.first_seen }}</td>
          <td>{{ inc.last_seen }}</td>
          <td><code style="font-size:.8rem;">{{ inc.sample_ports }}</code></td>
          <td>
            <a href="{{ inc.mitre_url }}" target="_blank" rel="noopener"
               class="mitre-badge">{{ inc.mitre_id }}</a>
            <div style="font-size:.72rem;color:#64748b;margin-top:.15rem;">
              {{ inc.mitre_tactic }}
            </div>
          </td>
          {% if ml_enabled %}
          <td>
            <div class="score-wrap">
              <span class="score-label">{{ "%.3f"|format(inc.anomaly_score) }}</span>
              <div class="bar-track">
                <div class="bar-fill" style="width:{{ (inc.anomaly_score*100)|int }}%;background:{{ inc.bar_color }};"></div>
              </div>
            </div>
          </td>
          {% endif %}
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% endif %}

  {% if flood_404_incidents %}
  <div class="section">
    <h2>&#x26A0;&#xFE0F; 404 Flood Incidents</h2>
    <table>
      <thead>
        <tr>
          <th>Source IP</th><th>Severity</th><th>404 Requests</th>
          <th>First Seen</th><th>Last Seen</th><th>Duration</th>
          <th>MITRE ATT&CK</th>
          {% if ml_enabled %}<th>Anomaly Score</th>{% endif %}
        </tr>
      </thead>
      <tbody>
        {% for inc in flood_404_incidents %}
        <tr>
          <td><code>{{ inc.source_ip }}</code></td>
          <td>
            <span class="badge"
                  style="background:{{ inc.sev_bg }};color:{{ inc.sev_fg }};">
              {{ inc.severity }}
            </span>
          </td>
          <td>{{ inc.event_count }}</td>
          <td>{{ inc.first_seen }}</td>
          <td>{{ inc.last_seen }}</td>
          <td>{{ inc.duration }}</td>
          <td>
            <a href="{{ inc.mitre_url }}" target="_blank" rel="noopener"
               class="mitre-badge">{{ inc.mitre_id }}</a>
            <div style="font-size:.72rem;color:#64748b;margin-top:.15rem;">
              {{ inc.mitre_tactic }}
            </div>
          </td>
          {% if ml_enabled %}
          <td>
            <div class="score-wrap">
              <span class="score-label">{{ "%.3f"|format(inc.anomaly_score) }}</span>
              <div class="bar-track">
                <div class="bar-fill" style="width:{{ (inc.anomaly_score*100)|int }}%;background:{{ inc.bar_color }};"></div>
              </div>
            </div>
          </td>
          {% endif %}
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% endif %}

  {% if not brute_force_incidents and not port_scan_incidents and not flood_404_incidents and not ml_anomalies %}
  <div class="section">
    <p style="color:#4ade80;font-size:1.1rem;">&#x2705; No incidents detected.</p>
  </div>
  {% endif %}

</main>
<script>
const _s = {
  x: { ticks:{color:'#94a3b8'}, grid:{color:'#334155'} },
  y: { ticks:{color:'#94a3b8'}, grid:{color:'#334155'} }
};
const _l = { labels:{color:'#94a3b8'} };

new Chart(document.getElementById('eventTypeChart'), {
  type:'bar',
  data:{ labels:{{ event_type_labels|tojson }},
         datasets:[{label:'Count', data:{{ event_type_values|tojson }},
           backgroundColor:['#3b82f6','#ef4444','#f59e0b','#8b5cf6','#10b981']}] },
  options:{ plugins:{legend:_l, title:{display:true,text:'Events by Type',color:'#f1f5f9'}}, scales:_s }
});

new Chart(document.getElementById('incidentTimelineChart'), {
  type:'line',
  data:{ labels:{{ timeline_labels|tojson }},
    datasets:[
      {label:'Brute Force', data:{{ timeline_bf|tojson }},
       borderColor:'#ef4444', backgroundColor:'rgba(239,68,68,0.15)', tension:0.3, fill:true},
      {label:'Port Scan', data:{{ timeline_ps|tojson }},
       borderColor:'#f59e0b', backgroundColor:'rgba(245,158,11,0.15)', tension:0.3, fill:true}
    ] },
  options:{ plugins:{legend:_l, title:{display:true,text:'Incidents Over Time',color:'#f1f5f9'}}, scales:_s }
});

new Chart(document.getElementById('topIpChart'), {
  type:'bar',
  data:{ labels:{{ top_ip_labels|tojson }},
         datasets:[{label:'Failed Logins', data:{{ top_ip_values|tojson }},
           backgroundColor:'#ef4444'}] },
  options:{ indexAxis:'y',
    plugins:{legend:_l, title:{display:true,text:'Top Attacker IPs',color:'#f1f5f9'}}, scales:_s }
});

new Chart(document.getElementById('incidentTypePie'), {
  type:'doughnut',
  data:{ labels:['Brute Force','Port Scan','404 Flood'],
         datasets:[{data:[{{ brute_force_count }},{{ port_scan_count }},{{ flood_404_count }}],
           backgroundColor:['#ef4444','#f59e0b','#06b6d4']}] },
  options:{ plugins:{legend:_l, title:{display:true,text:'Incident Types',color:'#f1f5f9'}} }
});

{% if ml_enabled and ml_chart_labels %}
new Chart(document.getElementById('mlAnomalyChart'), {
  type:'bar',
  data:{ labels:{{ ml_chart_labels|tojson }},
         datasets:[{label:'Anomaly Score', data:{{ ml_chart_values|tojson }},
           backgroundColor:{{ ml_chart_colors|tojson }}}] },
  options:{ indexAxis:'y',
    plugins:{legend:_l, title:{display:true,
      text:'ML Anomaly Scores by Source IP (Isolation Forest)', color:'#f1f5f9'}},
    scales:{ x:{..._s.x, min:0, max:1,
               title:{display:true,text:'Anomaly Score',color:'#94a3b8'}}, y:_s.y }
  }
});
{% endif %}
</script>
<footer style="max-width:1280px;margin:2rem auto;padding:1rem 1.25rem;
               border-top:1px solid #334155;color:#64748b;font-size:.82rem;
               text-align:center;">
  Free &amp; open-source (MIT) ·
  <a href="https://github.com/Romil2112/log-analyzer" style="color:#94a3b8;">log-analyzer on GitHub</a>
  · demonstration / trial project · authorized use only · provided as-is, no warranty.
  Handle any data in this report confidentially.
</footer>
</body>
</html>
"""


def _fmt_dt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def _duration(first: datetime, last: datetime) -> str:
    secs = int((last - first).total_seconds())
    if secs < 60:
        return f"{secs}s"
    if secs < 3600:
        return f"{secs // 60}m {secs % 60}s"
    return f"{secs // 3600}h {(secs % 3600) // 60}m"


def _score_color(score: float) -> str:
    if score >= 0.8:
        return "#ef4444"
    if score >= 0.65:
        return "#f97316"
    if score >= 0.5:
        return "#eab308"
    return "#3b82f6"


def _count_event_types(events: list[dict]) -> dict[str, int]:
    """Return a count of events keyed by ``event_type``."""
    counts: dict[str, int] = defaultdict(int)
    for e in events:
        counts[e["event_type"]] += 1
    return counts


def _top_failed_login_ips(events: list[dict], limit: int = 10) -> list[tuple[str, int]]:
    """Return the ``limit`` source IPs with the most failed logins, descending."""
    fails: dict[str, int] = defaultdict(int)
    for e in events:
        if e["event_type"] == "failed_login" and e.get("source_ip"):
            fails[e["source_ip"]] += 1
    return sorted(fails.items(), key=lambda x: -x[1])[:limit]


def _timeline_hours(incidents: list[dict]) -> list[datetime]:
    """Return the list of hourly buckets spanning the incidents' first-seen times."""
    times = [i["first_seen"] for i in incidents]
    if not times:
        return []
    hours: list[datetime] = []
    cur = min(times).replace(minute=0, second=0, microsecond=0)
    end = max(times).replace(minute=0, second=0, microsecond=0)
    while cur <= end:
        hours.append(cur)
        cur += timedelta(hours=1)
    return hours


def _bucket_count(incidents: list[dict], hour: datetime) -> int:
    """Count incidents whose ``first_seen`` falls within the one-hour bucket ``hour``."""
    return sum(1 for i in incidents if hour <= i["first_seen"] < hour + timedelta(hours=1))


def _mitre_coverage_cards(incidents: list[dict]) -> list[dict]:
    """Build MITRE technique coverage cards for techniques observed in ``incidents``."""
    counts = _count_mitre_ids(incidents)
    return [
        {**tech, "count": counts[tech["id"]]}
        for tech in MITRE_TECHNIQUES.values()
        if counts.get(tech["id"], 0) > 0
    ]


def _detection_labels(in_rules: bool) -> tuple[str, str, str]:
    """Return (detection_type, badge_bg, badge_fg) for a rule-corroborated ML hit."""
    if in_rules:
        return "Rule + ML", "#450a0a", "#fca5a5"
    return "ML Only", "#2e1065", "#d8b4fe"


def _ml_anomaly_rows(
    scores: dict[str, float],
    feature_rows: list[dict] | None,
    rule_ips: set[str],
) -> list[dict]:
    """Build the ML anomaly table rows for IPs scoring at/above the threshold."""
    feat_by_ip = {r["source_ip"]: r for r in (feature_rows or [])}
    rows: list[dict] = []
    for ip, score in sorted(scores.items(), key=lambda x: -x[1]):
        if score < ML_ANOMALY_THRESHOLD:
            continue
        feat = feat_by_ip.get(ip, {})
        detection_type, badge_bg, badge_fg = _detection_labels(ip in rule_ips)
        rows.append({
            "source_ip":       ip,
            "anomaly_score":   score,
            "bar_color":       _score_color(score),
            "detection_type":  detection_type,
            "badge_bg":        badge_bg,
            "badge_fg":        badge_fg,
            "failed_logins":   feat.get("failed_logins", 0),
            "unique_ports":    feat.get("unique_ports", 0),
            "events_per_minute": feat.get("events_per_minute", 0),
            "burst_score":     feat.get("burst_score", 0),
            "night_ratio":     feat.get("night_ratio", 0),
        })
    return rows


def _enrich_incident(inc: dict, scores: dict[str, float]) -> dict:
    """Augment an incident with anomaly score, severity colours, and MITRE fields."""
    sc = scores.get(inc["source_ip"], 0.0)
    sev = inc.get("severity", "LOW")
    bg, fg = _SEV_HTML_BG.get(sev, ("#172554", "#93c5fd"))
    mitre = inc.get("mitre", {})
    return {
        **inc,
        "anomaly_score": sc,
        "bar_color":     _score_color(sc),
        "sev_bg":        bg,
        "sev_fg":        fg,
        "mitre_id":      mitre.get("id", "-"),
        "mitre_tactic":  mitre.get("tactic", "-"),
        "mitre_url":     mitre.get("url", "#"),
    }


def _duration_incident_rows(incidents: list[dict], scores: dict[str, float]) -> list[dict]:
    """Render brute-force / flood incident rows (with a human-readable duration)."""
    return [
        {
            **_enrich_incident(i, scores),
            "first_seen": _fmt_dt(i["first_seen"]),
            "last_seen":  _fmt_dt(i["last_seen"]),
            "duration":   _duration(i["first_seen"], i["last_seen"]),
        }
        for i in sorted(incidents, key=lambda x: -x["event_count"])
    ]


def _port_scan_rows(incidents: list[dict], scores: dict[str, float]) -> list[dict]:
    """Render port-scan incident rows (with a truncated sample of scanned ports)."""
    rows: list[dict] = []
    for i in sorted(incidents, key=lambda x: -x["event_count"]):
        ports = i["details"].get("unique_ports", [])
        sample = ", ".join(str(p) for p in ports[:8]) + ("..." if len(ports) > 8 else "")
        rows.append({
            **_enrich_incident(i, scores),
            "first_seen":   _fmt_dt(i["first_seen"]),
            "last_seen":    _fmt_dt(i["last_seen"]),
            "sample_ports": sample,
        })
    return rows


def _split_incidents_by_type(incidents: list[dict]) -> tuple[list[dict], list[dict], list[dict]]:
    """Partition incidents into (brute_force, port_scan, flood_404) lists."""
    bf = [i for i in incidents if i["incident_type"] == "brute_force"]
    ps = [i for i in incidents if i["incident_type"] == "port_scan"]
    f4 = [i for i in incidents if i["incident_type"] == "flood_404"]
    return bf, ps, f4


def _ml_chart_data(top_ml: list[tuple[str, float]]) -> dict:
    """Build the Chart.js series (labels/values/colours) for the ML anomaly chart."""
    return {
        "ml_chart_labels": [ip for ip, _ in top_ml],
        "ml_chart_values": [s for _, s in top_ml],
        "ml_chart_colors": [_score_color(s) for _, s in top_ml],
    }


def _volume_chart_data(
    type_counts: dict[str, int],
    top_ips: list[tuple[str, int]],
    hours: list[datetime],
    bf_incidents: list[dict],
    ps_incidents: list[dict],
) -> dict:
    """Build the event-type, top-IP, and timeline Chart.js series."""
    return {
        "event_type_labels": list(type_counts.keys()),
        "event_type_values": list(type_counts.values()),
        "top_ip_labels": [ip for ip, _ in top_ips],
        "top_ip_values": [cnt for _, cnt in top_ips],
        "timeline_labels": [h.strftime("%m-%d %H:00") for h in hours],
        "timeline_bf": [_bucket_count(bf_incidents, h) for h in hours],
        "timeline_ps": [_bucket_count(ps_incidents, h) for h in hours],
    }


def generate_report(
    events: list[dict],
    incidents: list[dict],
    source_file: str,
    output_path: str,
    anomaly_scores: dict[str, float] | None = None,
    feature_rows:   list[dict] | None = None,
) -> None:
    """Render the standalone Chart.js HTML incident report and write it to
    output_path. Pass anomaly_scores/feature_rows to include the ML section."""
    bf_incidents, ps_incidents, f4_incidents = _split_incidents_by_type(incidents)
    ml_enabled   = anomaly_scores is not None
    scores       = anomaly_scores or {}
    rule_ips     = {i["source_ip"] for i in incidents}

    type_counts  = _count_event_types(events)
    top_ips      = _top_failed_login_ips(events)
    hours        = _timeline_hours(incidents)
    ml_anomalies = _ml_anomaly_rows(scores, feature_rows, rule_ips)
    top_ml       = sorted(scores.items(), key=lambda x: -x[1])[:15]

    html = Template(REPORT_TEMPLATE).render(
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        source_file=source_file,
        total_events=len(events),
        brute_force_count=len(bf_incidents),
        port_scan_count=len(ps_incidents),
        unique_ips=len(rule_ips),
        mitre_coverage=_mitre_coverage_cards(incidents),
        ml_enabled=ml_enabled,
        ml_anomaly_count=len(ml_anomalies),
        ml_threshold=ML_ANOMALY_THRESHOLD,
        ml_anomalies=ml_anomalies,
        brute_force_incidents=_duration_incident_rows(bf_incidents, scores),
        port_scan_incidents=_port_scan_rows(ps_incidents, scores),
        flood_404_count=len(f4_incidents),
        flood_404_incidents=_duration_incident_rows(f4_incidents, scores),
        **_ml_chart_data(top_ml),
        **_volume_chart_data(type_counts, top_ips, hours, bf_incidents, ps_incidents),
    )

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)


# ── 404 flood detection ──────────────────────────────────────────────────────

FLOOD_404_THRESHOLD = 30
FLOOD_404_WINDOW    = 5


def detect_404_flood(events: list[dict]) -> list[dict]:
    """Flag 404 floods: many HTTP 404s from one IP inside the window (web
    scanning). Returns one flood_404 incident per offending source IP."""
    by_ip: dict[str, list[datetime]] = defaultdict(list)
    for e in events:
        if e["event_type"] == "http_404" and e.get("source_ip"):
            by_ip[e["source_ip"]].append(e["event_time"])

    incidents = []
    window = timedelta(minutes=FLOOD_404_WINDOW)
    for ip, times in by_ip.items():
        times.sort()
        window_times = _first_time_window(times, window, FLOOD_404_THRESHOLD)
        if window_times:
            incidents.append({
                "incident_type": "flood_404",
                "source_ip":     ip,
                "first_seen":    window_times[0],
                "last_seen":     window_times[-1],
                "event_count":   len(window_times),
                "details":       {
                    "window_minutes": FLOOD_404_WINDOW,
                    "threshold":      FLOOD_404_THRESHOLD,
                },
            })
    return incidents


# ── Severity scoring (public) ─────────────────────────────────────────────────

def score_severity(incident: dict) -> str:
    """Public alias for get_severity() — return an incident's severity level."""
    return get_severity(incident)


# ── Allowlist helpers ─────────────────────────────────────────────────────────


def build_allowlist(entries: list[str]) -> list:
    """Parse IP/CIDR strings into ipaddress network objects, silently skipping
    any that don't parse."""
    networks = []
    for entry in entries:
        try:
            networks.append(_ipaddress.ip_network(entry, strict=False))
        except ValueError:
            pass
    return networks


def _is_allowed(ip: str, allowlist: list) -> bool:
    try:
        addr = _ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in network for network in allowlist)


def filter_allowlist(events: list[dict], allowlist: list) -> list[dict]:
    """Return a new event list with any event whose source IP falls inside an
    allowlisted network dropped. allowlist comes from build_allowlist()."""
    return [e for e in events if not (e.get("source_ip") and _is_allowed(e["source_ip"], allowlist))]


# ── CLI ───────────────────────────────────────────────────────────────────────

def _positive_int(value: str) -> int:
    """argparse type: accept only integers >= 1."""
    ivalue = int(value)
    if ivalue < 1:
        raise argparse.ArgumentTypeError(f"must be >= 1, got {ivalue}")
    return ivalue


def _nonneg_int(value: str) -> int:
    """argparse type: accept only integers >= 0."""
    ivalue = int(value)
    if ivalue < 0:
        raise argparse.ArgumentTypeError(f"must be >= 0, got {ivalue}")
    return ivalue


def build_parser() -> argparse.ArgumentParser:
    """Build and return the argparse parser for the log-analyzer CLI."""
    p = argparse.ArgumentParser(
        prog="log-analyzer",
        description=(
            "Analyze SSH auth.log or Windows Event Log CSV for brute force "
            "and port scan attacks. Stores events in PostgreSQL, runs ML "
            "anomaly detection, maps findings to MITRE ATT&CK, and generates "
            "an HTML incident report."
        ),
    )
    p.add_argument("logfile", help="Path to log file (auth.log or .csv)")
    p.add_argument(
        "--dsn",
        default=os.environ.get(
            "LOG_ANALYZER_DSN",
            "postgresql://postgres:postgres@localhost:5432/log_analyzer",
        ),
        help="PostgreSQL DSN (default: $LOG_ANALYZER_DSN)",
    )
    p.add_argument("--report",   default="incident_report.html", metavar="FILE",
                   help="Output HTML report path (default: incident_report.html)")
    p.add_argument("--format",   choices=["ssh", "windows", "web", "auto"], default="auto",
                   help="Log format (default: auto-detect)")
    p.add_argument("--no-db",    action="store_true", help="Skip PostgreSQL storage")
    p.add_argument("--no-ml",    action="store_true", help="Skip Isolation Forest")
    p.add_argument("--ml-threshold", type=float, default=ML_ANOMALY_THRESHOLD,
                   metavar="FLOAT",
                   help=f"Min anomaly score to display (default: {ML_ANOMALY_THRESHOLD})")
    p.add_argument("--init-schema", action="store_true",
                   help="(Re)create the database schema and exit")
    p.add_argument("--brute-force-threshold", type=_positive_int, default=BRUTE_FORCE_THRESHOLD,
                   metavar="N")
    p.add_argument("--brute-force-window",    type=_positive_int, default=BRUTE_FORCE_WINDOW,
                   metavar="MIN")
    p.add_argument("--port-scan-threshold",   type=_positive_int, default=PORT_SCAN_THRESHOLD,
                   metavar="N")
    p.add_argument("--port-scan-window",      type=_positive_int, default=PORT_SCAN_WINDOW,
                   metavar="MIN")
    p.add_argument("--flood-404-threshold",   type=_positive_int, default=FLOOD_404_THRESHOLD,
                   metavar="N")
    p.add_argument("--flood-404-window",      type=_positive_int, default=FLOOD_404_WINDOW,
                   metavar="MIN")
    p.add_argument("--allowlist", default="", metavar="CIDR,...",
                   help="Comma-separated IPs/CIDRs to exclude from all detection")
    p.add_argument("--ai-summary", action="store_true", help="Generate AI executive summary via Claude API")
    p.add_argument("--no-enrich", action="store_true",
                   help="Skip GeoIP + threat-intel enrichment")
    p.add_argument("--threat-intel-file", metavar="FILE", default=None,
                   help="Known-bad CIDR list (default: bundled threat_intel.txt)")
    p.add_argument("--geoip-db", metavar="FILE", default=None,
                   help="MaxMind GeoLite2-Country .mmdb path (or set GEOIP_DB_PATH)")
    p.add_argument("--export-sigma", metavar="DIR", default=None,
                   help="Write Sigma detection rules for observed incidents to DIR")
    p.add_argument("--export-siem", metavar="DIR", default=None,
                   help="Compile observed incidents into native SIEM queries "
                        "(Splunk SPL, Elastic ES|QL, Sentinel KQL) in DIR")
    p.add_argument("--push-soc", metavar="URL", default=None,
                   help="POST detected incidents to a SOC-Dashboard ingestion endpoint "
                        "(e.g. http://localhost:8000/api/alerts)")
    p.add_argument("--soc-api-key", metavar="KEY",
                   default=os.environ.get("SOC_ALERTS_API_KEY"),
                   help="X-API-Key for the SOC-Dashboard ingest endpoint "
                        "(default: $SOC_ALERTS_API_KEY). Required by a hardened dashboard.")

    # ── privacy / data-protection controls ────────────────────────────────────
    privacy = p.add_argument_group("privacy controls")
    privacy.add_argument("--scrub-usernames", action="store_true",
                         help="Replace usernames with SHA-256 pseudonyms before storage/reporting")
    privacy.add_argument("--no-raw-lines", action="store_true",
                         help="Do not store or report original raw log lines (they may contain PII)")
    privacy.add_argument("--pseudonymize", action="store_true",
                         help="Replace source IPs with stable per-run HMAC pseudonyms "
                              "(mapping kept in memory only)")
    privacy.add_argument("--retention-days", type=_nonneg_int, default=0, metavar="N",
                         help="Delete log_events/incidents older than N days after processing "
                              "(0 = keep forever)")
    return p


def _configure_thresholds(args: argparse.Namespace) -> None:
    """Apply CLI threshold/window overrides to the module-level detection globals."""
    global BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW
    global PORT_SCAN_THRESHOLD,   PORT_SCAN_WINDOW, ML_ANOMALY_THRESHOLD
    global FLOOD_404_THRESHOLD,   FLOOD_404_WINDOW
    BRUTE_FORCE_THRESHOLD = args.brute_force_threshold
    BRUTE_FORCE_WINDOW    = args.brute_force_window
    PORT_SCAN_THRESHOLD   = args.port_scan_threshold
    PORT_SCAN_WINDOW      = args.port_scan_window
    FLOOD_404_THRESHOLD   = args.flood_404_threshold
    FLOOD_404_WINDOW      = args.flood_404_window
    ML_ANOMALY_THRESHOLD  = args.ml_threshold


def _init_schema_and_exit(args: argparse.Namespace) -> None:
    """Create the database schema for ``--init-schema`` and print confirmation."""
    conn = get_connection(args.dsn)
    init_schema(conn)
    conn.close()
    console.print("[green][+][/green] Schema initialised.")


def _resolve_format(args: argparse.Namespace, log_path: str) -> str:
    """Return the log format, auto-detecting it when ``--format auto``."""
    if args.format == "auto":
        return detect_log_format(log_path)
    return args.format


def _print_encryption_status(fernet: object | None) -> None:
    """Print whether field-level encryption at rest is active."""
    if fernet is not None:
        console.print("[green][+][/green] Field encryption ACTIVE (DB_ENCRYPTION_KEY set)")
    else:
        console.print(
            "[dim][*] Field encryption DISABLED — set DB_ENCRYPTION_KEY to "
            "encrypt PII at rest[/dim]"
        )


def _parse_events(log_path: str, fmt: str, n_lines: int) -> list[dict]:
    """Parse ``log_path`` with a live progress bar, dispatching on ``fmt``."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=None),
        MofNCompleteColumn(),
        TextColumn("[dim]·[/dim]"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(f"Parsing {Path(log_path).name}", total=n_lines)
        if fmt == "ssh":
            return parse_ssh_log(log_path, progress=progress, task=task)
        if fmt == "web":
            return parse_web_log(log_path, progress=progress, task=task)
        return parse_windows_csv(log_path, progress=progress, task=task)


def _apply_allowlist(events: list[dict], args: argparse.Namespace) -> list[dict]:
    """Filter allowlisted IPs/CIDRs out of ``events`` when ``--allowlist`` is set."""
    if not args.allowlist:
        return events
    al = build_allowlist([e.strip() for e in args.allowlist.split(",")])
    before = len(events)
    events = filter_allowlist(events, al)
    plural = "ies" if len(al) != 1 else "y"
    console.print(
        f"[dim][*] Allowlist: {len(al)} entr{plural} — "
        f"{before - len(events)} events filtered.[/dim]"
    )
    return events


def _run_rule_detection(events: list[dict]) -> list[dict]:
    """Run the rule-based detectors and return enriched incidents.

    Calls ``contracts.assert_event_contract`` first so an orphaned detector
    (consuming an event type no parser produces) fails loud rather than
    silently finding nothing.
    """
    contracts.assert_event_contract()
    console.print("[cyan][*][/cyan] Running rule-based detections...")
    bf    = detect_brute_force(events)
    ps    = detect_port_scan(events)
    flood = detect_404_flood(events)
    return enrich_incidents(bf + ps + flood)


def _maybe_enrich(incidents: list[dict], args: argparse.Namespace) -> None:
    """Apply GeoIP + threat-intel enrichment in place unless ``--no-enrich``."""
    if args.no_enrich:
        return
    ti_networks = enrichment.load_threat_intel(args.threat_intel_file)
    geo = enrichment.GeoIP(args.geoip_db)
    enrichment.enrich_incidents(incidents, ti_networks, geo)
    geo.close()


def _print_detection_tables(incidents: list[dict], args: argparse.Namespace) -> None:
    """Print the incident, MITRE, and (optional) enrichment summary tables."""
    console.print()
    print_incident_table(incidents)
    console.print()
    print_mitre_summary(incidents)
    console.print()
    if not args.no_enrich:
        print_enrichment_summary(incidents)
        console.print()


def _fit_and_report_ml(
    events: list[dict],
    incidents: list[dict],
    unique_src: int,
) -> tuple[dict[str, float], list[dict]]:
    """Fit Isolation Forest, print the results table, and return (scores, features)."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(f"Isolation Forest on {unique_src} source IPs...", total=None)
        det            = AnomalyDetector()
        anomaly_scores = det.fit_score(events)
        feat_rows      = det.feature_rows(events)

    rule_ips = {i["source_ip"] for i in incidents}
    flagged  = sum(1 for s in anomaly_scores.values() if s >= ML_ANOMALY_THRESHOLD)
    console.print(
        f"[green][+][/green] Isolation Forest complete — "
        f"[bold]{flagged}[/bold] IP(s) above threshold "
        f"[dim]{ML_ANOMALY_THRESHOLD}[/dim]"
    )
    print_ml_table(anomaly_scores, rule_ips, ML_ANOMALY_THRESHOLD)
    console.print()
    return anomaly_scores, feat_rows


def _run_ml_detection(
    events: list[dict],
    incidents: list[dict],
    args: argparse.Namespace,
) -> tuple[dict[str, float] | None, list[dict] | None]:
    """Run Isolation Forest anomaly detection, returning (scores, feature_rows).

    Returns ``(None, None)`` when ML is disabled, unavailable, or there are too
    few unique source IPs to fit a meaningful model.
    """
    if args.no_ml:
        return None, None
    if not ML_AVAILABLE:
        console.print(
            "[yellow][!][/yellow] scikit-learn/numpy not installed — "
            "skipping ML [dim](pip install scikit-learn numpy)[/dim]"
        )
        return None, None
    unique_src = len({e["source_ip"] for e in events if e.get("source_ip")})
    if unique_src < AnomalyDetector.MIN_IPS:
        console.print(
            f"[yellow][!][/yellow] ML skipped — only [bold]{unique_src}[/bold] "
            f"unique source IP(s) (need >= {AnomalyDetector.MIN_IPS})."
        )
        return None, None
    return _fit_and_report_ml(events, incidents, unique_src)


def _store_to_db(
    events: list[dict],
    incidents: list[dict],
    log_path: str,
    args: argparse.Namespace,
    fernet: object | None,
) -> None:
    """Persist events + incidents to PostgreSQL and apply retention, unless ``--no-db``."""
    if args.no_db:
        console.print("[dim][*] Database skipped (--no-db).[/dim]")
        return
    try:
        console.print("[cyan][*][/cyan] Storing events to PostgreSQL...")
        conn = get_connection(args.dsn)
        init_schema(conn)
        store_events(conn, events, log_path, fernet)
        store_incidents(conn, incidents, fernet)
        console.print(
            f"[green][+][/green] Stored [bold]{len(events):,}[/bold] events "
            f"and [bold]{len(incidents)}[/bold] incidents."
        )
        if args.retention_days > 0:
            ev_del, inc_del = purge_old_records(conn, args.retention_days)
            console.print(
                f"[green][+][/green] Retention: purged [bold]{ev_del}[/bold] event(s) "
                f"and [bold]{inc_del}[/bold] incident(s) older than "
                f"[bold]{args.retention_days}[/bold] day(s)."
            )
        conn.close()
    except psycopg2.OperationalError as exc:
        console.print(f"[red][!] DB error:[/red] {exc}")
        console.print("[yellow][!] Use --no-db to skip database storage.[/yellow]")
        sys.exit(1)


def _export_sigma(incidents: list[dict], args: argparse.Namespace) -> None:
    """Write vendor-neutral Sigma rules for observed incidents if ``--export-sigma``."""
    if not args.export_sigma:
        return
    if not SIGMA_AVAILABLE:
        console.print("[yellow][!][/yellow] Sigma export unavailable — run: pip install pyyaml")
        return
    paths = sigma_export.export_sigma(incidents, args.export_sigma)
    console.print(
        f"[green][+][/green] Wrote [bold]{len(paths)}[/bold] Sigma rule(s) "
        f"to [bold]{args.export_sigma}[/bold]"
    )


def _export_siem(incidents: list[dict], args: argparse.Namespace) -> None:
    """Compile incidents into native SIEM queries if ``--export-siem`` is set."""
    if not args.export_siem:
        return
    if not SIEM_AVAILABLE:
        console.print(
            "[yellow][!][/yellow] SIEM export unavailable — run: "
            "pip install pysigma pysigma-backend-splunk "
            "pysigma-backend-elasticsearch pysigma-backend-kusto"
        )
        return
    paths = siem_export.export_siem(incidents, args.export_siem)
    console.print(
        f"[green][+][/green] Wrote [bold]{len(paths)}[/bold] native SIEM "
        f"query file(s) to [bold]{args.export_siem}[/bold]"
    )


def _push_to_soc(incidents: list[dict], args: argparse.Namespace) -> None:
    """Push detected incidents to a SOC-Dashboard ingest endpoint if ``--push-soc``."""
    if not args.push_soc:
        return
    console.print(f"[cyan][*][/cyan] Pushing incidents to SOC dashboard -> [bold]{args.push_soc}[/bold]...")
    if not args.soc_api_key:
        console.print("[yellow][!][/yellow] No --soc-api-key/$SOC_ALERTS_API_KEY set; "
                      "a hardened dashboard will reject the push with 401.")
    ok, errors = soc_push.push_incidents(incidents, args.push_soc, api_key=args.soc_api_key)
    console.print(
        f"[green][+][/green] Pushed [bold]{ok}/{len(incidents)}[/bold] incident(s) to the SOC dashboard."
    )
    if errors:
        console.print(f"[yellow][!][/yellow] {len(errors)} push error(s); first: {errors[0]}")


def _print_ai_summary(
    incidents: list[dict],
    anomaly_scores: dict[str, float] | None,
    args: argparse.Namespace,
) -> None:
    """Generate and print the Claude AI executive summary if ``--ai-summary``."""
    if not args.ai_summary:
        return
    if not AI_SUMMARY_AVAILABLE:
        console.print("[yellow][!][/yellow] AI summary unavailable — run: pip install anthropic")
        return
    console.print("[cyan][*][/cyan] Generating AI executive summary...")
    summary = _ai_summary(incidents, anomaly_scores or {})
    if summary:
        console.print(Panel(
            summary,
            title="[bold cyan]AI Executive Summary[/bold cyan]",
            border_style="cyan",
            padding=(1, 2),
        ))
    else:
        console.print("[yellow][!][/yellow] AI summary skipped — set ANTHROPIC_API_KEY to enable.")


def main() -> None:
    """Run the CLI end to end: parse, detect, enrich, store, and report."""
    args = build_parser().parse_args()
    _configure_thresholds(args)

    if args.init_schema:
        _init_schema_and_exit(args)
        return

    log_path = args.logfile
    if not Path(log_path).is_file():
        console.print(f"[red][!] Not a readable file: {log_path}[/red]", highlight=False)
        sys.exit(1)

    fmt     = _resolve_format(args, log_path)
    n_lines = _line_count(log_path)
    _print_header(log_path, fmt, n_lines)

    fernet = get_fernet()
    _print_encryption_status(fernet)

    events = _parse_events(log_path, fmt, n_lines)
    console.print(
        f"[green][+][/green] Parsed [bold]{len(events):,}[/bold] events  "
        f"[dim]({n_lines:,} lines)[/dim]"
    )
    events = _apply_allowlist(events, args)

    incidents = _run_rule_detection(events)
    _maybe_enrich(incidents, args)

    # Privacy transforms run after detection + enrichment (which need the real
    # values) but before anything is displayed, reported, or stored.
    for banner in apply_privacy_transforms(events, incidents, args):
        console.print(f"[yellow][*][/yellow] {banner}")

    _print_detection_tables(incidents, args)
    anomaly_scores, feat_rows = _run_ml_detection(events, incidents, args)
    _store_to_db(events, incidents, log_path, args, fernet)

    console.print(f"[cyan][*][/cyan] Generating HTML report -> [bold]{args.report}[/bold]...")
    generate_report(events, incidents, log_path, args.report, anomaly_scores, feat_rows)
    console.print(f"[green][+][/green] Report written: [bold]{args.report}[/bold]")

    _export_sigma(incidents, args)
    _export_siem(incidents, args)
    _push_to_soc(incidents, args)
    _print_ai_summary(incidents, anomaly_scores, args)


if __name__ == "__main__":
    main()
