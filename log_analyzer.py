#!/usr/bin/env python3
"""
log-analyzer: Detect brute force attacks and port scans from SSH auth.log
or Windows Event Log CSV files. Stores events in PostgreSQL, runs
Isolation Forest anomaly detection, maps findings to MITRE ATT&CK, and
generates an HTML incident report with Chart.js visualisations.
"""

import argparse
import csv
import json
import os
import re
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
    r'from (?P<ip>[\d.]+) port (?P<port>\d+)'
)
_SSH_ACCEPT  = re.compile(
    r'^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+).*'
    r'Accepted (?:password|publickey) for (?P<user>\S+) '
    r'from (?P<ip>[\d.]+) port (?P<port>\d+)'
)
_SSH_CONNECT = re.compile(
    r'^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+).*'
    r'Connection from (?P<ip>[\d.]+) port (?P<port>\d+)'
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
    events = []
    with open(path, "r", errors="replace") as fh:
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


def parse_windows_csv(path: str, progress: Progress | None = None, task=None) -> list[dict]:
    """
    Expects columns (case-insensitive): TimeCreated, EventID, IpAddress,
    TargetUserName, IpPort. EventID 4625 = failed logon, 4624 = successful.
    """
    events = []
    with open(path, newline="", errors="replace") as fh:
        reader  = csv.DictReader(fh)
        headers = {h.lower().strip(): h for h in (reader.fieldnames or [])}

        def col(*candidates):
            for c in candidates:
                if c in headers:
                    return headers[c]
            return None

        time_col = col("timecreated", "time created", "timestamp", "date/time")
        eid_col  = col("eventid", "event id", "id")
        ip_col   = col("ipaddress", "ip address", "source ip", "sourceip")
        user_col = col("targetusername", "username", "user name", "user")
        port_col = col("ipport", "port", "source port", "sourceport")

        for row in reader:
            try:
                raw_time = row.get(time_col, "") if time_col else ""
                eid      = int(row.get(eid_col, 0)) if eid_col else 0
                ip       = row.get(ip_col, "").strip() if ip_col else None
                user     = row.get(user_col, "").strip() if user_col else None
                port_raw = row.get(port_col, "").strip() if port_col else None

                if not raw_time:
                    continue
                event_time = dateparser.parse(raw_time)
                if event_time.tzinfo is None:
                    event_time = event_time.replace(tzinfo=timezone.utc)

                etype = {4625: "failed_login", 4624: "successful_login"}.get(eid, f"event_{eid}")
                events.append({
                    "log_type":   "windows",
                    "event_type": etype,
                    "event_time": event_time,
                    "source_ip":  ip or None,
                    "username":   user or None,
                    "port":       int(port_raw) if port_raw and port_raw.isdigit() else None,
                    "raw_line":   json.dumps(dict(row)),
                })
            except Exception:
                continue
            if progress is not None and task is not None:
                progress.advance(task)
    return events


def detect_log_format(path: str) -> str:
    ext = Path(path).suffix.lower()
    if ext == ".csv":
        return "windows"
    with open(path, "r", errors="replace") as fh:
        first = fh.readline()
    if re.match(r'^\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}', first):
        return "ssh"
    return "windows"


# ── Rule-based detection ──────────────────────────────────────────────────────

def detect_brute_force(events: list[dict]) -> list[dict]:
    by_ip: dict[str, list[datetime]] = defaultdict(list)
    for e in events:
        if e["event_type"] == "failed_login" and e.get("source_ip"):
            by_ip[e["source_ip"]].append(e["event_time"])

    incidents = []
    window = timedelta(minutes=BRUTE_FORCE_WINDOW)
    for ip, times in by_ip.items():
        times.sort()
        for i in range(len(times)):
            window_times = [t for t in times[i:] if t - times[i] <= window]
            if len(window_times) >= BRUTE_FORCE_THRESHOLD:
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
                break
    return incidents


def detect_port_scan(events: list[dict]) -> list[dict]:
    by_ip: dict[str, list[tuple[datetime, int]]] = defaultdict(list)
    for e in events:
        if e.get("source_ip") and e.get("port"):
            by_ip[e["source_ip"]].append((e["event_time"], e["port"]))

    incidents = []
    window = timedelta(minutes=PORT_SCAN_WINDOW)
    for ip, pairs in by_ip.items():
        pairs.sort()
        times = [p[0] for p in pairs]
        for i in range(len(pairs)):
            slice_      = [(t, p) for t, p in pairs[i:] if t - times[i] <= window]
            unique_ports = {p for _, p in slice_}
            if len(unique_ports) >= PORT_SCAN_THRESHOLD:
                slice_times = [t for t, _ in slice_]
                incidents.append({
                    "incident_type": "port_scan",
                    "source_ip":     ip,
                    "first_seen":    min(slice_times),
                    "last_seen":     max(slice_times),
                    "event_count":   len(unique_ports),
                    "details":       {
                        "window_minutes": PORT_SCAN_WINDOW,
                        "threshold":      PORT_SCAN_THRESHOLD,
                        "unique_ports":   sorted(unique_ports),
                    },
                })
                break
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
        if total <= 1:
            return 1.0
        w    = timedelta(seconds=60)
        best = max(sum(1 for t2 in times[i:] if t2 - t <= w) for i, t in enumerate(times))
        return best / total

    def _build_feature_matrix(self, events: list[dict]) -> tuple[list[str], list[list[float]]]:
        by_ip: dict[str, list[dict]] = defaultdict(list)
        for e in events:
            if e.get("source_ip"):
                by_ip[e["source_ip"]].append(e)

        ips, rows = [], []
        for ip, evts in by_ip.items():
            times      = sorted(e["event_time"] for e in evts)
            total      = len(evts)
            fails      = sum(1 for e in evts if e["event_type"] == "failed_login")
            ports      = {e["port"] for e in evts if e.get("port")}
            users      = {e.get("username") for e in evts if e.get("username")}
            span_s     = (times[-1] - times[0]).total_seconds() if len(times) > 1 else 0
            active_min = span_s / 60.0
            rate       = total / max(active_min, 1.0)
            night      = sum(1 for t in times if t.hour < 6) / total
            burst      = self._burst_score(times, total)
            rows.append([
                float(fails), float(len(ports)), float(len(users)),
                float(rate), float(active_min), float(night),
                float(burst), float(fails / total),
            ])
            ips.append(ip)
        return ips, rows

    def fit_score(self, events: list[dict]) -> dict[str, float]:
        """Return per-IP anomaly scores: 0.0 = normal, 1.0 = most anomalous."""
        if not ML_AVAILABLE:
            return {}
        ips, rows = self._build_feature_matrix(events)
        if len(ips) < self.MIN_IPS:
            return {}
        X        = np.array(rows, dtype=float)
        X_scaled = StandardScaler().fit_transform(X)
        clf      = IsolationForest(n_estimators=200, contamination="auto", random_state=42)
        clf.fit(X_scaled)
        raw      = clf.score_samples(X_scaled)
        lo, hi   = raw.min(), raw.max()
        norm     = 1.0 - (raw - lo) / (hi - lo) if hi > lo else np.zeros(len(raw))
        return {ip: float(round(s, 4)) for ip, s in zip(ips, norm)}

    def feature_rows(self, events: list[dict]) -> list[dict]:
        ips, rows = self._build_feature_matrix(events)
        return [{"source_ip": ip, **dict(zip(self.FEATURES, row))} for ip, row in zip(ips, rows)]


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

        if score >= 0.8:
            score_markup = f"[bold red]{score:.4f}[/bold red]"
        elif score >= 0.65:
            score_markup = f"[red]{score:.4f}[/red]"
        elif score >= 0.5:
            score_markup = f"[yellow]{score:.4f}[/yellow]"
        else:
            score_markup = f"[cyan]{score:.4f}[/cyan]"

        tbl.add_row(ip, score_markup, f"[{tag_style}]{tag_text}[/{tag_style}]")

    console.print(tbl)


def print_mitre_summary(incidents: list[dict]) -> None:
    """Print a compact MITRE ATT&CK coverage panel."""
    seen: dict[str, int] = defaultdict(int)
    for inc in incidents:
        mid = inc.get("mitre", {}).get("id", "")
        if mid:
            seen[mid] += 1
    if not seen:
        return

    lines = []
    for inc_type, tech in MITRE_TECHNIQUES.items():
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


# ── Database ──────────────────────────────────────────────────────────────────

def get_connection(dsn: str):
    return psycopg2.connect(dsn)


def init_schema(conn):
    schema_path = Path(__file__).parent / "schema.sql"
    with conn.cursor() as cur:
        cur.execute(schema_path.read_text())
    conn.commit()


def store_events(conn, events: list[dict], source_file: str):
    sql = """
        INSERT INTO log_events
            (source_file, event_time, log_type, event_type, source_ip, username, port, raw_line)
        VALUES
            (%(source_file)s, %(event_time)s, %(log_type)s, %(event_type)s,
             %(source_ip)s, %(username)s, %(port)s, %(raw_line)s)
    """
    rows = [{**e, "source_file": source_file} for e in events]
    with conn.cursor() as cur:
        psycopg2.extras.execute_batch(cur, sql, rows, page_size=500)
    conn.commit()


def store_incidents(conn, incidents: list[dict]):
    sql = """
        INSERT INTO incidents
            (incident_type, source_ip, first_seen, last_seen, event_count, severity, details)
        VALUES
            (%(incident_type)s, %(source_ip)s, %(first_seen)s, %(last_seen)s,
             %(event_count)s, %(severity)s, %(details)s)
    """
    rows = [{**i, "details": json.dumps(i["details"])} for i in incidents]
    with conn.cursor() as cur:
        psycopg2.extras.execute_batch(cur, sql, rows)
    conn.commit()


# ── HTML Report ───────────────────────────────────────────────────────────────

REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Log Analyzer — Incident Report</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
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
    if score >= 0.8:  return "#ef4444"
    if score >= 0.65: return "#f97316"
    if score >= 0.5:  return "#eab308"
    return "#3b82f6"


def generate_report(
    events: list[dict],
    incidents: list[dict],
    source_file: str,
    output_path: str,
    anomaly_scores: dict[str, float] | None = None,
    feature_rows:   list[dict] | None = None,
) -> None:
    bf_incidents = [i for i in incidents if i["incident_type"] == "brute_force"]
    ps_incidents = [i for i in incidents if i["incident_type"] == "port_scan"]
    f4_incidents = [i for i in incidents if i["incident_type"] == "flood_404"]
    ml_enabled   = anomaly_scores is not None
    scores       = anomaly_scores or {}
    rule_ips     = {i["source_ip"] for i in incidents}

    # Event type counts
    type_counts: dict[str, int] = defaultdict(int)
    for e in events:
        type_counts[e["event_type"]] += 1

    # Top IPs by failed login
    ip_fails: dict[str, int] = defaultdict(int)
    for e in events:
        if e["event_type"] == "failed_login" and e.get("source_ip"):
            ip_fails[e["source_ip"]] += 1
    top_ips = sorted(ip_fails.items(), key=lambda x: -x[1])[:10]

    # Incident timeline (hourly buckets)
    all_times = [i["first_seen"] for i in incidents]
    hours: list[datetime] = []
    if all_times:
        cur = min(all_times).replace(minute=0, second=0, microsecond=0)
        end = max(all_times).replace(minute=0, second=0, microsecond=0)
        while cur <= end:
            hours.append(cur)
            cur += timedelta(hours=1)

    def _bucket(lst: list[dict], h: datetime) -> int:
        return sum(1 for i in lst if h <= i["first_seen"] < h + timedelta(hours=1))

    # MITRE coverage for the report cards
    mitre_counts: dict[str, int] = defaultdict(int)
    for inc in incidents:
        mid = inc.get("mitre", {}).get("id", "")
        if mid:
            mitre_counts[mid] += 1

    mitre_coverage = [
        {**tech, "count": mitre_counts[tech["id"]]}
        for tech in MITRE_TECHNIQUES.values()
        if mitre_counts.get(tech["id"], 0) > 0
    ]

    # ML anomaly table rows
    feat_by_ip = {r["source_ip"]: r for r in (feature_rows or [])}
    ml_anomalies = []
    for ip, score in sorted(scores.items(), key=lambda x: -x[1]):
        if score < ML_ANOMALY_THRESHOLD:
            continue
        feat      = feat_by_ip.get(ip, {})
        in_rules  = ip in rule_ips
        ml_anomalies.append({
            "source_ip":       ip,
            "anomaly_score":   score,
            "bar_color":       _score_color(score),
            "detection_type":  "Rule + ML" if in_rules else "ML Only",
            "badge_bg":        "#450a0a" if in_rules else "#2e1065",
            "badge_fg":        "#fca5a5" if in_rules else "#d8b4fe",
            "failed_logins":   feat.get("failed_logins", 0),
            "unique_ports":    feat.get("unique_ports", 0),
            "events_per_minute": feat.get("events_per_minute", 0),
            "burst_score":     feat.get("burst_score", 0),
            "night_ratio":     feat.get("night_ratio", 0),
        })

    top_ml = sorted(scores.items(), key=lambda x: -x[1])[:15]

    def _enrich_inc(inc: dict) -> dict:
        sc    = scores.get(inc["source_ip"], 0.0)
        sev   = inc.get("severity", "LOW")
        bg, fg = _SEV_HTML_BG.get(sev, ("#172554", "#93c5fd"))
        mitre  = inc.get("mitre", {})
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

    tmpl = Template(REPORT_TEMPLATE)
    html = tmpl.render(
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        source_file=source_file,
        total_events=len(events),
        brute_force_count=len(bf_incidents),
        port_scan_count=len(ps_incidents),
        unique_ips=len({i["source_ip"] for i in incidents}),
        mitre_coverage=mitre_coverage,
        ml_enabled=ml_enabled,
        ml_anomaly_count=len(ml_anomalies),
        ml_threshold=ML_ANOMALY_THRESHOLD,
        ml_anomalies=ml_anomalies,
        ml_chart_labels=[ip for ip, _ in top_ml],
        ml_chart_values=[s for _, s in top_ml],
        ml_chart_colors=[_score_color(s) for _, s in top_ml],
        event_type_labels=list(type_counts.keys()),
        event_type_values=list(type_counts.values()),
        top_ip_labels=[ip for ip, _ in top_ips],
        top_ip_values=[cnt for _, cnt in top_ips],
        timeline_labels=[h.strftime("%m-%d %H:00") for h in hours],
        timeline_bf=[_bucket(bf_incidents, h) for h in hours],
        timeline_ps=[_bucket(ps_incidents, h) for h in hours],
        brute_force_incidents=[
            {
                **_enrich_inc(i),
                "first_seen": _fmt_dt(i["first_seen"]),
                "last_seen":  _fmt_dt(i["last_seen"]),
                "duration":   _duration(i["first_seen"], i["last_seen"]),
            }
            for i in sorted(bf_incidents, key=lambda x: -x["event_count"])
        ],
        port_scan_incidents=[
            {
                **_enrich_inc(i),
                "first_seen":   _fmt_dt(i["first_seen"]),
                "last_seen":    _fmt_dt(i["last_seen"]),
                "sample_ports": ", ".join(
                    str(p) for p in i["details"].get("unique_ports", [])[:8]
                ) + ("..." if len(i["details"].get("unique_ports", [])) > 8 else ""),
            }
            for i in sorted(ps_incidents, key=lambda x: -x["event_count"])
        ],
        flood_404_count=len(f4_incidents),
        flood_404_incidents=[
            {
                **_enrich_inc(i),
                "first_seen": _fmt_dt(i["first_seen"]),
                "last_seen":  _fmt_dt(i["last_seen"]),
                "duration":   _duration(i["first_seen"], i["last_seen"]),
            }
            for i in sorted(f4_incidents, key=lambda x: -x["event_count"])
        ],
    )

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)


# ── 404 flood detection ──────────────────────────────────────────────────────

FLOOD_404_THRESHOLD = 30
FLOOD_404_WINDOW    = 5


def detect_404_flood(events: list[dict]) -> list[dict]:
    by_ip: dict[str, list[datetime]] = defaultdict(list)
    for e in events:
        if e["event_type"] == "http_404" and e.get("source_ip"):
            by_ip[e["source_ip"]].append(e["event_time"])

    incidents = []
    window = timedelta(minutes=FLOOD_404_WINDOW)
    for ip, times in by_ip.items():
        times.sort()
        for i in range(len(times)):
            window_times = [t for t in times[i:] if t - times[i] <= window]
            if len(window_times) >= FLOOD_404_THRESHOLD:
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
                break
    return incidents


# ── Severity scoring (public) ─────────────────────────────────────────────────

def score_severity(incident: dict) -> str:
    return get_severity(incident)


# ── Allowlist helpers ─────────────────────────────────────────────────────────

import ipaddress as _ipaddress


def build_allowlist(entries: list[str]) -> list:
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
    return [e for e in events if not (e.get("source_ip") and _is_allowed(e["source_ip"], allowlist))]


# ── CLI ───────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
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
    p.add_argument("--format",   choices=["ssh", "windows", "auto"], default="auto",
                   help="Log format (default: auto-detect)")
    p.add_argument("--no-db",    action="store_true", help="Skip PostgreSQL storage")
    p.add_argument("--no-ml",    action="store_true", help="Skip Isolation Forest")
    p.add_argument("--ml-threshold", type=float, default=ML_ANOMALY_THRESHOLD,
                   metavar="FLOAT",
                   help=f"Min anomaly score to display (default: {ML_ANOMALY_THRESHOLD})")
    p.add_argument("--init-schema", action="store_true",
                   help="(Re)create the database schema and exit")
    p.add_argument("--brute-force-threshold", type=int, default=BRUTE_FORCE_THRESHOLD,
                   metavar="N")
    p.add_argument("--brute-force-window",    type=int, default=BRUTE_FORCE_WINDOW,
                   metavar="MIN")
    p.add_argument("--port-scan-threshold",   type=int, default=PORT_SCAN_THRESHOLD,
                   metavar="N")
    p.add_argument("--port-scan-window",      type=int, default=PORT_SCAN_WINDOW,
                   metavar="MIN")
    p.add_argument("--flood-404-threshold",   type=int, default=FLOOD_404_THRESHOLD,
                   metavar="N")
    p.add_argument("--flood-404-window",      type=int, default=FLOOD_404_WINDOW,
                   metavar="MIN")
    p.add_argument("--allowlist", default="", metavar="CIDR,...",
                   help="Comma-separated IPs/CIDRs to exclude from all detection")
    p.add_argument("--ai-summary", action="store_true", help="Generate AI executive summary via Claude API")
    return p


def main() -> None:  # noqa: C901
    parser = build_parser()
    args   = parser.parse_args()

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

    # ── --init-schema ─────────────────────────────────────────────────────────
    if args.init_schema:
        conn = get_connection(args.dsn)
        init_schema(conn)
        conn.close()
        console.print("[green][+][/green] Schema initialised.")
        return

    log_path = args.logfile
    if not Path(log_path).exists():
        console.print(f"[red][!] File not found: {log_path}[/red]", highlight=False)
        sys.exit(1)

    # ── detect format ─────────────────────────────────────────────────────────
    fmt = args.format
    if fmt == "auto":
        fmt = detect_log_format(log_path)

    n_lines = _line_count(log_path)
    _print_header(log_path, fmt, n_lines)

    # ── parse with live progress bar ──────────────────────────────────────────
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
            events = parse_ssh_log(log_path, progress=progress, task=task)
        else:
            events = parse_windows_csv(log_path, progress=progress, task=task)

    console.print(
        f"[green][+][/green] Parsed [bold]{len(events):,}[/bold] events  "
        f"[dim]({n_lines:,} lines)[/dim]"
    )

    # ── allowlist filtering ───────────────────────────────────────────────────
    if args.allowlist:
        al     = build_allowlist([e.strip() for e in args.allowlist.split(",")])
        before = len(events)
        events = filter_allowlist(events, al)
        console.print(
            f"[dim][*] Allowlist: {len(al)} entr{'ies' if len(al) != 1 else 'y'} — "
            f"{before - len(events)} events filtered.[/dim]"
        )

    # ── rule-based detection ──────────────────────────────────────────────────
    console.print("[cyan][*][/cyan] Running rule-based detections...")
    bf        = detect_brute_force(events)
    ps        = detect_port_scan(events)
    flood     = detect_404_flood(events)
    incidents = enrich_incidents(bf + ps + flood)

    # ── rich incident + MITRE table ───────────────────────────────────────────
    console.print()
    print_incident_table(incidents)
    console.print()
    print_mitre_summary(incidents)
    console.print()

    # ── ML anomaly detection ──────────────────────────────────────────────────
    anomaly_scores: dict[str, float] | None = None
    feat_rows: list[dict] | None = None

    if not args.no_ml:
        if not ML_AVAILABLE:
            console.print(
                "[yellow][!][/yellow] scikit-learn/numpy not installed — "
                "skipping ML [dim](pip install scikit-learn numpy)[/dim]"
            )
        else:
            unique_src = len({e["source_ip"] for e in events if e.get("source_ip")})
            if unique_src < AnomalyDetector.MIN_IPS:
                console.print(
                    f"[yellow][!][/yellow] ML skipped — only [bold]{unique_src}[/bold] "
                    f"unique source IP(s) (need >= {AnomalyDetector.MIN_IPS})."
                )
            else:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[bold cyan]{task.description}"),
                    TimeElapsedColumn(),
                    console=console,
                    transient=True,
                ) as progress:
                    task = progress.add_task(
                        f"Isolation Forest on {unique_src} source IPs...", total=None
                    )
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

    # ── database ──────────────────────────────────────────────────────────────
    if not args.no_db:
        try:
            console.print("[cyan][*][/cyan] Storing events to PostgreSQL...")
            conn = get_connection(args.dsn)
            init_schema(conn)
            store_events(conn, events, log_path)
            store_incidents(conn, incidents)
            conn.close()
            console.print(
                f"[green][+][/green] Stored [bold]{len(events):,}[/bold] events "
                f"and [bold]{len(incidents)}[/bold] incidents."
            )
        except psycopg2.OperationalError as exc:
            console.print(f"[red][!] DB error:[/red] {exc}")
            console.print("[yellow][!] Use --no-db to skip database storage.[/yellow]")
            sys.exit(1)
    else:
        console.print("[dim][*] Database skipped (--no-db).[/dim]")

    # ── generate report ───────────────────────────────────────────────────────
    console.print(f"[cyan][*][/cyan] Generating HTML report -> [bold]{args.report}[/bold]...")
    generate_report(events, incidents, log_path, args.report, anomaly_scores, feat_rows)
    console.print(f"[green][+][/green] Report written: [bold]{args.report}[/bold]")

    if args.ai_summary:
        if not AI_SUMMARY_AVAILABLE:
            console.print("[yellow][!][/yellow] AI summary unavailable — run: pip install anthropic")
        else:
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


if __name__ == "__main__":
    main()
