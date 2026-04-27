#!/usr/bin/env python3
"""
log-analyzer: Detect brute force attacks and port scans from SSH auth.log
or Windows Event Log CSV files, store events in PostgreSQL, and generate
an HTML incident report with charts.
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

# ── Constants ────────────────────────────────────────────────────────────────

BRUTE_FORCE_THRESHOLD = 5    # failed logins
BRUTE_FORCE_WINDOW    = 10   # minutes
PORT_SCAN_THRESHOLD   = 20   # unique ports
PORT_SCAN_WINDOW      = 5    # minutes

# SSH auth.log patterns
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


def parse_ssh_log(path: str) -> list[dict]:
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
    return events


def parse_windows_csv(path: str) -> list[dict]:
    """
    Expects columns (case-insensitive): TimeCreated, EventID, IpAddress,
    TargetUserName, IpPort (or similar variants).
    EventID 4625 = failed logon, 4624 = successful logon.
    """
    events = []
    with open(path, newline="", errors="replace") as fh:
        reader = csv.DictReader(fh)
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

                if eid == 4625:
                    etype = "failed_login"
                elif eid == 4624:
                    etype = "successful_login"
                else:
                    etype = f"event_{eid}"

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
    return events


def detect_log_format(path: str) -> str:
    ext = Path(path).suffix.lower()
    if ext == ".csv":
        return "windows"
    # Peek at first line for SSH syslog format
    with open(path, "r", errors="replace") as fh:
        first = fh.readline()
    if re.match(r'^\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}', first):
        return "ssh"
    return "windows"


# ── Detection ─────────────────────────────────────────────────────────────────

def detect_brute_force(events: list[dict]) -> list[dict]:
    by_ip = defaultdict(list)
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
                    "details":       {"window_minutes": BRUTE_FORCE_WINDOW, "threshold": BRUTE_FORCE_THRESHOLD},
                })
                break   # one incident per IP
    return incidents


def detect_port_scan(events: list[dict]) -> list[dict]:
    # Group (ip, port) pairs with timestamps
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
            slice_ = [(t, port) for t, port in pairs[i:] if t - times[i] <= window]
            unique_ports = {port for _, port in slice_}
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
            (incident_type, source_ip, first_seen, last_seen, event_count, details)
        VALUES
            (%(incident_type)s, %(source_ip)s, %(first_seen)s, %(last_seen)s,
             %(event_count)s, %(details)s)
    """
    rows = [{**i, "details": json.dumps(i["details"])} for i in incidents]
    with conn.cursor() as cur:
        psycopg2.extras.execute_batch(cur, sql, rows)
    conn.commit()


# ── Report ────────────────────────────────────────────────────────────────────

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
  header { background: #1e293b; padding: 1.5rem 2rem;
           border-bottom: 2px solid #3b82f6; }
  header h1 { font-size: 1.75rem; color: #60a5fa; }
  header p  { color: #94a3b8; margin-top: .25rem; font-size: .9rem; }
  main { max-width: 1200px; margin: 2rem auto; padding: 0 1rem; }
  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
           gap: 1rem; margin-bottom: 2rem; }
  .stat-card { background: #1e293b; border-radius: 8px; padding: 1.25rem;
               border-left: 4px solid #3b82f6; }
  .stat-card .value { font-size: 2rem; font-weight: bold; color: #60a5fa; }
  .stat-card .label { font-size: .85rem; color: #94a3b8; margin-top: .25rem; }
  .section { margin-bottom: 2.5rem; }
  .section h2 { font-size: 1.25rem; color: #f1f5f9; margin-bottom: 1rem;
                padding-bottom: .5rem; border-bottom: 1px solid #334155; }
  .chart-row { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem;
               margin-bottom: 2rem; }
  .chart-box { background: #1e293b; border-radius: 8px; padding: 1rem; }
  .chart-box canvas { max-height: 300px; }
  table { width: 100%; border-collapse: collapse; background: #1e293b;
          border-radius: 8px; overflow: hidden; font-size: .875rem; }
  th { background: #0f172a; padding: .75rem 1rem; text-align: left;
       color: #94a3b8; font-weight: 600; text-transform: uppercase;
       font-size: .75rem; letter-spacing: .05em; }
  td { padding: .65rem 1rem; border-top: 1px solid #334155; }
  tr:hover td { background: #263047; }
  .badge { display: inline-block; padding: .2rem .6rem; border-radius: 4px;
           font-size: .75rem; font-weight: 600; }
  .badge-red  { background: #450a0a; color: #fca5a5; }
  .badge-amber{ background: #431407; color: #fdba74; }
  .badge-blue { background: #172554; color: #93c5fd; }
  @media(max-width: 700px) { .chart-row { grid-template-columns: 1fr; } }
</style>
</head>
<body>
<header>
  <h1>&#x1F6E1; Log Analyzer — Incident Report</h1>
  <p>Generated {{ generated_at }} &nbsp;|&nbsp; Source: {{ source_file }}</p>
</header>
<main>
  <!-- Summary cards -->
  <div class="stats">
    <div class="stat-card">
      <div class="value">{{ total_events }}</div>
      <div class="label">Total Events Parsed</div>
    </div>
    <div class="stat-card" style="border-color:#ef4444">
      <div class="value" style="color:#f87171">{{ brute_force_count }}</div>
      <div class="label">Brute Force Incidents</div>
    </div>
    <div class="stat-card" style="border-color:#f59e0b">
      <div class="value" style="color:#fbbf24">{{ port_scan_count }}</div>
      <div class="label">Port Scan Incidents</div>
    </div>
    <div class="stat-card" style="border-color:#8b5cf6">
      <div class="value" style="color:#a78bfa">{{ unique_ips }}</div>
      <div class="label">Unique Attacker IPs</div>
    </div>
  </div>

  <!-- Charts -->
  <div class="section">
    <h2>Attack Overview</h2>
    <div class="chart-row">
      <div class="chart-box">
        <canvas id="eventTypeChart"></canvas>
      </div>
      <div class="chart-box">
        <canvas id="incidentTimelineChart"></canvas>
      </div>
    </div>
    <div class="chart-row">
      <div class="chart-box">
        <canvas id="topIpChart"></canvas>
      </div>
      <div class="chart-box">
        <canvas id="incidentTypePie"></canvas>
      </div>
    </div>
  </div>

  <!-- Brute Force Incidents -->
  {% if brute_force_incidents %}
  <div class="section">
    <h2>&#x1F525; Brute Force Incidents</h2>
    <table>
      <thead>
        <tr>
          <th>Source IP</th><th>Failed Attempts</th>
          <th>First Seen</th><th>Last Seen</th><th>Duration</th>
        </tr>
      </thead>
      <tbody>
        {% for inc in brute_force_incidents %}
        <tr>
          <td><code>{{ inc.source_ip }}</code></td>
          <td><span class="badge badge-red">{{ inc.event_count }}</span></td>
          <td>{{ inc.first_seen }}</td>
          <td>{{ inc.last_seen }}</td>
          <td>{{ inc.duration }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% endif %}

  <!-- Port Scan Incidents -->
  {% if port_scan_incidents %}
  <div class="section">
    <h2>&#x1F50D; Port Scan Incidents</h2>
    <table>
      <thead>
        <tr>
          <th>Source IP</th><th>Unique Ports</th>
          <th>First Seen</th><th>Last Seen</th><th>Sample Ports</th>
        </tr>
      </thead>
      <tbody>
        {% for inc in port_scan_incidents %}
        <tr>
          <td><code>{{ inc.source_ip }}</code></td>
          <td><span class="badge badge-amber">{{ inc.event_count }}</span></td>
          <td>{{ inc.first_seen }}</td>
          <td>{{ inc.last_seen }}</td>
          <td><code>{{ inc.sample_ports }}</code></td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% endif %}

  {% if not brute_force_incidents and not port_scan_incidents %}
  <div class="section">
    <p style="color:#4ade80; font-size:1.1rem;">&#x2705; No incidents detected.</p>
  </div>
  {% endif %}
</main>

<script>
const chartDefaults = {
  color: '#e2e8f0',
  plugins: { legend: { labels: { color: '#94a3b8' } } },
  scales: {
    x: { ticks: { color: '#94a3b8' }, grid: { color: '#334155' } },
    y: { ticks: { color: '#94a3b8' }, grid: { color: '#334155' } }
  }
};

// Event type bar chart
new Chart(document.getElementById('eventTypeChart'), {
  type: 'bar',
  data: {
    labels: {{ event_type_labels | tojson }},
    datasets: [{
      label: 'Count',
      data: {{ event_type_values | tojson }},
      backgroundColor: ['#3b82f6','#ef4444','#f59e0b','#8b5cf6','#10b981'],
    }]
  },
  options: { ...chartDefaults, plugins: { ...chartDefaults.plugins,
    title: { display: true, text: 'Events by Type', color: '#f1f5f9' } } }
});

// Incident timeline (hour buckets)
new Chart(document.getElementById('incidentTimelineChart'), {
  type: 'line',
  data: {
    labels: {{ timeline_labels | tojson }},
    datasets: [
      { label: 'Brute Force', data: {{ timeline_bf | tojson }},
        borderColor: '#ef4444', backgroundColor: 'rgba(239,68,68,0.15)', tension: 0.3, fill: true },
      { label: 'Port Scan', data: {{ timeline_ps | tojson }},
        borderColor: '#f59e0b', backgroundColor: 'rgba(245,158,11,0.15)', tension: 0.3, fill: true }
    ]
  },
  options: { ...chartDefaults, plugins: { ...chartDefaults.plugins,
    title: { display: true, text: 'Incidents Over Time', color: '#f1f5f9' } } }
});

// Top IPs horizontal bar
new Chart(document.getElementById('topIpChart'), {
  type: 'bar',
  data: {
    labels: {{ top_ip_labels | tojson }},
    datasets: [{
      label: 'Failed Logins',
      data: {{ top_ip_values | tojson }},
      backgroundColor: '#ef4444',
    }]
  },
  options: {
    indexAxis: 'y',
    ...chartDefaults,
    plugins: { ...chartDefaults.plugins,
      title: { display: true, text: 'Top Attacker IPs', color: '#f1f5f9' } }
  }
});

// Incident type pie
new Chart(document.getElementById('incidentTypePie'), {
  type: 'doughnut',
  data: {
    labels: ['Brute Force', 'Port Scan'],
    datasets: [{
      data: [{{ brute_force_count }}, {{ port_scan_count }}],
      backgroundColor: ['#ef4444', '#f59e0b'],
    }]
  },
  options: {
    plugins: {
      legend: { labels: { color: '#94a3b8' } },
      title: { display: true, text: 'Incident Types', color: '#f1f5f9' }
    }
  }
});
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


def generate_report(
    events: list[dict],
    incidents: list[dict],
    source_file: str,
    output_path: str,
):
    bf_incidents = [i for i in incidents if i["incident_type"] == "brute_force"]
    ps_incidents = [i for i in incidents if i["incident_type"] == "port_scan"]

    # Event type counts
    type_counts: dict[str, int] = defaultdict(int)
    for e in events:
        type_counts[e["event_type"]] += 1

    # Top IPs by failed login count
    ip_fails: dict[str, int] = defaultdict(int)
    for e in events:
        if e["event_type"] == "failed_login" and e.get("source_ip"):
            ip_fails[e["source_ip"]] += 1
    top_ips = sorted(ip_fails.items(), key=lambda x: -x[1])[:10]

    # Timeline: bucket incidents by hour
    all_times = [i["first_seen"] for i in incidents]
    if all_times:
        t_min = min(all_times).replace(minute=0, second=0, microsecond=0)
        t_max = max(all_times).replace(minute=0, second=0, microsecond=0)
        hours: list[datetime] = []
        cur = t_min
        while cur <= t_max:
            hours.append(cur)
            cur += timedelta(hours=1)
    else:
        hours = []

    def bucket(inc_list, hour):
        return sum(
            1 for i in inc_list
            if hour <= i["first_seen"] < hour + timedelta(hours=1)
        )

    timeline_labels = [h.strftime("%m-%d %H:00") for h in hours]
    timeline_bf = [bucket(bf_incidents, h) for h in hours]
    timeline_ps = [bucket(ps_incidents, h) for h in hours]

    unique_ips = len({i["source_ip"] for i in incidents})

    tmpl = Template(REPORT_TEMPLATE)
    html = tmpl.render(
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        source_file=source_file,
        total_events=len(events),
        brute_force_count=len(bf_incidents),
        port_scan_count=len(ps_incidents),
        unique_ips=unique_ips,
        event_type_labels=list(type_counts.keys()),
        event_type_values=list(type_counts.values()),
        top_ip_labels=[ip for ip, _ in top_ips],
        top_ip_values=[cnt for _, cnt in top_ips],
        timeline_labels=timeline_labels,
        timeline_bf=timeline_bf,
        timeline_ps=timeline_ps,
        brute_force_incidents=[
            {
                "source_ip":  i["source_ip"],
                "event_count": i["event_count"],
                "first_seen": _fmt_dt(i["first_seen"]),
                "last_seen":  _fmt_dt(i["last_seen"]),
                "duration":   _duration(i["first_seen"], i["last_seen"]),
            }
            for i in sorted(bf_incidents, key=lambda x: -x["event_count"])
        ],
        port_scan_incidents=[
            {
                "source_ip":   i["source_ip"],
                "event_count": i["event_count"],
                "first_seen":  _fmt_dt(i["first_seen"]),
                "last_seen":   _fmt_dt(i["last_seen"]),
                "sample_ports": ", ".join(
                    str(p) for p in i["details"].get("unique_ports", [])[:8]
                ) + ("…" if len(i["details"].get("unique_ports", [])) > 8 else ""),
            }
            for i in sorted(ps_incidents, key=lambda x: -x["event_count"])
        ],
    )

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)


# ── CLI entry point ───────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="log-analyzer",
        description=(
            "Analyze SSH auth.log or Windows Event Log CSV for brute force "
            "attacks and port scans. Stores events in PostgreSQL and generates "
            "an HTML incident report."
        ),
    )
    p.add_argument(
        "logfile",
        help="Path to the log file (auth.log or Windows Event Log .csv)",
    )
    p.add_argument(
        "--dsn",
        default=os.environ.get(
            "LOG_ANALYZER_DSN",
            "postgresql://postgres:postgres@localhost:5432/log_analyzer",
        ),
        help=(
            "PostgreSQL DSN "
            "(default: $LOG_ANALYZER_DSN or postgresql://postgres:postgres@localhost:5432/log_analyzer)"
        ),
    )
    p.add_argument(
        "--report",
        default="incident_report.html",
        metavar="FILE",
        help="Output HTML report path (default: incident_report.html)",
    )
    p.add_argument(
        "--format",
        choices=["ssh", "windows", "auto"],
        default="auto",
        help="Log format. 'auto' detects from extension/content (default: auto)",
    )
    p.add_argument(
        "--no-db",
        action="store_true",
        help="Skip database storage (useful for quick analysis / no PostgreSQL)",
    )
    p.add_argument(
        "--init-schema",
        action="store_true",
        help="(Re)create the database schema and exit",
    )
    p.add_argument(
        "--brute-force-threshold",
        type=int,
        default=BRUTE_FORCE_THRESHOLD,
        metavar="N",
        help=f"Failed logins to trigger brute force alert (default: {BRUTE_FORCE_THRESHOLD})",
    )
    p.add_argument(
        "--brute-force-window",
        type=int,
        default=BRUTE_FORCE_WINDOW,
        metavar="MINUTES",
        help=f"Time window for brute force detection in minutes (default: {BRUTE_FORCE_WINDOW})",
    )
    p.add_argument(
        "--port-scan-threshold",
        type=int,
        default=PORT_SCAN_THRESHOLD,
        metavar="N",
        help=f"Unique ports to trigger port scan alert (default: {PORT_SCAN_THRESHOLD})",
    )
    p.add_argument(
        "--port-scan-window",
        type=int,
        default=PORT_SCAN_WINDOW,
        metavar="MINUTES",
        help=f"Time window for port scan detection in minutes (default: {PORT_SCAN_WINDOW})",
    )
    return p


def main():
    parser = build_parser()
    args   = parser.parse_args()

    # Override globals from CLI args
    global BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW, PORT_SCAN_THRESHOLD, PORT_SCAN_WINDOW
    BRUTE_FORCE_THRESHOLD = args.brute_force_threshold
    BRUTE_FORCE_WINDOW    = args.brute_force_window
    PORT_SCAN_THRESHOLD   = args.port_scan_threshold
    PORT_SCAN_WINDOW      = args.port_scan_window

    # --init-schema only
    if args.init_schema:
        conn = get_connection(args.dsn)
        init_schema(conn)
        conn.close()
        print("Schema initialized successfully.")
        return

    log_path = args.logfile
    if not Path(log_path).exists():
        print(f"Error: file not found: {log_path}", file=sys.stderr)
        sys.exit(1)

    # Detect format
    fmt = args.format
    if fmt == "auto":
        fmt = detect_log_format(log_path)
    print(f"[*] Detected format: {fmt}")

    # Parse
    print(f"[*] Parsing {log_path} ...")
    if fmt == "ssh":
        events = parse_ssh_log(log_path)
    else:
        events = parse_windows_csv(log_path)
    print(f"[+] Parsed {len(events)} events.")

    # Detect
    print("[*] Running detections ...")
    bf = detect_brute_force(events)
    ps = detect_port_scan(events)
    incidents = bf + ps
    print(f"[+] Brute force incidents: {len(bf)}")
    print(f"[+] Port scan incidents:   {len(ps)}")

    # Database
    if not args.no_db:
        try:
            print("[*] Connecting to database ...")
            conn = get_connection(args.dsn)
            init_schema(conn)
            store_events(conn, events, log_path)
            store_incidents(conn, incidents)
            conn.close()
            print("[+] Events and incidents stored in PostgreSQL.")
        except psycopg2.OperationalError as exc:
            print(f"[!] Database error: {exc}", file=sys.stderr)
            print("[!] Use --no-db to skip database storage.", file=sys.stderr)
            sys.exit(1)
    else:
        print("[*] Skipping database storage (--no-db).")

    # Report
    print(f"[*] Generating HTML report -> {args.report} ...")
    generate_report(events, incidents, log_path, args.report)
    print(f"[+] Report written to {args.report}")


if __name__ == "__main__":
    main()
