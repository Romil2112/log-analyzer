#!/usr/bin/env python3
"""
Generate synthetic log files for testing log_analyzer.py.

Modes
-----
  python generate_test_logs.py          -- small (48-line SSH + 33-row CSV)
  python generate_test_logs.py --scale  -- 10k-event SSH log for scale testing
"""

import argparse
import csv
import random
from datetime import datetime, timedelta

BASE = datetime(2024, 6, 15, 2, 0, 0)


# ── Small SSH log (original) ──────────────────────────────────────────────────

def ssh_log(path: str = "test_auth.log") -> None:
    attacker1, attacker2 = "192.168.1.100", "10.0.0.55"
    lines: list[str] = []

    # Brute force: 12 failed logins in 4 minutes
    for i in range(12):
        t  = BASE + timedelta(seconds=i * 20)
        ts = t.strftime("%b %d %H:%M:%S")
        lines.append(
            f"{ts} server sshd[1234]: Failed password for root "
            f"from {attacker1} port {random.randint(40000, 60000)} ssh2"
        )

    # Port scan: 25 unique ports in 3 minutes
    for i in range(25):
        t  = BASE + timedelta(minutes=10, seconds=i * 7)
        ts = t.strftime("%b %d %H:%M:%S")
        lines.append(
            f"{ts} server sshd[2345]: Connection from {attacker2} "
            f"port {1000 + i * 50} on 0.0.0.0 port 22"
        )

    # Legitimate logins
    for i in range(5):
        t  = BASE + timedelta(hours=1, minutes=i * 10)
        ts = t.strftime("%b %d %H:%M:%S")
        lines.append(
            f"{ts} server sshd[3456]: Accepted password for alice "
            f"from 172.16.0.10 port 54321 ssh2"
        )

    # Scattered failures from two other IPs
    for ip in ["203.0.113.1", "198.51.100.7"]:
        for i in range(3):
            t  = BASE + timedelta(hours=2, minutes=i * 5)
            ts = t.strftime("%b %d %H:%M:%S")
            lines.append(
                f"{ts} server sshd[4567]: Failed password for admin "
                f"from {ip} port 55000 ssh2"
            )

    with open(path, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"Written: {path}  ({len(lines)} lines)")


# ── Small Windows CSV (original) ─────────────────────────────────────────────

def windows_csv(path: str = "test_events.csv") -> None:
    rows: list[dict] = []
    attacker1, attacker2 = "192.168.1.100", "10.0.0.55"

    for i in range(8):
        t = BASE + timedelta(seconds=i * 30)
        rows.append({"TimeCreated": t.isoformat(), "EventID": 4625,
                     "IpAddress": attacker1, "TargetUserName": "Administrator",
                     "IpPort": random.randint(49000, 60000)})

    for i in range(22):
        t = BASE + timedelta(minutes=5, seconds=i * 12)
        rows.append({"TimeCreated": t.isoformat(), "EventID": 4625,
                     "IpAddress": attacker2, "TargetUserName": "admin",
                     "IpPort": 8000 + i * 100})

    for i in range(3):
        t = BASE + timedelta(hours=1, minutes=i * 20)
        rows.append({"TimeCreated": t.isoformat(), "EventID": 4624,
                     "IpAddress": "172.16.0.5", "TargetUserName": "jdoe",
                     "IpPort": 54000 + i})

    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(
            fh, fieldnames=["TimeCreated", "EventID", "IpAddress", "TargetUserName", "IpPort"]
        )
        writer.writeheader()
        writer.writerows(rows)
    print(f"Written: {path}  ({len(rows)} rows)")


# ── 10 000-event SSH scale log ────────────────────────────────────────────────

_SCALE_USERNAMES = ["root", "admin", "ubuntu", "pi", "deploy", "git", "postgres",
                    "oracle", "user", "test", "dev", "ops", "service", "backup"]
_SCALE_LEGIT_USERS = ["alice", "bob", "charlie", "diana", "evan"]
_SCALE_BF_IPS = ["185.220.101.10", "45.33.32.156", "198.199.82.244"]
_SCALE_SCAN_IPS = ["203.0.113.42", "198.51.100.100"]
_SCALE_NOISE_IPS = [f"10.0.{i}.{j}" for i, j in [(0, 200), (0, 201), (1, 100),
                    (1, 101), (1, 102), (2, 50), (2, 51), (3, 10), (3, 11),
                    (4, 200), (4, 201), (5, 99), (5, 100), (6, 50), (6, 51)]]


def _ssh_line(t: datetime, body: str) -> tuple[datetime, str]:
    """Build a (timestamp, formatted-SSH-line) tuple with a random pid."""
    ts = t.strftime("%b %d %H:%M:%S")
    return (t, f"{ts} server sshd[{random.randint(1000, 9999)}]: {body}")


def _scale_brute_force_lines() -> list[tuple[datetime, str]]:
    """Brute-force attackers: high-volume sub-10-min bursts across the span."""
    lines = []
    for attacker_ip in _SCALE_BF_IPS:
        for burst_offset in range(0, 120, 20):
            t = BASE + timedelta(minutes=burst_offset)
            for _ in range(random.randint(8, 18)):
                t += timedelta(seconds=random.randint(2, 45))
                user = random.choice(_SCALE_USERNAMES)
                port = random.randint(40000, 65000)
                lines.append(_ssh_line(
                    t, f"Failed password for {user} from {attacker_ip} port {port} ssh2"))
    return lines


def _scale_scanner_lines() -> list[tuple[datetime, str]]:
    """Port scanners: 30 deterministic unique ports in a tight window."""
    lines = []
    for scanner_ip in _SCALE_SCAN_IPS:
        t = BASE + timedelta(minutes=random.randint(5, 30))
        for port_offset in range(30):
            t += timedelta(seconds=random.randint(1, 10))
            src_port = 20000 + port_offset * 73
            lines.append(_ssh_line(
                t, f"Connection from {scanner_ip} port {src_port} on 0.0.0.0 port 22"))
    return lines


def _scale_stuffer_lines() -> list[tuple[datetime, str]]:
    """Slow credential stuffer: stays below the burst threshold (ML-only)."""
    lines = []
    t = BASE
    for _ in range(30):
        t += timedelta(minutes=random.randint(4, 9))
        user = random.choice(_SCALE_USERNAMES)
        port = random.randint(40000, 65000)
        lines.append(_ssh_line(
            t, f"Failed password for invalid user {user} from 91.108.4.200 port {port} ssh2"))
    return lines


def _scale_noise_lines() -> list[tuple[datetime, str]]:
    """Background IPs generating occasional failed logins."""
    lines = []
    for noise_ip in _SCALE_NOISE_IPS:
        for _ in range(random.randint(1, 4)):
            t = BASE + timedelta(minutes=random.randint(0, 120))
            lines.append(_ssh_line(
                t, f"Failed password for {random.choice(_SCALE_USERNAMES)} "
                   f"from {noise_ip} port {random.randint(40000, 65000)} ssh2"))
    return lines


def _scale_legit_lines() -> list[tuple[datetime, str]]:
    """Legitimate users with accepted logins from a trusted source."""
    lines = []
    for user in _SCALE_LEGIT_USERS:
        for _ in range(random.randint(10, 25)):
            t = BASE + timedelta(minutes=random.randint(0, 118))
            lines.append(_ssh_line(
                t, f"Accepted password for {user} from 172.16.0.10 "
                   f"port {random.randint(40000, 65000)} ssh2"))
    return lines


def _scale_pad_lines(needed: int) -> list[tuple[datetime, str]]:
    """Filler failed-login lines to reach the requested total."""
    lines = []
    for _ in range(max(needed, 0)):
        t = BASE + timedelta(minutes=random.randint(0, 120), seconds=random.randint(0, 59))
        lines.append(_ssh_line(
            t, f"Failed password for {random.choice(_SCALE_USERNAMES)} "
               f"from 10.99.99.99 port {random.randint(40000, 65000)} ssh2"))
    return lines


def ssh_log_scale(path: str = "test_auth_10k.log", total: int = 10_000) -> None:
    """
    Generates a realistic 10 000-line SSH auth.log with:
    - 3 brute-force attacker IPs (high-volume, sub-10-min bursts)
    - 2 port-scanner IPs (20+ unique ports in 5-min window)
    - 1 slow credential-stuffer (stays below threshold, detectable only by ML)
    - 15 background IPs generating occasional failed logins and connections
    - 5 legitimate user IPs with accepted logins
    """
    random.seed(42)
    lines: list[tuple[datetime, str]] = []
    lines += _scale_brute_force_lines()
    lines += _scale_scanner_lines()
    lines += _scale_stuffer_lines()
    lines += _scale_noise_lines()
    lines += _scale_legit_lines()
    lines += _scale_pad_lines(total - len(lines))

    lines.sort(key=lambda x: x[0])
    lines = lines[:total]

    with open(path, "w") as fh:
        fh.write("\n".join(line for _, line in lines) + "\n")
    print(f"Written: {path}  ({len(lines):,} lines)")
    print(f"  Contains: {len(_SCALE_BF_IPS)} brute-force IPs, "
          f"{len(_SCALE_SCAN_IPS)} port-scanner IPs, "
          f"1 slow credential-stuffer (ML-only), "
          f"{len(_SCALE_NOISE_IPS)} background IPs, "
          f"{len(_SCALE_LEGIT_USERS)} legitimate users")


# ── Generic scenario-phase builders (shared by the fixtures below) ────────────

def _multi_burst_bf_lines(ips, usernames, span_min, step_min, attempts, gap):
    """Brute force emitted as repeated short bursts across a time span."""
    lines = []
    for ip in ips:
        for burst_offset in range(0, span_min, step_min):
            t = BASE + timedelta(minutes=burst_offset)
            for _ in range(random.randint(*attempts)):
                t += timedelta(seconds=random.randint(*gap))
                user = random.choice(usernames)
                port = random.randint(40000, 65000)
                lines.append(_ssh_line(
                    t, f"Failed password for {user} from {ip} port {port} ssh2"))
    return lines


def _sustained_bf_lines(ips, usernames, start, count, gap):
    """Brute force emitted as one sustained run of ``count`` attempts per IP."""
    lines = []
    for ip in ips:
        t = BASE + timedelta(minutes=random.randint(*start))
        for _ in range(count):
            t += timedelta(seconds=random.randint(*gap))
            user = random.choice(usernames)
            port = random.randint(40000, 65000)
            lines.append(_ssh_line(
                t, f"Failed password for {user} from {ip} port {port} ssh2"))
    return lines


def _scan_ports_lines(ips, start, count, base_port, stride, gap):
    """Port scan: ``count`` deterministic unique ports per IP in a tight window.

    ``start`` may be an int (fixed minute offset) or a ``(lo, hi)`` tuple.
    """
    lines = []
    for ip in ips:
        offset = random.randint(*start) if isinstance(start, tuple) else start
        t = BASE + timedelta(minutes=offset)
        for i in range(count):
            t += timedelta(seconds=random.randint(*gap))
            src_port = base_port + i * stride
            lines.append(_ssh_line(
                t, f"Connection from {ip} port {src_port} on 0.0.0.0 port 22"))
    return lines


def _slow_stuffer_lines(ip, usernames, count):
    """Slow credential stuffer against invalid users (below burst threshold)."""
    lines = []
    t = BASE
    for _ in range(count):
        t += timedelta(minutes=random.randint(3, 8), seconds=random.randint(0, 59))
        user = random.choice(usernames)
        lines.append(_ssh_line(
            t, f"Failed password for invalid user {user} from {ip} "
               f"port {random.randint(40000, 65000)} ssh2"))
    return lines


def _noise_burst_lines(ips, usernames, count, span_min):
    """Occasional failed logins from background IPs (each below threshold)."""
    lines = []
    for ip in ips:
        for _ in range(random.randint(*count)):
            t = BASE + timedelta(minutes=random.randint(0, span_min))
            lines.append(_ssh_line(
                t, f"Failed password for {random.choice(usernames)} "
                   f"from {ip} port {random.randint(40000, 65000)} ssh2"))
    return lines


def _legit_login_lines(users, src, count, span_min):
    """Accepted logins from legitimate users on a trusted source IP."""
    lines = []
    for user in users:
        for _ in range(random.randint(*count)):
            t = BASE + timedelta(minutes=random.randint(0, span_min))
            lines.append(_ssh_line(
                t, f"Accepted password for {user} from {src} "
                   f"port {random.randint(40000, 65000)} ssh2"))
    return lines


def _pad_pool_lines(pad_ips, usernames, span_min, needed):
    """Filler failed-login lines from a pool of pad IPs to reach the total."""
    lines = []
    for _ in range(max(needed, 0)):
        t = BASE + timedelta(minutes=random.randint(0, span_min), seconds=random.randint(0, 59))
        lines.append(_ssh_line(
            t, f"Failed password for {random.choice(usernames)} "
               f"from {random.choice(pad_ips)} port {random.randint(40000, 65000)} ssh2"))
    return lines


# ── 50 000-event high-volume SSH log ─────────────────────────────────────────

_HV_USERNAMES = [
    "root", "admin", "ubuntu", "pi", "deploy", "git", "postgres",
    "oracle", "user", "test", "dev", "ops", "service", "backup",
    "nagios", "zabbix", "ansible", "puppet", "chef", "jenkins",
]
_HV_LEGIT_USERS = ["alice", "bob", "charlie", "diana", "evan",
                   "frank", "grace", "helen", "ivan", "judy"]
_HV_BF_IPS = [
    "185.220.101.10", "45.33.32.156", "198.199.82.244", "91.92.249.100",
    "194.165.16.77",  "179.43.175.5", "77.247.110.14",  "104.244.74.3",
    "5.188.206.26",   "80.94.95.107",
]
_HV_SCAN_IPS = ["203.0.113.42", "198.51.100.100",
                "222.186.30.112", "117.21.226.74", "45.155.205.20"]
_HV_NOISE_IPS = [f"10.{a}.{b}.1" for a, b in [
    (0,200),(0,201),(1,100),(1,101),(1,102),(2,50),(2,51),(3,10),(3,11),
    (4,200),(4,201),(5,99),(5,100),(6,50),(6,51),
    (7,10),(8,200),(9,100),(10,50),(11,75),
]]


def high_volume_log(path: str = "test_highvol.log", total: int = 50_000) -> None:
    """
    50 000-line SSH auth.log stress-test fixture:
    - 10 brute-force IPs (dense sub-5-min bursts)
    - 5 port-scanner IPs (40+ unique ports in 3-min windows)
    - 20 background noise IPs (1-6 failures each)
    - 10 legitimate users with accepted logins
    """
    random.seed(99)
    lines: list[tuple[datetime, str]] = []
    lines += _multi_burst_bf_lines(_HV_BF_IPS, _HV_USERNAMES, 240, 15, (15, 35), (1, 15))
    lines += _scan_ports_lines(_HV_SCAN_IPS, (5, 60), 50, 10000, 97, (1, 6))
    lines += _noise_burst_lines(_HV_NOISE_IPS, _HV_USERNAMES, (1, 6), 240)
    lines += _legit_login_lines(_HV_LEGIT_USERS, "172.16.0.10", (20, 40), 230)
    pad_ips = [f"172.20.{i}.1" for i in range(50)]
    lines += _pad_pool_lines(pad_ips, _HV_USERNAMES, 240, total - len(lines))

    lines.sort(key=lambda x: x[0])
    lines = lines[:total]

    with open(path, "w") as fh:
        fh.write("\n".join(line for _, line in lines) + "\n")
    print(f"Written: {path}  ({len(lines):,} lines)")
    print(f"  Contains: {len(_HV_BF_IPS)} brute-force IPs, "
          f"{len(_HV_SCAN_IPS)} port-scanner IPs, "
          f"{len(_HV_NOISE_IPS)} background IPs, "
          f"{len(_HV_LEGIT_USERS)} legitimate users")


# ── Mixed-attack SSH log ──────────────────────────────────────────────────────

def mixed_attack_log(path: str = "test_mixed.log", total: int = 10_000) -> None:
    """
    Multi-technique fixture: brute force (3 IPs) + port scan (2 IPs)
    + 25 background IPs + 1 slow credential stuffer (ML-detectable).
    Note: 404 flood events must be injected programmatically in tests
    (SSH format cannot carry http_404 events).
    """
    random.seed(77)
    usernames = [
        "root", "admin", "ubuntu", "pi", "deploy", "git", "postgres",
        "oracle", "user", "test", "dev", "ops", "service", "backup",
    ]
    bf_ips   = ["45.155.205.20", "80.94.95.107", "194.165.16.77"]
    scan_ips = ["198.211.10.50", "203.0.113.77"]
    slow_ip  = "176.10.99.200"
    bg_ips   = [f"10.{a}.{b}.1" for a, b in [
        (1,1),(1,2),(1,3),(1,4),(1,5),(2,1),(2,2),(2,3),(2,4),(2,5),
        (3,1),(3,2),(3,3),(3,4),(3,5),(4,1),(4,2),(4,3),(4,4),(4,5),
        (5,1),(5,2),(5,3),(5,4),(5,5),
    ]]
    pad_ips = [f"172.20.{i}.1" for i in range(30)]

    lines: list[tuple[datetime, str]] = []
    lines += _sustained_bf_lines(bf_ips, usernames, (0, 10), 60, (2, 20))
    lines += _scan_ports_lines(scan_ips, 15, 35, 30000, 131, (1, 8))
    lines += _slow_stuffer_lines(slow_ip, usernames, 80)
    lines += _noise_burst_lines(bg_ips, usernames, (1, 5), 120)
    lines += _pad_pool_lines(pad_ips, usernames, 120, total - len(lines))

    lines.sort(key=lambda x: x[0])
    lines = lines[:total]

    with open(path, "w") as fh:
        fh.write("\n".join(line for _, line in lines) + "\n")
    print(f"Written: {path}  ({len(lines):,} lines)")
    print(f"  BF IPs: {bf_ips}")
    print(f"  Scan IPs: {scan_ips}")
    print(f"  Slow stuffer: {slow_ip}  |  Background IPs: {len(bg_ips)}")


# ── Slow brute-force log (ML-detectable, rule-invisible) ─────────────────────

def _slow_brute_stuffer_lines(ip, usernames):
    """~400 events at 4 failures per 12 min — just under the rule threshold."""
    lines = []
    t = BASE
    while t < BASE + timedelta(hours=20):
        for _ in range(4):
            t += timedelta(seconds=random.randint(60, 150))
            lines.append(_ssh_line(
                t, f"Failed password for {random.choice(usernames)} "
                   f"from {ip} port {random.randint(40000, 65000)} ssh2"))
        t += timedelta(minutes=12)
    return lines


def slow_brute_force_log(path: str = "test_slow_brute.log", total: int = 5_000) -> None:
    """
    4 failed logins per 12 min from one IP — just under the 5-per-10-min rule threshold.
    Rules miss it; Isolation Forest should flag it.
    Remainder filled with 30 background IPs making random noise.
    """
    random.seed(13)
    usernames = ["root", "admin", "ubuntu", "deploy", "git"]
    stuffer_ip = "185.100.87.202"
    bg_ips = [f"10.20.{i}.{j}" for i, j in [
        (1,1),(1,2),(1,3),(2,1),(2,2),(2,3),(3,1),(3,2),(3,3),(4,1),
        (4,2),(4,3),(5,1),(5,2),(5,3),(6,1),(6,2),(6,3),(7,1),(7,2),
        (7,3),(8,1),(8,2),(8,3),(9,1),(9,2),(9,3),(10,1),(10,2),(10,3),
    ]]
    pad_ips = [f"172.21.{i}.{j}" for i in range(10) for j in range(10)]

    lines: list[tuple[datetime, str]] = []
    lines += _slow_brute_stuffer_lines(stuffer_ip, usernames)
    lines += _noise_burst_lines(bg_ips, usernames, (2, 8), 1200)
    lines += _pad_pool_lines(pad_ips, usernames, 1200, total - len(lines))

    lines.sort(key=lambda x: x[0])
    lines = lines[:total]

    with open(path, "w") as fh:
        fh.write("\n".join(line for _, line in lines) + "\n")
    print(f"Written: {path}  ({len(lines):,} lines)")
    print(f"  Stuffer: {stuffer_ip} — 4 attempts/12 min (below 5/10-min threshold)")
    print(f"  Background: {len(bg_ips)} IPs")


# ── IPv6 log ──────────────────────────────────────────────────────────────────

def ipv6_log(path: str = "test_ipv6.log") -> None:
    """SSH log with IPv6 source addresses (mapped and native)."""
    random.seed(55)
    ipv6_attackers = [
        "::ffff:192.168.1.1",
        "2001:db8::1",
        "::ffff:10.0.0.55",
        "fe80::1",
        "2001:db8:85a3::8a2e:370:7334",
    ]
    lines: list[tuple[datetime, str]] = []
    t = BASE

    for ipv6 in ipv6_attackers[:2]:
        for _ in range(8):
            t += timedelta(seconds=random.randint(5, 30))
            ts = t.strftime("%b %d %H:%M:%S")
            lines.append((t, (
                f"{ts} server sshd[{random.randint(1000,9999)}]: "
                f"Failed password for root from {ipv6} port "
                f"{random.randint(40000,65000)} ssh2"
            )))

    scan_ipv6 = "2001:db8::cafe"
    for i in range(25):
        t += timedelta(seconds=random.randint(2, 8))
        ts = t.strftime("%b %d %H:%M:%S")
        lines.append((t, (
            f"{ts} server sshd[{random.randint(1000,9999)}]: "
            f"Connection from {scan_ipv6} port {10000 + i * 100} on 0.0.0.0 port 22"
        )))

    for ipv6 in ipv6_attackers[2:]:
        t += timedelta(minutes=5)
        ts = t.strftime("%b %d %H:%M:%S")
        lines.append((t, (
            f"{ts} server sshd[{random.randint(1000,9999)}]: "
            f"Accepted password for alice from {ipv6} port "
            f"{random.randint(40000,65000)} ssh2"
        )))

    lines.sort(key=lambda x: x[0])
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(line for _, line in lines) + "\n")
    print(f"Written: {path}  ({len(lines)} lines)  IPv6 sources: {len(ipv6_attackers)+1} IPs")


# ── Empty log ─────────────────────────────────────────────────────────────────

def empty_log(path: str = "test_empty.log") -> None:
    with open(path, "w"):
        pass
    print(f"Written: {path}  (0 lines)")


# ── Single-event log ──────────────────────────────────────────────────────────

def single_event_log(path: str = "test_single.log") -> None:
    ts = BASE.strftime("%b %d %H:%M:%S")
    line = f"{ts} server sshd[1234]: Failed password for root from 1.2.3.4 port 50000 ssh2"
    with open(path, "w") as fh:
        fh.write(line + "\n")
    print(f"Written: {path}  (1 line)")


# ── Malformed log ─────────────────────────────────────────────────────────────

def malformed_log(path: str = "test_malformed.log", total: int = 2_000) -> None:
    """40% corrupt/unparseable lines mixed with valid brute-force + port-scan events."""
    random.seed(7)
    lines: list[tuple[datetime, str]] = []
    usernames = ["root", "admin", "ubuntu", "pi"]

    attacker_ip = "192.0.2.77"
    t = BASE
    for _ in range(60):
        t += timedelta(seconds=random.randint(2, 15))
        ts = t.strftime("%b %d %H:%M:%S")
        lines.append((t, (
            f"{ts} server sshd[{random.randint(1000,9999)}]: "
            f"Failed password for {random.choice(usernames)} from {attacker_ip} "
            f"port {random.randint(40000,65000)} ssh2"
        )))

    scan_ip = "10.10.10.10"
    for i in range(30):
        t += timedelta(seconds=random.randint(1, 5))
        ts = t.strftime("%b %d %H:%M:%S")
        lines.append((t, (
            f"{ts} server sshd[{random.randint(1000,9999)}]: "
            f"Connection from {scan_ip} port {20000 + i * 50} on 0.0.0.0 port 22"
        )))

    corrupt_templates = [
        "THIS IS NOT A LOG LINE AT ALL",
        "%%% MALFORMED {incomplete entry",
        "Jun 15 BAD_TIME server sshd[]: no event",
        "Failed password but no timestamp or IP",
        "",
        "   ",
        "random text 123 !@#$%",
        "Jun 15 02:00:00 trailing garbage only",
        "<corrupted entry>",
        "kernel: segfault at 0x0 ip 0x0 sp 0x0",
    ]
    n_corrupt = int(total * 0.4)
    for _ in range(n_corrupt):
        t = BASE + timedelta(minutes=random.randint(0, 60))
        lines.append((t, random.choice(corrupt_templates)))

    pad_ip = "172.20.10.1"
    while len(lines) < total:
        t = BASE + timedelta(minutes=random.randint(0, 120),
                             seconds=random.randint(0, 59))
        ts = t.strftime("%b %d %H:%M:%S")
        lines.append((t, (
            f"{ts} server sshd[{random.randint(1000,9999)}]: "
            f"Failed password for {random.choice(usernames)} "
            f"from {pad_ip} port {random.randint(40000,65000)} ssh2"
        )))

    lines.sort(key=lambda x: x[0])
    lines = lines[:total]

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(line for _, line in lines) + "\n")
    print(f"Written: {path}  ({len(lines):,} lines)  (~40% corrupt)")


# ── Large port-scan log ───────────────────────────────────────────────────────

def _fast_scan_lines(ip, count):
    """A single IP hitting ``count`` guaranteed-unique ports ~0.1-0.24s apart."""
    lines = []
    t = BASE
    for i in range(count):
        t += timedelta(milliseconds=random.randint(100, 240))
        src_port = 10000 + i
        lines.append(_ssh_line(
            t, f"Connection from {ip} port {src_port} on 0.0.0.0 port 22"))
    return lines


def large_port_scan_log(path: str = "test_large_scan.log", total: int = 5_000) -> None:
    """500 unique ports from one IP in 2 minutes (CRITICAL), plus 20 background IPs."""
    random.seed(31)
    usernames = ["root", "admin", "ubuntu", "deploy"]
    scanner_ip = "203.0.113.200"
    bg_ips = [f"10.30.{i}.1" for i in range(20)]
    pad_ips = [f"172.22.{i}.1" for i in range(30)]

    lines: list[tuple[datetime, str]] = []
    lines += _fast_scan_lines(scanner_ip, 500)
    lines += _noise_burst_lines(bg_ips, usernames, (2, 10), 120)
    lines += _pad_pool_lines(pad_ips, usernames, 120, total - len(lines))

    lines.sort(key=lambda x: x[0])
    lines = lines[:total]

    with open(path, "w") as fh:
        fh.write("\n".join(line for _, line in lines) + "\n")
    print(f"Written: {path}  ({len(lines):,} lines)")
    print(f"  Scanner: {scanner_ip} — 500 unique ports in ~2 min (CRITICAL severity)")


# ── Unicode username log ──────────────────────────────────────────────────────

def unicode_log(path: str = "test_unicode.log", total: int = 2_000) -> None:
    """SSH log with unicode usernames: 用户, Ümit, José, Ångström, محمد, 陈伟, Søren."""
    random.seed(66)
    lines: list[tuple[datetime, str]] = []
    unicode_users = ["用户", "Ümit", "José", "Ångström", "محمد", "陈伟", "Søren"]
    ascii_users   = ["root", "admin", "ubuntu"]

    attacker_ip = "192.0.2.200"
    t = BASE
    for _ in range(20):
        t += timedelta(seconds=random.randint(2, 30))
        ts = t.strftime("%b %d %H:%M:%S")
        user = random.choice(unicode_users)
        lines.append((t, (
            f"{ts} server sshd[{random.randint(1000,9999)}]: "
            f"Failed password for {user} from {attacker_ip} port "
            f"{random.randint(40000,65000)} ssh2"
        )))

    legit_ip = "172.16.5.1"
    for user in unicode_users:
        t += timedelta(minutes=5)
        ts = t.strftime("%b %d %H:%M:%S")
        lines.append((t, (
            f"{ts} server sshd[{random.randint(1000,9999)}]: "
            f"Accepted password for {user} from {legit_ip} port "
            f"{random.randint(40000,65000)} ssh2"
        )))

    pad_ips = [f"10.40.{i}.1" for i in range(20)]
    while len(lines) < total:
        t = BASE + timedelta(minutes=random.randint(0, 120),
                             seconds=random.randint(0, 59))
        ts = t.strftime("%b %d %H:%M:%S")
        user = random.choice(unicode_users + ascii_users)
        lines.append((t, (
            f"{ts} server sshd[{random.randint(1000,9999)}]: "
            f"Failed password for {user} from {random.choice(pad_ips)} port "
            f"{random.randint(40000,65000)} ssh2"
        )))

    lines.sort(key=lambda x: x[0])
    lines = lines[:total]

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(line for _, line in lines) + "\n")
    user_repr = ", ".join(u.encode("ascii", "replace").decode() for u in unicode_users)
    print(f"Written: {path}  ({len(lines):,} lines)  Unicode users: {user_repr}")


# ── Coordinated attack log ────────────────────────────────────────────────────

def _coordinated_ips() -> list[str]:
    """Build the 50 coordinated-attacker IPs (10 per /24 across 5 subnets)."""
    subnets = [(45, 33, 32), (185, 220, 101), (198, 199, 82), (91, 92, 249), (194, 165, 16)]
    return [f"{a}.{b}.{c}.{i}" for a, b, c in subnets for i in range(1, 11)]


def _coordinated_lines(coord_ips, usernames):
    """Distributed attack: each IP hits every username a few times, below threshold."""
    lines = []
    for coord_ip in coord_ips:
        for username in usernames:
            for _ in range(3):   # 15 events/IP — below threshold
                t = BASE + timedelta(minutes=random.randint(0, 120),
                                     seconds=random.randint(0, 59))
                lines.append(_ssh_line(
                    t, f"Failed password for {username} from {coord_ip} "
                       f"port {random.randint(40000, 65000)} ssh2"))
    return lines


def coordinated_attack_log(path: str = "test_coordinated.log", total: int = 20_000) -> None:
    """
    50 IPs all attacking the same 5 usernames in coordinated fashion.
    Each IP stays under the per-IP brute-force threshold — distributed
    attack detectable only via ML (shared target-username pattern).
    """
    random.seed(88)
    usernames = ["root", "admin", "ubuntu", "pi", "deploy"]
    coord_ips = _coordinated_ips()   # 50 IPs total
    noise_ips = [f"10.50.{i}.1" for i in range(20)]
    pad_ips   = [f"172.23.{i}.1" for i in range(40)]

    lines: list[tuple[datetime, str]] = []
    lines += _coordinated_lines(coord_ips, usernames)
    lines += _noise_burst_lines(noise_ips, usernames, (2, 6), 120)
    lines += _pad_pool_lines(pad_ips, usernames, 120, total - len(lines))

    lines.sort(key=lambda x: x[0])
    lines = lines[:total]

    with open(path, "w") as fh:
        fh.write("\n".join(line for _, line in lines) + "\n")
    print(f"Written: {path}  ({len(lines):,} lines)")
    print(f"  Coordinated: {len(coord_ips)} IPs × {len(usernames)} targets × 3 attempts "
          f"(each IP below threshold, ML-detectable)")


# ── Entry point ───────────────────────────────────────────────────────────────

def _build_fixture_parser() -> argparse.ArgumentParser:
    """Build the CLI parser for the fixture generator."""
    p = argparse.ArgumentParser(description="Generate test log files for log_analyzer.py")
    p.add_argument("--scale",       action="store_true", help="Generate 10k SSH log")
    p.add_argument("--only-scale",  action="store_true", help="Generate only the 10k log")
    p.add_argument("--size",        type=int, default=10_000, help="Events in scale log")
    p.add_argument("--high-volume", action="store_true", help="Generate 50k high-volume log")
    p.add_argument("--mixed",       action="store_true", help="Generate mixed-attack log")
    p.add_argument("--slow-brute",  action="store_true", help="Generate slow brute-force log")
    p.add_argument("--ipv6",        action="store_true", help="Generate IPv6 log")
    p.add_argument("--empty",       action="store_true", help="Generate empty log")
    p.add_argument("--single",      action="store_true", help="Generate single-event log")
    p.add_argument("--malformed",   action="store_true", help="Generate malformed log")
    p.add_argument("--large-scan",  action="store_true", help="Generate large port-scan log")
    p.add_argument("--unicode",     action="store_true", help="Generate unicode username log")
    p.add_argument("--coordinated", action="store_true", help="Generate coordinated attack log")
    p.add_argument("--all",         action="store_true", help="Generate every fixture")
    return p


# (arg-attribute name, generator) — run when its flag or --all is set.
_OPTIONAL_FIXTURES = [
    ("high_volume", high_volume_log),
    ("mixed",       mixed_attack_log),
    ("slow_brute",  slow_brute_force_log),
    ("ipv6",        ipv6_log),
    ("empty",       empty_log),
    ("single",      single_event_log),
    ("malformed",   malformed_log),
    ("large_scan",  large_port_scan_log),
    ("unicode",     unicode_log),
    ("coordinated", coordinated_attack_log),
]


def _dispatch_optional_fixtures(args, run_all: bool) -> None:
    """Run each optional fixture generator whose flag (or --all) is set."""
    for flag, generate in _OPTIONAL_FIXTURES:
        if run_all or getattr(args, flag):
            generate()


def main() -> None:
    args = _build_fixture_parser().parse_args()
    run_all = args.all

    if not args.only_scale:
        ssh_log()
        windows_csv()
    if run_all or args.scale or args.only_scale:
        ssh_log_scale(total=args.size)
    _dispatch_optional_fixtures(args, run_all)


if __name__ == "__main__":
    main()
