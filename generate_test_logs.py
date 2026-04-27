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

    usernames  = ["root", "admin", "ubuntu", "pi", "deploy", "git", "postgres",
                  "oracle", "user", "test", "dev", "ops", "service", "backup"]
    legit_users = ["alice", "bob", "charlie", "diana", "evan"]

    # ── Brute-force attackers ─────────────────────────────────────────────────
    bf_ips = ["185.220.101.10", "45.33.32.156", "198.199.82.244"]
    for attacker_ip in bf_ips:
        # Multiple burst windows spread across the log's time span
        for burst_offset in range(0, 120, 20):
            t = BASE + timedelta(minutes=burst_offset)
            for attempt in range(random.randint(8, 18)):
                t += timedelta(seconds=random.randint(2, 45))
                ts   = t.strftime("%b %d %H:%M:%S")
                user = random.choice(usernames)
                port = random.randint(40000, 65000)
                lines.append((t, (
                    f"{ts} server sshd[{random.randint(1000,9999)}]: "
                    f"Failed password for {user} from {attacker_ip} port {port} ssh2"
                )))

    # ── Port scanners ─────────────────────────────────────────────────────────
    scan_ips = ["203.0.113.42", "198.51.100.100"]
    for scanner_ip in scan_ips:
        t = BASE + timedelta(minutes=random.randint(5, 30))
        for port_offset in range(30):
            t  += timedelta(seconds=random.randint(1, 10))
            ts  = t.strftime("%b %d %H:%M:%S")
            src_port = 20000 + port_offset * 73          # deterministic unique ports
            lines.append((t, (
                f"{ts} server sshd[{random.randint(1000,9999)}]: "
                f"Connection from {scanner_ip} port {src_port} on 0.0.0.0 port 22"
            )))

    # ── Slow credential stuffer (ML-only, under threshold rate) ──────────────
    stuffer_ip = "91.108.4.200"
    t = BASE
    for attempt in range(30):
        t  += timedelta(minutes=random.randint(4, 9))  # stays below burst threshold
        ts  = t.strftime("%b %d %H:%M:%S")
        user = random.choice(usernames)
        port = random.randint(40000, 65000)
        lines.append((t, (
            f"{ts} server sshd[{random.randint(1000,9999)}]: "
            f"Failed password for invalid user {user} "
            f"from {stuffer_ip} port {port} ssh2"
        )))

    # ── Background noise IPs (occasional failures) ────────────────────────────
    noise_ips = [f"10.0.{i}.{j}" for i, j in [(0, 200), (0, 201), (1, 100),
                 (1, 101), (1, 102), (2, 50), (2, 51), (3, 10), (3, 11),
                 (4, 200), (4, 201), (5, 99), (5, 100), (6, 50), (6, 51)]]
    for noise_ip in noise_ips:
        for _ in range(random.randint(1, 4)):
            t  = BASE + timedelta(minutes=random.randint(0, 120))
            ts = t.strftime("%b %d %H:%M:%S")
            lines.append((t, (
                f"{ts} server sshd[{random.randint(1000,9999)}]: "
                f"Failed password for {random.choice(usernames)} "
                f"from {noise_ip} port {random.randint(40000,65000)} ssh2"
            )))

    # ── Legitimate logins ─────────────────────────────────────────────────────
    legit_src = "172.16.0.10"
    for i, user in enumerate(legit_users):
        for session in range(random.randint(10, 25)):
            t  = BASE + timedelta(minutes=random.randint(0, 118))
            ts = t.strftime("%b %d %H:%M:%S")
            lines.append((t, (
                f"{ts} server sshd[{random.randint(1000,9999)}]: "
                f"Accepted password for {user} from {legit_src} "
                f"port {random.randint(40000,65000)} ssh2"
            )))

    # ── Pad to target total ───────────────────────────────────────────────────
    pad_ip = "10.99.99.99"
    while len(lines) < total:
        t  = BASE + timedelta(minutes=random.randint(0, 120),
                              seconds=random.randint(0, 59))
        ts = t.strftime("%b %d %H:%M:%S")
        lines.append((t, (
            f"{ts} server sshd[{random.randint(1000,9999)}]: "
            f"Failed password for {random.choice(usernames)} "
            f"from {pad_ip} port {random.randint(40000,65000)} ssh2"
        )))

    # Sort chronologically (realistic log ordering)
    lines.sort(key=lambda x: x[0])
    lines = lines[:total]

    with open(path, "w") as fh:
        fh.write("\n".join(line for _, line in lines) + "\n")
    print(f"Written: {path}  ({len(lines):,} lines)")
    print(f"  Contains: {len(bf_ips)} brute-force IPs, "
          f"{len(scan_ips)} port-scanner IPs, "
          f"1 slow credential-stuffer (ML-only), "
          f"{len(noise_ips)} background IPs, "
          f"{len(legit_users)} legitimate users")


# ── 50 000-event high-volume SSH log ─────────────────────────────────────────

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

    usernames = [
        "root", "admin", "ubuntu", "pi", "deploy", "git", "postgres",
        "oracle", "user", "test", "dev", "ops", "service", "backup",
        "nagios", "zabbix", "ansible", "puppet", "chef", "jenkins",
    ]
    legit_users = ["alice", "bob", "charlie", "diana", "evan",
                   "frank", "grace", "helen", "ivan", "judy"]

    # ── Brute-force attackers (10 IPs) ────────────────────────────────────────
    bf_ips = [
        "185.220.101.10", "45.33.32.156", "198.199.82.244", "91.92.249.100",
        "194.165.16.77",  "179.43.175.5", "77.247.110.14",  "104.244.74.3",
        "5.188.206.26",   "80.94.95.107",
    ]
    for attacker_ip in bf_ips:
        for burst_offset in range(0, 240, 15):
            t = BASE + timedelta(minutes=burst_offset)
            for _ in range(random.randint(15, 35)):
                t += timedelta(seconds=random.randint(1, 15))
                ts   = t.strftime("%b %d %H:%M:%S")
                user = random.choice(usernames)
                port = random.randint(40000, 65000)
                lines.append((t, (
                    f"{ts} server sshd[{random.randint(1000,9999)}]: "
                    f"Failed password for {user} from {attacker_ip} port {port} ssh2"
                )))

    # ── Port scanners (5 IPs) ─────────────────────────────────────────────────
    scan_ips = [
        "203.0.113.42", "198.51.100.100",
        "222.186.30.112", "117.21.226.74", "45.155.205.20",
    ]
    for scanner_ip in scan_ips:
        t = BASE + timedelta(minutes=random.randint(5, 60))
        for port_offset in range(50):
            t  += timedelta(seconds=random.randint(1, 6))
            ts  = t.strftime("%b %d %H:%M:%S")
            src_port = 10000 + port_offset * 97
            lines.append((t, (
                f"{ts} server sshd[{random.randint(1000,9999)}]: "
                f"Connection from {scanner_ip} port {src_port} on 0.0.0.0 port 22"
            )))

    # ── Background noise IPs (20 IPs) ─────────────────────────────────────────
    noise_ips = [f"10.{a}.{b}.1" for a, b in [
        (0,200),(0,201),(1,100),(1,101),(1,102),(2,50),(2,51),(3,10),(3,11),
        (4,200),(4,201),(5,99),(5,100),(6,50),(6,51),
        (7,10),(8,200),(9,100),(10,50),(11,75),
    ]]
    for noise_ip in noise_ips:
        for _ in range(random.randint(1, 6)):
            t  = BASE + timedelta(minutes=random.randint(0, 240))
            ts = t.strftime("%b %d %H:%M:%S")
            lines.append((t, (
                f"{ts} server sshd[{random.randint(1000,9999)}]: "
                f"Failed password for {random.choice(usernames)} "
                f"from {noise_ip} port {random.randint(40000,65000)} ssh2"
            )))

    # ── Legitimate logins (10 users) ──────────────────────────────────────────
    legit_src = "172.16.0.10"
    for user in legit_users:
        for _ in range(random.randint(20, 40)):
            t  = BASE + timedelta(minutes=random.randint(0, 230))
            ts = t.strftime("%b %d %H:%M:%S")
            lines.append((t, (
                f"{ts} server sshd[{random.randint(1000,9999)}]: "
                f"Accepted password for {user} from {legit_src} "
                f"port {random.randint(40000,65000)} ssh2"
            )))

    # ── Pad to target total ───────────────────────────────────────────────────
    pad_ips = [f"172.20.{i}.1" for i in range(50)]
    while len(lines) < total:
        t  = BASE + timedelta(minutes=random.randint(0, 240),
                              seconds=random.randint(0, 59))
        ts = t.strftime("%b %d %H:%M:%S")
        lines.append((t, (
            f"{ts} server sshd[{random.randint(1000,9999)}]: "
            f"Failed password for {random.choice(usernames)} "
            f"from {random.choice(pad_ips)} port {random.randint(40000,65000)} ssh2"
        )))

    lines.sort(key=lambda x: x[0])
    lines = lines[:total]

    with open(path, "w") as fh:
        fh.write("\n".join(line for _, line in lines) + "\n")
    print(f"Written: {path}  ({len(lines):,} lines)")
    print(f"  Contains: {len(bf_ips)} brute-force IPs, "
          f"{len(scan_ips)} port-scanner IPs, "
          f"{len(noise_ips)} background IPs, "
          f"{len(legit_users)} legitimate users")


# ── Mixed-attack SSH log ──────────────────────────────────────────────────────

def mixed_attack_log(path: str = "test_mixed.log", total: int = 10_000) -> None:
    """
    Multi-technique fixture: brute force (3 IPs) + port scan (2 IPs)
    + 25 background IPs + 1 slow credential stuffer (ML-detectable).
    Note: 404 flood events must be injected programmatically in tests
    (SSH format cannot carry http_404 events).
    """
    random.seed(77)
    lines: list[tuple[datetime, str]] = []

    usernames = [
        "root", "admin", "ubuntu", "pi", "deploy", "git", "postgres",
        "oracle", "user", "test", "dev", "ops", "service", "backup",
    ]

    # ── 3 brute-force IPs ────────────────────────────────────────────────────
    bf_ips = ["45.155.205.20", "80.94.95.107", "194.165.16.77"]
    for bf_ip in bf_ips:
        t = BASE + timedelta(minutes=random.randint(0, 10))
        for _ in range(60):
            t  += timedelta(seconds=random.randint(2, 20))
            ts  = t.strftime("%b %d %H:%M:%S")
            user = random.choice(usernames)
            port = random.randint(40000, 65000)
            lines.append((t, (
                f"{ts} server sshd[{random.randint(1000,9999)}]: "
                f"Failed password for {user} from {bf_ip} port {port} ssh2"
            )))

    # ── 2 port-scan IPs ──────────────────────────────────────────────────────
    scan_ips = ["198.211.10.50", "203.0.113.77"]
    for scan_ip in scan_ips:
        t = BASE + timedelta(minutes=15)
        for port_idx in range(35):
            t  += timedelta(seconds=random.randint(1, 8))
            ts  = t.strftime("%b %d %H:%M:%S")
            src_port = 30000 + port_idx * 131
            lines.append((t, (
                f"{ts} server sshd[{random.randint(1000,9999)}]: "
                f"Connection from {scan_ip} port {src_port} on 0.0.0.0 port 22"
            )))

    # ── 1 slow credential stuffer (ML-only) ──────────────────────────────────
    slow_ip = "176.10.99.200"
    t = BASE
    for _ in range(80):
        t  += timedelta(minutes=random.randint(3, 8), seconds=random.randint(0, 59))
        ts  = t.strftime("%b %d %H:%M:%S")
        user = random.choice(usernames)
        lines.append((t, (
            f"{ts} server sshd[{random.randint(1000,9999)}]: "
            f"Failed password for invalid user {user} from {slow_ip} port "
            f"{random.randint(40000,65000)} ssh2"
        )))

    # ── 25 background IPs ────────────────────────────────────────────────────
    bg_ips = [f"10.{a}.{b}.1" for a, b in [
        (1,1),(1,2),(1,3),(1,4),(1,5),(2,1),(2,2),(2,3),(2,4),(2,5),
        (3,1),(3,2),(3,3),(3,4),(3,5),(4,1),(4,2),(4,3),(4,4),(4,5),
        (5,1),(5,2),(5,3),(5,4),(5,5),
    ]]
    for bg_ip in bg_ips:
        for _ in range(random.randint(1, 5)):
            t  = BASE + timedelta(minutes=random.randint(0, 120))
            ts = t.strftime("%b %d %H:%M:%S")
            lines.append((t, (
                f"{ts} server sshd[{random.randint(1000,9999)}]: "
                f"Failed password for {random.choice(usernames)} "
                f"from {bg_ip} port {random.randint(40000,65000)} ssh2"
            )))

    # ── Pad to total ──────────────────────────────────────────────────────────
    pad_ips = [f"172.20.{i}.1" for i in range(30)]
    while len(lines) < total:
        t  = BASE + timedelta(minutes=random.randint(0, 120),
                              seconds=random.randint(0, 59))
        ts = t.strftime("%b %d %H:%M:%S")
        lines.append((t, (
            f"{ts} server sshd[{random.randint(1000,9999)}]: "
            f"Failed password for {random.choice(usernames)} "
            f"from {random.choice(pad_ips)} port {random.randint(40000,65000)} ssh2"
        )))

    lines.sort(key=lambda x: x[0])
    lines = lines[:total]

    with open(path, "w") as fh:
        fh.write("\n".join(line for _, line in lines) + "\n")
    print(f"Written: {path}  ({len(lines):,} lines)")
    print(f"  BF IPs: {bf_ips}")
    print(f"  Scan IPs: {scan_ips}")
    print(f"  Slow stuffer: {slow_ip}  |  Background IPs: {len(bg_ips)}")


# ── Slow brute-force log (ML-detectable, rule-invisible) ─────────────────────

def slow_brute_force_log(path: str = "test_slow_brute.log", total: int = 5_000) -> None:
    """
    4 failed logins per 12 min from one IP — just under the 5-per-10-min rule threshold.
    Rules miss it; Isolation Forest should flag it.
    Remainder filled with 30 background IPs making random noise.
    """
    random.seed(13)
    lines: list[tuple[datetime, str]] = []
    usernames = ["root", "admin", "ubuntu", "deploy", "git"]

    stuffer_ip = "185.100.87.202"
    t = BASE
    # Generate ~400 stuffer events spread over 20 hours
    while t < BASE + timedelta(hours=20):
        for _ in range(4):
            t += timedelta(seconds=random.randint(60, 150))
            ts = t.strftime("%b %d %H:%M:%S")
            lines.append((t, (
                f"{ts} server sshd[{random.randint(1000,9999)}]: "
                f"Failed password for {random.choice(usernames)} "
                f"from {stuffer_ip} port {random.randint(40000,65000)} ssh2"
            )))
        t += timedelta(minutes=12)

    # 30 background IPs with realistic noise
    bg_ips = [f"10.20.{i}.{j}" for i, j in [
        (1,1),(1,2),(1,3),(2,1),(2,2),(2,3),(3,1),(3,2),(3,3),(4,1),
        (4,2),(4,3),(5,1),(5,2),(5,3),(6,1),(6,2),(6,3),(7,1),(7,2),
        (7,3),(8,1),(8,2),(8,3),(9,1),(9,2),(9,3),(10,1),(10,2),(10,3),
    ]]
    for bg_ip in bg_ips:
        for _ in range(random.randint(2, 8)):
            t = BASE + timedelta(minutes=random.randint(0, 1200))
            ts = t.strftime("%b %d %H:%M:%S")
            lines.append((t, (
                f"{ts} server sshd[{random.randint(1000,9999)}]: "
                f"Failed password for {random.choice(usernames)} "
                f"from {bg_ip} port {random.randint(40000,65000)} ssh2"
            )))

    # Pad distributing across many IPs so no single IP dominates
    pad_ips = [f"172.21.{i}.{j}" for i in range(10) for j in range(10)]
    while len(lines) < total:
        t = BASE + timedelta(minutes=random.randint(0, 1200),
                             seconds=random.randint(0, 59))
        ts = t.strftime("%b %d %H:%M:%S")
        lines.append((t, (
            f"{ts} server sshd[{random.randint(1000,9999)}]: "
            f"Failed password for {random.choice(usernames)} "
            f"from {random.choice(pad_ips)} port {random.randint(40000,65000)} ssh2"
        )))

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
    with open(path, "w") as fh:
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

def large_port_scan_log(path: str = "test_large_scan.log", total: int = 5_000) -> None:
    """500 unique ports from one IP in 2 minutes (CRITICAL), plus 20 background IPs."""
    random.seed(31)
    lines: list[tuple[datetime, str]] = []
    usernames = ["root", "admin", "ubuntu", "deploy"]

    scanner_ip = "203.0.113.200"
    t = BASE
    for i in range(500):
        # ~0.24 s apart → 500 events ≈ 120 s = 2 minutes
        t += timedelta(milliseconds=random.randint(100, 240))
        ts = t.strftime("%b %d %H:%M:%S")
        src_port = 10000 + i   # guaranteed unique
        lines.append((t, (
            f"{ts} server sshd[{random.randint(1000,9999)}]: "
            f"Connection from {scanner_ip} port {src_port} on 0.0.0.0 port 22"
        )))

    bg_ips = [f"10.30.{i}.1" for i in range(20)]
    for bg_ip in bg_ips:
        for _ in range(random.randint(2, 10)):
            t2 = BASE + timedelta(minutes=random.randint(5, 120))
            ts = t2.strftime("%b %d %H:%M:%S")
            lines.append((t2, (
                f"{ts} server sshd[{random.randint(1000,9999)}]: "
                f"Failed password for {random.choice(usernames)} "
                f"from {bg_ip} port {random.randint(40000,65000)} ssh2"
            )))

    pad_ips = [f"172.22.{i}.1" for i in range(30)]
    while len(lines) < total:
        t2 = BASE + timedelta(minutes=random.randint(0, 120),
                              seconds=random.randint(0, 59))
        ts = t2.strftime("%b %d %H:%M:%S")
        lines.append((t2, (
            f"{ts} server sshd[{random.randint(1000,9999)}]: "
            f"Failed password for {random.choice(usernames)} "
            f"from {random.choice(pad_ips)} port {random.randint(40000,65000)} ssh2"
        )))

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

def coordinated_attack_log(path: str = "test_coordinated.log", total: int = 20_000) -> None:
    """
    50 IPs all attacking the same 5 usernames in coordinated fashion.
    Each IP stays under the per-IP brute-force threshold — distributed
    attack detectable only via ML (shared target-username pattern).
    """
    random.seed(88)
    lines: list[tuple[datetime, str]] = []
    usernames = ["root", "admin", "ubuntu", "pi", "deploy"]

    coord_ips = [
        f"{a}.{b}.{c}.{d}" for a, b, c, d in [
            (45,33,32,i) for i in range(1, 11)
        ] + [
            (185,220,101,i) for i in range(1, 11)
        ] + [
            (198,199,82,i) for i in range(1, 11)
        ] + [
            (91,92,249,i) for i in range(1, 11)
        ] + [
            (194,165,16,i) for i in range(1, 11)
        ]
    ]   # 50 IPs total

    for coord_ip in coord_ips:
        for username in usernames:
            for _ in range(3):   # 15 events/IP — below threshold
                t = BASE + timedelta(minutes=random.randint(0, 120),
                                     seconds=random.randint(0, 59))
                ts = t.strftime("%b %d %H:%M:%S")
                lines.append((t, (
                    f"{ts} server sshd[{random.randint(1000,9999)}]: "
                    f"Failed password for {username} from {coord_ip} port "
                    f"{random.randint(40000,65000)} ssh2"
                )))

    noise_ips = [f"10.50.{i}.1" for i in range(20)]
    for noise_ip in noise_ips:
        for _ in range(random.randint(2, 6)):
            t = BASE + timedelta(minutes=random.randint(0, 120))
            ts = t.strftime("%b %d %H:%M:%S")
            lines.append((t, (
                f"{ts} server sshd[{random.randint(1000,9999)}]: "
                f"Failed password for {random.choice(usernames)} "
                f"from {noise_ip} port {random.randint(40000,65000)} ssh2"
            )))

    pad_ips = [f"172.23.{i}.1" for i in range(40)]
    while len(lines) < total:
        t = BASE + timedelta(minutes=random.randint(0, 120),
                             seconds=random.randint(0, 59))
        ts = t.strftime("%b %d %H:%M:%S")
        lines.append((t, (
            f"{ts} server sshd[{random.randint(1000,9999)}]: "
            f"Failed password for {random.choice(usernames)} "
            f"from {random.choice(pad_ips)} port {random.randint(40000,65000)} ssh2"
        )))

    lines.sort(key=lambda x: x[0])
    lines = lines[:total]

    with open(path, "w") as fh:
        fh.write("\n".join(line for _, line in lines) + "\n")
    print(f"Written: {path}  ({len(lines):,} lines)")
    print(f"  Coordinated: {len(coord_ips)} IPs × {len(usernames)} targets × 3 attempts "
          f"(each IP below threshold, ML-detectable)")


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
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
    args = p.parse_args()

    run_all = args.all

    if not args.only_scale:
        ssh_log()
        windows_csv()

    if args.scale or args.only_scale or run_all:
        ssh_log_scale(total=args.size)
    if args.high_volume or run_all:
        high_volume_log()
    if args.mixed or run_all:
        mixed_attack_log()
    if args.slow_brute or run_all:
        slow_brute_force_log()
    if args.ipv6 or run_all:
        ipv6_log()
    if args.empty or run_all:
        empty_log()
    if args.single or run_all:
        single_event_log()
    if args.malformed or run_all:
        malformed_log()
    if args.large_scan or run_all:
        large_port_scan_log()
    if args.unicode or run_all:
        unicode_log()
    if args.coordinated or run_all:
        coordinated_attack_log()


if __name__ == "__main__":
    main()
