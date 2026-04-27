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

def high_volume_log(path: str = "test_auth_50k.log", total: int = 50_000) -> None:
    """
    50 000-line SSH auth.log stress-test fixture:
    - 6 brute-force IPs (dense sub-5-min bursts, 20-40 attempts each)
    - 4 port-scanner IPs (40+ unique ports in 3-min windows)
    - 3 slow credential-stuffers (inter-attempt gap > threshold, ML-detectable)
    - 1 password-sprayer (fixed password 'Summer2024!', 200 distinct usernames)
    - 30 background noise IPs (1-6 failures each)
    - 8 legitimate users with accepted logins
    """
    random.seed(99)
    lines: list[tuple[datetime, str]] = []

    usernames = [
        "root", "admin", "ubuntu", "pi", "deploy", "git", "postgres",
        "oracle", "user", "test", "dev", "ops", "service", "backup",
        "nagios", "zabbix", "ansible", "puppet", "chef", "jenkins",
        "mysql", "redis", "mongo", "elastic", "kafka", "spark",
        "hadoop", "airflow", "celery", "nginx", "apache", "tomcat",
    ]
    spray_users = [f"user{i:04d}" for i in range(200)]
    legit_users = ["alice", "bob", "charlie", "diana", "evan", "frank", "grace", "helen"]

    # ── Brute-force attackers ─────────────────────────────────────────────────
    bf_ips = [
        "185.220.101.10", "45.33.32.156", "198.199.82.244",
        "91.92.249.100",  "194.165.16.77", "179.43.175.5",
    ]
    for attacker_ip in bf_ips:
        for burst_offset in range(0, 240, 15):
            t = BASE + timedelta(minutes=burst_offset)
            for _ in range(random.randint(20, 40)):
                t += timedelta(seconds=random.randint(1, 15))
                ts   = t.strftime("%b %d %H:%M:%S")
                user = random.choice(usernames)
                port = random.randint(40000, 65000)
                lines.append((t, (
                    f"{ts} server sshd[{random.randint(1000,9999)}]: "
                    f"Failed password for {user} from {attacker_ip} port {port} ssh2"
                )))

    # ── Port scanners ─────────────────────────────────────────────────────────
    scan_ips = [
        "203.0.113.42", "198.51.100.100",
        "222.186.30.112", "117.21.226.74",
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

    # ── Slow credential stuffers (sub-threshold rate, ML-detectable) ─────────
    stuffers = ["91.108.4.200", "77.247.110.14", "104.244.74.3"]
    for stuffer_ip in stuffers:
        t = BASE
        for _ in range(40):
            t  += timedelta(minutes=random.randint(3, 8))
            ts  = t.strftime("%b %d %H:%M:%S")
            user = random.choice(usernames)
            port = random.randint(40000, 65000)
            lines.append((t, (
                f"{ts} server sshd[{random.randint(1000,9999)}]: "
                f"Failed password for invalid user {user} "
                f"from {stuffer_ip} port {port} ssh2"
            )))

    # ── Password sprayer (T1110.003 — fixed password, rotating users) ─────────
    spray_ip = "5.188.206.26"
    t = BASE + timedelta(minutes=10)
    for spray_user in spray_users:
        t  += timedelta(seconds=random.randint(5, 30))
        ts  = t.strftime("%b %d %H:%M:%S")
        port = random.randint(40000, 65000)
        lines.append((t, (
            f"{ts} server sshd[{random.randint(1000,9999)}]: "
            f"Failed password for {spray_user} from {spray_ip} port {port} ssh2"
        )))

    # ── Background noise IPs ──────────────────────────────────────────────────
    noise_ips = [f"10.{a}.{b}.{c}" for a, b, c in [
        (0,200,1),(0,201,2),(1,100,3),(1,101,4),(1,102,5),(2,50,6),(2,51,7),
        (3,10,8),(3,11,9),(4,200,10),(4,201,11),(5,99,12),(5,100,13),(6,50,14),
        (6,51,15),(7,10,16),(7,11,17),(8,200,18),(8,201,19),(9,100,20),
        (10,50,21),(11,75,22),(12,30,23),(13,90,24),(14,180,25),
        (15,25,26),(16,130,27),(17,240,28),(18,60,29),(19,150,30),
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

    # ── Legitimate logins ─────────────────────────────────────────────────────
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
    pad_ip = "10.99.99.99"
    while len(lines) < total:
        t  = BASE + timedelta(minutes=random.randint(0, 240),
                              seconds=random.randint(0, 59))
        ts = t.strftime("%b %d %H:%M:%S")
        lines.append((t, (
            f"{ts} server sshd[{random.randint(1000,9999)}]: "
            f"Failed password for {random.choice(usernames)} "
            f"from {pad_ip} port {random.randint(40000,65000)} ssh2"
        )))

    lines.sort(key=lambda x: x[0])
    lines = lines[:total]

    with open(path, "w") as fh:
        fh.write("\n".join(line for _, line in lines) + "\n")
    print(f"Written: {path}  ({len(lines):,} lines)")
    print(f"  Contains: {len(bf_ips)} brute-force IPs, "
          f"{len(scan_ips)} port-scanner IPs, "
          f"{len(stuffers)} slow stuffers, "
          f"1 password-sprayer ({len(spray_users)} targets), "
          f"{len(noise_ips)} background IPs, "
          f"{len(legit_users)} legitimate users")


# ── Mixed-attack SSH log ──────────────────────────────────────────────────────

def mixed_attack_log(path: str = "test_mixed.log") -> None:
    """
    Compact multi-technique fixture covering diverse MITRE ATT&CK patterns:
    T1110.001 Brute Force          -- rapid failures, one user
    T1110.003 Password Spraying    -- slow rate, many users
    T1046    Network Service Scan  -- connection probes, unique ports
    T1078    Valid Accounts        -- successful login after failures (compromise)
    T1021.004 Lateral Movement     -- accepted logins from internal IP post-breach
    T1133    External Remote Svcs  -- off-hours VPN/SSH from unusual geo
    Low-and-slow (ML-only)         -- 1 attempt per ~6 min, 24 h window
    """
    random.seed(77)
    lines: list[tuple[datetime, str]] = []

    usernames = [
        "root", "admin", "ubuntu", "pi", "deploy", "git", "postgres",
        "oracle", "user", "test", "dev", "ops", "service", "backup",
    ]

    # T1110.001 — Classic SSH brute force (single user 'root', rapid)
    bf_ip = "45.155.205.20"
    t = BASE
    for _ in range(50):
        t  += timedelta(seconds=random.randint(2, 20))
        ts  = t.strftime("%b %d %H:%M:%S")
        port = random.randint(40000, 65000)
        lines.append((t, (
            f"{ts} server sshd[{random.randint(1000,9999)}]: "
            f"Failed password for root from {bf_ip} port {port} ssh2"
        )))

    # T1110.003 — Password spraying (many users, slow rate ~30s between)
    spray_ip = "192.0.2.88"
    t = BASE + timedelta(minutes=5)
    spray_targets = [f"svc_{x}" for x in [
        "api", "db", "cache", "queue", "mail", "ftp", "www", "vpn",
        "backup", "monitor", "deploy", "ci", "registry", "proxy", "bastion",
    ]]
    for target in spray_targets:
        t  += timedelta(seconds=random.randint(25, 45))
        ts  = t.strftime("%b %d %H:%M:%S")
        lines.append((t, (
            f"{ts} server sshd[{random.randint(1000,9999)}]: "
            f"Failed password for {target} from {spray_ip} port "
            f"{random.randint(40000,65000)} ssh2"
        )))

    # T1046 — Port scan (many unique source ports in rapid succession)
    scan_ip = "198.211.10.50"
    t = BASE + timedelta(minutes=15)
    for port_idx in range(35):
        t  += timedelta(seconds=random.randint(1, 8))
        ts  = t.strftime("%b %d %H:%M:%S")
        src_port = 30000 + port_idx * 131
        lines.append((t, (
            f"{ts} server sshd[{random.randint(1000,9999)}]: "
            f"Connection from {scan_ip} port {src_port} on 0.0.0.0 port 22"
        )))

    # T1078 — Valid account compromise: failures then success (same IP)
    compromise_ip = "80.94.95.107"
    t = BASE + timedelta(minutes=30)
    for _ in range(8):
        t  += timedelta(seconds=random.randint(5, 30))
        ts  = t.strftime("%b %d %H:%M:%S")
        lines.append((t, (
            f"{ts} server sshd[{random.randint(1000,9999)}]: "
            f"Failed password for admin from {compromise_ip} port "
            f"{random.randint(40000,65000)} ssh2"
        )))
    t += timedelta(seconds=15)
    ts  = t.strftime("%b %d %H:%M:%S")
    lines.append((t, (
        f"{ts} server sshd[{random.randint(1000,9999)}]: "
        f"Accepted password for admin from {compromise_ip} port "
        f"{random.randint(40000,65000)} ssh2"
    )))

    # T1021.004 — Lateral movement (internal subnet, rapid multi-host logins)
    lateral_ip = "10.0.1.50"
    t = BASE + timedelta(minutes=45)
    for host_sfx in range(10):
        t  += timedelta(seconds=random.randint(3, 12))
        ts  = t.strftime("%b %d %H:%M:%S")
        lines.append((t, (
            f"{ts} server{host_sfx} sshd[{random.randint(1000,9999)}]: "
            f"Accepted password for admin from {lateral_ip} port "
            f"{random.randint(40000,65000)} ssh2"
        )))

    # T1133 — External remote services: off-hours login from unusual IP
    ext_ip = "203.119.72.33"
    t = BASE + timedelta(hours=3, minutes=17)   # 05:17 — off-hours
    ts = t.strftime("%b %d %H:%M:%S")
    lines.append((t, (
        f"{ts} server sshd[{random.randint(1000,9999)}]: "
        f"Accepted password for alice from {ext_ip} port "
        f"{random.randint(40000,65000)} ssh2"
    )))

    # Low-and-slow (ML-detectable only, 1 attempt every ~6 min over 24 h)
    slow_ip = "176.10.99.200"
    t = BASE
    for _ in range(60):
        t  += timedelta(minutes=random.randint(5, 8), seconds=random.randint(0, 59))
        ts  = t.strftime("%b %d %H:%M:%S")
        user = random.choice(usernames)
        lines.append((t, (
            f"{ts} server sshd[{random.randint(1000,9999)}]: "
            f"Failed password for invalid user {user} from {slow_ip} port "
            f"{random.randint(40000,65000)} ssh2"
        )))

    # Legitimate background logins
    legit_src = "172.16.0.10"
    for user in ["alice", "bob", "carol"]:
        for _ in range(5):
            t  = BASE + timedelta(minutes=random.randint(0, 200))
            ts = t.strftime("%b %d %H:%M:%S")
            lines.append((t, (
                f"{ts} server sshd[{random.randint(1000,9999)}]: "
                f"Accepted password for {user} from {legit_src} port "
                f"{random.randint(40000,65000)} ssh2"
            )))

    lines.sort(key=lambda x: x[0])

    with open(path, "w") as fh:
        fh.write("\n".join(line for _, line in lines) + "\n")
    print(f"Written: {path}  ({len(lines)} lines)")
    print("  Techniques: T1110.001 brute-force, T1110.003 spray, "
          "T1046 port-scan, T1078 account-compromise, "
          "T1021.004 lateral-movement, T1133 ext-remote, low-and-slow ML")


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    p = argparse.ArgumentParser(description="Generate test log files for log_analyzer.py")
    p.add_argument(
        "--scale", action="store_true",
        help="Also generate 10k-event SSH log (test_auth_10k.log)"
    )
    p.add_argument(
        "--only-scale", action="store_true",
        help="Generate only the 10k scale log"
    )
    p.add_argument(
        "--size", type=int, default=10_000,
        help="Number of events in scale log (default: 10000)"
    )
    p.add_argument(
        "--high-volume", action="store_true",
        help="Generate 50k-event high-volume SSH log (test_auth_50k.log)"
    )
    p.add_argument(
        "--mixed", action="store_true",
        help="Generate mixed-attack log covering multiple MITRE techniques (test_mixed.log)"
    )
    p.add_argument(
        "--all", action="store_true",
        help="Generate all log fixtures (small, 10k, 50k, mixed)"
    )
    args = p.parse_args()

    if not args.only_scale:
        ssh_log()
        windows_csv()

    if args.scale or args.only_scale or args.all:
        ssh_log_scale(total=args.size)

    if args.high_volume or args.all:
        high_volume_log()

    if args.mixed or args.all:
        mixed_attack_log()


if __name__ == "__main__":
    main()
