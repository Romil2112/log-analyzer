#!/usr/bin/env python3
"""Generate sample log files for testing log_analyzer.py."""

import csv
import random
from datetime import datetime, timedelta

BASE = datetime(2024, 6, 15, 2, 0, 0)


def ssh_log(path="test_auth.log"):
    attacker1 = "192.168.1.100"
    attacker2 = "10.0.0.55"
    lines = []

    # Brute force from attacker1 — 12 failed logins within 4 minutes
    for i in range(12):
        t = BASE + timedelta(seconds=i * 20)
        ts = t.strftime("%b %d %H:%M:%S")
        lines.append(
            f"{ts} server sshd[1234]: Failed password for root from {attacker1} port {random.randint(40000,60000)} ssh2"
        )

    # Port scan from attacker2 — connections to 25 unique ports within 3 minutes
    for i in range(25):
        t = BASE + timedelta(minutes=10, seconds=i * 7)
        ts = t.strftime("%b %d %H:%M:%S")
        lines.append(
            f"{ts} server sshd[2345]: Connection from {attacker2} port {1000 + i * 50} on 0.0.0.0 port 22"
        )

    # Legitimate logins
    for i in range(5):
        t = BASE + timedelta(hours=1, minutes=i * 10)
        ts = t.strftime("%b %d %H:%M:%S")
        lines.append(
            f"{ts} server sshd[3456]: Accepted password for alice from 172.16.0.10 port 54321 ssh2"
        )

    # A few more scattered failures
    for ip in ["203.0.113.1", "198.51.100.7"]:
        for i in range(3):
            t = BASE + timedelta(hours=2, minutes=i * 5)
            ts = t.strftime("%b %d %H:%M:%S")
            lines.append(
                f"{ts} server sshd[4567]: Failed password for admin from {ip} port 55000 ssh2"
            )

    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"Written: {path}  ({len(lines)} lines)")


def windows_csv(path="test_events.csv"):
    rows = []
    attacker1 = "192.168.1.100"
    attacker2 = "10.0.0.55"

    # Brute force: EventID 4625
    for i in range(8):
        t = BASE + timedelta(seconds=i * 30)
        rows.append({
            "TimeCreated": t.isoformat(),
            "EventID": 4625,
            "IpAddress": attacker1,
            "TargetUserName": "Administrator",
            "IpPort": random.randint(49000, 60000),
        })

    # Port scan: EventID 4625 from many ports
    for i in range(22):
        t = BASE + timedelta(minutes=5, seconds=i * 12)
        rows.append({
            "TimeCreated": t.isoformat(),
            "EventID": 4625,
            "IpAddress": attacker2,
            "TargetUserName": "admin",
            "IpPort": 8000 + i * 100,
        })

    # Successful logins
    for i in range(3):
        t = BASE + timedelta(hours=1, minutes=i * 20)
        rows.append({
            "TimeCreated": t.isoformat(),
            "EventID": 4624,
            "IpAddress": "172.16.0.5",
            "TargetUserName": "jdoe",
            "IpPort": 54000 + i,
        })

    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["TimeCreated", "EventID", "IpAddress", "TargetUserName", "IpPort"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"Written: {path}  ({len(rows)} rows)")


if __name__ == "__main__":
    ssh_log()
    windows_csv()
