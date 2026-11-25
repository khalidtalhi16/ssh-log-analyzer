#!/usr/bin/env python3
"""Creates a FAKE auth.log for testing. All IPs are reserved documentation addresses."""
import random
from datetime import datetime, timedelta

random.seed(7)
start = datetime(2026, 11, 20, 2, 0, 0)
lines = []

def add(t, msg):
    lines.append((t, f"{t:%b} {t.day:>2} {t:%H:%M:%S} webserver sshd[{random.randint(1000,9999)}]: {msg}"))

# Normal activity
for i in range(12):
    t = start + timedelta(minutes=random.randint(0, 600))
    add(t, f"Accepted publickey for ahmed from 192.0.2.10 port {random.randint(40000,60000)} ssh2")
for i in range(3):
    t = start + timedelta(minutes=random.randint(0, 600))
    add(t, f"Failed password for ahmed from 192.0.2.10 port {random.randint(40000,60000)} ssh2")

# Attacker 1: brute force on root, then gets in
t = start + timedelta(hours=3)
for i in range(40):
    t += timedelta(seconds=random.randint(1, 3))
    add(t, f"Failed password for root from 203.0.113.45 port {random.randint(40000,60000)} ssh2")
t += timedelta(seconds=4)
add(t, "Accepted password for root from 203.0.113.45 port 51122 ssh2")

# Attacker 2: username spraying
t = start + timedelta(hours=5)
for u in ["admin", "test", "oracle", "ubuntu", "postgres", "guest", "git", "pi"]:
    t += timedelta(seconds=random.randint(5, 20))
    add(t, f"Failed password for invalid user {u} from 198.51.100.77 port {random.randint(40000,60000)} ssh2")

lines.sort()
with open("sample_auth.log", "w") as f:
    f.write("\n".join(l for _, l in lines) + "\n")
print(f"Wrote sample_auth.log with {len(lines)} lines")
