#!/usr/bin/env python3
"""
SSH Log Analyzer
----------------
Reads a Linux SSH auth log (e.g. /var/log/auth.log) and detects:
  * Brute-force attempts   (many failed logins from one IP in a short time)
  * Username spraying      (one IP trying many different usernames)
  * Possible compromise    (a successful login AFTER a brute-force attack)
Then prints a report with a timeline you can use in an incident write-up.

Defensive tool: only analyze logs from systems you own or are authorized to review.
"""
import argparse
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime

LINE_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<msg>.*)$"
)
FAILED_RE = re.compile(
    r"Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+"
)
ACCEPTED_RE = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port \d+"
)


@dataclass
class Event:
    time: datetime
    kind: str  # "failed" or "accepted"
    user: str
    ip: str


@dataclass
class Finding:
    severity: str
    type: str
    ip: str
    description: str
    first_seen: str
    last_seen: str
    count: int


def parse_log(lines, year):
    """Turn raw log lines into Event objects. Unrecognized lines are skipped."""
    events = []
    for line in lines:
        m = LINE_RE.match(line.strip())
        if not m:
            continue
        try:
            ts = datetime.strptime(f"{year} {' '.join(m['ts'].split())}", "%Y %b %d %H:%M:%S")
        except ValueError:
            continue
        msg = m["msg"]
        f = FAILED_RE.search(msg)
        if f:
            events.append(Event(ts, "failed", f["user"], f["ip"]))
            continue
        a = ACCEPTED_RE.search(msg)
        if a:
            events.append(Event(ts, "accepted", a["user"], a["ip"]))
    return sorted(events, key=lambda e: e.time)


def find_brute_force(events, threshold, window):
    """Return {ip: (first_hit_time, max_failures_in_window)} for IPs over the threshold."""
    fails = defaultdict(list)
    for e in events:
        if e.kind == "failed":
            fails[e.ip].append(e.time)
    result = {}
    for ip, times in fails.items():
        start, best, first_hit = 0, 0, None
        for end in range(len(times)):
            while (times[end] - times[start]).total_seconds() > window:
                start += 1
            count = end - start + 1
            best = max(best, count)
            if count >= threshold and first_hit is None:
                first_hit = times[end]
        if first_hit:
            result[ip] = (first_hit, best)
    return result


def analyze(events, threshold=5, window=60, spray_users=5):
    findings = []
    by_ip_fail = defaultdict(list)
    for e in events:
        if e.kind == "failed":
            by_ip_fail[e.ip].append(e)

    brute = find_brute_force(events, threshold, window)
    fmt = "%Y-%m-%d %H:%M:%S"

    for ip, (first_hit, best) in brute.items():
        evs = by_ip_fail[ip]
        findings.append(Finding(
            "MEDIUM", "BRUTE_FORCE", ip,
            f"{best} failed logins within {window}s ({len(evs)} failures total)",
            evs[0].time.strftime(fmt), evs[-1].time.strftime(fmt), len(evs)))

    for ip, evs in by_ip_fail.items():
        users = {e.user for e in evs}
        if len(users) >= spray_users:
            findings.append(Finding(
                "MEDIUM", "USERNAME_SPRAYING", ip,
                f"Tried {len(users)} different usernames: {', '.join(sorted(users)[:8])}"
                + ("..." if len(users) > 8 else ""),
                evs[0].time.strftime(fmt), evs[-1].time.strftime(fmt), len(evs)))

    for e in events:
        if e.kind == "accepted" and e.ip in brute and e.time >= brute[e.ip][0]:
            findings.append(Finding(
                "CRITICAL", "POSSIBLE_COMPROMISE", e.ip,
                f"Successful login as '{e.user}' AFTER a brute-force attack from this IP",
                e.time.strftime(fmt), e.time.strftime(fmt), 1))

    order = {"CRITICAL": 0, "MEDIUM": 1}
    return sorted(findings, key=lambda f: (order[f.severity], f.first_seen))


def build_timeline(events, findings):
    """Chronological list of events from IPs that raised a finding."""
    bad_ips = {f.ip for f in findings}
    return [e for e in events if e.ip in bad_ips]


RECOMMENDATIONS = {
    "BRUTE_FORCE": "Block the IP, install fail2ban, disable password login (use SSH keys).",
    "USERNAME_SPRAYING": "Block the IP and disable root login (PermitRootLogin no).",
    "POSSIBLE_COMPROMISE": "Treat as an incident: check the account, kill sessions, rotate credentials, review commands run.",
}


def print_report(events, findings, timeline_limit=25):
    fails = sum(1 for e in events if e.kind == "failed")
    oks = sum(1 for e in events if e.kind == "accepted")
    print("=" * 64)
    print(" SSH LOG ANALYSIS REPORT")
    print("=" * 64)
    print(f" Events parsed : {len(events)}  (failed: {fails}, successful: {oks})")
    print(f" Findings      : {len(findings)}")
    print("-" * 64)
    if not findings:
        print(" No suspicious activity detected.")
        return
    for i, f in enumerate(findings, 1):
        print(f"\n[{i}] {f.severity} - {f.type}")
        print(f"    IP        : {f.ip}")
        print(f"    Details   : {f.description}")
        print(f"    Time      : {f.first_seen}  ->  {f.last_seen}")
        print(f"    Fix       : {RECOMMENDATIONS[f.type]}")
    tl = build_timeline(events, findings)
    print("\n" + "-" * 64)
    print(f" TIMELINE (suspicious IPs, first {timeline_limit} of {len(tl)} events)")
    print("-" * 64)
    for e in tl[:timeline_limit]:
        label = "FAILED  " if e.kind == "failed" else "ACCEPTED"
        print(f" {e.time:%Y-%m-%d %H:%M:%S}  {label}  user={e.user:<10} ip={e.ip}")


def main():
    p = argparse.ArgumentParser(description="Detect brute-force SSH activity in auth logs.")
    p.add_argument("logfile", help="path to auth log (e.g. /var/log/auth.log)")
    p.add_argument("--year", type=int, default=datetime.now().year,
                   help="year of the log (syslog lines don't include it)")
    p.add_argument("--threshold", type=int, default=5, help="failed logins to flag (default 5)")
    p.add_argument("--window", type=int, default=60, help="window in seconds (default 60)")
    p.add_argument("--json", metavar="FILE", help="also save findings as JSON")
    args = p.parse_args()

    try:
        with open(args.logfile, encoding="utf-8", errors="replace") as fh:
            events = parse_log(fh, args.year)
    except OSError as err:
        sys.exit(f"Cannot read log file: {err}")

    findings = analyze(events, args.threshold, args.window)
    print_report(events, findings)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as out:
            json.dump([asdict(f) for f in findings], out, indent=2)
        print(f"\nJSON saved to {args.json}")


if __name__ == "__main__":
    main()
