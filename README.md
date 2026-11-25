# SSH Log Analyzer

A small Python tool that reads Linux SSH logs and detects signs of attack, then prints a report with fix recommendations and a timeline of suspicious activity. Built as part of my cybersecurity portfolio (digital forensics and incident investigation).

## What it detects

| Finding | Meaning | Severity |
|---|---|---|
| `BRUTE_FORCE` | Many failed logins from one IP in a short window | Medium |
| `USERNAME_SPRAYING` | One IP trying many different usernames | Medium |
| `POSSIBLE_COMPROMISE` | A successful login *after* a brute-force attack from the same IP | Critical |

## Quick start

No dependencies needed, only Python 3.8+.

```bash
python3 generate_sample_log.py                 # creates a FAKE sample_auth.log
python3 log_analyzer.py sample_auth.log --year 2026
python3 log_analyzer.py sample_auth.log --year 2026 --json findings.json
```

Run on a real log (only systems you own or are authorized to review):

```bash
sudo python3 log_analyzer.py /var/log/auth.log
```

### Options

| Option | Default | Description |
|---|---|---|
| `--threshold` | 5 | Failed logins needed to flag an IP |
| `--window` | 60 | Time window in seconds |
| `--year` | current year | Syslog lines have no year, so set it here |
| `--json FILE` | off | Save findings as JSON |

## Example output

```
[1] CRITICAL - POSSIBLE_COMPROMISE
    IP        : 203.0.113.45
    Details   : Successful login as 'root' AFTER a brute-force attack from this IP
    Fix       : Treat as an incident: check the account, kill sessions, rotate credentials...
```

## How it works

1. **Parse**: regex extracts the time, user, and IP from `sshd` lines.
2. **Detect**: a sliding time window counts failures per IP.
3. **Correlate**: a successful login from an IP that already brute-forced is escalated to CRITICAL.
4. **Report**: findings, recommended fixes, and a chronological timeline.

## Tests

```bash
python3 -m unittest discover tests -v
```

## What I learned

- How SSH authentication events appear in logs
- Sliding-window detection and event correlation
- How an investigator reconstructs an attack timeline

## Ideas for improvement

- Support `journalctl` / `secure` (RHEL) log formats
- IP geolocation lookup
- Export a Markdown or HTML incident report
- Auto-generate firewall block rules

## Disclaimer

For educational and defensive use only. The sample log is fake and uses reserved documentation IP addresses.
