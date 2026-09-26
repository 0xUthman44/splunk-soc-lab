# Detection Logic — SPL Queries

All saved searches used across the investigations and dashboard, organized by project. Populate this as each project's detections are built, so it doubles as a single reference of the search logic used throughout the portfolio.

## Project 01 — SSH Brute-Force Investigation

Full write-up: [`projects/01-ssh-brute-force-investigation/`](../projects/01-ssh-brute-force-investigation/)

**Detection — repeated failed SSH authentication, accounting for syslog message aggregation:**

```spl
index=ubuntu sourcetype=linux_secure "Failed password"
| rex "message repeated (?<repeat_count>\d+) times"
| rex "from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| eval attempts=coalesce(repeat_count,0)+1
| stats sum(attempts) as failed_attempts by src_ip
| where failed_attempts >= 5
| sort - failed_attempts
```

Maps to MITRE ATT&CK **T1110 — Brute Force**.

## Project 02 — PowerShell & Suspicious Process

_TBD_

## Project 03 — Windows Persistence

_TBD_
