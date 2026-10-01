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

## Project 02 — PowerShell Detection & Endpoint Investigation

Full write-up: [`projects/02-powershell-process-investigation/`](../projects/02-powershell-process-investigation/)

**Detection — Encoded PowerShell execution:**

```spl
index=* EventCode=1 host="DESKTOP-TEDQ8NH" Image="*\\powershell.exe" CommandLine="*-EncodedCommand*"
| stats count min(_time) as first_seen max(_time) as last_seen by host User Image
| convert ctime(first_seen) ctime(last_seen)
| sort - count
```

**Detection summary — classifies discovery, encoded PowerShell, and process-spawning activity in one pass:**

```spl
index=* EventCode=1 host="DESKTOP-TEDQ8NH"
| eval Activity=case(
    match(CommandLine,"-EncodedCommand"),"Encoded PowerShell",
    match(CommandLine,"Get-ComputerInfo"),"System Information Discovery",
    match(CommandLine,"Get-Process"),"Process Discovery",
    match(CommandLine,"Get-Service"),"Service Discovery",
    match(CommandLine,"Start-Process cmd.exe"),"PowerShell spawning CMD",
    true(),"Other"
)
| search Activity!="Other"
| stats count by Activity
| sort - count
```

Maps to MITRE ATT&CK **T1059.001, T1082, T1057, T1007, T1016, T1033**.

## Project 03 — Windows Persistence

_TBD_
