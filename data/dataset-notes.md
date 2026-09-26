# Dataset / Telemetry Notes

Telemetry is self-generated, not a pre-packaged public dataset (e.g. not Splunk BOTS).

- **Source:** Sysmon + native Windows Security/Application/System event logs (Windows endpoint), auth.log/SSH (Ubuntu endpoint)
- **Malicious activity:** Generated from the Kali attacker host — direct attack tooling for Linux-based projects, Atomic Red Team for Windows-based projects — mapped to specific ATT&CK technique IDs per project
- **Rationale:** Full control over the collection pipeline (Universal Forwarder configuration, Sysmon config) and over what maps to which project, rather than querying already-answered public data

## Project 01 — SSH Brute-Force Investigation

- **Technique:** T1110 — Brute Force
- **Method:** Repeated SSH authentication attempts with incorrect credentials, from Kali (`192.168.56.103`) against the Ubuntu endpoint (`192.168.56.102`)
- **Date:** 2026-09-24

_To fill in for Projects 02–03: which Atomic Red Team tests were run, their ATT&CK technique IDs, and the date/time window they were executed in._
