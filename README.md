# Splunk SOC Lab

A hands-on Splunk portfolio built to demonstrate detection engineering and SOC monitoring skills, from raw telemetry through investigation to a working dashboard.

## Environment

- Splunk Enterprise (60-day Enterprise Trial license), single instance
- Ubuntu 24.04 LTS endpoint (SSH, Apache) and Windows endpoint (Sysmon, Security/PowerShell logging), both forwarding via Splunk Universal Forwarder
- Malicious activity generated from a Kali Linux attacker host — direct attack simulation for Linux-based projects, Atomic Red Team executions for Windows-based projects — mapped to specific MITRE ATT&CK techniques per project
- Full build and verification steps: [`setup/setup.md`](setup/setup.md)

## Projects

| # | Project | Primary skill | Status |
|---|---|---|---|
| 01 | [SSH Brute-Force Investigation](projects/01-ssh-brute-force-investigation/) | Authentication analysis + SPL | ✅ Complete |
| 02 | [PowerShell & Suspicious Process Investigation](projects/02-powershell-process-investigation/) | Sysmon + process analysis + detection | Not started |
| 03 | [Windows Persistence Investigation](projects/03-windows-persistence/) | Persistence detection + ATT&CK | Not started |
| — | [SOC Monitoring & Threat Detection Dashboard](dashboard/) | SPL + dashboards + SOC monitoring | Not started |

The dashboard is built incrementally as each investigation project is completed, using the detections and telemetry those projects generate rather than separate synthetic data.

## Repository structure

```
splunk-soc-lab/
├── setup/          # environment build and pipeline verification
├── data/           # telemetry source notes
├── detections/     # SPL queries, organized by project
├── dashboard/       # SOC monitoring dashboard (built alongside 01-03)
└── projects/        # the three investigations
```
