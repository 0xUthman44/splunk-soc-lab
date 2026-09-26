# Lab Setup — Splunk SOC Environment

This documents the build and verification of the Splunk ingestion pipeline for the lab, before any investigation work began.

## Environment

| Role | Host | IP | Notes |
|---|---|---|---|
| Splunk Enterprise (indexer + search head) | Splunk-SOC VM | 192.168.56.105 | Ubuntu Server 24.04 LTS, 2 vCPU, 4 GB RAM, Enterprise Trial license |
| Linux telemetry source | Ubuntu | 192.168.56.102 | SSH, Apache, auth.log — forwards via Universal Forwarder |
| Windows telemetry source | Windows | 192.168.56.101 | Sysmon, Security/Application/System event logs, PowerShell — forwards via Universal Forwarder |
| Attacker | Kali | 192.168.56.103 | Powered on only when generating activity |
| Legacy SIEM | Wazuh | 192.168.56.104 | Kept off for this lab |

## 1. Configure Splunk to receive forwarded data

Before either endpoint can forward, the Splunk instance needs to listen for incoming forwarder connections.

1. Forwarding and Receiving page, before any receiver is configured.
   ![Splunk forwarding and receiving overview](screenshots/01-splunk-forwarding-and-receiving-overview.png)
2. Configured to listen on TCP 9997, the standard Splunk forwarder-to-indexer port.
   ![Configure receiving on port 9997](screenshots/02-splunk-configure-receiving-port-9997.png)
3. Confirmed on the Splunk server itself that `splunkd` is bound and listening on 9997.
   ![splunkd listening on port 9997](screenshots/03-splunk-server-listening-on-9997.png)

## 2. Ubuntu (.102) Universal Forwarder

1. Installed the Splunk Universal Forwarder and confirmed the service is running.
   ![Ubuntu forwarder installed and running](screenshots/04-ubuntu-forwarder-installed-and-running.png)
2. Verified network reachability from Ubuntu to the indexer on port 9997.
   ![Ubuntu forwarder connectivity test](screenshots/05-ubuntu-forwarder-connectivity-test.png)
3. Confirmed events arriving in Splunk under `index=ubuntu` — `auth.log` entries via `sourcetype=linux_secure`.
   ![Splunk search confirming Ubuntu events received](screenshots/06-splunk-search-ubuntu-index-events-received.png)
4. Narrowed the search to `sourcetype=linux_secure` to confirm ongoing, real-time ingestion.
   ![Splunk search filtered to linux_secure sourcetype](screenshots/07-splunk-search-ubuntu-linux-secure-sourcetype.png)

## 3. Windows (.101) Universal Forwarder

1. Verified network reachability to the indexer and confirmed an active forward-server entry.
   ![Windows connectivity test and active forward](screenshots/08-windows-forwarder-connectivity-and-active-forward.png)
2. Edited `inputs.conf` to enable Application, Security, and System event logs plus the Sysmon operational log.
   ![Windows inputs.conf with EventLog and Sysmon stanzas](screenshots/09-windows-inputs-conf-eventlog-and-sysmon.png)
3. Used `btool` to confirm each input stanza was applied correctly:
   - Application log
     ![btool check — Application log](screenshots/10-windows-btool-check-application-log.png)
   - Security log
     ![btool check — Security log](screenshots/11-windows-btool-check-security-log.png)
   - Sysmon operational log
     ![btool check — Sysmon operational](screenshots/12-windows-btool-check-sysmon-operational.png)
4. Confirmed Sysmon events arriving in Splunk under `index=windows` from `DESKTOP-TEDQ8NH`.
   ![Splunk search confirming Windows Sysmon events received](screenshots/13-splunk-search-windows-index-sysmon-events-received.png)

## Result

Both endpoints are forwarding to the Splunk indexer and their telemetry is confirmed searchable. Detection and investigation work for Projects 01–03 builds on this pipeline.
