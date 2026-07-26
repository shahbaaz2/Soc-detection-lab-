# Lab Architecture

This document describes how the detection lab is built and how log data flows from the monitored endpoint into Splunk for detection and alerting.

---

## Overview

The lab models a minimal but complete Security Operations Center pipeline: a monitored Windows endpoint generating security telemetry, a forwarder shipping that telemetry to a central SIEM, and detection logic running against the collected data. The entire environment runs on a single Apple Silicon (M1) MacBook.

```
┌─────────────────────────────┐         ┌──────────────────────────────┐
│   Windows 11 Endpoint (VM)  │         │       macOS Host (M1)        │
│                             │  logs   │                              │
│  • Security event log       │ ──────► │   Splunk Enterprise (SIEM)   │
│  • System event log         │  :9997  │   • Indexing                 │
│  • Process creation (4688)  │         │   • Detections / alerts      │
│  • Splunk Universal Fwder   │         │   • RBA engine + dashboard   │
└─────────────────────────────┘         └──────────────────────────────┘
        (attacker + victim)                    (monitoring / SOC)
```

---

## Components

| Component | Role | Details |
|-----------|------|---------|
| **Splunk Enterprise** | SIEM | Runs on the macOS host (Free license). Indexes forwarded logs, runs detection searches, hosts the dashboard. |
| **Windows 11 (VM)** | Monitored endpoint | Runs in VMware Fusion. Serves as both the "victim" (generating telemetry) and the point where simulated attacks are executed. |
| **Splunk Universal Forwarder** | Log shipper | Installed on the Windows endpoint. Forwards Windows event logs to Splunk over TCP port 9997. |
| **Windows Event Logs** | Data source | Security and System channels — logons, account changes, service installs, log clears. |
| **Event 4688 (command-line auditing)** | Data source | Native process-creation logging with full command line, enabling execution-based detections without a third-party agent. |

---

## Data Flow

1. **Activity occurs** on the Windows endpoint — a logon attempt, an account change, a process launch, a registry write.
2. **Windows records the event** in the Security or System event log (and, for process launches, Event 4688 with the full command line).
3. **The Universal Forwarder ships the event** to Splunk over port 9997.
4. **Splunk indexes the event**, making it searchable.
5. **Detection searches evaluate the event** — matching it against known malicious patterns and, in the RBA engine, assigning it a risk score.
6. **Alerts fire and the dashboard updates**, surfacing the activity to the analyst.

---

## Telemetry Design

Process-execution visibility in this lab is delivered through **native Windows Event 4688 process-creation auditing with command-line capture**, enabled via audit policy and a registry setting:

```powershell
auditpol /set /subcategory:"Process Creation" /success:enable
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

This provides full command-line telemetry — the foundation for the execution and defense-evasion detections — on the reliable Windows Security channel, with no third-party agent required. In Splunk, the relevant fields are `Process_Command_Line`, `New_Process_Name`, `Creator_Process_Name`, and `Account_Name`.

---

## Log Sources and Event IDs Used

| Event ID | Meaning | Used by detection |
|----------|---------|-------------------|
| 4625 | Failed logon | 01 — Brute Force |
| 4720 / 4732 | Account created / added to group | 02 — Account Creation + Priv Esc |
| 1102 | Security audit log cleared | 03 — Log Cleared |
| 4688 | Process creation (with command line) | 04, 05, 06, 07, 08 |

---

## Design Notes

- **Isolated environment** — the endpoint runs in a VM, keeping all attack simulation contained.
- **Centralized logging** — forwarding logs off the host means locally-cleared logs still exist in Splunk, which is what makes the log-clearing detection (03) meaningful.
- **Agentless process visibility** — using native 4688 auditing rather than a separate endpoint agent keeps the pipeline simple and reliable while still capturing full command lines.
