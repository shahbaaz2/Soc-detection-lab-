# SOC Detection Lab

**A home-built security monitoring lab: a Splunk SIEM, a Windows endpoint, and 8 detections mapped to MITRE ATT&CK — including a risk-based alerting engine that prioritizes hosts instead of drowning analysts in per-event alerts.**

> Built end-to-end on Apple Silicon (M1): Splunk Enterprise on macOS, a Windows 11 VM as the monitored endpoint, logs shipped via the Splunk Universal Forwarder.

<img width="1920" height="6086" alt="Soc-Dashboard" src="https://github.com/user-attachments/assets/1c769e6f-c96b-46ff-9b89-b29da1c5d45e" />

---

## Overview

This project reproduces the core work of a Security Operations Center: **collect logs, detect malicious behavior, and prioritize what matters.**

I built a complete detection pipeline — a Windows endpoint generating security telemetry, forwarded into Splunk, where I wrote and tuned **8 detections** spanning the attack lifecycle (credential access, persistence, privilege escalation, defense evasion, impact, and discovery). For every detection I **simulated the attack, confirmed the alert fired, and mapped it to MITRE ATT&CK.**

The centerpiece is a **risk-based alerting (RBA)** engine: instead of firing one alert per event, it scores each suspicious behavior by risk, sums the risk per host, and surfaces only hosts that cross a threshold — the same approach mature SOCs use to fight alert fatigue.

---

## Architecture

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

| Component | Choice | Notes |
|-----------|--------|-------|
| SIEM | Splunk Enterprise (Free license) | Runs on macOS via Rosetta 2 |
| Endpoint | Windows 11 (ARM) in VMware Fusion | The monitored "victim" machine |
| Log shipping | Splunk Universal Forwarder | Forwards Windows logs to Splunk over port 9997 |
| Telemetry | Windows Security + System logs, Event 4688 with command-line auditing | Native process-execution visibility, agentless |

A key engineering choice: process-execution visibility is delivered through **native Windows Event 4688 command-line auditing** (enabled via Group Policy / registry), rather than a third-party agent — a lightweight foundation that powers the command-line detections in this lab.

---

## Detection Coverage

Each detection was validated by generating the attack on the endpoint and confirming it surfaced in Splunk. Full writeups live in [`/detections`](detections/).

| # | Detection | MITRE ATT&CK | Tactic |
|---|-----------|--------------|--------|
| 01 | Brute force / failed logins | [T1110](https://attack.mitre.org/techniques/T1110/) | Credential Access |
| 02 | New account + privilege escalation | [T1136](https://attack.mitre.org/techniques/T1136/) | Persistence |
| 03 | Windows event log cleared | [T1070.001](https://attack.mitre.org/techniques/T1070/001/) | Defense Evasion |
| 04 | Shadow copy deletion (ransomware precursor) | [T1490](https://attack.mitre.org/techniques/T1490/) | Impact |
| 05 | Defender tampering | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Defense Evasion |
| 06 | Credential dumping (SAM hive) | [T1003.002](https://attack.mitre.org/techniques/T1003/002/) | Credential Access |
| 07 | Run key persistence | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Persistence |
| 08 | Discovery / recon burst (behavioral) | [T1087](https://attack.mitre.org/techniques/T1087/) / [T1082](https://attack.mitre.org/techniques/T1082/) | Discovery |

Detection #08 is **behavioral** rather than signature-based: it fires only when a host runs 3+ distinct reconnaissance tools within a 5-minute window — catching the "attacker just landed and is mapping the system" pattern while ignoring benign one-off use of any single tool.

---

## Risk-Based Alerting (the differentiator)

A traditional SIEM fires one alert per suspicious event. The problem: most single events are benign (one failed login is a typo), so analysts drown in noise and real intrusions hide in the flood — the #1 complaint of every real SOC.

This lab implements **risk-based alerting** instead:

1. Each suspicious behavior is assigned a **risk score** based on how dangerous it actually is
2. Risk is **accumulated per host**
3. An alert fires **only when a host crosses a risk threshold** (100)

The scores reflect real analyst judgment — a failed login is `10` because it's usually harmless; **shadow copy deletion is `90`** because almost nothing legitimate deletes backups (it's ransomware about to detonate).

| Behavior | Risk Score | Reasoning |
|----------|-----------|-----------|
| Failed login | 10 | Common, usually benign |
| New admin account | 40 | Notable account change |
| Run key persistence | 40 | Autostart foothold |
| Encoded / suspicious process | 60 | Signals intent to hide |
| Defender tampering | 70 | Active defense evasion |
| Credential dumping | 80 | Credential theft in progress |
| Log clearing | 80 | Covering tracks |
| Shadow copy deletion | 90 | Ransomware precursor |

**Result:** the test endpoint accumulated high cumulative risk across the attack simulation — one host, clearly flagged and prioritized, instead of dozens of scattered low-value alerts. This is the model behind Splunk Enterprise Security's RBA framework, built here from scratch.

---

## Dashboard

A SOC dashboard visualizes the full picture in one view — detection volume, distinct MITRE techniques observed, host risk scores, an attack timeline, and a live activity feed showing every detection event with its host, account, and command.

<img width="1920" height="6086" alt="Soc-Dashboard" src="https://github.com/user-attachments/assets/d4b829f6-a203-4307-a7a4-13697b344835" />

- **KPI tiles** — detection events matched, distinct techniques observed, hosts above the risk threshold
- **Top Risky Hosts (RBA)** — cumulative risk per host, broken down by technique
- **MITRE ATT&CK Techniques Detected** — coverage breadth at a glance
- **Detection Activity Over Time** — the intrusion unfolding on a timeline
- **Attack Activity Timeline** — every detection event with host, account, and the command that ran

---

## Tools & Skills Demonstrated

`Splunk` · `SPL` · `MITRE ATT&CK` · `Windows Event Logs` · `Universal Forwarder` · `Risk-Based Alerting` · `Detection Engineering` · `Attack Simulation` · `VMware`

---

## Repository Structure

```
soc-detection-lab/
├── README.md
├── soc-dashboard.png
└── detections/
    ├── 01-brute-force.md
    ├── 02-account-creation.md
    ├── 03-log-cleared.md
    ├── 04-shadow-copy-deletion.md
    ├── 05-defender-tampering.md
    ├── 06-credential-dumping.md
    ├── 07-run-key-persistence.md
    └── 08-discovery-recon-burst.md
```

---

*Built by Shahbaaz Singh — [LinkedIn](https://www.linkedin.com/in/shahbaaz-singh-1b9a571b7/)
