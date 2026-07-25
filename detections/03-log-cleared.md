# Detection 03 — Windows Event Log Cleared

**MITRE ATT&CK:** [T1070.001 — Indicator Removal: Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/) · Tactic: Defense Evasion
**Data source:** Windows Security log (Event ID 1102)

---

## What it detects

The clearing of the Windows Security audit log. When the log is wiped, Windows records one mandatory event — **Event ID 1102 (the audit log was cleared)**. Attackers clear logs to destroy evidence of their activity, so this is one of the highest-fidelity signals available: almost nothing legitimate clears the Security audit log, and the event cannot be suppressed.

## The attack (simulation)

On the Windows endpoint, I cleared the Security event log:

```powershell
wevtutil cl Security
```

This produces **Event ID 1102**, capturing who cleared the log and when.

## The detection (SPL)

```spl
index=* host=DESKTOP* EventCode=1102 earliest=0 latest=+1d
```

**How it works:**
- `EventCode=1102` — the audit-log-cleared event; because it is inherently high-signal, no threshold or aggregation is needed
- A single occurrence warrants investigation

 <img width="3024" height="1636" alt="image" src="https://github.com/user-attachments/assets/3626a72d-01a5-4af5-9339-17943855f8fd" />

*Event ID 1102 (audit log cleared) captured on host DESKTOP-8C25V7F.*

## Why this is high-fidelity

Event 1102 is **mandatory** — Windows logs it regardless of audit policy, and it cannot be turned off. Combined with the fact that clearing the Security log is almost never legitimate, this makes it a near-zero-false-positive detection: an alert that should fire immediately and be treated seriously every time.

## MITRE ATT&CK mapping

[T1070.001 — Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/) (Defense Evasion): adversaries clear event logs to remove evidence of their activity and hinder investigation.

## Analyst response

1. **Treat as high priority immediately** — log clearing usually marks the cleanup phase of an intrusion.
2. **Identify the account** that cleared the log and determine whether it is compromised.
3. **Reconstruct the timeline** — because logs were already forwarded to Splunk, the cleared local evidence still exists centrally. Rebuild what happened on the host before the clear.
4. **Contain and investigate** — isolate the host and scope the activity.

## Notes

This detection demonstrates a core SOC principle: **forwarding logs off the host defeats log-clearing.** An attacker can wipe the local Security log, but the events already shipped to Splunk remain intact — so the act of clearing becomes a loud alert rather than a successful cover-up.
