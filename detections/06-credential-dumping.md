# Detection 06 — Credential Dumping (SAM Hive)

**MITRE ATT&CK:** [T1003.002 — OS Credential Dumping: Security Account Manager](https://attack.mitre.org/techniques/T1003/002/) · Tactic: Credential Access
**Data source:** Windows process creation (Event ID 4688) with command-line auditing

---

## What it detects

The theft of the Windows **SAM registry hive** — where local account password hashes are stored — via `reg save hklm\sam`. Attackers export the SAM (often alongside the SYSTEM and SECURITY hives) to crack the hashes offline or reuse them elsewhere. Almost nothing legitimate saves the SAM hive to a file, making this a high-confidence credential-access indicator.

## The attack (simulation)

```powershell
reg save hklm\sam C:\Windows\Temp\sam.save
```

This launches `reg.exe`, captured by **Event ID 4688** with the full command line.

## The detection (SPL)

```spl
index=* EventCode=4688 reg earliest=0 latest=+1d
| eval cmd=lower(Process_Command_Line)
| where match(cmd,"reg") AND match(cmd,"save")
     AND (match(cmd,"sam") OR match(cmd,"system") OR match(cmd,"security"))
| table _time, host, Account_Name, Process_Command_Line
```

**How it works:**
- `eval cmd=lower(...)` — case-insensitive matching
- `match(cmd,"reg") AND match(cmd,"save")` — a registry export operation
- `... AND (sam OR system OR security)` — specifically targeting the credential-bearing hives, which is what makes this malicious rather than routine

<img width="3024" height="1456" alt="image" src="https://github.com/user-attachments/assets/e328f3a5-0771-4c65-9765-813e9d7196cc" />

## MITRE ATT&CK mapping

[T1003.002 — Security Account Manager](https://attack.mitre.org/techniques/T1003/002/) (Credential Access): adversaries extract credential material from the SAM database to obtain account password hashes.

## Analyst response

1. **Treat as an active credential-theft event.** SAM export is a pivot point — it turns one compromised host into stolen credentials for potentially the whole environment.
2. **Isolate the host** and locate the exported file (e.g. the `.save` output path).
3. **Force password resets** for accounts on the affected host; treat the local hashes as compromised.
4. **Identify the account and parent process** that performed the export.
5. **Hunt** for lateral movement using the stolen credentials (unusual logons elsewhere).

## Notes

Catching SAM export early is high-value because it sits at the transition from "they got in" to "they can get in anywhere." The detection targets the specific abusive pattern (`reg save` of a credential hive), keeping it high-signal while ignoring routine registry operations.
