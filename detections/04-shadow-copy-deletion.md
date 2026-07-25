# Detection 04 — Shadow Copy Deletion (Ransomware Indicator)

**MITRE ATT&CK:** [T1490 — Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/) · Tactic: Impact
**Data source:** Windows process creation (Event ID 4688) with command-line auditing

---

## What it detects

The deletion of Volume Shadow Copies — Windows' automatic file-restore snapshots. Ransomware deletes these snapshots immediately before encrypting files, so that victims cannot restore from backup. Detecting `vssadmin delete shadows` (or the `wmic shadowcopy delete` variant) is one of the highest-value alerts in any SOC, because it flags ransomware in the seconds before encryption begins.

## The attack (simulation)

```powershell
vssadmin delete shadows /all /quiet
```

This launches `vssadmin.exe`, captured by **Event ID 4688** with its full command line.

## The detection (SPL)

```spl
index=* EventCode=4688 (vssadmin OR wmic OR "shadowcopy") earliest=0 latest=+1d
| eval cmd=lower(Process_Command_Line)
| where (match(cmd,"vssadmin") AND match(cmd,"delete") AND match(cmd,"shadow"))
     OR (match(cmd,"wmic") AND match(cmd,"shadowcopy") AND match(cmd,"delete"))
| table _time, host, Account_Name, Process_Command_Line
```

**How it works:**
- `eval cmd=lower(...)` — lowercases the command line so the detection is not defeated by changing capitalization
- Independent `match()` token checks (`vssadmin` AND `delete` AND `shadow`) match the deletion regardless of argument order — more reliable than a single ordered pattern
- Covers both the `vssadmin` and `wmic` deletion methods in one search

<img width="3024" height="1456" alt="image" src="https://github.com/user-attachments/assets/dd2d044f-8158-457b-92e8-8c5196820d84" />

## MITRE ATT&CK mapping

[T1490 — Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/) (Impact): adversaries delete or disable recovery features such as Volume Shadow Copies to prevent victims from recovering encrypted or destroyed data.

## Analyst response

1. **Treat as a potential active ransomware event — highest priority.** Shadow copy deletion typically precedes mass encryption by seconds to minutes.
2. **Isolate the host immediately** to prevent encryption from spreading to network shares.
3. **Identify the account and parent process** that ran the command.
4. **Hunt across the environment** for the same command on other hosts — ransomware often deletes shadow copies fleet-wide.
5. **Escalate** to incident response; preserve remaining backups.

## Notes

This is a behavioral detection on the *command*, independent of any specific ransomware family — so it catches novel or custom ransomware that signature-based antivirus would miss. It is a strong example of detecting attacker *technique* rather than known malware.
