# Detection 05 — Defender Tampering (Impair Defenses)

**MITRE ATT&CK:** [T1562.001 — Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/) · Tactic: Defense Evasion
**Data source:** Windows process creation (Event ID 4688) with command-line auditing

---

## What it detects

Attempts to disable or weaken Microsoft Defender — turning off real-time monitoring or adding scan exclusions via `Set-MpPreference` / `Add-MpPreference`. Attackers blind the antivirus immediately before deploying a payload, so this command is a strong signal that an attack is being staged. Almost no legitimate workflow disables real-time protection this way.

## The attack (simulation)

```powershell
powershell.exe -Command "Set-MpPreference -DisableRealtimeMonitoring $true"
```

This launches `powershell.exe` with the tampering command on its command line, captured by **Event ID 4688**.

## The detection (SPL)

```spl
index=* EventCode=4688 mppreference earliest=0 latest=+1d
| table _time, host, Process_Command_Line
```

**How it works:**
- `EventCode=4688 mppreference` — surfaces any process whose command line references the Defender preference cmdlets
- `table ...` — shows when, on which host, and the exact tampering command

 <img width="3024" height="1456" alt="image" src="https://github.com/user-attachments/assets/eccd282e-3f40-4f30-b136-b5cc741e22ce" />


## MITRE ATT&CK mapping

[T1562.001 — Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/) (Defense Evasion): adversaries disable or modify security tools to avoid detection of their activity.

## Analyst response

1. **Investigate immediately** — disabling AV is rarely benign and usually precedes a payload.
2. **Confirm whether the change succeeded** — modern Windows Tamper Protection may block the disable, but the *attempt* is still an indicator worth acting on.
3. **Identify the account and parent process** that issued the command.
4. **Re-enable protection** and run a full scan on the host.
5. **Hunt** for what executed on the host immediately after the tampering attempt.

## Notes

This detection captures the *attempt* regardless of outcome — a key strength, since catching "an attacker tried to turn off AV" is as valuable as catching a successful disable. It is a clean demonstration of command-line-based defense-evasion detection.
