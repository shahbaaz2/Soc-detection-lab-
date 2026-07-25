# Detection 07 — Run Key Persistence

**MITRE ATT&CK:** [T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys](https://attack.mitre.org/techniques/T1547/001/) · Tactic: Persistence
**Data source:** Windows process creation (Event ID 4688) with command-line auditing

---

## What it detects

The creation of a registry **Run key** — an entry under `...\CurrentVersion\Run` that automatically launches a program every time the user logs in. Run keys are the most common persistence mechanism in the wild: an attacker points one at their payload so their access survives logoffs and reboots, and it requires no administrative rights.

## The attack (simulation)

```powershell
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Updater /t REG_SZ /d "C:\Windows\Temp\evil.exe" /f
```

This launches `reg.exe`, captured by **Event ID 4688** with the full command line.

## The detection (SPL)

```spl
index=* EventCode=4688 reg earliest=0 latest=+1d
| eval cmd=lower(Process_Command_Line)
| where match(cmd,"reg") AND match(cmd,"add")
     AND match(cmd,"currentversion") AND match(cmd,"run")
| table _time, host, Account_Name, Process_Command_Line
```

**How it works:**
- `eval cmd=lower(...)` — case-insensitive matching
- `match(cmd,"reg") AND match(cmd,"add")` — a registry write
- `... AND currentversion AND run` — specifically targeting the autostart Run key location

 <img width="3024" height="1456" alt="image" src="https://github.com/user-attachments/assets/0864044b-a1fd-4ae6-a0ba-2b62e59a3266" />

## MITRE ATT&CK mapping

[T1547.001 — Registry Run Keys](https://attack.mitre.org/techniques/T1547/001/) (Persistence): adversaries add programs to registry Run keys so they execute automatically at logon, maintaining access across reboots.

## Analyst response

1. **Inspect the target of the Run key** — the path/executable it points to. A binary in a temp or user directory (e.g. `C:\Windows\Temp\evil.exe`) is a strong indicator.
2. **Identify the account** that created the key.
3. **Contain** — remove the Run key and locate/quarantine the referenced payload.
4. **Hunt** — check other hosts for the same Run key value name or target path.

## Notes

Run key persistence is high-frequency and low-privilege, so this detection focuses on the *target* of the key — payloads in non-standard locations are the strongest signal. Known-good autostart entries can be baselined out to keep the alert high-signal in production.
