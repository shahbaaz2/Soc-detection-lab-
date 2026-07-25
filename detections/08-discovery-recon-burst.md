# Detection 08 — Discovery / Recon Burst (Behavioral)

**MITRE ATT&CK:** [T1087 — Account Discovery](https://attack.mitre.org/techniques/T1087/) / [T1082 — System Information Discovery](https://attack.mitre.org/techniques/T1082/) · Tactic: Discovery
**Data source:** Windows process creation (Event ID 4688), process names

---

## What it detects

A burst of reconnaissance activity — a single host running several different discovery tools in a short window. When an attacker first lands on a machine, they map their surroundings: who they are, what accounts exist, what the system is, what network it's on, what's running. Any one of these commands is benign on its own, so this detection fires on the **pattern**: 3 or more distinct recon tools within a 5-minute window.

## The attack (simulation)

```powershell
whoami /priv; net user; net localgroup administrators; systeminfo; ipconfig /all; tasklist
```

Each command launches its own process, all captured by **Event ID 4688**.

## The detection (SPL)

```spl
index=* EventCode=4688 earliest=0 latest=+1d
| eval proc=lower(New_Process_Name)
| where like(proc,"%whoami.exe") OR like(proc,"%systeminfo.exe") OR like(proc,"%ipconfig.exe")
     OR like(proc,"%tasklist.exe") OR like(proc,"%net.exe") OR like(proc,"%net1.exe") OR like(proc,"%nltest.exe")
| bin _time span=5m
| stats dc(proc) as recon_tools, values(proc) as tools_used, count as total by host, _time
| where recon_tools >= 3
```

**How it works:**
- `where like(proc, ...)` — keeps only known reconnaissance binaries
- `bin _time span=5m` — groups events into 5-minute windows
- `stats dc(proc) ... by host, _time` — counts *distinct* recon tools per host per window
- `where recon_tools >= 3` — fires only when a host ran 3+ different recon tools together — the burst pattern


<img width="3024" height="1456" alt="image" src="https://github.com/user-attachments/assets/21b32f93-de8b-4a41-8bee-3aa45cb39c43" />


## MITRE ATT&CK mapping

[T1087 — Account Discovery](https://attack.mitre.org/techniques/T1087/) and [T1082 — System Information Discovery](https://attack.mitre.org/techniques/T1082/) (Discovery): adversaries enumerate accounts, groups, and system/network configuration to plan their next move after gaining access.

## Analyst response

1. **Correlate with initial access** — a recon burst shortly after a logon or process-execution alert strongly suggests a hands-on-keyboard intruder.
2. **Review the specific tools used** — the `tools_used` list shows exactly what the attacker enumerated (accounts, admins, network, running processes).
3. **Identify the account and session** performing the recon.
4. **Contain and hunt** — recon precedes lateral movement and privilege escalation; look for what the same account did next.

## Notes

This is a **behavioral** detection — it aggregates benign individual events into a suspicious pattern over time, rather than matching a single signature. It demonstrates a more advanced detection style: reducing false positives by requiring a *combination* of activity within a time window, instead of alerting on any one recon command.
