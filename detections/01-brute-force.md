# Detection 01 — Brute Force / Failed Logins

**MITRE ATT&CK:** [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/) · Tactic: Credential Access
**Data source:** Windows Security log (Event ID 4625)

---

## What it detects

Repeated failed logon attempts against a host — the signature of someone guessing passwords. A single failed login is almost always benign (a typo); a cluster of failures in a short window is not. Each failed attempt generates **Windows Event ID 4625 (An account failed to log on)**, which this detection surfaces from the Security log.

## The attack (simulation)

On the Windows endpoint, I locked the session and deliberately entered the wrong password several times before logging in correctly. Each failed attempt produced a 4625 event, forwarded into Splunk.

## The detection (SPL)

```spl
index=* host=DESKTOP* EventCode=4625 earliest=0 latest=+1d
```

**How it works:**
- `EventCode=4625` — isolates failed-logon events
- `host=DESKTOP*` — scopes the search to the monitored endpoint
- The result set surfaces every failed login with its account, source, and failure reason for review

Saved as a scheduled alert that runs on a recurring schedule and triggers when failed-login events appear.

<img width="3024" height="1636" alt="image" src="https://github.com/user-attachments/assets/b0294491-a9f5-4a35-8d57-908f2886f5f4" />


## MITRE ATT&CK mapping

[T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/) (Credential Access): adversaries systematically guess account passwords through repeated logon attempts to gain access.

## Analyst response

1. **Confirm the pattern** — is it one account (targeted brute force) or many accounts (password spraying)?
2. **Check for a success after the failures** — a burst of 4625s followed by a 4624 (successful logon) from the same source indicates a **successful** brute force and an active compromise.
3. **Identify the source** — internal host (possible malware / lateral movement) vs. external (internet-facing exposure).
4. **Contain** — lock or disable the targeted account; block the source if external.
5. **Escalate** if a successful logon followed the failures.

## Notes (tuning)

For a higher-fidelity, threshold-based alert, this detection can be aggregated to fire only when an account exceeds a failure count in a short window:

```spl
index=* EventCode=4625
| stats count as failures, values(Failure_Reason) as reason by Account_Name, host
| where failures >= 5
```

Production environments typically alert at 5+ failures within a tight window to balance detection against noise from users who simply forgot a password. The natural next step is a **correlation search** pairing failures with a subsequent success from the same account — turning "someone tried" into "someone got in," the higher-value alert.
