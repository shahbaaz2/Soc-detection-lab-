# Detection 02 — New Account Creation + Privilege Escalation

**MITRE ATT&CK:** [T1136 — Create Account](https://attack.mitre.org/techniques/T1136/) · Tactic: Persistence
**Data source:** Windows Security log (Event IDs 4720, 4732)

---

## What it detects

The creation of a new user account, immediately followed by that account being added to a privileged group (Administrators). A new account on its own is routine IT activity. A new account that instantly becomes an administrator is a classic attacker move — it establishes a persistent foothold *and* escalates privilege in one motion, so the intruder keeps access even if their original entry point is closed.

## The attack (simulation)

On the Windows endpoint, I created a new local user and added it straight to the Administrators group:

```powershell
net user hacker P@ssw0rd123 /add
net localgroup administrators hacker /add
```

This generates two Windows Security events: **4720** (a user account was created) and **4732** (a member was added to a security-enabled local group).

## The detection (SPL)

```spl
index=* host=DESKTOP* (EventCode=4720 OR EventCode=4732) earliest=0 latest=+1d
| table _time, EventCode, Account_Name, Target_User_Name
```

**How it works:**
- `EventCode=4720 OR EventCode=4732` — captures both the account creation and the privileged group change
- `table ...` — shows when it happened, which event fired, who performed it, and which account was affected

Saved as a scheduled alert, triggering when results are greater than 0.

<img width="3024" height="1636" alt="image" src="https://github.com/user-attachments/assets/37ee2446-ac6a-4431-9512-ad87a1095604" />

*Account creation (4720) and Administrators group addition (4732) events captured on host DESKTOP-8C25V7F.*

## MITRE ATT&CK mapping

[T1136 — Create Account](https://attack.mitre.org/techniques/T1136/) (Persistence): adversaries create accounts to maintain access to a system. The immediate group-membership change also relates to [T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/) / privilege escalation, since the attacker grants the new account administrative rights.

## Analyst response

1. **Verify legitimacy** — was this account creation part of an approved IT / onboarding process, or unexpected?
2. **Identify who created it** — the account performing the action; a compromised admin creating new admins is a serious indicator.
3. **Inspect the new account** — its name, privileges, and whether it has logged on since.
4. **Contain** — disable or delete the rogue account (`net user hacker /delete`) and reset the credentials of the account that created it.
5. **Hunt** — review what the creating account did before and after; account creation rarely happens in isolation during an intrusion.

## Notes

The high-fidelity version of this detection pairs a 4720 and a 4732 for the *same* target account within a short window — the "created then immediately escalated" signature. In production, known service-account and provisioning activity is baselined out so that only *unexpected* privileged account changes alert.
