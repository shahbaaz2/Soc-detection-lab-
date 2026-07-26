# Risk-Based Alerting (RBA)

The centerpiece of this lab is a risk-based alerting engine — a detection model that scores suspicious behaviors, accumulates risk per host, and alerts only when a host crosses a risk threshold. This is the same approach used by mature Security Operations Centers (and the model behind Splunk Enterprise Security's RBA framework), built here from scratch in SPL.

---

## The problem it solves

Traditional alerting fires one alert per suspicious event. The problem is signal-to-noise:

- A single failed login is almost always a typo, not an attack.
- A single process launch is almost always legitimate.

If every one of these fires an alert, analysts drown in low-value notifications — and the real intrusion hides inside the flood. **Alert fatigue is the number-one operational complaint of real SOCs.**

## The approach

Rather than alerting on individual events, RBA works in three steps:

1. **Score each behavior** by how dangerous it actually is.
2. **Accumulate risk per host** across all observed behaviors.
3. **Alert only when a host crosses a threshold**, meaning multiple suspicious things happened on the same machine — the signature of a real intrusion, not a one-off.

The insight: a host doing *one* slightly-suspicious thing is probably fine. A host that fails logins **and** creates a new admin **and** dumps credentials **and** clears the logs is not a coincidence — it is an attack in progress.

## Risk scoring model

Scores reflect analyst judgment about how strongly each behavior indicates malicious intent:

| Behavior | MITRE | Risk Score | Reasoning |
|----------|-------|-----------|-----------|
| Failed login | T1110 | 10 | Common, usually benign |
| New admin account | T1136 | 40 | Notable privileged change |
| Run key persistence | T1547.001 | 40 | Autostart foothold |
| Defender tampering | T1562.001 | 70 | Active defense evasion |
| Credential dumping | T1003.002 | 80 | Credential theft in progress |
| Log clearing | T1070.001 | 80 | Covering tracks |
| Shadow copy deletion | T1490 | 90 | Ransomware precursor |

A failed login scores `10` because it is usually harmless. Shadow copy deletion scores `90` because almost nothing legitimate deletes backups — it is typically the final action before ransomware encrypts a system. The scoring is where detection-engineering judgment lives.

## The detection (SPL)

```spl
index=* (EventCode=4625 OR EventCode=4720 OR EventCode=4732 OR EventCode=1102 OR EventCode=4688)
| eval risk=case(
    EventCode=4625, 10,
    EventCode=4720 OR EventCode=4732, 40,
    EventCode=1102, 80,
    EventCode=4688 AND match(lower(Process_Command_Line),"vssadmin.*delete|shadowcopy.*delete"), 90,
    EventCode=4688 AND match(lower(Process_Command_Line),"mppreference"), 70,
    EventCode=4688 AND match(lower(Process_Command_Line),"reg.*save.*(sam|system|security)"), 80,
    EventCode=4688 AND match(lower(Process_Command_Line),"currentversion.*run"), 40,
    1=1, 0)
| where risk > 0
| stats sum(risk) as total_risk by host
| where total_risk >= 100
| sort - total_risk
```

**How it works:**
- `eval risk=case(...)` — assigns a risk score to each event based on its type and, for process events, its command line
- `where risk > 0` — keeps only events that match a scored behavior
- `stats sum(risk) as total_risk by host` — accumulates total risk per host
- `where total_risk >= 100` — surfaces only hosts that cross the threshold (multiple suspicious behaviors)
- `sort - total_risk` — highest-risk hosts first, so the analyst sees the priority target immediately

## Result

In the lab, the monitored endpoint accumulated risk well past the threshold across the attack simulation — surfacing as a single, high-confidence alert identifying the compromised host and the techniques that drove its score. Instead of dozens of scattered low-value alerts, the analyst sees one prioritized answer: *this host, right now.*

## Why it matters

This is the difference between a detection library that *fires alerts* and one that *prioritizes response*. RBA demonstrates an understanding of the operational reality of a SOC — that the goal is not to detect everything, but to surface what matters, in priority order, without burying the analyst in noise.

## Extending the model

The engine is designed to grow: every new detection simply adds a scored line to the `case()` block, contributing to each host's cumulative risk. Natural next steps include per-user risk (not just per-host), time-decay so old risk ages out, and risk contributions from correlation searches (e.g. failed logins *followed by* a success).
