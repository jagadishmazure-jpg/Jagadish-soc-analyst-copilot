# Hunt Playbooks

The copilot's built-in hunt suggestions, mapped to MITRE ATT&CK tactics. Each fires deterministically when the finding pattern is present.

## Credential Access (TA0006)

**Trigger:** failed-logon burst (≥ 20 failures, concentrated sources).

- Check whether any logons from the same source IPs **succeeded** — a burst followed by success means the brute force worked.
- Block/rate-limit offending IPs at the perimeter; force password resets on targeted accounts.
- Pivot: `logons by <user>` to see the full authentication timeline around the burst.

## Valid Accounts (T1078) / Anomalous Geo (Initial Access, TA0001)

**Trigger:** > 30% of a user's activity from an unusual geo (≥ 5 events).

- Run impossible-travel analysis: same user, two geos, short window.
- Check for concurrent sessions and token reuse across the geos.
- Pivot: `traffic from <ip>` for the unusual-geo source IPs.

## Execution / Defense Evasion (TA0002, TA0005)

**Trigger:** process never seen in the baseline executes.

- Trace the parent process lineage (e.g. `cmd.exe → mimikatz.exe`).
- Check prevalence across the fleet: one host suggests targeted intrusion; many hosts suggest worm or sanctioned tooling.
- Pull the full command line and files written for malware triage.

## Command and Control / Exfiltration (TA0011, TA0010)

**Trigger:** firewall deny rate > 30% (≥ 10 flows).

- Pivot to auth logs for the same source IPs — denied egress plus failed logons is the classic compromised-host pattern.
- Review allowed flows to the same destinations: what got out before the blocks started.

## Extending

Add a new trigger in `hunts.py` keyed to a `flags` entry produced by `engine.py`, and document the tactic mapping here. Keep suggestions deterministic and explain *why* each step matters — the analyst should learn the hunt, not just follow it.
