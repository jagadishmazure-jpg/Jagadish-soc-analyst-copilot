"""Hunt suggestions: deterministic next steps keyed to finding patterns.

Each suggestion tells the analyst what to check next and why, following
standard threat-hunting pivots (same-IP success check, impossible travel,
process lineage, auth/firewall pivots).
"""
from __future__ import annotations

from soc_copilot.engine import QueryResult
from soc_copilot.query import QueryPlan


def suggest_next_steps(result: QueryResult, plan: QueryPlan) -> list[str]:
    flags = result.details.get("flags", {})
    intent = result.details.get("intent", plan.intent)
    steps: list[str] = []

    if flags.get("burst"):
        top = result.details.get("top_src_ips", [])
        ips = ", ".join(ip for ip, _ in top[:3]) or "the top source IPs"
        steps.append(
            f"Check whether any logons from {ips} SUCCEEDED "
            "(a brute-force burst followed by success means compromise)."
        )
        steps.append(
            "Block or rate-limit the offending source IPs at the perimeter "
            "and force a password reset for the targeted account(s)."
        )

    if flags.get("unusual_geo"):
        steps.append(
            "Compare against the user's last known location for impossible-travel "
            "analysis (two geos, one user, short window)."
        )

    if flags.get("rare_process"):
        procs = ", ".join(f"'{p}'" for p in result.details.get("rare_processes", {}))
        steps.append(
            f"Trace the parent process lineage of {procs} and check prevalence "
            "across the fleet (one host = targeted, many hosts = worm/tooling)."
        )
        steps.append(
            "Pull the full command line and any files written by the process "
            "for malware triage."
        )

    if flags.get("high_deny"):
        steps.append(
            "Pivot to auth logs for the same source IPs: denied egress plus "
            "failed logons is a classic compromised-host pattern."
        )

    if intent == "traffic_by_ip" and plan.ip and not flags.get("high_deny"):
        steps.append(
            f"Baseline {plan.ip}'s normal traffic profile before concluding; "
            "a single spike without denies is often benign (backups, updates)."
        )

    return steps
