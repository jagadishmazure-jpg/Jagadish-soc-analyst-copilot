"""Findings explainer: turns a QueryResult into plain-English findings.

Every sentence cites the numbers it is based on so the analyst can
verify the claim against the raw rows.
"""
from __future__ import annotations

from soc_copilot.engine import QueryResult
from soc_copilot.query import QueryPlan


def _fmt_ip_list(pairs: list[tuple[str, int]], limit: int = 3) -> str:
    return ", ".join(f"{ip} ({c})" for ip, c in pairs[:limit])


def explain(result: QueryResult, plan: QueryPlan) -> str:
    d = result.details
    intent = d.get("intent", plan.intent)
    window = f"last {plan.hours_back}h"

    if intent == "clarify":
        return plan.explain()

    if intent == "failed_logons":
        who = f" for '{plan.username}'" if plan.username else ""
        if result.count == 0:
            return f"No failed logons{who} in the {window}. Nothing anomalous."
        base = d.get("baseline_failed_per_user", 0) or 0
        mult = f", {result.count / base:.0f}x the per-user baseline of {base}" if base > 0 else ""
        lines = [f"{result.count} failed logons{who} in the {window}{mult}."]
        if d.get("top_src_ips"):
            lines.append(f"Top sources: {_fmt_ip_list(d['top_src_ips'])}.")
        if d.get("unusual_geo_share", 0) > 0:
            lines.append(
                f"{int(d['unusual_geo_share'] * 100)}% originated from an unusual geo."
            )
        if d["flags"].get("burst"):
            lines.append("Pattern is consistent with a brute-force burst: investigate urgently.")
        return " ".join(lines)

    if intent == "logons_by_user":
        by_result = d.get("by_result", {})
        who = f"'{plan.username}'" if plan.username else "all users"
        return (
            f"{result.count} logons for {who} in the {window}: "
            f"{by_result.get('success', 0)} successful, {by_result.get('failed', 0)} failed."
        )

    if intent == "traffic_by_ip":
        where = f" involving {plan.ip}" if plan.ip else ""
        lines = [
            f"{result.count} firewall flows{where} in the {window}, "
            f"{d.get('total_bytes', 0):,} bytes total."
        ]
        if d.get("actions"):
            acts = ", ".join(f"{k}={v}" for k, v in d["actions"].items())
            lines.append(f"Actions: {acts}.")
        if d.get("top_src_ips"):
            lines.append(f"Top sources: {_fmt_ip_list(d['top_src_ips'])}.")
        if d["flags"].get("high_deny"):
            lines.append("Deny rate is elevated: possible scanning or blocked exfiltration.")
        return " ".join(lines)

    if intent == "process_anomalies":
        if result.count == 0:
            return f"No rare processes in the {window}. Endpoint activity looks normal."
        procs = ", ".join(f"'{p}' (x{c})" for p, c in d["rare_processes"].items())
        return (
            f"{result.count} executions of rare processes in the {window}: {procs}. "
            "These never appear in the baseline: treat as suspicious until cleared."
        )

    if intent == "summary":
        return (
            f"Summary for the {window}: {d.get('auth_total', 0)} auth events "
            f"({d.get('auth_failed', 0)} failed), {d.get('firewall_total', 0)} firewall flows "
            f"({d.get('firewall_denied', 0)} denied), {d.get('endpoint_total', 0)} process "
            f"executions ({d.get('rare_processes', 0)} rare)."
        )

    return f"{result.count} matching events in the {window}."
