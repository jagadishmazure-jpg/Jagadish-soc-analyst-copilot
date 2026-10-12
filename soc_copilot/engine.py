"""Query execution: runs a QueryPlan against the in-memory LogStore.

Supports time windows, field filters, grouping, and top-N. Results carry
a ``details`` dict with the aggregates the explainer and hunt suggester
need (baselines, top entities, anomaly flags).
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from soc_copilot.logs import COMMON_GEO, COMMON_PROCESSES, LogStore
from soc_copilot.query import QueryPlan

MAX_ROWS = 100
TOP_N = 10


@dataclass
class QueryResult:
    rows: list[dict]
    count: int
    truncated: bool
    details: dict = field(default_factory=dict)


def _in_window(logs: list[dict], now: int, hours_back: int) -> list[dict]:
    cutoff = now - hours_back * 3600
    return [l for l in logs if l["ts"] >= cutoff]


def _top(counter: Counter, n: int = TOP_N) -> list[tuple[str, int]]:
    return counter.most_common(n)


def _execute_failed_logons(plan: QueryPlan, store: LogStore, now: int) -> QueryResult:
    logs = _in_window(store.auth, now, plan.hours_back)
    rows = [l for l in logs if l["result"] == "failed"]
    if plan.username:
        rows = [l for l in rows if l["user"] == plan.username]

    ips = Counter(l["src_ip"] for l in rows)
    geos = Counter(l["geo"] for l in rows)
    per_user = Counter(l["user"] for l in logs if l["result"] == "failed")
    n_users = len({l["user"] for l in logs})
    baseline = (sum(per_user.values()) / n_users) if n_users else 0.0
    unusual = sum(c for g, c in geos.items() if g != COMMON_GEO)
    unusual_share = (unusual / len(rows)) if rows else 0.0

    details = {
        "intent": "failed_logons",
        "top_src_ips": _top(ips),
        "per_user": dict(per_user),
        "baseline_failed_per_user": round(baseline, 1),
        "unusual_geo_share": round(unusual_share, 2),
        "flags": {
            "burst": len(rows) >= 20,
            "unusual_geo": unusual_share > 0.3 and len(rows) >= 5,
        },
    }
    return QueryResult(rows=rows[:MAX_ROWS], count=len(rows),
                       truncated=len(rows) > MAX_ROWS, details=details)


def _execute_logons_by_user(plan: QueryPlan, store: LogStore, now: int) -> QueryResult:
    logs = _in_window(store.auth, now, plan.hours_back)
    rows = [l for l in logs if plan.username is None or l["user"] == plan.username]
    by_result = Counter(l["result"] for l in rows)
    details = {
        "intent": "logons_by_user",
        "by_result": dict(by_result),
        "by_user": dict(Counter(l["user"] for l in rows)),
        "flags": {"burst": by_result.get("failed", 0) >= 20},
    }
    return QueryResult(rows=rows[:MAX_ROWS], count=len(rows),
                       truncated=len(rows) > MAX_ROWS, details=details)


def _execute_traffic(plan: QueryPlan, store: LogStore, now: int) -> QueryResult:
    logs = _in_window(store.firewall, now, plan.hours_back)
    if plan.ip:
        rows = [l for l in logs if l["src_ip"] == plan.ip or l["dst_ip"] == plan.ip]
    else:
        rows = logs
    by_src = Counter(l["src_ip"] for l in rows)
    actions = Counter(l["action"] for l in rows)
    deny_share = (actions.get("deny", 0) / len(rows)) if rows else 0.0
    total_bytes = sum(l["bytes"] for l in rows)
    details = {
        "intent": "traffic_by_ip",
        "top_src_ips": _top(by_src),
        "actions": dict(actions),
        "deny_share": round(deny_share, 2),
        "total_bytes": total_bytes,
        "flags": {"high_deny": deny_share > 0.3 and len(rows) >= 10},
    }
    return QueryResult(rows=rows[:MAX_ROWS], count=len(rows),
                       truncated=len(rows) > MAX_ROWS, details=details)


def _execute_processes(plan: QueryPlan, store: LogStore, now: int) -> QueryResult:
    logs = _in_window(store.endpoint, now, plan.hours_back)
    rare = [l for l in logs if l["process"] not in COMMON_PROCESSES]
    by_proc = Counter(l["process"] for l in rare)
    details = {
        "intent": "process_anomalies",
        "rare_processes": dict(by_proc),
        "rare_count": len(rare),
        "flags": {"rare_process": len(rare) > 0},
    }
    rows = rare if rare else logs[:0]
    return QueryResult(rows=rows[:MAX_ROWS], count=len(rare),
                       truncated=len(rare) > MAX_ROWS, details=details)


def _execute_summary(plan: QueryPlan, store: LogStore, now: int) -> QueryResult:
    auth = _in_window(store.auth, now, plan.hours_back)
    fw = _in_window(store.firewall, now, plan.hours_back)
    ep = _in_window(store.endpoint, now, plan.hours_back)
    failed = sum(1 for l in auth if l["result"] == "failed")
    denied = sum(1 for l in fw if l["action"] == "deny")
    rare = sum(1 for l in ep if l["process"] not in COMMON_PROCESSES)
    details = {
        "intent": "summary",
        "auth_total": len(auth),
        "auth_failed": failed,
        "firewall_total": len(fw),
        "firewall_denied": denied,
        "endpoint_total": len(ep),
        "rare_processes": rare,
        "flags": {
            "burst": failed >= 20,
            "high_deny": (denied / len(fw) > 0.3) if fw else False,
            "rare_process": rare > 0,
        },
    }
    return QueryResult(rows=[], count=0, truncated=False, details=details)


def execute(plan: QueryPlan, store: LogStore, *, now: int | None = None) -> QueryResult:
    """Run a QueryPlan and return rows plus analytic details."""
    if plan.intent == "clarify":
        return QueryResult(rows=[], count=0, truncated=False,
                           details={"intent": "clarify"})
    now = max(store.latest_ts(s) for s in ("auth", "firewall", "endpoint")) if now is None else now
    if plan.intent == "failed_logons":
        return _execute_failed_logons(plan, store, now)
    if plan.intent == "logons_by_user":
        return _execute_logons_by_user(plan, store, now)
    if plan.intent == "traffic_by_ip":
        return _execute_traffic(plan, store, now)
    if plan.intent == "process_anomalies":
        return _execute_processes(plan, store, now)
    if plan.intent == "summary":
        return _execute_summary(plan, store, now)
    raise ValueError(f"unknown intent: {plan.intent}")
