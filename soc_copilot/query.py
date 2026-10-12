"""Rule-based natural-language question parser (no LLM required).

Extracts an intent and entities (username, IP, time window) from an
analyst's plain-English question and produces a QueryPlan. Anything it
cannot map becomes a ``clarify`` plan that asks for specifics.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

INTENTS = (
    "failed_logons",
    "logons_by_user",
    "traffic_by_ip",
    "process_anomalies",
    "summary",
    "clarify",
)

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HOURS_RE = re.compile(r"last\s+(\d+)\s*hours?")
_DAYS_RE = re.compile(r"last\s+(\d+)\s*days?")
_USER_RE = re.compile(r"user\s+['\"]?([a-zA-Z][\w.-]*)['\"]?")
_FOR_USER_RE = re.compile(r"\bfor\s+['\"]?([a-z][a-z0-9_.-]*)['\"]?")
_BY_USER_RE = re.compile(r"\bby\s+['\"]?([a-z][a-z0-9_.-]*)['\"]?")

_STOPWORDS = {
    "the", "a", "an", "for", "by", "from", "last", "past", "failed",
    "successful", "all", "any", "me", "my", "user", "users",
}


@dataclass
class QueryPlan:
    intent: str
    username: str | None = None
    ip: str | None = None
    hours_back: int = 24
    raw: str = ""
    notes: list[str] = field(default_factory=list)

    def explain(self) -> str:
        """Render the plan in plain English for the analyst."""
        window = f"last {self.hours_back}h"
        if self.intent == "clarify":
            return (
                "I couldn't map that to a known investigation. "
                "Try asking about failed logons (optionally for a user), "
                "network traffic from an IP, suspicious processes, or a summary."
            )
        if self.intent == "failed_logons":
            who = f" for user '{self.username}'" if self.username else ""
            return f"I will search auth logs{who} with result=failed over the {window}."
        if self.intent == "logons_by_user":
            who = f" for user '{self.username}'" if self.username else " for all users"
            return f"I will search auth logs{who} over the {window}."
        if self.intent == "traffic_by_ip":
            where = f" involving {self.ip}" if self.ip else " (top talkers)"
            return f"I will search firewall logs{where} over the {window}."
        if self.intent == "process_anomalies":
            return f"I will search endpoint logs for rare or suspicious processes over the {window}."
        if self.intent == "summary":
            return f"I will summarize activity across auth, firewall, and endpoint logs over the {window}."
        return f"Plan: {self.intent} over the {window}."


def _extract_ip(text: str) -> str | None:
    m = _IP_RE.search(text)
    return m.group(0) if m else None


def _extract_hours(text: str) -> int:
    m = _HOURS_RE.search(text)
    if m:
        return int(m.group(1))
    m = _DAYS_RE.search(text)
    if m:
        return int(m.group(1)) * 24
    return 24


def _extract_user(text: str) -> str | None:
    for pattern in (_USER_RE, _FOR_USER_RE, _BY_USER_RE):
        m = pattern.search(text)
        if m and m.group(1).lower() not in _STOPWORDS:
            return m.group(1)
    return None


def parse_question(text: str) -> QueryPlan:
    """Parse a plain-English question into a QueryPlan (deterministic)."""
    lowered = text.lower().strip()
    hours = _extract_hours(lowered)
    ip = _extract_ip(text)
    username = _extract_user(lowered)

    has_logon = any(w in lowered for w in ("logon", "login", "sign-in", "signin", "sign in"))
    has_failed = "fail" in lowered
    has_traffic = any(w in lowered for w in ("traffic", "connection", "firewall", "network", "flow"))
    has_process = any(w in lowered for w in ("process", "command line", "commandline", "malware", "endpoint"))
    has_summary = any(w in lowered for w in ("summary", "summarize", "overview", "what happened", "report"))

    if has_failed and has_logon or "brute force" in lowered:
        intent = "failed_logons"
    elif has_traffic or (ip and not has_logon):
        intent = "traffic_by_ip"
    elif has_process:
        intent = "process_anomalies"
    elif has_logon:
        intent = "logons_by_user"
    elif has_summary:
        intent = "summary"
    else:
        intent = "clarify"

    plan = QueryPlan(intent=intent, username=username, ip=ip, hours_back=hours, raw=text)
    if intent == "traffic_by_ip" and ip is None:
        plan.notes.append("no IP given; will show top talkers instead")
    return plan


class LLMParser:
    """Production-path parser backed by an LLM (stub).

    Shares the QueryPlan interface with :func:`parse_question`. In
    production this would call an LLM with function-calling to produce
    the plan; without credentials it refuses rather than guessing.
    """

    def __init__(self, *, api_key: str | None = None, model: str = "gpt-4o"):
        self.api_key = api_key
        self.model = model

    def parse(self, text: str) -> QueryPlan:
        if not self.api_key:
            raise RuntimeError(
                "LLMParser needs an API key; falling back to the rule-based "
                "parse_question() keeps the copilot working offline."
            )
        raise NotImplementedError("wire model + function schema here")
