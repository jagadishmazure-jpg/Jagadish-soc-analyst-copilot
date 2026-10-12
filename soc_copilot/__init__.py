"""soc_copilot: a natural-language SOC investigation agent.

Analysts ask questions in plain English; the copilot turns them into
query plans, executes them against security logs, explains the findings,
and suggests next hunt steps. Every step is audit-logged.
"""

from soc_copilot.agent import Copilot, Investigation
from soc_copilot.audit import InvestigationLedger
from soc_copilot.engine import QueryResult, execute
from soc_copilot.explainer import explain
from soc_copilot.hunts import suggest_next_steps
from soc_copilot.logs import (
    LogStore,
    gen_auth_logs,
    gen_endpoint_logs,
    gen_firewall_logs,
    inject_brute_force,
    inject_rare_process,
    inject_unusual_geo,
)
from soc_copilot.query import LLMParser, QueryPlan, parse_question

__all__ = [
    "Copilot",
    "Investigation",
    "InvestigationLedger",
    "LogStore",
    "QueryPlan",
    "QueryResult",
    "LLMParser",
    "execute",
    "explain",
    "gen_auth_logs",
    "gen_endpoint_logs",
    "gen_firewall_logs",
    "inject_brute_force",
    "inject_rare_process",
    "inject_unusual_geo",
    "parse_question",
    "suggest_next_steps",
]

__version__ = "0.1.0"
