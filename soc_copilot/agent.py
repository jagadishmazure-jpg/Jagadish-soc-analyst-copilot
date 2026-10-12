"""The copilot: parse -> execute -> explain -> suggest -> audit."""
from __future__ import annotations

from dataclasses import dataclass, field

from soc_copilot.audit import InvestigationLedger
from soc_copilot.engine import QueryResult, execute
from soc_copilot.explainer import explain
from soc_copilot.hunts import suggest_next_steps
from soc_copilot.logs import LogStore
from soc_copilot.query import QueryPlan, parse_question


@dataclass
class Investigation:
    question: str
    plan: QueryPlan
    result: QueryResult
    findings: str
    suggestions: list[str]
    plan_text: str = ""
    ledger: InvestigationLedger = field(default_factory=InvestigationLedger)

    def to_dict(self) -> dict:
        return {
            "question": self.question,
            "plan": self.plan_text,
            "intent": self.plan.intent,
            "match_count": self.result.count,
            "findings": self.findings,
            "suggestions": self.suggestions,
            "audit_kinds": self.ledger.kinds(),
        }


class Copilot:
    """Natural-language SOC investigation agent."""

    def __init__(self, store: LogStore | None = None):
        self.store = store or LogStore.demo()

    def investigate(self, question: str) -> Investigation:
        ledger = InvestigationLedger()
        ledger.record("question", {"text": question})

        plan = parse_question(question)
        plan_text = plan.explain()
        ledger.record("plan", {"intent": plan.intent, "text": plan_text,
                              "username": plan.username, "ip": plan.ip,
                              "hours_back": plan.hours_back})

        result = execute(plan, self.store)
        ledger.record("result", {"count": result.count,
                                "truncated": result.truncated,
                                "details": result.details})

        findings = explain(result, plan)
        ledger.record("explanation", {"text": findings})

        suggestions = suggest_next_steps(result, plan)
        ledger.record("suggestions", {"items": suggestions})

        return Investigation(
            question=question,
            plan=plan,
            result=result,
            findings=findings,
            suggestions=suggestions,
            plan_text=plan_text,
            ledger=ledger,
        )
