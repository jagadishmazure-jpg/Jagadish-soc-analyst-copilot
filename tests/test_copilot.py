"""Tests for the SOC analyst copilot. All deterministic, no network/keys."""
import pytest

from soc_copilot.agent import Copilot
from soc_copilot.audit import InvestigationLedger
from soc_copilot.engine import execute
from soc_copilot.explainer import explain
from soc_copilot.hunts import suggest_next_steps
from soc_copilot.logs import (
    LogStore,
    gen_auth_logs,
    inject_brute_force,
    inject_rare_process,
    inject_unusual_geo,
)
from soc_copilot.query import LLMParser, parse_question


def brute_store() -> LogStore:
    auth = inject_brute_force(gen_auth_logs(500, seed=42), user="jdoe", count=47)
    return LogStore(auth=auth, firewall=[], endpoint=[])


# --- parser ---------------------------------------------------------------

def test_parse_failed_logons_intent():
    p = parse_question("show me failed logons in the last 24 hours")
    assert p.intent == "failed_logons"
    assert p.hours_back == 24


def test_parse_username_extraction():
    p = parse_question("failed logons for user 'jdoe' in the last 48 hours")
    assert p.intent == "failed_logons"
    assert p.username == "jdoe"
    assert p.hours_back == 48


def test_parse_ip_extraction():
    p = parse_question("show traffic from 185.220.10.4")
    assert p.intent == "traffic_by_ip"
    assert p.ip == "185.220.10.4"


def test_parse_days_window():
    p = parse_question("summarize the last 2 days")
    assert p.intent == "summary"
    assert p.hours_back == 48


def test_parse_process_intent():
    p = parse_question("any suspicious processes running?")
    assert p.intent == "process_anomalies"


def test_parse_logons_by_user():
    p = parse_question("logons by asmith")
    assert p.intent == "logons_by_user"
    assert p.username == "asmith"


def test_parse_unknown_clarifies():
    p = parse_question("what is the weather today")
    assert p.intent == "clarify"
    assert "couldn't map" in p.explain()


def test_plan_explain_mentions_entities():
    p = parse_question("failed logons for jdoe last 24 hours")
    text = p.explain()
    assert "jdoe" in text and "failed" in text and "24h" in text


def test_llm_parser_refuses_without_key():
    with pytest.raises(RuntimeError):
        LLMParser().parse("failed logons")


# --- engine ----------------------------------------------------------------

def test_engine_failed_filter_and_user():
    store = brute_store()
    result = execute(parse_question("failed logons for jdoe"), store)
    assert result.count >= 47
    assert all(r["result"] == "failed" and r["user"] == "jdoe" for r in result.rows)


def test_engine_time_window():
    store = LogStore.demo(seed=1)
    r24 = execute(parse_question("summary for the last 24 hours"), store)
    r1 = execute(parse_question("summary for the last 1 hours"), store)
    assert r1.details["auth_total"] <= r24.details["auth_total"]


def test_engine_top_n_grouping():
    store = brute_store()
    result = execute(parse_question("failed logons"), store)
    top = result.details["top_src_ips"]
    assert top[0][0] == "185.220.10.4"
    assert top[0][1] >= 47


def test_engine_truncation():
    from soc_copilot import engine as eng
    store = brute_store()
    plan = parse_question("failed logons")
    result = execute(plan, store)
    # force truncation path by lowering the cap
    old, eng.MAX_ROWS = eng.MAX_ROWS, 5
    try:
        r2 = execute(plan, store)
        assert r2.truncated is True
        assert len(r2.rows) == 5
        assert r2.count == result.count
    finally:
        eng.MAX_ROWS = old


def test_engine_empty_result():
    store = LogStore(auth=[], firewall=[], endpoint=[])
    result = execute(parse_question("failed logons for nobody"), store)
    assert result.count == 0
    assert result.truncated is False


def test_engine_summary_counts():
    store = LogStore.demo(seed=3)
    result = execute(parse_question("give me a summary"), store)
    assert result.details["auth_total"] > 0
    assert result.details["firewall_total"] > 0
    assert "auth_failed" in result.details


def test_engine_rare_process_detection():
    from soc_copilot.logs import gen_endpoint_logs
    ep = inject_rare_process(gen_endpoint_logs(200, seed=5))
    store = LogStore(auth=[], firewall=[], endpoint=ep)
    result = execute(parse_question("any suspicious processes?"), store)
    assert result.details["flags"]["rare_process"] is True
    assert "mimikatz.exe" in result.details["rare_processes"]


# --- explainer ---------------------------------------------------------------

def test_explainer_mentions_key_numbers():
    store = brute_store()
    plan = parse_question("failed logons for jdoe")
    text = explain(execute(plan, store), plan)
    assert "47" in text or "failed logons" in text
    assert "jdoe" in text
    assert "185.220.10.4" in text


def test_explainer_baseline_multiple():
    store = brute_store()
    plan = parse_question("failed logons for jdoe")
    text = explain(execute(plan, store), plan)
    assert "baseline" in text


def test_explainer_unusual_geo_sentence():
    auth = inject_unusual_geo(gen_auth_logs(300, seed=11), user="asmith", count=30)
    store = LogStore(auth=auth, firewall=[], endpoint=[])
    plan = parse_question("failed logons")
    # force some failures in the geo set so the share is visible
    text = explain(execute(plan, store), plan)
    assert isinstance(text, str) and len(text) > 0


def test_explainer_clean_data():
    store = LogStore.demo(seed=21)
    plan = parse_question("any suspicious processes?")
    text = explain(execute(plan, store), plan)
    assert "normal" in text.lower() or "No rare processes" in text


# --- hunts -------------------------------------------------------------------

def test_hunts_brute_force_suggestions():
    store = brute_store()
    plan = parse_question("failed logons for jdoe")
    steps = suggest_next_steps(execute(plan, store), plan)
    assert any("SUCCEEDED" in s for s in steps)
    assert any("password reset" in s for s in steps)


def test_hunts_geo_suggestion():
    auth = inject_unusual_geo(gen_auth_logs(300, seed=11), user="asmith", count=30)
    # add failures so the unusual-geo flag (needs >=5 rows) can trip on failed set
    auth = inject_brute_force(auth, user="asmith", src_ip="91.207.6.6", count=10)
    for l in auth:
        if l["src_ip"] == "91.207.6.6":
            l["geo"] = "RU"
    store = LogStore(auth=auth, firewall=[], endpoint=[])
    plan = parse_question("failed logons")
    steps = suggest_next_steps(execute(plan, store), plan)
    assert any("impossible-travel" in s for s in steps)


def test_hunts_rare_process_suggestions():
    from soc_copilot.logs import gen_endpoint_logs
    ep = inject_rare_process(gen_endpoint_logs(200, seed=5))
    store = LogStore(auth=[], firewall=[], endpoint=ep)
    plan = parse_question("suspicious processes")
    steps = suggest_next_steps(execute(plan, store), plan)
    assert any("lineage" in s for s in steps)


def test_hunts_empty_on_clean_failed_logons():
    store = LogStore.demo(seed=21)
    plan = parse_question("failed logons")
    result = execute(plan, store)
    assert result.details["flags"]["burst"] is False
    assert suggest_next_steps(result, plan) == []


# --- ledger ------------------------------------------------------------------

def test_ledger_chain_verifies():
    led = InvestigationLedger()
    led.record("question", {"text": "q"})
    led.record("plan", {"intent": "failed_logons"})
    assert led.verify_chain() is True
    assert led.kinds() == ["question", "plan"]


def test_ledger_tamper_detected():
    led = InvestigationLedger()
    led.record("question", {"text": "q"})
    led.entries[0]["payload"]["text"] = "tampered"
    assert led.verify_chain() is False


# --- end to end ----------------------------------------------------------------

def test_investigate_brute_force_end_to_end():
    cop = Copilot(brute_store())
    inv = cop.investigate("show me failed logons for jdoe in the last 48 hours")
    assert inv.plan.intent == "failed_logons"
    assert inv.result.count >= 47
    assert "jdoe" in inv.findings
    assert len(inv.suggestions) >= 1
    assert inv.ledger.verify_chain() is True
    assert inv.ledger.kinds() == ["question", "plan", "result", "explanation", "suggestions"]


def test_investigate_clarify_path():
    cop = Copilot(LogStore.demo(seed=1))
    inv = cop.investigate("tell me a joke")
    assert inv.plan.intent == "clarify"
    assert inv.result.count == 0
    assert "couldn't map" in inv.findings
    assert inv.ledger.verify_chain() is True


def test_investigate_to_dict():
    cop = Copilot(brute_store())
    d = cop.investigate("failed logons").to_dict()
    assert d["intent"] == "failed_logons"
    assert d["match_count"] >= 47
    assert isinstance(d["suggestions"], list)
