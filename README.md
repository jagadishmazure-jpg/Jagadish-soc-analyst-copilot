# SOC Analyst Copilot

A natural-language investigation agent for security operations. Analysts ask questions in plain English; the copilot turns them into query plans, executes them against security logs, explains the findings, and suggests next hunt steps. Every step is audit-logged on a hash-chained ledger.

## The problem

SOC analysts drown in query languages. Writing correct KQL/SPL takes months to learn, and the security skills gap keeps growing. Meanwhile most "AI for security" tooling either hallucinates answers or can't show its work. This copilot takes the middle path: deterministic parsing and execution (no guessing), with plain-English plans and findings the analyst can verify against raw rows.

## How it works

```
analyst question
      │
      ▼
┌─────────────┐
│    parse    │  rule-based NL parser → QueryPlan (intent + entities + window)
└──────┬──────┘  unknown questions → clarify plan (asks for specifics)
       ▼
┌─────────────┐
│   execute   │  filters / grouping / top-N over auth, firewall, endpoint logs
└──────┬──────┘
       ▼
┌─────────────┐
│   explain   │  findings in plain English, every claim citing numbers
└──────┬──────┘
       ▼
┌─────────────┐
│    hunts    │  next-step suggestions keyed to finding patterns
└──────┬──────┘
       ▼
  audit ledger   hash-chained record of question → plan → result → findings → suggestions
```

## Example investigation

```
Analyst:  show me failed logons for jdoe in the last 48 hours

Plan:     I will search auth logs for user 'jdoe' with result=failed over the last 48h.

Findings: 48 failed logons for 'jdoe' in the last 48h, 5x the per-user
          baseline of 9.3. Top sources: 185.220.10.4 (47), 10.19.165.127 (1).
          Pattern is consistent with a brute-force burst: investigate urgently.

Next:     - Check whether any logons from 185.220.10.4, 10.19.165.127 SUCCEEDED
            (a brute-force burst followed by success means compromise).
          - Block or rate-limit the offending source IPs at the perimeter
            and force a password reset for the targeted account(s).
```

## Query coverage

| Ask about | Example |
|---|---|
| Failed logons (optional user) | "failed logons for jdoe last 24 hours" |
| Logons by user | "logons by asmith" |
| Network traffic (optional IP) | "traffic from 185.220.10.4" / "top talkers" |
| Suspicious processes | "any rare processes running?" |
| Summary | "summarize the last 2 days" |

Time windows: `last N hours` / `last N days` (default 24h).

## Quickstart

```bash
pip install pytest
python -m pytest -q

python - <<'EOF'
from soc_copilot import Copilot, LogStore, inject_brute_force, gen_auth_logs

store = LogStore(auth=inject_brute_force(gen_auth_logs(500), user="jdoe", count=47),
                 firewall=[], endpoint=[])
inv = Copilot(store).investigate("show me failed logons for jdoe")
print(inv.plan_text)
print(inv.findings)
for s in inv.suggestions:
    print("-", s)
EOF
```

## Production path

- **Parser:** `LLMParser` shares the `QueryPlan` interface; swap the rule-based
  parser for function-calling against a real LLM when credentials exist.
- **Logs:** replace the synthetic `LogStore` with a SIEM connector
  (Splunk, Microsoft Sentinel) implementing the same `execute()` contract.
- **Hunts:** extend `hunts.py` with org-specific playbooks; see `docs/hunt-playbooks.md`.

## Repo layout

```
soc_copilot/
  logs.py       seeded synthetic log generators + anomaly injectors
  query.py      rule-based NL parser → QueryPlan (+ LLMParser stub)
  engine.py     plan execution: filters, grouping, top-N, analytic details
  explainer.py  plain-English findings with cited numbers
  hunts.py      deterministic next-step hunt suggestions
  audit.py      hash-chained investigation ledger
  agent.py      Copilot.investigate(): the full pipeline
tests/          29 deterministic tests, no network or keys
docs/           hunt playbooks mapped to MITRE ATT&CK tactics
```

## Disclaimer

All logs are synthetic and generated deterministically for demonstration and testing. This is an independent project, not affiliated with any SIEM vendor.
