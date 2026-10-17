"""Ask the copilot plain-English questions over synthetic logs with three injected attacks (offline)."""
from soc_copilot import (
    Copilot,
    LogStore,
    gen_auth_logs,
    gen_endpoint_logs,
    gen_firewall_logs,
    inject_brute_force,
    inject_rare_process,
    inject_unusual_geo,
)

auth = inject_unusual_geo(inject_brute_force(gen_auth_logs(500), user="jdoe", count=47), user="asmith")
store = LogStore(auth=auth, firewall=gen_firewall_logs(500), endpoint=inject_rare_process(gen_endpoint_logs(300)))
copilot = Copilot(store)

questions = [
    "show me failed logons for jdoe in the last 48 hours",
    "logons by asmith",
    "logons by asmith in the last 48 hours",
    "any rare processes running?",
    "what is the weather like",
]
for q in questions:
    inv = copilot.investigate(q)
    print(f"Q: {q}")
    print(f"Plan: {inv.plan_text}")
    print(f"Findings: {inv.findings}")
    for s in inv.suggestions[:2]:
        print(f"  next: {s}")
    print(f"Ledger: {inv.ledger.kinds()} verifies={inv.ledger.verify_chain()}\n")
