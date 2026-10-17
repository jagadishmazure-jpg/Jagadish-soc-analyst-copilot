# Interview points

Short, honest talking points for Jagadish-soc-analyst-copilot. Every number quoted is from the
real run shown in the README.

- Deterministic parsing and execution with a visible plan: the analyst can check every claim against raw rows.
- Real run: 50 failed logons for jdoe, 47 from one IP, 5x the per-user baseline, flagged as a brute-force burst.
- I kept a known miss in the demo: six unusual-geo logons out of 64 fall under the 30% trigger.
- Clarify instead of guess: an off-topic question gets guidance, not a fabricated query.

## Likely follow-up questions

- How would you add an LLM safely? (It proposes a plan; schema validation and analyst approval come before execution.)
- How would you fix the geo miss? (Absolute-count trigger or impossible-travel check in addition to share.)
- Why not let the agent block IPs? (Containment needs approval; see the approval-gated flow in Jagadish-azure-ai-soc.)
