# Implementation guide: from offline build to Azure

> Status: **planned**. Nothing here has been deployed. The offline build in this
> repository is what exists today; this guide is how it would be taken to a
> real Azure environment.

## Azure service mapping

| Offline component | Azure service (planned) | Notes |
|---|---|---|
| `LogStore` | Microsoft Sentinel / Log Analytics workspace (SigninLogs, CommonSecurityLog, DeviceProcessEvents) | Read-only Log Analytics Reader role |
| `QueryPlan` execution | Generated KQL run through the Log Analytics query API | Validate against the table schema first |
| `LLMParser` | Azure OpenAI function calling producing a `QueryPlan` | Plan shown to the analyst before running |
| Ledger | Log Analytics custom table or immutable blob | Investigation audit |
| Copilot host | Azure Container Apps with managed identity | Entra ID sign-in for analysts |

## Steps

1. Add a KQL renderer for each `QueryPlan` intent and test it against a schema of the Sentinel tables.
2. Run queries with a managed identity holding only Log Analytics Reader.
3. Put the LLM parser behind the plan interface; the analyst approves the plan before it runs.
4. Build a 50-question gold set and measure plan accuracy and KQL validity.
5. Write the ledger to a custom Log Analytics table for audit.

## Guardrails to keep when going live

- Read-only: the copilot queries logs and suggests actions; it never blocks an IP or resets a password.
- Unknown questions get a clarify plan, never a guessed query.
- Every finding cites the counts it is based on, so the analyst can check them against raw rows.
- Question, plan, result, explanation and suggestions are each recorded on a hash-chained ledger.
- All logs are synthetic and seeded.

## What to measure before calling it production-ready

- Plan accuracy and KQL validity on a gold question set.
- Analyst time to answer versus writing KQL by hand.
- Rate of clarify responses and of wrong plans accepted.
