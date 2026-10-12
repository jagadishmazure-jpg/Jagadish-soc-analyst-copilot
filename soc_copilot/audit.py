"""Hash-chained investigation ledger.

Every copilot step (question, plan, result summary, explanation,
suggestions) is appended with a SHA-256 chain link so the investigation
trail is tamper-evident. Mirrors the audit style used across the
portfolio's governance modules.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _hash(payload: dict, prev: str) -> str:
    body = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(f"{prev}|{body}".encode()).hexdigest()


@dataclass
class InvestigationLedger:
    entries: list[dict] = field(default_factory=list)

    def record(self, kind: str, payload: dict) -> dict:
        prev = self.entries[-1]["hash"] if self.entries else "GENESIS"
        entry = {
            "seq": len(self.entries) + 1,
            "ts": _now(),
            "kind": kind,
            "payload": payload,
            "prev_hash": prev,
        }
        entry["hash"] = _hash(
            {"seq": entry["seq"], "ts": entry["ts"], "kind": kind, "payload": payload},
            prev,
        )
        self.entries.append(entry)
        return entry

    def verify_chain(self) -> bool:
        prev = "GENESIS"
        for e in self.entries:
            if e["prev_hash"] != prev:
                return False
            recomputed = _hash(
                {"seq": e["seq"], "ts": e["ts"], "kind": e["kind"], "payload": e["payload"]},
                prev,
            )
            if recomputed != e["hash"]:
                return False
            prev = e["hash"]
        return True

    def kinds(self) -> list[str]:
        return [e["kind"] for e in self.entries]

    def to_jsonl(self) -> str:
        return "\n".join(json.dumps(e, default=str) for e in self.entries)
