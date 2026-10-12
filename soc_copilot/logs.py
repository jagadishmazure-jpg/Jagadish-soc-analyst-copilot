"""Deterministic synthetic security log generators (seeded RNG).

Produces realistic enterprise log shapes for three sources:
- auth:     user logon attempts (user, timestamp, src_ip, result, geo)
- firewall: network flows (src/dst ip, port, action, bytes)
- endpoint: process executions (host, user, process, commandline, parent)

Anomalies (brute-force bursts, unusual geo, rare processes) are injected
explicitly so tests and demos are reproducible.
"""
from __future__ import annotations

import calendar
import random
from dataclasses import dataclass, field
from datetime import datetime, timezone

BASE_TS = calendar.timegm(datetime(2026, 10, 10, tzinfo=timezone.utc).timetuple())
SPAN_HOURS = 48

USERS = ["jdoe", "asmith", "bpatel", "cgarcia", "dlee", "ekim"]
HOSTS = ["WS-1042", "WS-2207", "SRV-DB01", "WS-3318", "SRV-WEB02"]
COMMON_PROCESSES = [
    "explorer.exe",
    "chrome.exe",
    "outlook.exe",
    "svchost.exe",
    "powershell.exe",
    "cmd.exe",
]
COMMON_GEO = "US-East"


def _rng(seed: int) -> random.Random:
    return random.Random(seed)


def _private_ip(rng: random.Random) -> str:
    return f"10.{rng.randint(0, 20)}.{rng.randint(0, 255)}.{rng.randint(2, 254)}"


def _public_ip(rng: random.Random) -> str:
    return f"185.220.{rng.randint(0, 255)}.{rng.randint(2, 254)}"


def gen_auth_logs(n: int = 500, seed: int = 42) -> list[dict]:
    """User logon attempts. Baseline: ~5% failed, all from the home geo."""
    rng = _rng(seed)
    logs = []
    for _ in range(n):
        logs.append(
            {
                "ts": BASE_TS + rng.randint(0, SPAN_HOURS * 3600),
                "user": rng.choice(USERS),
                "src_ip": _private_ip(rng),
                "result": "failed" if rng.random() < 0.05 else "success",
                "geo": COMMON_GEO,
            }
        )
    return sorted(logs, key=lambda l: l["ts"])


def gen_firewall_logs(n: int = 500, seed: int = 42) -> list[dict]:
    """Network flows. Baseline: ~8% denied."""
    rng = _rng(seed)
    logs = []
    for _ in range(n):
        logs.append(
            {
                "ts": BASE_TS + rng.randint(0, SPAN_HOURS * 3600),
                "src_ip": _private_ip(rng),
                "dst_ip": f"172.16.{rng.randint(0, 10)}.{rng.randint(2, 254)}",
                "port": rng.choice([80, 443, 443, 443, 22, 3389]),
                "action": "deny" if rng.random() < 0.08 else "allow",
                "bytes": rng.randint(500, 2_000_000),
            }
        )
    return sorted(logs, key=lambda l: l["ts"])


def gen_endpoint_logs(n: int = 300, seed: int = 42) -> list[dict]:
    """Process executions on hosts."""
    rng = _rng(seed)
    logs = []
    for _ in range(n):
        proc = rng.choice(COMMON_PROCESSES)
        logs.append(
            {
                "ts": BASE_TS + rng.randint(0, SPAN_HOURS * 3600),
                "host": rng.choice(HOSTS),
                "user": rng.choice(USERS),
                "process": proc,
                "commandline": f"C:\\Windows\\System32\\{proc} -session {rng.randint(1000, 9999)}",
                "parent_process": "services.exe" if proc == "svchost.exe" else "explorer.exe",
            }
        )
    return sorted(logs, key=lambda l: l["ts"])


def inject_brute_force(
    logs: list[dict],
    *,
    user: str = "jdoe",
    src_ip: str = "185.220.10.4",
    count: int = 47,
    start_ts: int | None = None,
    seed: int = 7,
) -> list[dict]:
    """Inject a burst of failed logons for one user from one IP (~10 min)."""
    rng = _rng(seed)
    start = BASE_TS + 30 * 3600 if start_ts is None else start_ts
    burst = [
        {
            "ts": start + rng.randint(0, 600),
            "user": user,
            "src_ip": src_ip,
            "result": "failed",
            "geo": COMMON_GEO,
        }
        for _ in range(count)
    ]
    return sorted(logs + burst, key=lambda l: l["ts"])


def inject_unusual_geo(
    logs: list[dict],
    *,
    user: str = "asmith",
    geo: str = "RU",
    count: int = 6,
    seed: int = 8,
) -> list[dict]:
    """Inject successful logons from a geo the user never uses."""
    rng = _rng(seed)
    extra = [
        {
            "ts": BASE_TS + rng.randint(30 * 3600, 40 * 3600),
            "user": user,
            "src_ip": _public_ip(rng),
            "result": "success",
            "geo": geo,
        }
        for _ in range(count)
    ]
    return sorted(logs + extra, key=lambda l: l["ts"])


def inject_rare_process(
    logs: list[dict],
    *,
    host: str = "WS-1042",
    user: str = "jdoe",
    process: str = "mimikatz.exe",
    count: int = 2,
    seed: int = 9,
) -> list[dict]:
    """Inject executions of a process never seen in the baseline."""
    rng = _rng(seed)
    extra = [
        {
            "ts": BASE_TS + rng.randint(30 * 3600, 40 * 3600),
            "host": host,
            "user": user,
            "process": process,
            "commandline": f"C:\\Temp\\{process} sekurlsa::logonpasswords",
            "parent_process": "cmd.exe",
        }
        for _ in range(count)
    ]
    return sorted(logs + extra, key=lambda l: l["ts"])


@dataclass
class LogStore:
    """In-memory holder for the three log sources."""

    auth: list[dict] = field(default_factory=list)
    firewall: list[dict] = field(default_factory=list)
    endpoint: list[dict] = field(default_factory=list)

    @classmethod
    def demo(cls, seed: int = 42) -> "LogStore":
        return cls(
            auth=gen_auth_logs(seed=seed),
            firewall=gen_firewall_logs(seed=seed),
            endpoint=gen_endpoint_logs(seed=seed),
        )

    def latest_ts(self, source: str) -> int:
        logs = getattr(self, source)
        return max((l["ts"] for l in logs), default=BASE_TS)
