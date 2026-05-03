"""
Scanner orchestrator — runs all checks against a GraphQL endpoint.
"""

from __future__ import annotations

import socket
from datetime import datetime, timezone
from typing import Any

from .checks import (
    Finding,
    Severity,
    INTROSPECTION_QUERY,
    INTROSPECTION_VARIANTS,
    _INJECTION_PAYLOADS,
    build_depth_query,
    check_alias_dos,
    check_auth_bypass,
    check_batch_attack,
    check_depth_dos,
    check_field_suggestion,
    check_injection,
    check_introspection,
)
from .client import GraphQLClient


DEPTH_TEST   = 15
BATCH_SIZE   = 50
ALIAS_COUNT  = 100
PROBE_FIELDS = ["user", "users", "me", "viewer", "account", "profile", "admin"]


def _build_alias_query(field: str, count: int) -> str:
    aliases = "\n  ".join(f"a{i}: {field} {{ __typename }}" for i in range(count))
    return "{\n  " + aliases + "\n}"


def _build_injection_query(field: str, payload: str) -> str:
    escaped = payload.replace('"', '\\"')
    return f'{{ {field}(id: "{escaped}") {{ __typename }} }}'


class ScanReport:
    def __init__(self, endpoint: str) -> None:
        self.endpoint   = endpoint
        self.findings: list[Finding] = []
        self.scanned_at = datetime.now(timezone.utc)
        try:
            self.host = socket.gethostname()
        except Exception:
            self.host = "unknown"

    def add(self, f: Finding | None) -> None:
        if f is not None:
            self.findings.append(f)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    def to_dict(self) -> dict:
        return {
            "endpoint":   self.endpoint,
            "scanned_at": self.scanned_at.isoformat(),
            "total":      len(self.findings),
            "high":       sum(1 for f in self.findings if f.severity == Severity.HIGH),
            "medium":     sum(1 for f in self.findings if f.severity == Severity.MEDIUM),
            "low":        sum(1 for f in self.findings if f.severity == Severity.LOW),
            "info":       sum(1 for f in self.findings if f.severity == Severity.INFO),
            "findings":   [f.to_dict() for f in self.findings],
        }


class Scanner:
    def __init__(
        self,
        endpoint: str,
        auth_header: str | None = None,
        probe_fields: list[str] | None = None,
        depth: int = DEPTH_TEST,
        batch_size: int = BATCH_SIZE,
        alias_count: int = ALIAS_COUNT,
    ) -> None:
        headers: dict[str, str] = {}
        if auth_header:
            headers["Authorization"] = auth_header

        self.client_auth   = GraphQLClient(endpoint, headers=headers)
        self.client_noauth = GraphQLClient(endpoint)
        self.endpoint      = endpoint
        self.probe_fields  = probe_fields or PROBE_FIELDS
        self.depth         = depth
        self.batch_size    = batch_size
        self.alias_count   = alias_count

    def run(self) -> ScanReport:
        report = ScanReport(self.endpoint)

        # C01 — Introspection
        for q in INTROSPECTION_VARIANTS:
            resp = self.client_auth.query(q)
            f = check_introspection(resp)
            if f:
                report.add(f)
                break

        # C02 — Field suggestion (send a typo for each probe field)
        for field in self.probe_fields[:3]:
            typo_q = "{ " + field[:-1] + "x { __typename } }"
            resp = self.client_auth.query(typo_q)
            f = check_field_suggestion(resp)
            if f:
                report.add(f)
                break

        # C03 — Depth DoS
        depth_q = build_depth_query(self.probe_fields, self.depth)
        resp = self.client_auth.query(depth_q)
        report.add(check_depth_dos(resp, self.depth))

        # C04 — Batch attack
        batch_queries = [f"{{ __typename }}" for _ in range(self.batch_size)]
        resp_batch: Any = self.client_auth.batch(batch_queries)
        report.add(check_batch_attack(resp_batch, self.batch_size))

        # C05 — Auth bypass (test each probe field with and without auth)
        for field in self.probe_fields[:5]:
            q = f"{{ {field} {{ __typename }} }}"
            r_auth   = self.client_auth.query(q)
            r_noauth = self.client_noauth.query(q)
            f = check_auth_bypass(r_auth, r_noauth, field)
            if f:
                report.add(f)
                break

        # C06 — Injection (test each probe field with each payload)
        for field in self.probe_fields[:3]:
            for payload in _INJECTION_PAYLOADS:
                q = _build_injection_query(field, payload)
                resp = self.client_auth.query(q)
                f = check_injection(resp, payload)
                if f:
                    report.add(f)
                    break

        # C07 — Alias amplification
        for field in self.probe_fields[:2]:
            alias_q = _build_alias_query(field, self.alias_count)
            resp = self.client_auth.query(alias_q)
            f = check_alias_dos(resp, self.alias_count)
            if f:
                report.add(f)
                break

        return report
