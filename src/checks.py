"""
GraphQL security checks.

Each check function receives a GraphQLClient and returns a Finding (or None).
No third-party GraphQL libraries required — raw HTTP only.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    HIGH   = "HIGH"
    MEDIUM = "MEDIUM"
    LOW    = "LOW"
    INFO   = "INFO"


@dataclass
class Finding:
    check_id:    str
    title:       str
    severity:    Severity
    description: str
    evidence:    list[str] = field(default_factory=list)
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "check_id":    self.check_id,
            "title":       self.title,
            "severity":    self.severity.value,
            "description": self.description,
            "evidence":    self.evidence,
            "remediation": self.remediation,
        }


# ---------------------------------------------------------------------------
# Introspection
# ---------------------------------------------------------------------------

INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        args { name type { name kind } }
        type { name kind }
      }
    }
  }
}
""".strip()

INTROSPECTION_VARIANTS = [
    INTROSPECTION_QUERY,
    # Some servers block __schema but not __type
    '{ __type(name: "Query") { name fields { name } } }',
]


def check_introspection(response: dict) -> Finding | None:
    """
    C01 — Introspection enabled.
    Fires when the server returns a non-empty __schema or __type response.
    """
    data = response.get("data") or {}
    schema = data.get("__schema")
    typ    = data.get("__type")

    if schema or typ:
        types = []
        if schema:
            types = [t["name"] for t in (schema.get("types") or [])
                     if not t["name"].startswith("__")]
        evidence = [f"Schema exposes {len(types)} types"] if types else ["Introspection returned data"]
        return Finding(
            check_id="C01",
            title="Introspection Enabled",
            severity=Severity.MEDIUM,
            description=(
                "The GraphQL endpoint responds to introspection queries, exposing "
                "the full API schema. Attackers can enumerate all types, fields, "
                "and mutations without any documentation."
            ),
            evidence=evidence,
            remediation=(
                "Disable introspection in production. Most servers expose a flag: "
                "introspection=False (graphene), introspection: false (Apollo Server), "
                "or use a middleware that blocks __schema queries."
            ),
        )
    return None


# ---------------------------------------------------------------------------
# Field suggestion leakage
# ---------------------------------------------------------------------------

_SUGGESTION_RE = re.compile(
    r"Did you mean.*?[\"'](\w+)[\"']", re.IGNORECASE
)


def check_field_suggestion(response: dict) -> Finding | None:
    """
    C02 — Field suggestion leakage.
    Even without introspection, error messages may hint at valid field names.
    """
    errors = response.get("errors") or []
    suggestions = []
    for err in errors:
        msg = err.get("message", "")
        for m in _SUGGESTION_RE.finditer(msg):
            suggestions.append(m.group(1))

    if suggestions:
        return Finding(
            check_id="C02",
            title="Field Suggestion Leakage",
            severity=Severity.LOW,
            description=(
                "The server returns 'Did you mean …?' suggestions in error messages, "
                "leaking valid field names even when introspection is disabled."
            ),
            evidence=[f"Suggested field: {s}" for s in suggestions],
            remediation=(
                "Disable field suggestions. In Apollo Server set "
                "fieldSuggestions: false. In graphene, override the default "
                "error formatter to strip suggestion messages."
            ),
        )
    return None


# ---------------------------------------------------------------------------
# Query depth DoS
# ---------------------------------------------------------------------------

def build_depth_query(field_chain: list[str], depth: int) -> str:
    """Build a deeply nested query using the given field chain."""
    if not field_chain:
        return "{ __typename }"
    # Cycle through the chain to build nesting
    parts = []
    for i in range(depth):
        parts.append(field_chain[i % len(field_chain)])
    # Build nested: { f0 { f1 { f2 { ... __typename } } } }
    inner = "__typename"
    for f in reversed(parts):
        inner = f"{f} {{ {inner} }}"
    return "{ " + inner + " }"


def check_depth_dos(response: dict, depth: int) -> Finding | None:
    """
    C03 — Unbounded query depth.
    The server accepted a deeply nested query without rejecting it.
    """
    errors = response.get("errors") or []
    # Server should reject with a depth/complexity error
    rejected = any(
        any(kw in (e.get("message") or "").lower()
            for kw in ("depth", "complexity", "too deep", "nested", "limit"))
        for e in errors
    )
    if not rejected and response.get("data") is not None:
        return Finding(
            check_id="C03",
            title="Unbounded Query Depth",
            severity=Severity.MEDIUM,
            description=(
                f"The server accepted a query nested {depth} levels deep without "
                "applying a depth limit. Deeply nested queries can cause "
                "exponential database load and denial of service."
            ),
            evidence=[f"Depth-{depth} query succeeded (no depth limit error)"],
            remediation=(
                "Add query depth limiting middleware. "
                "Recommended max depth: 10–15. "
                "Libraries: graphql-depth-limit (JS), graphene-django-optimizer (Python)."
            ),
        )
    return None


# ---------------------------------------------------------------------------
# Batch query attack
# ---------------------------------------------------------------------------

def check_batch_attack(response: Any, batch_size: int) -> Finding | None:
    """
    C04 — Batch query attack.
    Server accepted an array of N queries in a single HTTP request,
    bypassing per-request rate limits.
    """
    if not isinstance(response, list):
        return None
    successful = sum(1 for r in response if r.get("data") is not None)
    if successful >= batch_size:
        return Finding(
            check_id="C04",
            title="Batch Query Attack (Rate Limit Bypass)",
            severity=Severity.HIGH,
            description=(
                f"The server executed {successful} operations in a single batched "
                "request. Attackers can use batching to bypass rate limiting, "
                "brute-force credentials, or perform enumeration attacks."
            ),
            evidence=[f"Batch of {batch_size} queries: {successful} succeeded"],
            remediation=(
                "Disable query batching in production unless explicitly required. "
                "If batching is needed, limit batch size (e.g., max 5 operations). "
                "Apply rate limiting per GraphQL operation, not per HTTP request."
            ),
        )
    return None


# ---------------------------------------------------------------------------
# Authorization (IDOR / broken access control)
# ---------------------------------------------------------------------------

def check_auth_bypass(
    auth_response: dict,
    noauth_response: dict,
    field_path: str,
) -> Finding | None:
    """
    C05 — Authorization bypass.
    The same field returns data both with and without authentication.
    """
    def _has_data(r: dict) -> bool:
        data = r.get("data") or {}
        # Walk the path (e.g. "user.email")
        node: Any = data
        for part in field_path.split("."):
            if not isinstance(node, dict):
                return False
            node = node.get(part)
        return node is not None

    if _has_data(auth_response) and _has_data(noauth_response):
        return Finding(
            check_id="C05",
            title="Authorization Bypass — Unauthenticated Field Access",
            severity=Severity.HIGH,
            description=(
                f"The field '{field_path}' returns data for both authenticated "
                "and unauthenticated requests, indicating missing auth check."
            ),
            evidence=[f"Field '{field_path}' accessible without authentication"],
            remediation=(
                "Apply authentication checks at the resolver level, not just at "
                "the HTTP middleware layer. Use a per-field auth directive or "
                "shield library."
            ),
        )
    return None


# ---------------------------------------------------------------------------
# SQL / NoSQL injection in arguments
# ---------------------------------------------------------------------------

_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "1; DROP TABLE users--",
    '{"$gt": ""}',
    "<script>alert(1)</script>",
    "../../../../etc/passwd",
]

_ERROR_INJECTION_RE = re.compile(
    r"(syntax error|sql|mysql|postgresql|mongo|exception|traceback|"
    r"stacktrace|internal server|unhandled|error at|near \")",
    re.IGNORECASE,
)


def check_injection(response: dict, payload: str) -> Finding | None:
    """
    C06 — Injection vulnerability.
    Server error messages expose database/backend details when injection payloads are sent.
    """
    errors = response.get("errors") or []
    raw = json.dumps(errors)
    if _ERROR_INJECTION_RE.search(raw):
        return Finding(
            check_id="C06",
            title="Potential Injection Vulnerability",
            severity=Severity.HIGH,
            description=(
                f"The server returned an error exposing internal details when "
                f"the payload {payload!r} was sent in a query argument."
            ),
            evidence=[f"Payload: {payload}", f"Server error: {raw[:300]}"],
            remediation=(
                "Sanitize and validate all GraphQL arguments before passing to "
                "database queries. Use parameterized queries. Disable detailed "
                "error messages in production (debug: false)."
            ),
        )
    return None


# ---------------------------------------------------------------------------
# Aliases for mass query
# ---------------------------------------------------------------------------

def check_alias_dos(response: dict, alias_count: int) -> Finding | None:
    """
    C07 — Alias-based query amplification.
    A query using N aliases counts as one request but executes N resolvers.
    """
    errors = response.get("errors") or []
    rejected = any(
        any(kw in (e.get("message") or "").lower()
            for kw in ("alias", "complexity", "limit", "too many"))
        for e in errors
    )
    if not rejected and response.get("data") is not None:
        return Finding(
            check_id="C07",
            title="Alias-Based Query Amplification",
            severity=Severity.MEDIUM,
            description=(
                f"The server executed a query with {alias_count} aliases without "
                "complexity limiting. Aliases allow one request to trigger many "
                "resolver executions, amplifying load on backends."
            ),
            evidence=[f"{alias_count} aliases accepted in a single query"],
            remediation=(
                "Implement query complexity analysis (each field/alias adds cost). "
                "Set a maximum complexity budget per query."
            ),
        )
    return None
