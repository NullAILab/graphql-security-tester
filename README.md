# GraphQL Security Tester

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)
![Tests](https://img.shields.io/badge/Tests-50%20passing-brightgreen)
![License](https://img.shields.io/badge/License-MIT-green)

Automated GraphQL endpoint security scanner. Runs 7 attack checks against any GraphQL API — no third-party libraries required, stdlib HTTP only.

---

## Example Output

```
══════════════════════════════════════════════════════════
  GraphQL Security Tester — Scan Report
══════════════════════════════════════════════════════════
  Endpoint  : http://api.example.com/graphql
  Findings  : 3

  HIGH   : 1
  MEDIUM : 2
  LOW    : 0

[C04] 🔴 Batch Query Attack (Rate Limit Bypass)
  Severity    : HIGH
  Description : The server executed 50 operations in a single batched request.
  Evidence    : Batch of 50 queries: 50 succeeded
  Fix         : Disable query batching. If needed, limit batch size to ≤5.

[C01] 🟠 Introspection Enabled
  Severity    : MEDIUM
  Description : The GraphQL endpoint responds to introspection queries, exposing the full API schema.
  Evidence    : Schema exposes 34 types
  Fix         : Disable introspection in production (introspection=False).

[C03] 🟠 Unbounded Query Depth
  Severity    : MEDIUM
  Evidence    : Depth-15 query succeeded (no depth limit error)
  Fix         : Add query depth limiting middleware. Recommended max depth: 10–15.
```

---

## Checks

| ID  | Attack | Severity |
|-----|--------|----------|
| C01 | Introspection enabled — full schema exposed to anyone | MEDIUM |
| C02 | Field suggestion leakage — valid field names in error messages | LOW |
| C03 | Unbounded query depth — exponential database load | MEDIUM |
| C04 | Batch query attack — bypasses per-request rate limits | HIGH |
| C05 | Authorization bypass — field accessible without auth token | HIGH |
| C06 | Injection in arguments — SQL/NoSQL/path traversal | HIGH |
| C07 | Alias amplification — one request triggers N resolver calls | MEDIUM |

---

## Usage

```bash
pip install -r requirements.txt

# Scan all checks against an endpoint
python -m src http://api.example.com/graphql

# Authenticated scan
python -m src http://api.example.com/graphql --auth "Bearer eyJ..."

# JSON output
python -m src http://api.example.com/graphql --format json

# Save report
python -m src http://api.example.com/graphql --output report.json --format json

# Custom depth and batch size
python -m src http://localhost:4000/graphql --depth 20 --batch-size 100
```

Exit code `1` if HIGH severity issues are found.

---

## Attack Examples

**Introspection — full schema in one query:**
```graphql
{ __schema { types { name fields { name type { name } } } } }
```

**Depth DoS — exponential resolver load:**
```graphql
{ user { friends { friends { friends { friends { friends { id } } } } } } }
```

**Batch attack — 50 operations, one HTTP request:**
```json
[
  {"query": "{ user(id: 1) { email } }"},
  {"query": "{ user(id: 2) { email } }"},
  ...
]
```

**Alias amplification — 100 resolver calls, one query:**
```graphql
{
  a0: expensiveQuery { result }
  a1: expensiveQuery { result }
  a99: expensiveQuery { result }
}
```

---

## Project Structure

```
src/
├── checks.py    ← 7 attack check functions + Finding dataclass
├── client.py    ← Minimal HTTP GraphQL client (stdlib only, no deps)
├── scanner.py   ← Orchestrator — runs all checks, returns ScanReport
├── report.py    ← Console (ANSI color) + JSON renderer
└── __main__.py  ← CLI entry point
tests/
└── test_graphql_tester.py  ← 50 tests
```

---

## Tests

```bash
pytest tests/ -v
```

---

## References

- [OWASP GraphQL Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
- [InQL — GraphQL Security Scanner](https://github.com/doyensec/inql)
- [HackTricks — GraphQL](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/graphql)
- [GraphQL Security — Escape.tech](https://escape.tech/blog/graphql-security/)

---

## License

MIT
