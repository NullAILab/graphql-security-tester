# GraphQL Security Tester

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Tests](https://img.shields.io/badge/Tests-50%20passing-brightgreen)

Automated GraphQL endpoint security scanner — detects introspection leakage, field suggestion enumeration, query depth DoS, batch query abuse, authorization bypass, injection vulnerabilities, and alias-based amplification attacks.

---

## Checks

| ID  | Check | Severity |
|-----|-------|----------|
| C01 | Introspection enabled — full schema exposed | MEDIUM |
| C02 | Field suggestion leakage via error messages | LOW |
| C03 | Unbounded query depth — no depth limit | MEDIUM |
| C04 | Batch query attack — rate limit bypass | HIGH |
| C05 | Authorization bypass — unauthenticated field access | HIGH |
| C06 | Injection vulnerability in query arguments | HIGH |
| C07 | Alias amplification — resolver abuse | MEDIUM |

---

## Usage

```bash
pip install -r requirements.txt

# Run all checks
python -m src http://api.example.com/graphql

# With auth token
python -m src http://api.example.com/graphql --auth "Bearer TOKEN"

# JSON output
python -m src http://api.example.com/graphql --format json

# Save to file
python -m src http://api.example.com/graphql --output report.json --format json

# Custom depth and batch size
python -m src http://localhost:4000/graphql --depth 20 --batch-size 100
```

---

## Attack Examples

**Introspection — schema enumeration:**
```graphql
{ __schema { types { name fields { name } } } }
```

**Depth DoS:**
```graphql
{ user { friends { friends { friends { friends { friends { id } } } } } } }
```

**Batch attack — 50 queries, one HTTP request:**
```json
[
  {"query": "{ user(id: 1) { email } }"},
  {"query": "{ user(id: 2) { email } }"}
]
```

**Alias amplification:**
```graphql
{
  a0: expensiveQuery { result }
  a1: expensiveQuery { result }
  ...
  a99: expensiveQuery { result }
}
```

---

## Project Structure

```
src/
├── checks.py    ← 7 check functions + Finding dataclass
├── client.py    ← Minimal HTTP GraphQL client (stdlib only)
├── scanner.py   ← Orchestrator + ScanReport
├── report.py    ← Console (ANSI) + JSON renderer
└── __main__.py  ← CLI entry point
tests/
└── test_graphql_tester.py  ← 50 tests
```

---

## References

- [OWASP GraphQL Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
- [InQL — GraphQL Security Scanner](https://github.com/doyensec/inql)
- [HackTricks — GraphQL](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/graphql)

---

## License

MIT
