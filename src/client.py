"""
Minimal synchronous GraphQL HTTP client — no third-party dependencies.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any


class GraphQLClient:
    """Sends GraphQL queries over HTTP/HTTPS using stdlib only."""

    def __init__(
        self,
        endpoint: str,
        headers: dict[str, str] | None = None,
        timeout: int = 15,
    ) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.headers = headers or {}
        self.timeout = timeout

    def query(self, q: str, variables: dict | None = None) -> dict:
        """Send a single query and return the parsed JSON response."""
        payload = {"query": q}
        if variables:
            payload["variables"] = variables
        return self._post(payload)

    def batch(self, queries: list[str]) -> Any:
        """Send a batch (array) of queries in one HTTP request."""
        payload = [{"query": q} for q in queries]
        return self._post(payload)

    def _post(self, payload: Any) -> Any:
        data = json.dumps(payload).encode()
        headers = {
            "Content-Type": "application/json",
            "Accept":       "application/json",
            "User-Agent":   "graphql-security-tester/1.0",
        }
        headers.update(self.headers)

        req = urllib.request.Request(
            self.endpoint,
            data=data,
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            try:
                body = e.read().decode()
                return json.loads(body)
            except Exception:
                return {"errors": [{"message": f"HTTP {e.code}"}]}
        except Exception as exc:
            return {"errors": [{"message": str(exc)}]}
