"""Tests for the GraphQL security tester."""

from __future__ import annotations

import json

import pytest

from src.checks import (
    Finding,
    Severity,
    build_depth_query,
    check_alias_dos,
    check_auth_bypass,
    check_batch_attack,
    check_depth_dos,
    check_field_suggestion,
    check_injection,
    check_introspection,
)
from src.report import render_console, render_json
from src.scanner import ScanReport


# ---------------------------------------------------------------------------
# C01 — Introspection
# ---------------------------------------------------------------------------

class TestIntrospection:
    def test_detects_schema_response(self):
        resp = {"data": {"__schema": {"types": [{"name": "Query"}, {"name": "User"}]}}}
        f = check_introspection(resp)
        assert f is not None
        assert f.check_id == "C01"
        assert f.severity == Severity.MEDIUM

    def test_detects_type_response(self):
        resp = {"data": {"__type": {"name": "Query", "fields": []}}}
        f = check_introspection(resp)
        assert f is not None

    def test_no_finding_on_empty_data(self):
        assert check_introspection({"data": {}}) is None

    def test_no_finding_on_error(self):
        resp = {"errors": [{"message": "introspection disabled"}]}
        assert check_introspection(resp) is None

    def test_no_finding_on_null_data(self):
        assert check_introspection({}) is None

    def test_evidence_includes_type_count(self):
        types = [{"name": f"Type{i}"} for i in range(10)]
        resp = {"data": {"__schema": {"types": types}}}
        f = check_introspection(resp)
        assert f is not None
        assert any("10" in e for e in f.evidence)

    def test_has_remediation(self):
        resp = {"data": {"__schema": {"types": [{"name": "Query"}]}}}
        f = check_introspection(resp)
        assert f.remediation != ""


# ---------------------------------------------------------------------------
# C02 — Field suggestion
# ---------------------------------------------------------------------------

class TestFieldSuggestion:
    def test_detects_did_you_mean(self):
        resp = {"errors": [{"message": "Cannot query field 'usr'. Did you mean 'user'?"}]}
        f = check_field_suggestion(resp)
        assert f is not None
        assert f.check_id == "C02"
        assert any("user" in e for e in f.evidence)

    def test_multiple_suggestions(self):
        resp = {"errors": [
            {"message": "Did you mean 'email'?"},
            {"message": "Did you mean 'name'?"},
        ]}
        f = check_field_suggestion(resp)
        assert f is not None
        assert len(f.evidence) == 2

    def test_no_suggestion_in_errors(self):
        resp = {"errors": [{"message": "Unexpected error"}]}
        assert check_field_suggestion(resp) is None

    def test_no_errors(self):
        assert check_field_suggestion({"data": {"user": {"id": 1}}}) is None

    def test_severity_low(self):
        resp = {"errors": [{"message": "Did you mean 'id'?"}]}
        f = check_field_suggestion(resp)
        assert f.severity == Severity.LOW


# ---------------------------------------------------------------------------
# C03 — Depth DoS
# ---------------------------------------------------------------------------

class TestDepthDoS:
    def test_vulnerable_when_accepted(self):
        resp = {"data": {"user": {"friends": {"__typename": "User"}}}}
        f = check_depth_dos(resp, 15)
        assert f is not None
        assert f.check_id == "C03"
        assert "15" in f.evidence[0]

    def test_safe_when_depth_error(self):
        resp = {"errors": [{"message": "Query depth limit exceeded"}]}
        assert check_depth_dos(resp, 15) is None

    def test_safe_when_complexity_error(self):
        resp = {"errors": [{"message": "Query is too complex"}]}
        assert check_depth_dos(resp, 15) is None

    def test_safe_when_no_data(self):
        resp = {"errors": [{"message": "too deep"}]}
        assert check_depth_dos(resp, 15) is None

    def test_severity_medium(self):
        resp = {"data": {"__typename": "Query"}}
        f = check_depth_dos(resp, 20)
        assert f.severity == Severity.MEDIUM


# ---------------------------------------------------------------------------
# C04 — Batch attack
# ---------------------------------------------------------------------------

class TestBatchAttack:
    def test_detects_successful_batch(self):
        resp = [{"data": {"__typename": "Query"}} for _ in range(50)]
        f = check_batch_attack(resp, 50)
        assert f is not None
        assert f.check_id == "C04"
        assert f.severity == Severity.HIGH

    def test_not_list(self):
        assert check_batch_attack({"data": {}}, 50) is None

    def test_partial_batch_below_threshold(self):
        resp = [{"data": {"__typename": "Query"}} for _ in range(10)]
        resp += [{"errors": [{}]} for _ in range(40)]
        # Only 10 succeeded out of 50 threshold
        assert check_batch_attack(resp, 50) is None

    def test_evidence_includes_counts(self):
        resp = [{"data": {}} for _ in range(50)]
        f = check_batch_attack(resp, 50)
        assert any("50" in e for e in f.evidence)


# ---------------------------------------------------------------------------
# C05 — Auth bypass
# ---------------------------------------------------------------------------

class TestAuthBypass:
    def test_detects_bypass(self):
        auth_resp   = {"data": {"user": {"id": 1, "email": "a@b.com"}}}
        noauth_resp = {"data": {"user": {"id": 1, "email": "a@b.com"}}}
        f = check_auth_bypass(auth_resp, noauth_resp, "user.email")
        assert f is not None
        assert f.check_id == "C05"
        assert f.severity == Severity.HIGH

    def test_no_bypass_when_noauth_empty(self):
        auth_resp   = {"data": {"user": {"email": "a@b.com"}}}
        noauth_resp = {"errors": [{"message": "Unauthorized"}]}
        assert check_auth_bypass(auth_resp, noauth_resp, "user.email") is None

    def test_no_bypass_on_missing_field(self):
        auth_resp   = {"data": {"user": {"id": 1}}}
        noauth_resp = {"data": {"user": {"id": 1}}}
        # Path "user.email" not present in either
        assert check_auth_bypass(auth_resp, noauth_resp, "user.email") is None

    def test_simple_top_level_path(self):
        auth_resp   = {"data": {"user": {"id": 1}}}
        noauth_resp = {"data": {"user": {"id": 1}}}
        f = check_auth_bypass(auth_resp, noauth_resp, "user")
        assert f is not None

    def test_evidence_mentions_field(self):
        a = {"data": {"me": {"token": "secret"}}}
        b = {"data": {"me": {"token": "secret"}}}
        f = check_auth_bypass(a, b, "me.token")
        assert any("me.token" in e for e in f.evidence)


# ---------------------------------------------------------------------------
# C06 — Injection
# ---------------------------------------------------------------------------

class TestInjection:
    def test_detects_sql_error(self):
        resp = {"errors": [{"message": "syntax error near 'OR'"}]}
        f = check_injection(resp, "' OR '1'='1")
        assert f is not None
        assert f.check_id == "C06"

    def test_detects_db_error_keywords(self):
        for keyword in ["mysql", "postgresql", "mongo", "exception", "traceback"]:
            resp = {"errors": [{"message": f"Internal {keyword} error"}]}
            f = check_injection(resp, "payload")
            assert f is not None, f"Expected finding for keyword '{keyword}'"

    def test_no_finding_on_clean_response(self):
        resp = {"errors": [{"message": "Field not found"}]}
        assert check_injection(resp, "payload") is None

    def test_no_finding_on_success(self):
        resp = {"data": {"user": {"id": 1}}}
        assert check_injection(resp, "1") is None

    def test_evidence_includes_payload(self):
        resp = {"errors": [{"message": "SQL syntax error"}]}
        f = check_injection(resp, "' OR '1'='1")
        assert any("OR" in e for e in f.evidence)

    def test_severity_high(self):
        resp = {"errors": [{"message": "postgresql exception"}]}
        f = check_injection(resp, "payload")
        assert f.severity == Severity.HIGH


# ---------------------------------------------------------------------------
# C07 — Alias DoS
# ---------------------------------------------------------------------------

class TestAliasDos:
    def test_detects_accepted_aliases(self):
        resp = {"data": {"a0": None, "a1": None, "a99": None}}
        f = check_alias_dos(resp, 100)
        assert f is not None
        assert f.check_id == "C07"

    def test_no_finding_when_rejected(self):
        resp = {"errors": [{"message": "Query complexity limit exceeded"}]}
        assert check_alias_dos(resp, 100) is None

    def test_no_finding_when_alias_error(self):
        resp = {"errors": [{"message": "Too many aliases"}]}
        assert check_alias_dos(resp, 100) is None

    def test_no_data_no_finding(self):
        assert check_alias_dos({"errors": [{"message": "error"}]}, 100) is None

    def test_severity_medium(self):
        resp = {"data": {"a0": None}}
        f = check_alias_dos(resp, 100)
        assert f.severity == Severity.MEDIUM


# ---------------------------------------------------------------------------
# build_depth_query
# ---------------------------------------------------------------------------

class TestBuildDepthQuery:
    def test_returns_string(self):
        q = build_depth_query(["user", "friends"], 5)
        assert isinstance(q, str)
        assert "{" in q

    def test_empty_fields_fallback(self):
        q = build_depth_query([], 5)
        assert "__typename" in q

    def test_depth_one(self):
        q = build_depth_query(["user"], 1)
        assert "user" in q

    def test_nested_structure(self):
        q = build_depth_query(["user"], 3)
        # Should have nested braces
        assert q.count("{") >= 3


# ---------------------------------------------------------------------------
# ScanReport
# ---------------------------------------------------------------------------

class TestScanReport:
    def _make_report(self) -> ScanReport:
        r = ScanReport("http://example.com/graphql")
        r.add(Finding("C01", "Introspection", Severity.MEDIUM, "desc"))
        r.add(Finding("C04", "Batch", Severity.HIGH, "desc"))
        return r

    def test_to_dict(self):
        r = self._make_report()
        d = r.to_dict()
        assert d["total"] == 2
        assert d["high"] == 1
        assert d["medium"] == 1
        assert d["endpoint"] == "http://example.com/graphql"

    def test_critical_count(self):
        r = self._make_report()
        assert r.critical_count == 1  # HIGH == critical

    def test_add_none_ignored(self):
        r = ScanReport("http://x.com/graphql")
        r.add(None)
        assert r.to_dict()["total"] == 0

    def test_empty_report(self):
        r = ScanReport("http://x.com/graphql")
        assert r.to_dict()["total"] == 0
        assert r.critical_count == 0


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------

class TestReport:
    def _report(self) -> ScanReport:
        r = ScanReport("http://test.com/graphql")
        r.add(Finding("C01", "Introspection Enabled", Severity.MEDIUM,
                      "Server exposes schema", ["25 types exposed"],
                      "Disable introspection"))
        r.add(Finding("C04", "Batch Attack", Severity.HIGH,
                      "Batch succeeded", ["50/50 queries ok"],
                      "Disable batching"))
        return r

    def test_console_no_color(self):
        out = render_console(self._report(), color=False)
        assert "\033[" not in out
        assert "Introspection Enabled" in out
        assert "Batch Attack" in out
        assert "C01" in out

    def test_console_with_color(self):
        out = render_console(self._report(), color=True)
        assert "\033[" in out

    def test_json_valid(self):
        out = render_json(self._report())
        data = json.loads(out)
        assert data["total"] == 2
        assert len(data["findings"]) == 2

    def test_empty_report_no_crash(self):
        r = ScanReport("http://x.com/graphql")
        out = render_console(r, color=False)
        assert "No security issues" in out

    def test_json_finding_fields(self):
        r = ScanReport("http://x.com/graphql")
        r.add(Finding("C06", "Injection", Severity.HIGH, "SQL error",
                      ["payload sent"], "Use parameterized queries"))
        data = json.loads(render_json(r))
        f = data["findings"][0]
        assert f["check_id"] == "C06"
        assert f["severity"] == "HIGH"
        assert "payload sent" in f["evidence"]
        assert f["remediation"] != ""
