"""
Report renderer — console (ANSI) and JSON.
"""

from __future__ import annotations

import io
import json

from .checks import Finding, Severity
from .scanner import ScanReport

_R = "\033[0m"
_B = "\033[1m"
_RED = "\033[91m"
_YEL = "\033[93m"
_CYN = "\033[96m"
_GRN = "\033[92m"
_DIM = "\033[2m"

_SEV_COLOR = {
    Severity.HIGH:   _RED,
    Severity.MEDIUM: _YEL,
    Severity.LOW:    _CYN,
    Severity.INFO:   _GRN,
}
_SEV_ICON = {
    Severity.HIGH:   "🔴",
    Severity.MEDIUM: "🟠",
    Severity.LOW:    "🟡",
    Severity.INFO:   "🔵",
}


def render_console(report: ScanReport, color: bool = True) -> str:
    def c(code: str, text: str) -> str:
        return f"{code}{text}{_R}" if color else text

    buf = io.StringIO()
    w = buf.write

    w(c(_B, "═" * 58) + "\n")
    w(c(_B, "  GraphQL Security Tester — Scan Report") + "\n")
    w(c(_B, "═" * 58) + "\n")
    w(f"  Endpoint  : {report.endpoint}\n")
    w(f"  Scanned   : {report.scanned_at.strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
    w(f"  Findings  : {len(report.findings)}\n\n")

    if not report.findings:
        w(c(_GRN, "  No security issues detected.\n"))
        return buf.getvalue()

    d = report.to_dict()
    w(f"  {c(_RED,'HIGH')}   : {d['high']}\n")
    w(f"  {c(_YEL,'MEDIUM')} : {d['medium']}\n")
    w(f"  {c(_CYN,'LOW')}    : {d['low']}\n\n")

    _order = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2, Severity.INFO: 3}
    for f in sorted(report.findings, key=lambda x: _order[x.severity]):
        icon = _SEV_ICON[f.severity]
        sc   = _SEV_COLOR[f.severity]
        w(c(_B, f"[{f.check_id}] {icon} {f.title}") + "\n")
        w(f"  Severity    : {c(sc, f.severity.value)}\n")
        w(f"  Description : {f.description}\n")
        if f.evidence:
            w("  Evidence    :\n")
            for ev in f.evidence:
                w(f"    • {ev}\n")
        if f.remediation:
            w(c(_GRN, f"  Fix         : {f.remediation}") + "\n")
        w("\n")

    w(c(_B, "═" * 58) + "\n")
    return buf.getvalue()


def render_json(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2) + "\n"
