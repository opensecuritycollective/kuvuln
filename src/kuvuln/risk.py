"""Risk scoring.

The score is deliberately transparent: start from CVSS (or the scanner
severity), then add the exploitability signals (EPSS/KEV), reachability from
govulncheck and the absence of a fix. It is a triage aid, not a replacement
for CVSS.
"""

from __future__ import annotations

from .models import Finding

_SEVERITY_BASE = {
    "CRITICAL": 95.0,
    "HIGH": 75.0,
    "MEDIUM": 45.0,
    "LOW": 20.0,
    "INFO": 5.0,
    "UNKNOWN": 15.0,
}


def compute_risk(finding: Finding) -> float:
    base = finding.cvss_score * 10.0 if finding.cvss_score is not None else None
    if base is None or base <= 0:
        base = _SEVERITY_BASE.get(finding.severity, 15.0)

    risk = base
    if finding.epss is not None:
        risk += min(finding.epss * 10.0, 10.0)
    if finding.kev:
        risk = max(risk, 90.0)
        risk += 5.0
    if finding.category == "sca" and not finding.fixed_version:
        risk += 5.0
    if finding.reachable:
        risk += 8.0
    if finding.category == "secret" and finding.severity in {"CRITICAL", "HIGH"}:
        risk = max(risk, 88.0)
    if finding.category in {"kubernetes", "rbac", "network", "supply-chain"}:
        if finding.severity in {"CRITICAL", "HIGH"}:
            risk += 2.0
    return round(min(100.0, max(0.0, risk)), 1)


def enrich_risk(findings: list[Finding]) -> None:
    for finding in findings:
        finding.risk_score = compute_risk(finding)
