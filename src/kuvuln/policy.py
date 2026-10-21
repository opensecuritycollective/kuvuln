"""Security policy evaluation: thresholds, KEV/EPSS gates and budgets."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from .config import Config
from .models import (
    SEVERITY_RANK,
    Finding,
    category_counts,
    normalize_severity,
    severity_at_least,
    severity_counts,
)


@dataclass
class PolicyResult:
    passed: bool
    reasons: list[str] = field(default_factory=list)
    counts_by_severity: dict[str, int] = field(default_factory=dict)
    counts_by_category: dict[str, dict[str, int]] = field(default_factory=dict)
    total: int = 0
    suppressed: int = 0
    threshold: str = "HIGH"
    kev_count: int = 0
    epss_count: int = 0
    fixable_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "reasons": self.reasons,
            "threshold": self.threshold,
            "counts_by_severity": self.counts_by_severity,
            "counts_by_category": self.counts_by_category,
            "total": self.total,
            "suppressed": self.suppressed,
            "kev_count": self.kev_count,
            "epss_count": self.epss_count,
            "fixable_count": self.fixable_count,
        }


def apply_suppressions(
    findings: Iterable[Finding], config: Config
) -> tuple[list[Finding], list[dict[str, Any]]]:
    kept: list[Finding] = []
    suppressed: list[dict[str, Any]] = []
    for finding in findings:
        reason = config.suppression_reason(finding)
        if reason:
            suppressed.append(_suppression_entry(finding, reason, "configuration"))
            continue
        kept.append(finding)
    return kept, suppressed


def evaluate_policy(kept: list[Finding], suppressed_count: int, config: Config) -> PolicyResult:
    counts = severity_counts(kept)
    categories = category_counts(kept)
    threshold = config.fail_on
    reasons: list[str] = []

    if threshold != "NONE" and any(
        severity_at_least(severity, threshold)
        for severity, count in counts.items()
        if count > 0
    ):
        failing = ", ".join(
            f"{count} {severity}"
            for severity, count in sorted(
                counts.items(), key=lambda item: -SEVERITY_RANK.get(item[0], 0)
            )
            if count > 0 and severity_at_least(severity, threshold)
        )
        reasons.append(
            f"Findings meet or exceed fail_on_severity={threshold}: {failing}"
        )

    kev_count = sum(1 for finding in kept if finding.kev)
    if config.get("settings.fail_on_kev", True) and kev_count:
        reasons.append(
            f"{kev_count} finding(s) are listed in the CISA Known Exploited "
            "Vulnerabilities catalog"
        )

    epss_threshold = float(config.get("settings.fail_on_epss", 0.0) or 0.0)
    epss_count = sum(
        1
        for finding in kept
        if finding.epss is not None and finding.epss >= epss_threshold
    )
    if epss_threshold > 0 and epss_count:
        reasons.append(
            f"{epss_count} finding(s) have EPSS >= {epss_threshold}"
        )

    max_allowed = config.get("settings.max_allowed", {}) or {}
    for severity, allowed in max_allowed.items():
        count = counts.get(normalize_severity(severity), 0)
        if count > allowed:
            reasons.append(
                f"{count} {severity} finding(s) exceed the allowed maximum of {allowed}"
            )

    return PolicyResult(
        passed=not reasons,
        reasons=reasons,
        counts_by_severity=counts,
        counts_by_category=categories,
        total=len(kept),
        suppressed=suppressed_count,
        threshold=threshold,
        kev_count=kev_count,
        epss_count=epss_count,
        fixable_count=sum(1 for finding in kept if finding.fixed_version),
    )


def score(findings: Iterable[Finding]) -> float:
    """Heuristic 0-100 score; 100 means no findings."""
    findings = list(findings)
    if not findings:
        return 100.0
    penalty = 0.0
    for finding in findings:
        weight = {
            "CRITICAL": 20.0,
            "HIGH": 8.0,
            "MEDIUM": 2.0,
            "LOW": 0.5,
            "INFO": 0.1,
            "UNKNOWN": 0.0,
        }.get(finding.severity, 0.0)
        if finding.kev:
            weight += 10.0
        if finding.epss is not None:
            weight += min(finding.epss * 5.0, 5.0)
        penalty += weight
    return round(max(0.0, 100.0 - penalty), 1)


def _suppression_entry(
    finding: Finding, reason: str, source: str
) -> dict[str, Any]:
    return {
        "fingerprint": finding.fingerprint,
        "rule_id": finding.rule_id,
        "title": finding.title,
        "severity": finding.severity,
        "category": finding.category,
        "path": finding.location.path,
        "package": finding.package,
        "reason": reason,
        "source": source,
    }
