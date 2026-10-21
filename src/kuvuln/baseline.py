"""Baseline support for accepting existing findings with an expiry date."""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable
from datetime import date, timedelta
from pathlib import Path
from typing import Any

from .models import Finding, Location
from .utils import is_expired, iso_now

LOGGER = logging.getLogger("kuvuln.baseline")


def create_baseline(
    findings: Iterable[Finding],
    expires_days: int = 90,
    reason: str = "accepted risk",
) -> dict[str, Any]:
    expires = (date.today() + timedelta(days=expires_days)).isoformat()
    entries = []
    for finding in findings:
        entries.append(
            {
                "fingerprint": finding.fingerprint,
                "rule_id": finding.rule_id,
                "severity": finding.severity,
                "category": finding.category,
                "path": finding.location.path,
                "package": finding.package,
                "reason": reason,
                "expires": expires,
            }
        )
    return {
        "schema_version": 1,
        "generated_at": iso_now(),
        "expires_days": expires_days,
        "expires": expires,
        "entries": entries,
    }


def create_baseline_from_report(
    report_path: str | Path,
    output_path: str | Path,
    expires_days: int = 90,
    reason: str = "accepted risk",
) -> dict[str, Any]:
    with open(report_path, "r", encoding="utf-8") as handle:
        report = json.load(handle)
    findings = []
    for item in report.get("findings", []):
        findings.append(
            Finding(
                rule_id=item.get("rule_id", ""),
                title=item.get("title", ""),
                description=item.get("description", ""),
                category=item.get("category", "unknown"),
                severity=item.get("severity", "UNKNOWN"),
                source=item.get("source", "baseline"),
                location=Location(
                    path=(item.get("location") or {}).get("path", ""),
                    start_line=(item.get("location") or {}).get("start_line"),
                ),
                package=item.get("package"),
                version=item.get("version"),
                ecosystem=item.get("ecosystem"),
                fingerprint=item.get("fingerprint", ""),
            )
        )
    baseline = create_baseline(findings, expires_days, reason)
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(baseline, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    return baseline


def load_baseline(path: str | Path) -> dict[str, Any] | None:
    path = Path(path)
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        LOGGER.warning("Could not load baseline %s: %s", path, exc)
        return None
    if not isinstance(data, dict) or not isinstance(data.get("entries"), list):
        LOGGER.warning("Baseline %s is not a valid KuVuln baseline", path)
        return None
    return data


def apply_baseline(
    findings: Iterable[Finding],
    baseline: dict[str, Any] | None,
    warnings: list[str],
) -> tuple[list[Finding], list[dict[str, Any]]]:
    if not baseline:
        return list(findings), []
    entries = baseline.get("entries") or []
    index: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if isinstance(entry, dict) and entry.get("fingerprint"):
            index[str(entry["fingerprint"])] = entry
    kept: list[Finding] = []
    suppressed: list[dict[str, Any]] = []
    expired: set[str] = set()
    for finding in findings:
        entry = index.get(finding.fingerprint)
        if not entry:
            kept.append(finding)
            continue
        expires = entry.get("expires")
        if expires and is_expired(expires):
            key = f"{finding.fingerprint}:{expires}"
            if key not in expired:
                expired.add(key)
                warnings.append(
                    f"Baseline entry for {finding.rule_id} in "
                    f"{finding.location.path} expired on {expires}"
                )
            kept.append(finding)
            continue
        suppressed.append(
            {
                "fingerprint": finding.fingerprint,
                "rule_id": finding.rule_id,
                "title": finding.title,
                "severity": finding.severity,
                "category": finding.category,
                "path": finding.location.path,
                "package": finding.package,
                "reason": entry.get("reason", "baseline"),
                "source": "baseline",
                "expires": expires,
            }
        )
    return kept, suppressed


def write_baseline(path: str | Path, baseline: dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(baseline, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
