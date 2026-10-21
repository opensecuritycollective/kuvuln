"""Core data models shared by every KuVuln layer."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any
from urllib.parse import quote

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN")

SEVERITY_RANK = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
    "UNKNOWN": 0,
}

SEVERITY_WEIGHT = {
    "CRITICAL": 20.0,
    "HIGH": 8.0,
    "MEDIUM": 2.0,
    "LOW": 0.5,
    "INFO": 0.1,
    "UNKNOWN": 0.0,
}

_SEVERITY_ALIASES = {
    "CRIT": "CRITICAL",
    "SEVERE": "CRITICAL",
    "ERROR": "HIGH",
    "ERR": "HIGH",
    "IMPORTANT": "HIGH",
    "WARNING": "MEDIUM",
    "WARN": "MEDIUM",
    "MODERATE": "MEDIUM",
    "NOTE": "LOW",
    "NEGLIGIBLE": "LOW",
    "TRIVIAL": "INFO",
    "NONE": "INFO",
    "UNKNOWN": "UNKNOWN",
    "INFORMATIONAL": "INFO",
}

_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
    "UNKNOWN": "note",
}

_SARIF_TO_SEVERITY = {
    "error": "HIGH",
    "warning": "MEDIUM",
    "note": "LOW",
    "none": "UNKNOWN",
}

# Categories used by the report and by scan_targets.
CATEGORIES = (
    "kubernetes",
    "rbac",
    "network",
    "supply-chain",
    "container",
    "sca",
    "secret",
    "sast",
    "iac",
    "license",
    "lifecycle",
    "ci",
    "unknown",
)

CATEGORY_LABELS = {
    "kubernetes": "Kubernetes workloads",
    "rbac": "RBAC",
    "network": "Network policies",
    "supply-chain": "Helm / Kustomize / supply chain",
    "container": "Container images",
    "sca": "Dependencies (SCA)",
    "secret": "Secrets",
    "sast": "SAST",
    "iac": "IaC / misconfiguration",
    "license": "Licenses",
    "lifecycle": "Lifecycle / EOL",
    "ci": "GitHub Actions",
    "unknown": "Other",
}


def normalize_severity(value: Any, default: str = "UNKNOWN") -> str:
    """Return a canonical severity label from scanner-specific wording."""
    if not isinstance(value, str):
        return default
    token = value.strip().upper().replace(" ", "_")
    token = token.removeprefix("SEVERITY_")
    token = _SEVERITY_ALIASES.get(token, token)
    return token if token in SEVERITY_RANK else default


def severity_from_cvss(score: float | None) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "INFO"


def severity_at_least(severity: str, threshold: str) -> bool:
    """True when *severity* is at or above *threshold*.

    ``NONE``/``OFF`` thresholds never match.
    """
    threshold = threshold.upper()
    if threshold in {"NONE", "OFF", "DISABLED"}:
        return False
    return SEVERITY_RANK.get(normalize_severity(severity), 0) >= SEVERITY_RANK.get(
        normalize_severity(threshold, "UNKNOWN"), 0
    )


def sarif_level(severity: str) -> str:
    return _SARIF_LEVEL.get(normalize_severity(severity), "note")


def severity_from_sarif(level: str | None) -> str:
    return _SARIF_TO_SEVERITY.get((level or "").lower(), "UNKNOWN")


def stable_fingerprint(*parts: Any) -> str:
    digest = sha256()
    for part in parts:
        digest.update(str(part or "").encode("utf-8", "replace"))
        digest.update(b"\x1f")
    return digest.hexdigest()[:32]


@dataclass
class Location:
    path: str
    start_line: int | None = None
    end_line: int | None = None
    start_column: int | None = None

    def label(self) -> str:
        if not self.path:
            return "repository"
        if self.start_line:
            return f"{self.path}:{self.start_line}"
        return self.path

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"path": self.path}
        if self.start_line:
            out["start_line"] = self.start_line
        if self.end_line:
            out["end_line"] = self.end_line
        if self.start_column:
            out["start_column"] = self.start_column
        return out


@dataclass
class Dependency:
    """A resolved package version discovered in the repository."""

    name: str
    version: str
    ecosystem: str
    path: str
    scope: str = "runtime"
    direct: bool = False
    license: str | None = None
    paths: list[str] = field(default_factory=list)
    properties: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.path and self.path not in self.paths:
            self.paths.append(self.path)

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.ecosystem.lower(), self.name.lower(), self.version)

    def add_path(self, path: str) -> None:
        if path and path not in self.paths:
            self.paths.append(path)

    @property
    def primary_path(self) -> str:
        return self.paths[0] if self.paths else self.path

    @property
    def purl(self) -> str:
        return package_url(self.name, self.version, self.ecosystem)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "scope": self.scope,
            "direct": self.direct,
            "license": self.license,
            "paths": self.paths or ([self.path] if self.path else []),
            "purl": self.purl,
        }


def package_url(name: str, version: str, ecosystem: str) -> str:
    """Best-effort Package URL (purl) for SBOM output."""
    eco = ecosystem.lower()
    safe_name = quote(name, safe="/._~-")
    if eco == "npm":
        # Encode the scope separator of scoped npm packages.
        safe_name = safe_name.replace("@", "%40", 1) if safe_name.startswith("@") else safe_name
        return f"pkg:npm/{safe_name}@{quote(version, safe='.+-_~')}"
    if eco == "pypi":
        import re

        normalized = re.sub(r"[-_.]+", "-", name).lower()
        return f"pkg:pypi/{normalized}@{quote(version, safe='.+-_~')}"
    if eco == "go":
        return f"pkg:golang/{safe_name}@{quote(version, safe='.+-_~')}"
    if eco == "crates.io":
        return f"pkg:cargo/{safe_name}@{quote(version, safe='.+-_~')}"
    if eco == "maven":
        group, _, artifact = name.partition(":")
        if artifact:
            return (
                "pkg:maven/"
                f"{quote(group, safe='._~-')}/{quote(artifact, safe='._~-')}"
                f"@{quote(version, safe='.+-_~')}"
            )
        return f"pkg:maven/{safe_name}@{quote(version, safe='.+-_~')}"
    if eco == "packagist":
        return f"pkg:composer/{safe_name}@{quote(version, safe='.+-_~')}"
    if eco == "rubygems":
        return f"pkg:gem/{safe_name}@{quote(version, safe='.+-_~')}"
    if eco == "nuget":
        return f"pkg:nuget/{safe_name}@{quote(version, safe='.+-_~')}"
    if eco == "pub":
        return f"pkg:pub/{safe_name}@{quote(version, safe='.+-_~')}"
    if eco == "hex":
        return f"pkg:hex/{safe_name}@{quote(version, safe='.+-_~')}"
    return f"pkg:generic/{safe_name}@{quote(version, safe='.+-_~')}"


@dataclass
class Finding:
    """A normalized, source-independent security finding."""

    rule_id: str
    title: str
    category: str = "unknown"
    severity: str = "UNKNOWN"
    description: str = ""
    source: str = "kuvuln"
    location: Location = field(default_factory=lambda: Location(""))
    package: str | None = None
    version: str | None = None
    ecosystem: str | None = None
    fixed_version: str | None = None
    identifiers: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    cvss_score: float | None = None
    cvss_vector: str | None = None
    epss: float | None = None
    epss_percentile: float | None = None
    kev: bool = False
    reachable: bool | None = None
    risk_score: float = 0.0
    remediation: str | None = None
    url: str | None = None
    references: list[str] = field(default_factory=list)
    properties: dict[str, Any] = field(default_factory=dict)
    fingerprint: str = ""

    def __post_init__(self) -> None:
        self.severity = normalize_severity(self.severity)
        self.category = (self.category or "unknown").lower()
        if self.cvss_score is None and self.cvss_vector:
            from .cvss import base_score

            self.cvss_score = base_score(self.cvss_vector)
        if self.identifiers:
            self.identifiers = _dedupe(self.identifiers)
        else:
            self.identifiers = [self.rule_id] if self.rule_id else []
        if not self.fingerprint:
            self.fingerprint = stable_fingerprint(
                self.category,
                self.rule_id,
                self.location.path,
                self.location.start_line or 0,
                (self.package or "").lower(),
                self.version or "",
                (self.title or "")[:160],
            )

    @property
    def primary_id(self) -> str:
        return self.identifiers[0] if self.identifiers else self.rule_id

    @property
    def cvss(self) -> float | None:
        return self.cvss_score

    @property
    def package_label(self) -> str:
        if not self.package:
            return ""
        if self.version:
            return f"{self.package}@{self.version}"
        return self.package

    @property
    def fixable(self) -> bool:
        return bool(self.fixed_version)

    def all_identifiers(self) -> list[str]:
        return _dedupe([self.rule_id, *self.identifiers, *self.aliases])

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "category": self.category,
            "severity": self.severity,
            "source": self.source,
            "location": self.location.to_dict(),
            "package": self.package,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "fixed_version": self.fixed_version,
            "identifiers": self.identifiers,
            "aliases": self.aliases,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "epss": self.epss,
            "epss_percentile": self.epss_percentile,
            "kev": self.kev,
            "reachable": self.reachable,
            "risk_score": self.risk_score,
            "remediation": self.remediation,
            "url": self.url,
            "references": self.references,
            "properties": self.properties,
        }


def _dedupe(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if not value:
            continue
        key = value.upper()
        if key in seen:
            continue
        seen.add(key)
        out.append(value)
    return out


def severity_counts(findings: Iterable[Finding]) -> dict[str, int]:
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        counts[normalize_severity(finding.severity)] += 1
    return counts


def category_counts(findings: Iterable[Finding]) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for finding in findings:
        category = finding.category or "unknown"
        bucket = out.setdefault(
            category, {severity: 0 for severity in SEVERITIES}
        )
        bucket[normalize_severity(finding.severity)] += 1
    return out


def dedupe_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Deduplicate identical findings while keeping the richest record."""
    priority = {
        "govulncheck": 100,
        "kuvuln": 90,
        "osv": 80,
        "trivy": 60,
        "semgrep": 50,
        "gosec": 50,
        "checkov": 40,
        "kubescape": 40,
        "kube-linter": 40,
        "gitleaks": 70,
    }
    merged: dict[str, Finding] = {}
    for finding in findings:
        key = finding.fingerprint
        existing = merged.get(key)
        if existing is None:
            merged[key] = finding
            continue
        if priority.get(finding.source, 10) > priority.get(existing.source, 10):
            merged[key] = finding
            winner, loser = finding, existing
        else:
            winner, loser = existing, finding
        # Preserve useful context from the losing scanner.
        if not winner.fixed_version and loser.fixed_version:
            winner.fixed_version = loser.fixed_version
        if winner.epss is None and loser.epss is not None:
            winner.epss = loser.epss
        if winner.cvss_score is None and loser.cvss_score is not None:
            winner.cvss_score = loser.cvss_score
        if winner.reachable is None and loser.reachable is not None:
            winner.reachable = loser.reachable
        winner.kev = winner.kev or loser.kev
        winner.aliases = _dedupe([*winner.aliases, *loser.aliases])
        winner.identifiers = _dedupe([*winner.identifiers, *loser.identifiers])
        reported_by = set(winner.properties.get("reported_by", []))
        reported_by.add(loser.source)
        reported_by.update(loser.properties.get("reported_by", []))
        winner.properties["reported_by"] = sorted(reported_by)
        merged[key] = winner
    return sorted(merged.values(), key=finding_sort_key)


def finding_sort_key(finding: Finding) -> tuple[int, float, str, str]:
    return (
        -SEVERITY_RANK.get(finding.severity, 0),
        -finding.risk_score,
        finding.location.path,
        finding.title,
    )
