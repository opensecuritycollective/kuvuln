"""Cross-engine correlation and de-duplication.

Multiple scanners frequently report the same Kubernetes control. This module
merges identical SCA advisories and fuzzy-matches misconfiguration findings
that share a location and describe the same problem.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from .models import (
    SEVERITY_RANK,
    Finding,
    dedupe_findings,
    finding_sort_key,
)

_SOURCE_PRIORITY = {
    "govulncheck": 100,
    "kuvuln": 90,
    "osv": 80,
    "gitleaks": 75,
    "trivy": 65,
    "semgrep": 55,
    "gosec": 55,
    "osv-scanner": 60,
    "checkov": 45,
    "kubescape": 45,
    "kube-linter": 45,
}

_CONFIG_CATEGORIES = {
    "kubernetes",
    "rbac",
    "network",
    "supply-chain",
    "iac",
    "container",
    "ci",
}

_ID_RE = re.compile(r"^(CVE-|GHSA-|GO-|DS-|DIO-|MAL-|OSV-)", re.IGNORECASE)
_STOPWORDS = {
    "a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "in",
    "is", "it", "of", "on", "or", "the", "to", "with", "use", "uses",
    "using", "not", "no", "true", "false", "set", "must", "should", "into",
}
_SIMILARITY_THRESHOLD = 0.45


def correlate_findings(findings: Iterable[Finding]) -> list[Finding]:
    exact = dedupe_findings(findings)

    sca_groups: dict[tuple[str, str, str, str], list[Finding]] = {}
    config_buckets: dict[tuple[str, str], list[Finding]] = {}
    other: list[Finding] = []
    native_groups: dict[tuple[str, str, str], list[Finding]] = {}
    native_used: set[int] = set()

    for finding in exact:
        if finding.source == "kuvuln" and finding.properties.get("resource"):
            detail = (
                str(finding.properties.get("container") or "")
                or str(finding.properties.get("volume") or "")
                or str(finding.properties.get("webhook") or "")
                or str(finding.properties.get("namespace") or "")
            )
            key = (finding.rule_id.lower(), str(finding.properties["resource"]), detail)
            native_groups.setdefault(key, []).append(finding)
            native_used.add(id(finding))

    correlated: list[Finding] = []
    for group in native_groups.values():
        correlated.append(_merge_group(group) if len(group) > 1 else group[0])

    for finding in exact:
        if id(finding) in native_used:
            continue
        if finding.category == "sca":
            primary = finding.primary_id
            if _ID_RE.match(primary) and finding.package:
                key = ("sca", primary.lower(), finding.package.lower(), (finding.version or "").lower())
            elif finding.package:
                key = ("sca", finding.rule_id.lower(), finding.package.lower(), (finding.version or "").lower())
            else:
                key = ("sca", primary.lower(), finding.location.path, str(finding.location.start_line or ""))
            sca_groups.setdefault(key, []).append(finding)
        elif finding.category in _CONFIG_CATEGORIES and finding.location.path:
            config_buckets.setdefault(
                (finding.location.path, str(finding.location.start_line or "")), []
            ).append(finding)
        else:
            other.append(finding)

    for group in sca_groups.values():
        correlated.append(_merge_group(group) if len(group) > 1 else group[0])

    for bucket in config_buckets.values():
        if len(bucket) == 1:
            correlated.append(bucket[0])
            continue
        clusters = _cluster_by_similarity(bucket)
        correlated.extend(
            cluster[0] if len(cluster) == 1 else _merge_group(cluster)
            for cluster in clusters
        )

    correlated.extend(other)
    return sorted(correlated, key=finding_sort_key)


def _cluster_by_similarity(findings: list[Finding]) -> list[list[Finding]]:
    parent = list(range(len(findings)))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parent[right_root] = left_root

    for i in range(len(findings)):
        for j in range(i + 1, len(findings)):
            left, right = findings[i], findings[j]
            control_left = str(left.properties.get("control", ""))
            control_right = str(right.properties.get("control", ""))
            if control_left and control_left == control_right:
                union(i, j)
                continue
            if similarity(left.title, right.title) >= _SIMILARITY_THRESHOLD:
                union(i, j)

    clusters: dict[int, list[Finding]] = {}
    for index in range(len(findings)):
        clusters.setdefault(find(index), []).append(findings[index])
    return list(clusters.values())


def _merge_group(group: list[Finding]) -> Finding:
    def sort_key(finding: Finding) -> tuple[int, int, float]:
        return (
            1 if finding.reachable else 0,
            _SOURCE_PRIORITY.get(finding.source, 10),
            finding.risk_score,
        )

    ordered = sorted(group, key=sort_key, reverse=True)
    winner = ordered[0]
    for loser in ordered[1:]:
        _absorb(winner, loser)
    return winner


def _absorb(winner: Finding, loser: Finding) -> None:
    if not winner.fixed_version and loser.fixed_version:
        winner.fixed_version = loser.fixed_version
    if not winner.package and loser.package:
        winner.package = loser.package
    if not winner.version and loser.version:
        winner.version = loser.version
    if not winner.ecosystem and loser.ecosystem:
        winner.ecosystem = loser.ecosystem
    if winner.cvss_score is None and loser.cvss_score is not None:
        winner.cvss_score = loser.cvss_score
    if winner.cvss_vector is None and loser.cvss_vector is not None:
        winner.cvss_vector = loser.cvss_vector
    if winner.epss is None and loser.epss is not None:
        winner.epss = loser.epss
    if winner.epss_percentile is None and loser.epss_percentile is not None:
        winner.epss_percentile = loser.epss_percentile
    if not winner.remediation and loser.remediation:
        winner.remediation = loser.remediation
    if not winner.url and loser.url:
        winner.url = loser.url
    if SEVERITY_RANK.get(loser.severity, 0) > SEVERITY_RANK.get(winner.severity, 0):
        winner.severity = loser.severity
    winner.kev = winner.kev or loser.kev
    winner.reachable = winner.reachable or loser.reachable
    winner.identifiers = _unique(winner.identifiers + loser.identifiers)
    winner.aliases = _unique(winner.aliases + loser.aliases)
    winner.references = _unique(winner.references + loser.references)[:20]
    reported = set(winner.properties.get("reported_by", []))
    reported.add(winner.source)
    reported.add(loser.source)
    reported.update(loser.properties.get("reported_by", []))
    winner.properties["reported_by"] = sorted(reported)
    for key, value in loser.properties.items():
        if key not in {"reported_by", "sarif_fingerprint", "tool", "tool_version"}:
            winner.properties.setdefault(key, value)


def _unique(values: Iterable[str]) -> list[str]:
    out: list[str] = []
    for value in values:
        if value and value not in out:
            out.append(value)
    return out


def token_set(text: str) -> set[str]:
    tokens = set(re.findall(r"[a-z0-9]{3,}", (text or "").lower()))
    return {token for token in tokens if token not in _STOPWORDS}


def similarity(left: str, right: str) -> float:
    left_tokens, right_tokens = token_set(left), token_set(right)
    if not left_tokens or not right_tokens:
        return 0.0
    return len(left_tokens & right_tokens) / len(left_tokens | right_tokens)
