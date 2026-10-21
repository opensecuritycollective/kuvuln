"""OSV client and advisory-to-finding conversion.

OSV is the public vulnerability database behind GitHub Dependabot, govulncheck
and many scanners. Querying it directly gives KuVuln a dependency-agnostic SCA
engine with per-package fixed versions.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any

from .cache import Cache
from .cvss import cvss_from_severity_entries
from .http import HttpClient, OfflineError
from .models import Dependency, Finding, Location, severity_from_cvss
from .utils import normalize_path

LOGGER = logging.getLogger("kuvuln.osv")

_BATCH_SIZE = 250
_MAX_WORKERS = 8


@dataclass
class OsvQuery:
    dependency: Dependency
    vulnerabilities: list[str]
    details: dict[str, dict[str, Any]]


class OsvClient:
    def __init__(
        self,
        base_url: str,
        http: HttpClient,
        cache: Cache,
        timeout: float = 20,
        retries: int = 3,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.http = http
        self.cache = cache
        self.timeout = timeout
        self.retries = retries

    def query_dependencies(self, dependencies: Iterable[Dependency]) -> list[OsvQuery]:
        queries: list[Dependency] = []
        seen: set[tuple[str, str, str]] = set()
        for dependency in dependencies:
            key = (dependency.ecosystem.lower(), dependency.name.lower(), dependency.version)
            if key in seen:
                continue
            seen.add(key)
            queries.append(dependency)
        if not queries:
            return []

        vuln_ids: dict[tuple[str, str, str], list[str]] = {}
        all_ids: set[str] = set()
        for start in range(0, len(queries), _BATCH_SIZE):
            chunk = queries[start : start + _BATCH_SIZE]
            for key, ids in self._query_chunk(chunk).items():
                vuln_ids[key] = ids
                all_ids.update(ids)

        details = self._fetch_details(all_ids)
        results: list[OsvQuery] = []
        for dependency in queries:
            ids = vuln_ids.get(
                (dependency.ecosystem.lower(), dependency.name.lower(), dependency.version), []
            )
            if not ids:
                continue
            available = {vuln_id: details[vuln_id] for vuln_id in ids if vuln_id in details}
            if available:
                results.append(OsvQuery(dependency, list(available), available))
        return results

    def _query_chunk(
        self, chunk: list[Dependency]
    ) -> dict[tuple[str, str, str], list[str]]:
        payload = {
            "queries": [
                {
                    "package": {
                        "name": dependency.name,
                        "ecosystem": dependency.ecosystem,
                    },
                    "version": dependency.version,
                }
                for dependency in chunk
            ]
        }
        cache_key = f"osv:query:{self.base_url}:{json.dumps(payload, sort_keys=True)}"
        if self.http.offline:
            cached = self.cache.get(cache_key, allow_stale=True)
            if cached is not None:
                return self._decode_query_response(payload, cached)
        try:
            response = self.http.json(
                "POST",
                f"{self.base_url}/v1/querybatch",
                payload=payload,
                timeout=self.timeout,
                retries=self.retries,
            )
        except OfflineError:
            return {}
        except Exception as exc:  # noqa: BLE001 - report a warning upstream
            LOGGER.warning("OSV query failed: %s", exc)
            return {}
        if isinstance(response, dict):
            self.cache.set(cache_key, response)
            return self._decode_query_response(payload, response)
        return {}

    def _decode_query_response(
        self, payload: dict[str, Any], response: dict[str, Any]
    ) -> dict[tuple[str, str, str], list[str]]:
        out: dict[tuple[str, str, str], list[str]] = {}
        results = response.get("results") if isinstance(response, dict) else None
        if not isinstance(results, list):
            return out
        requests = payload.get("queries", []) if isinstance(payload, dict) else []
        for index, result in enumerate(results):
            if index >= len(requests) or not isinstance(result, dict):
                continue
            package = requests[index].get("package", {})
            key = (
                str(package.get("name", "")).lower(),
                str(package.get("ecosystem", "")).lower(),
                str(requests[index].get("version", "")),
            )
            vulns = result.get("vulns")
            out[key] = [
                item.get("id")
                for item in vulns
                if isinstance(item, dict) and item.get("id")
            ] if isinstance(vulns, list) else []
        return out

    def _fetch_details(self, ids: set[str]) -> dict[str, dict[str, Any]]:
        if not ids:
            return {}
        results: dict[str, dict[str, Any]] = {}
        unique = sorted(ids)
        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
            futures = {
                pool.submit(self._fetch_detail, vuln_id): vuln_id for vuln_id in unique
            }
            for future in as_completed(futures):
                vuln_id = futures[future]
                try:
                    value = future.result()
                except Exception as exc:  # noqa: BLE001
                    LOGGER.debug("Could not fetch OSV %s: %s", vuln_id, exc)
                    value = None
                if value:
                    results[vuln_id] = value
        return results

    def _fetch_detail(self, vuln_id: str) -> dict[str, Any] | None:
        cache_key = f"osv:vuln:{self.base_url}:{vuln_id}"
        if self.http.offline:
            cached = self.cache.get(cache_key, allow_stale=True)
            if cached is not None:
                return cached
        try:
            value = self.http.json(
                "GET",
                f"{self.base_url}/v1/vulns/{vuln_id}",
                timeout=self.timeout,
                retries=self.retries,
            )
        except OfflineError:
            return None
        except Exception as exc:  # noqa: BLE001
            LOGGER.debug("Could not fetch OSV %s: %s", vuln_id, exc)
            return None
        if isinstance(value, dict):
            self.cache.set(cache_key, value)
            return value
        return None


def findings_from_osv(queries: Iterable[OsvQuery]) -> list[Finding]:
    """Convert OSV matches into normalized findings, collapsing aliases."""
    findings: list[Finding] = []
    for query in queries:
        _validate_aliases(query)
        details = {
            vuln_id: detail
            for vuln_id, detail in query.details.items()
            if not detail.get("withdrawn")
        }
        if not details:
            continue
        groups = _group_vulnerabilities(details)
        for members in groups.values():
            finding = _build_finding(query.dependency, members)
            if finding:
                findings.append(finding)
    return findings


def _validate_aliases(query: OsvQuery) -> None:
    for vuln_id, detail in query.details.items():
        aliases = detail.get("aliases")
        if aliases and vuln_id not in aliases:
            detail.setdefault("aliases", list(aliases)).append(vuln_id)


def _group_vulnerabilities(details: dict[str, dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    parent: dict[str, str] = {vuln_id: vuln_id for vuln_id in details}

    def find(value: str) -> str:
        while parent.get(value, value) != value:
            parent[value] = parent.get(parent[value], parent[value])
            value = parent[value]
        return value

    def union(left: str, right: str) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parent[right_root] = left_root

    alias_owner: dict[str, str] = {}
    for vuln_id, detail in details.items():
        aliases = [vuln_id]
        aliases.extend(detail.get("aliases") or [])
        aliases.extend(detail.get("related") or [])
        for alias in aliases:
            alias = str(alias).strip().upper()
            if not alias:
                continue
            owner = alias_owner.get(alias)
            if owner is None:
                alias_owner[alias] = vuln_id
            else:
                union(owner, vuln_id)

    groups: dict[str, list[dict[str, Any]]] = {}
    for vuln_id in sorted(details):
        groups.setdefault(find(vuln_id), []).append(details[vuln_id])
    return groups


def _representative(members: list[dict[str, Any]]) -> dict[str, Any]:
    def score(detail: dict[str, Any]) -> tuple[float, int, str]:
        _, _, severity = cvss_from_severity_entries(detail.get("severity"))
        rank = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2}.get(severity, 0)
        return (rank, len(str(detail.get("details", ""))), detail.get("id", ""))

    return max(members, key=score)


def _build_finding(dependency: Dependency, members: list[dict[str, Any]]) -> Finding | None:
    representative = _representative(members)
    vuln_id = str(representative.get("id", ""))
    if not vuln_id:
        return None
    aliases = _collect_aliases(members)
    primary = _primary_identifier(vuln_id, aliases, dependency.ecosystem)
    aliases = [alias for alias in aliases if alias.upper() != primary.upper()]
    identifiers = [primary] + aliases

    fixed_versions = _fixed_versions(members, dependency)
    current = dependency.version.lstrip("v")
    fixed = None
    for candidate in sorted(set(fixed_versions), key=_version_key):
        if _version_greater(candidate, current):
            fixed = candidate
            break

    summary = str(representative.get("summary") or f"Known vulnerability {primary}")
    details = str(representative.get("details") or "").strip()
    severity_score, severity_vector, severity_label = _severity(members)
    if severity_label == "UNKNOWN":
        severity_label = severity_from_cvss(severity_score)
    if severity_vector is None:
        severity_vector = _first_cvss_vector(members)

    references = _references(members, primary)
    url = _advisory_url(members, primary)
    remediation = _remediation(dependency, fixed)

    return Finding(
        rule_id=primary,
        title=summary[:240],
        description=details[:4000] or summary,
        category="sca",
        severity=severity_label,
        source="osv",
        location=Location(path=normalize_path(dependency.primary_path)),
        package=dependency.name,
        version=dependency.version,
        ecosystem=dependency.ecosystem,
        fixed_version=fixed,
        identifiers=identifiers,
        aliases=aliases,
        cvss_score=severity_score,
        cvss_vector=severity_vector,
        remediation=remediation,
        url=url,
        references=references,
        properties={
            "package": dependency.name,
            "ecosystem": dependency.ecosystem,
            "installed_version": dependency.version,
            "fixed_version": fixed,
            "direct": dependency.direct,
            "scope": dependency.scope,
            "osv_ids": sorted(
                {str(member.get("id", "")) for member in members if member.get("id")}
            ),
            "data_source": "osv",
            **dependency.properties,
        },
    )


def _collect_aliases(members: list[dict[str, Any]]) -> list[str]:
    aliases: list[str] = []
    for member in members:
        for alias in member.get("aliases") or []:
            if alias and str(alias) not in aliases:
                aliases.append(str(alias))
        for related in member.get("related") or []:
            if related and str(related) not in aliases:
                aliases.append(str(related))
    return aliases


def _primary_identifier(vuln_id: str, aliases: list[str], ecosystem: str) -> str:
    for alias in aliases:
        if str(alias).upper().startswith("CVE-"):
            return str(alias)
    if ecosystem == "Go":
        for alias in aliases:
            if str(alias).upper().startswith("GO-"):
                return str(alias)
    return vuln_id


def _severity(members: list[dict[str, Any]]) -> tuple[float | None, str | None, str]:
    score: float | None = None
    vector: str | None = None
    label = "UNKNOWN"
    for member in members:
        member_score, member_vector, member_label = cvss_from_severity_entries(
            member.get("severity")
        )
        if member_score is not None and (score is None or member_score > score):
            score, vector, label = member_score, member_vector, member_label
        for key in ("database_specific", "ecosystem_specific"):
            specific = member.get(key) or {}
            if isinstance(specific, dict):
                raw_label = specific.get("severity")
                if raw_label and label == "UNKNOWN":
                    label = str(raw_label).upper()
    return score, vector, label


def _first_cvss_vector(members: list[dict[str, Any]]) -> str | None:
    for member in members:
        _, vector, _ = cvss_from_severity_entries(member.get("severity"))
        if vector:
            return vector
    return None


def _fixed_versions(
    members: list[dict[str, Any]], dependency: Dependency
) -> list[str]:
    fixed: list[str] = []
    package_name = dependency.name.lower()
    ecosystem = dependency.ecosystem.lower()
    for member in members:
        affected = member.get("affected") or []
        if not isinstance(affected, list):
            continue
        for entry in affected:
            if not isinstance(entry, dict):
                continue
            package = entry.get("package") or {}
            if not isinstance(package, dict):
                continue
            if str(package.get("name", "")).lower() != package_name:
                continue
            if str(package.get("ecosystem", "")).lower() != ecosystem:
                continue
            for range_entry in entry.get("ranges") or []:
                if not isinstance(range_entry, dict):
                    continue
                events = range_entry.get("events") or []
                if not isinstance(events, list):
                    continue
                for event in events:
                    if isinstance(event, dict) and event.get("fixed"):
                        value = str(event["fixed"]).strip()
                        if value and value != "0" and value not in fixed:
                            fixed.append(value)
            specific = entry.get("ecosystem_specific") or {}
            if isinstance(specific, dict) and specific.get("last_affected"):
                # last_affected tells us a fixed version exists; the range
                # usually carries the exact value.
                pass
    return fixed


def _version_greater(candidate: str, current: str) -> bool:
    try:
        return _version_key(candidate) > _version_key(current)
    except (TypeError, ValueError):
        return candidate != current


def _version_key(version: str) -> tuple[tuple[int, Any], ...]:
    text = str(version).strip().lstrip("vV")
    parts = re.split(r"[.-]", text)
    key: list[tuple[int, Any]] = []
    has_prerelease = False
    for part in parts:
        if part.isdigit():
            key.append((0, int(part)))
        elif part:
            key.append((1, part))
            has_prerelease = True
    # A release version sorts after any pre-release suffix.
    if not has_prerelease:
        key.append((2,))
    return tuple(key)


def _references(members: list[dict[str, Any]], primary: str) -> list[str]:
    references: list[str] = []
    for member in members:
        for reference in member.get("references") or []:
            if isinstance(reference, dict) and reference.get("url"):
                url = str(reference["url"])
                if url not in references:
                    references.append(url)
    if not any(primary.lower() in url.lower() for url in references):
        references.append(f"https://osv.dev/vulnerability/{primary}")
    return references[:20]


def _advisory_url(members: list[dict[str, Any]], primary: str) -> str:
    preferred: list[str] = []
    for member in members:
        for reference in member.get("references") or []:
            if not isinstance(reference, dict):
                continue
            url = str(reference.get("url", ""))
            if not url:
                continue
            if "github.com/advisories" in url or "pkg.go.dev/vuln" in url:
                preferred.insert(0, url)
            elif "nvd.nist.gov" in url:
                preferred.append(url)
    if preferred:
        return preferred[0]
    return f"https://osv.dev/vulnerability/{primary}"


def _remediation(dependency: Dependency, fixed: str | None) -> str:
    if fixed:
        return (
            f"Upgrade {dependency.name} from {dependency.version} to {fixed} "
            "(or the newest compatible patched release)."
        )
    return (
        f"No fixed version is published for {dependency.name}@{dependency.version}. "
        "Upgrade the dependency to a patched version as soon as one is released, "
        "restrict its use, or replace it."
    )


def osv_disabled(base_url: str) -> bool:
    return not (base_url or "").strip()
