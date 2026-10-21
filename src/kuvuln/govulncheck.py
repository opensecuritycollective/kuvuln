"""govulncheck JSON ingestion.

govulncheck is the Go vulnerability database with call-graph analysis. It
reports only vulnerabilities that are reachable from your packages, which
makes its findings substantially more actionable than a raw dependency scan.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from .models import Dependency, Finding, Location
from .osv import _primary_identifier, _references, _remediation, _severity
from .parsers import _iter_json_stream
from .utils import normalize_path

LOGGER = logging.getLogger("kuvuln.govulncheck")

_GOVULNCHECK_FILES = ("govulncheck.json", "govulncheck.jsonl")
_PSEUDO_VERSION = re.compile(r"^go\d+\.\d+(?:\.\d+)?$")


def ingest_govulncheck_file(path: str | Path, rel: str = "") -> tuple[list[Finding], dict[str, Any]]:
    path = Path(path)
    rel = rel or path.name
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [], {"warning": f"Could not read {rel}: {exc}"}
    findings, metadata = govulncheck_findings(text)
    metadata["path"] = normalize_path(rel)
    return findings, metadata


def govulncheck_findings(text: str) -> tuple[list[Finding], dict[str, Any]]:
    config: dict[str, Any] = {}
    osv: dict[str, dict[str, Any]] = {}
    raw_findings: list[dict[str, Any]] = []
    for value in _iter_json_stream(text):
        if not isinstance(value, dict):
            continue
        if "config" in value:
            config = value.get("config") or {}
        elif "osv" in value and isinstance(value.get("osv"), dict):
            osv_id = value["osv"].get("id")
            if osv_id:
                osv[str(osv_id)] = value["osv"]
        elif "finding" in value and isinstance(value.get("finding"), dict):
            raw_findings.append(value["finding"])

    scan_level = str(config.get("scan_level", "symbol")).lower()
    go_version = str(config.get("go_version", "") or "").lstrip("go")
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for raw in raw_findings:
        finding = _build_finding(
            raw, osv, scan_level=scan_level, go_version=go_version
        )
        if finding is None:
            continue
        key = (
            finding.rule_id.upper(),
            (finding.package or "").lower(),
            finding.version or "",
        )
        if key in seen:
            continue
        seen.add(key)
        findings.append(finding)
    return findings, {
        "scanner": "govulncheck",
        "scanner_version": config.get("scanner_version"),
        "scan_level": scan_level,
        "go_version": go_version or None,
        "vulnerabilities": len(findings),
    }


def _build_finding(
    raw: dict[str, Any],
    osv: dict[str, dict[str, Any]],
    scan_level: str,
    go_version: str,
) -> Finding | None:
    vuln_id = str(raw.get("osv", ""))
    detail = osv.get(vuln_id) or {}
    fixed = raw.get("fixed_version") or _range_fixed(detail, raw)
    trace = raw.get("trace") or []
    if not isinstance(trace, list):
        trace = []
    module, version, package_path, function, position = _trace_info(
        trace, go_version
    )
    if not module:
        return None
    if not detail:
        # govulncheck may stream a finding without a matching osv record when
        # the OSV is embedded directly. Nothing useful can be built.
        return None

    aliases = _aliases(detail, vuln_id)
    primary = _primary_identifier(vuln_id, aliases, "Go")
    aliases = [alias for alias in aliases if alias.upper() != primary.upper()]
    score, vector, severity = _severity([detail])
    reachable = scan_level != "module" or bool(function)
    title = str(detail.get("summary") or f"Vulnerable Go module {module}")
    details = str(detail.get("details") or "").strip()
    if function:
        details = (
            f"Reachable from {module}.{function}: {details}"
            if details
            else f"Reachable from {module}.{function}"
        )
    path = position.get("file") or position.get("filename") if isinstance(position, dict) else None
    line = position.get("line") if isinstance(position, dict) else None

    return Finding(
        rule_id=primary,
        title=title[:240],
        description=details[:4000] or title,
        category="sca",
        severity=severity,
        source="govulncheck",
        location=Location(
            path=normalize_path(path) if path else "go.mod",
            start_line=int(line) if line else None,
        ),
        package=module,
        version=version,
        ecosystem="Go",
        fixed_version=fixed,
        identifiers=[primary] + aliases,
        aliases=aliases,
        cvss_score=score,
        cvss_vector=vector,
        reachable=reachable,
        remediation=_remediation(Dependency(module, version, "Go", "go.mod"), fixed),
        url=_advisory_url(detail, primary),
        references=_references([detail], primary),
        properties={
            "govulncheck_id": vuln_id,
            "module": module,
            "module_package": package_path,
            "function": function,
            "reachable": reachable,
            "scan_level": scan_level,
            "go_version": go_version or None,
            "fixed_version": fixed,
            "trace": _trace_summary(trace),
            "data_source": "govulncheck",
        },
    )


def _range_fixed(detail: dict[str, Any], raw: dict[str, Any]) -> str | None:
    fixed = raw.get("fixed_version")
    if fixed:
        return str(fixed)
    affected = detail.get("affected") or []
    for entry in affected:
        if not isinstance(entry, dict):
            continue
        package = entry.get("package") or {}
        if not isinstance(package, dict):
            continue
        if str(package.get("name", "")).lower() != "stdlib":
            continue
        for range_entry in entry.get("ranges") or []:
            if not isinstance(range_entry, dict):
                continue
            for event in range_entry.get("events") or []:
                if isinstance(event, dict) and event.get("fixed"):
                    return str(event["fixed"])
    return None


def _trace_info(
    trace: list[dict[str, Any]], go_version: str
) -> tuple[str, str, str | None, str | None, dict[str, Any] | None]:
    module = ""
    version = ""
    package_path: str | None = None
    function: str | None = None
    position: dict[str, Any] | None = None
    for entry in trace:
        if not isinstance(entry, dict):
            continue
        if entry.get("module"):
            module = str(entry["module"])
            version = str(entry.get("version") or "")
        if entry.get("package") and not package_path:
            package_path = str(entry["package"])
        if entry.get("function") and not function:
            function = str(entry["function"])
        if isinstance(entry.get("position"), dict):
            position = entry["position"]
    if module.lower() == "stdlib" and not version:
        version = go_version
    return module, version, package_path, function, position


def _trace_summary(trace: list[dict[str, Any]]) -> list[dict[str, str]]:
    summary: list[dict[str, str]] = []
    for entry in trace:
        if not isinstance(entry, dict):
            continue
        item: dict[str, str] = {}
        if entry.get("module"):
            item["module"] = str(entry["module"])
        if entry.get("version"):
            item["version"] = str(entry["version"])
        if entry.get("package"):
            item["package"] = str(entry["package"])
        if entry.get("function"):
            item["function"] = str(entry["function"])
        if item:
            summary.append(item)
    return summary


def _aliases(detail: dict[str, Any], vuln_id: str) -> list[str]:
    aliases: list[str] = []
    for alias in detail.get("aliases") or []:
        if alias and str(alias) not in aliases:
            aliases.append(str(alias))
    if vuln_id not in aliases:
        aliases.insert(0, vuln_id)
    return aliases


def _advisory_url(detail: dict[str, Any], primary: str) -> str:
    from .osv import _advisory_url as osv_url

    return osv_url([detail], primary)


def is_govulncheck_file(name: str) -> bool:
    lower = name.lower()
    return lower in _GOVULNCHECK_FILES or lower.startswith("govulncheck-")
