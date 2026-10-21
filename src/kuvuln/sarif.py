"""SARIF ingestion (third-party scanners) and unified SARIF export."""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from . import __version__
from .cvss import base_score
from .models import (
    Finding,
    Location,
    normalize_severity,
    sarif_level,
    severity_from_cvss,
    severity_from_sarif,
    stable_fingerprint,
)
from .utils import normalize_path, read_text

LOGGER = logging.getLogger("kuvuln.sarif")

_ADVISORY_RE = re.compile(r"\b(CVE-\d{4}-\d{4,7}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})\b", re.IGNORECASE)
_SECRET_RULE_RE = re.compile(r"(secret|credential|token|password|api[_-]?key)", re.IGNORECASE)
_GENERIC_NAMES = {"misconfiguration", "unknown", "vulnerability", "security finding"}
_KUBERNETES_RULE_RE = re.compile(
    r"(kubernetes|kube|pod|workload|namespace|securitycontext|privileged|"
    r"rbac|clusterrole|rolebinding|serviceaccount|networkpolicy|"
    r"default-deny|hostpath|hostnetwork|hostpid)",
    re.IGNORECASE,
)
_CONTAINER_RULE_RE = re.compile(r"(dockerfile|container|image)", re.IGNORECASE)
_RBAC_RULE_RE = re.compile(r"(rbac|clusterrole|rolebinding|serviceaccount)", re.IGNORECASE)
_NETWORK_RULE_RE = re.compile(r"(networkpolicy|network policy|default-deny)", re.IGNORECASE)
_HELM_KUSTOMIZE_RE = re.compile(r"(helm|kustomize|chart)", re.IGNORECASE)


@dataclass
class SarifReport:
    findings: list[Finding]
    tools: list[dict[str, Any]]
    warnings: list[str]


def sarif_files(paths: Iterable[str | Path]) -> list[Path]:
    files: list[Path] = []
    for value in paths:
        path = Path(value)
        if path.is_file() and path.suffix.lower() == ".sarif":
            files.append(path)
        elif path.is_dir():
            for candidate in sorted(path.rglob("*.sarif")):
                files.append(candidate)
    return sorted(set(files))


def ingest_sarif(path: str | Path, root: str | Path = ".") -> SarifReport:
    path = Path(path)
    rel = normalize_path(_relative(path, root))
    try:
        payload = json.loads(read_text(path, max_bytes=20 * 1024 * 1024))
    except json.JSONDecodeError as exc:
        return SarifReport([], [], [f"{rel}: invalid SARIF ({exc})"])
    if not isinstance(payload, dict):
        return SarifReport([], [], [f"{rel}: SARIF root is not an object"])

    findings: list[Finding] = []
    tools: list[dict[str, Any]] = []
    warnings: list[str] = []
    runs = payload.get("runs") if isinstance(payload.get("runs"), list) else []
    if not runs:
        warnings.append(f"{rel}: SARIF file contains no runs")
    for run in runs:
        run_findings, tool = _ingest_run(run, rel, root)
        findings.extend(run_findings)
        if tool:
            tools.append(tool)
    return SarifReport(findings, tools, warnings)


def _relative(path: Path, root: str | Path) -> Path:
    try:
        return path.resolve().relative_to(Path(root).resolve())
    except ValueError:
        return path


def _ingest_run(run: dict[str, Any], rel: str, root: str | Path) -> tuple[list[Finding], dict[str, Any]]:
    tool = run.get("tool") or {}
    driver = tool.get("driver") or {}
    tool_name = str(driver.get("name") or "unknown").lower().replace(" ", "-")
    tool_version = driver.get("version")
    rules: dict[int, dict[str, Any]] = {}
    for index, rule in enumerate(driver.get("rules") or []):
        if isinstance(rule, dict):
            rules[index] = rule
            rule.setdefault("index", index)
    tool_meta = {
        "name": tool_name,
        "version": tool_version,
        "information_uri": driver.get("informationUri"),
        "rules": len(rules),
        "results": len(run.get("results") or []),
        "file": rel,
    }

    findings: list[Finding] = []
    for result in run.get("results") or []:
        if not isinstance(result, dict):
            continue
        finding = _convert_result(result, rules, tool_name, tool_version, rel, root)
        if finding is not None:
            findings.append(finding)
    return findings, tool_meta


def _convert_result(
    result: dict[str, Any],
    rules: dict[int, dict[str, Any]],
    tool_name: str,
    tool_version: str | None,
    rel: str,
    root: str | Path,
) -> Finding | None:
    rule_index = result.get("ruleIndex")
    rule: dict[str, Any] = {}
    if isinstance(rule_index, int) and rule_index in rules:
        rule = rules[rule_index]
    elif isinstance(result.get("ruleId"), str):
        for candidate in rules.values():
            if candidate.get("id") == result.get("ruleId"):
                rule = candidate
                break

    rule_id = str(result.get("ruleId") or rule.get("id") or "unknown")
    message_data = result.get("message") or {}
    message_text = str(
        message_data.get("text")
        or message_data.get("markdown")
        or result.get("message")
        or ""
    ).strip()
    if not message_text:
        message_text = str(rule.get("shortDescription", {}).get("text", "") or "")
    short_description = str(
        rule.get("shortDescription", {}).get("text") or ""
    ).strip()
    rule_name = str(rule.get("name") or "").strip()
    if rule_name and rule_name.lower() not in _GENERIC_NAMES:
        title_source = rule_name or short_description or message_text
    else:
        title_source = short_description or rule_name or message_text
    title = _clean_title(title_source)
    if len(title) > 240:
        title = title[:237] + "..."

    raw_level = str(result.get("level") or rule.get("defaultConfiguration", {}).get("level") or "note")
    severity = severity_from_sarif(raw_level)
    properties = _merge_properties(result.get("properties"), rule.get("properties"))
    tags = _tags(properties)
    security_severity = _find_value(
        properties,
        "security-severity",
        "security_severity",
        "cvssScore",
        "cvss_score",
    )
    if security_severity is not None:
        score = _to_float(security_severity)
        if score is not None:
            severity = severity_from_cvss(score)
            properties["security_severity"] = score
    vector = _find_value(properties, "cvssVector", "cvss_vector", "vectorString")
    if vector and severity in {"UNKNOWN", "INFO"}:
        computed = base_score(str(vector))
        if computed is not None:
            severity = severity_from_cvss(computed)
    severity = normalize_severity(severity, "UNKNOWN")
    declared_severity = _find_value(properties, "severity")
    if declared_severity and severity in {"UNKNOWN", "INFO"}:
        severity = normalize_severity(declared_severity, severity)
    parsed_severity = _severity_from_message(message_text)
    if parsed_severity:
        severity = parsed_severity
    description = _message_body(message_text)

    package, installed, fixed, ecosystem = _package_info(result, properties, message_text)
    category = _infer_category(
        tool_name, rule_id, tags, properties, title, message_text, package
    )
    if category == "secret":
        message_text = _redact_secret_message(tool_name, title, message_text)
        description = message_text

    location = _location(result, root)
    identifiers = _identifiers(rule_id, tags, title, message_text)
    fp = _fingerprint(result, tool_name, rule_id, location, message_text)

    finding = Finding(
        rule_id=rule_id,
        title=title or "Security finding",
        description=description[:4000] or title,
        category=category,
        severity=severity,
        source=tool_name or "unknown",
        location=location,
        package=package,
        version=installed,
        ecosystem=ecosystem,
        fixed_version=fixed,
        identifiers=identifiers,
        aliases=_aliases_from_tags(tags),
        cvss_score=_to_float(security_severity) if security_severity is not None else None,
        cvss_vector=str(vector) if vector else None,
        remediation=_remediation(rule, package, installed, fixed),
        url=_url(rule),
        references=_urls(rule, message_text),
        properties={
            "tool": tool_name,
            "tool_version": tool_version,
            "sarif_file": rel,
            "raw_level": raw_level,
            "sarif_fingerprint": fp,
            "tags": sorted(tags),
            **properties,
        },
        fingerprint=fp,
    )
    return finding


def _clean_title(value: str) -> str:
    return " ".join(str(value).split())[:240] or "Security finding"


def _message_body(message: str) -> str:
    """Extract the human-readable body from Trivy/other multi-line messages."""
    if not message:
        return ""
    match = re.search(r"(?:^|\n)Message:\s*(.+?)(?=\n(?:Link|URL|Fix)\s*:|\Z)", message, re.IGNORECASE | re.DOTALL)
    if match:
        return " ".join(match.group(1).split())
    return message


def _severity_from_message(message: str) -> str | None:
    if not message:
        return None
    match = re.search(r"(?:^|\n)Severity:\s*([A-Za-z]+)", message)
    if not match:
        return None
    return normalize_severity(match.group(1), "UNKNOWN")


def _merge_properties(*sources: Any) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for source in sources:
        if isinstance(source, dict):
            merged.update(source)
    return merged


def _tags(properties: dict[str, Any]) -> set[str]:
    raw = properties.get("tags")
    if not isinstance(raw, list):
        raw = []
    return {str(item).strip().lower() for item in raw if str(item).strip()}


def _find_value(properties: dict[str, Any], *keys: str) -> Any:
    lowered = {key.lower(): key for key in properties}
    for key in keys:
        if key.lower() in lowered:
            return properties[lowered[key.lower()]]
    return None


def _package_info(
    result: dict[str, Any], properties: dict[str, Any], message_text: str
) -> tuple[str | None, str | None, str | None, str | None]:
    package = _find_value(properties, "pkgName", "packageName", "package", "PkgName")
    installed = _find_value(
        properties, "installedVersion", "installed_version", "version", "InstalledVersion"
    )
    fixed = _find_value(properties, "fixedVersion", "fixed_version", "FixedVersion")
    ecosystem = _find_value(properties, "pkgType", "packageEcosystem", "ecosystem")

    if not package:
        match = re.search(r"(?:Package|Pkg(?:Name)?|module)\s*[:=]\s*([^\n,;]+)", message_text, re.IGNORECASE)
        if match:
            package = match.group(1).strip()
    if not installed:
        match = re.search(
            r"(?:Installed\s+Version|Vulnerable\s+Version|version)\s*[:=]\s*([^\n,;]+)",
            message_text,
            re.IGNORECASE,
        )
        if match:
            installed = match.group(1).strip()
    if not fixed:
        match = re.search(
            r"(?:Fixed\s+Version|fixed_version)\s*[:=]\s*([^\n,;]+)", message_text, re.IGNORECASE
        )
        if match:
            fixed = match.group(1).strip()
    return (
        str(package) if package else None,
        str(installed) if installed else None,
        str(fixed) if fixed else None,
        str(ecosystem) if ecosystem else None,
    )


def _infer_category(
    tool_name: str,
    rule_id: str,
    tags: set[str],
    properties: dict[str, Any],
    title: str,
    message: str,
    package: str | None,
) -> str:
    haystack = " ".join(
        [tool_name, rule_id, " ".join(tags), title, message[:400], str(properties)]
    ).lower()
    if "license" in haystack or str(rule_id).upper().startswith("LICENSE"):
        return "license"
    if tool_name in {"gitleaks", "trufflehog", "secretscanner"} or "secret" in tags or "secrets" in tags:
        return "secret"
    if (
        "secret" in haystack
        and not package
        and not _KUBERNETES_RULE_RE.search(haystack)
    ):
        return "secret"
    if tool_name in {"semgrep", "codeql", "gosec", "bandit", "sonar"}:
        return "sast"
    if tool_name in {"zizmor"}:
        return "ci"
    if tool_name in {"osv-scanner", "dependency-review", "govulncheck"}:
        return "sca"
    if tool_name in {"kubescape", "kube-linter", "checkov", "kics", "terrascan", "trivy"}:
        if package:
            return "sca"
        if tool_name == "trivy" and ("misconfiguration" in haystack or "config" in haystack):
            return _infer_k8s_subcategory(haystack)
        return _infer_k8s_subcategory(haystack)
    if package:
        return "sca"
    if "dockerfile" in haystack:
        return "container"
    if _KUBERNETES_RULE_RE.search(haystack):
        return _infer_k8s_subcategory(haystack)
    if tool_name in {"grype", "syft"}:
        return "sca"
    return "unknown"


def _infer_k8s_subcategory(haystack: str) -> str:
    if _RBAC_RULE_RE.search(haystack):
        return "rbac"
    if _NETWORK_RULE_RE.search(haystack):
        return "network"
    if _HELM_KUSTOMIZE_RE.search(haystack):
        return "supply-chain"
    if _KUBERNETES_RULE_RE.search(haystack):
        return "kubernetes"
    return "iac"


def _redact_secret_message(tool_name: str, title: str, message: str) -> str:
    # Never propagate captured secret values into PR comments, step summaries
    # or artifacts owned by users.
    return (
        f"Potential secret detected by {tool_name} ({title}). "
        "The captured value is intentionally not shown. Review the file and "
        "rotate the credential."
    )


def _location(result: dict[str, Any], root: str | Path) -> Location:
    locations = result.get("locations")
    if not isinstance(locations, list) or not locations:
        return Location(path="")
    physical = locations[0].get("physicalLocation") or {}
    artifact = physical.get("artifactLocation") or {}
    uri = artifact.get("uri")
    path = ""
    if uri:
        parsed = urlparse(str(uri))
        if parsed.scheme == "file":
            path = unquote(parsed.path)
            if path.startswith("///"):
                path = path[2:]
        else:
            path = unquote(str(uri))
        path = _make_relative(path, root)
    region = physical.get("region") or {}
    start_line = region.get("startLine")
    end_line = region.get("endLine")
    start_column = region.get("startColumn")
    return Location(
        path=path or "",
        start_line=int(start_line) if isinstance(start_line, int) and start_line > 0 else None,
        end_line=int(end_line) if isinstance(end_line, int) and end_line > 0 else None,
        start_column=int(start_column) if isinstance(start_column, int) else None,
    )


def _make_relative(path: str, root: str | Path) -> str:
    normalized = normalize_path(path)
    candidate = Path(path)
    if candidate.is_absolute():
        try:
            normalized = normalize_path(candidate.resolve().relative_to(Path(root).resolve()))
        except ValueError:
            normalized = normalize_path(candidate)
    return normalized


def _identifiers(rule_id: str, tags: set[str], title: str, message: str) -> list[str]:
    identifiers: list[str] = []
    for value in [rule_id, *tags]:
        if re.match(r"^(CVE-|GHSA-|GO-|DS-|KSV|CKV|DIO-|CWE-)", str(value), re.IGNORECASE):
            identifiers.append(str(value))
    for match in _ADVISORY_RE.finditer(f"{title} {message}"):
        identifiers.append(match.group(1))
    if not identifiers and rule_id and rule_id != "unknown":
        identifiers.append(rule_id)
    out: list[str] = []
    for value in identifiers:
        if value not in out:
            out.append(value)
    return out[:10]


def _aliases_from_tags(tags: set[str]) -> list[str]:
    aliases = []
    for value in tags:
        if re.match(r"^(CVE-|GHSA-|GO-)", value, re.IGNORECASE):
            aliases.append(value)
    return aliases[:10]


def _fingerprint(
    result: dict[str, Any], tool_name: str, rule_id: str, location: Location, message: str
) -> str:
    partial = result.get("partialFingerprints") or {}
    if isinstance(partial, dict):
        for key in ("primaryLocationLineHash", "kuvuln/v1", "primary-location"):
            value = partial.get(key)
            if isinstance(value, str) and value:
                return stable_fingerprint("sarif", value)
        for value in partial.values():
            if isinstance(value, str) and value:
                return stable_fingerprint("sarif", value)
    return stable_fingerprint(
        "sarif", tool_name, rule_id, location.path, location.start_line or 0, message[:160]
    )


def _remediation(
    rule: dict[str, Any], package: str | None, installed: str | None, fixed: str | None
) -> str | None:
    full = rule.get("fullDescription") or {}
    text = str(full.get("text") or full.get("markdown") or "").strip()
    if fixed and package:
        return f"Upgrade {package} from {installed or 'the installed version'} to {fixed}. {text}".strip()
    if text:
        return text[:1000]
    return None


def _url(rule: dict[str, Any]) -> str | None:
    help_uri = rule.get("helpUri")
    if isinstance(help_uri, str) and help_uri.startswith("http"):
        return help_uri
    return None


def _urls(rule: dict[str, Any], message: str) -> list[str]:
    urls = _url(rule)
    out = [urls] if urls else []
    for match in re.finditer(r"https?://[^\s)>\]]+", message):
        url = match.group(0).rstrip(".,;")
        if url not in out:
            out.append(url)
    return out[:10]


def _to_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------


def build_sarif(
    findings: Iterable[Finding],
    meta: dict[str, Any] | None = None,
    uri: str = "https://github.com/bleon-ethical/kuvuln",
) -> dict[str, Any]:
    findings = list(findings)
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in findings:
        rule_key = f"{finding.rule_id}|{finding.category}"
        rule = rules.get(rule_key)
        if rule is None:
            tags = [finding.category, finding.source, "security", *finding.identifiers[:5]]
            rule = {
                "id": finding.rule_id,
                "name": finding.rule_id,
                "shortDescription": {"text": finding.title[:500]},
                "fullDescription": {
                    "text": (finding.description or finding.title)[:4000]
                },
                "helpUri": finding.url or uri,
                "help": {
                    "text": (finding.remediation or finding.description or finding.title)[:4000]
                },
                "defaultConfiguration": {"level": sarif_level(finding.severity)},
                "properties": {
                    "tags": _unique(tags),
                    "category": finding.category,
                    "security-severity": str(_security_severity(finding)),
                    "precision": "high",
                },
            }
            rules[rule_key] = rule
        location = finding.location
        physical: dict[str, Any] = {}
        if location.path:
            physical["artifactLocation"] = {"uri": location.path}
        if location.start_line:
            physical["region"] = {"startLine": location.start_line}
            if location.end_line:
                physical["region"]["endLine"] = location.end_line
        result: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "ruleIndex": list(rules).index(rule_key),
            "level": sarif_level(finding.severity),
            "message": {"text": _result_message(finding)},
            "locations": [{"physicalLocation": physical}] if physical else [],
            "partialFingerprints": {"kuvuln/v1": finding.fingerprint},
            "properties": {
                "category": finding.category,
                "source": finding.source,
                "severity": finding.severity,
                "risk_score": finding.risk_score,
                "package": finding.package,
                "version": finding.version,
                "fixed_version": finding.fixed_version,
                "cvss_score": finding.cvss_score,
                "epss": finding.epss,
                "kev": finding.kev,
                "reachable": finding.reachable,
                **finding.properties,
            },
        }
        if finding.identifiers:
            result["properties"]["identifiers"] = finding.identifiers
        if finding.references:
            result["properties"]["references"] = finding.references[:10]
        results.append(result)

    meta = meta or {}
    tool = {
        "driver": {
            "name": "KuVuln",
            "version": __version__,
            "informationUri": uri,
            "rules": list(rules.values()),
        }
    }
    invocation = {
        "executionSuccessful": True,
        "toolExecutionNotifications": [],
        "endTimeUtc": meta.get("generated_at"),
    }
    return {
        "$schema": (
            "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/"
            "sarif-schema-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [
            {
                "tool": tool,
                "invocations": [invocation],
                "results": results,
            }
        ],
    }


def _result_message(finding: Finding) -> str:
    parts = [finding.title]
    if finding.package:
        label = finding.package
        if finding.version:
            label += f"@{finding.version}"
        parts.append(f"Package: {label}")
    if finding.fixed_version:
        parts.append(f"Fixed version: {finding.fixed_version}")
    if finding.location.path:
        parts.append(f"Location: {finding.location.label()}")
    if finding.kev:
        parts.append("CISA KEV: known exploited")
    return " | ".join(parts)[:4000]


def _security_severity(finding: Finding) -> float:
    if finding.cvss_score is not None:
        return round(finding.cvss_score, 1)
    return {
        "CRITICAL": 9.8,
        "HIGH": 8.0,
        "MEDIUM": 5.5,
        "LOW": 2.0,
        "INFO": 0.1,
        "UNKNOWN": 0.0,
    }.get(finding.severity, 0.0)


def _unique(values: Iterable[str]) -> list[str]:
    out: list[str] = []
    for value in values:
        if value and value not in out:
            out.append(value)
    return out
