"""License compliance checks for discovered dependencies."""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Iterable

from .config import Config
from .models import (
    Dependency,
    Finding,
    Location,
    normalize_severity,
    stable_fingerprint,
)
from .utils import is_expired, slugify

_DENIED_TOKEN_RE = re.compile(r"\b(AGPL|GPL|LGPL|SSPL|BUSL|CC-BY-NC|CPAL|EUPL|OSL|Sleepycat)\b", re.IGNORECASE)
_EXCEPTION_KEYS = ("package", "ecosystem", "version", "expires", "reason")


def license_findings(dependencies: Iterable[Dependency], config: Config) -> list[Finding]:
    license_config = config.get("license", {}) or {}
    if not license_config.get("enabled", True):
        return []
    denied = [str(item).strip() for item in license_config.get("deny", []) if str(item).strip()]
    if not denied:
        return []
    exceptions = [
        entry
        for entry in license_config.get("exceptions", []) or []
        if isinstance(entry, dict)
    ]
    severity = normalize_severity(license_config.get("severity", "HIGH"), "HIGH")
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for dependency in dependencies:
        if not dependency.license:
            continue
        if _is_exception(dependency, exceptions):
            continue
        denied_licenses = _denied_licenses(dependency.license, denied)
        for license_id in denied_licenses:
            key = (
                dependency.name.lower(),
                dependency.version,
                license_id.upper(),
            )
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    rule_id=f"LICENSE-{slugify(license_id, 40)}",
                    title=f"{dependency.name} uses denied license {license_id}",
                    description=f"Package {dependency.name}@{dependency.version} "
                    f"declares license {dependency.license}. This license is in the "
                    "configured deny list and is not compatible with the project's "
                    "licensing policy.",
                    severity=severity,
                    category="license",
                    source="kuvuln",
                    location=Location(path=dependency.primary_path),
                    package=dependency.name,
                    version=dependency.version,
                    ecosystem=dependency.ecosystem,
                    remediation="Upgrade or replace the dependency, or add an "
                    "explicit exception with a review date if the license is "
                    "acceptable.",
                    properties={
                        "package": dependency.name,
                        "license": dependency.license,
                        "denied_license": license_id,
                        "ecosystem": dependency.ecosystem,
                    },
                    fingerprint=stable_fingerprint(
                        "license", dependency.ecosystem, dependency.name, dependency.version, license_id.upper()
                    ),
                )
            )
    return findings


def _denied_licenses(expression: str, denied: list[str]) -> list[str]:
    normalized = expression.strip()
    out: list[str] = []
    for entry in denied:
        candidate = entry.strip()
        if not candidate:
            continue
        pattern = re.escape(candidate)
        if candidate.upper().endswith(("-ONLY", "-OR-LATER")):
            # SPDX expression matching: also accept the bare version.
            bare = candidate.split("-", 1)[0]
            if re.search(pattern, normalized, re.IGNORECASE) or re.search(
                re.escape(bare), normalized, re.IGNORECASE
            ):
                out.append(candidate)
        elif re.search(pattern, normalized, re.IGNORECASE):
            out.append(candidate)
    return out


def _is_exception(dependency: Dependency, exceptions: list[dict[str, object]]) -> bool:
    for entry in exceptions:
        package = str(entry.get("package", ""))
        if not package:
            continue
        if not fnmatch.fnmatchcase(dependency.name.lower(), package.lower()):
            continue
        ecosystem = entry.get("ecosystem")
        if ecosystem and (dependency.ecosystem or "").lower() != str(ecosystem).lower():
            continue
        version = entry.get("version")
        if version and dependency.version != str(version):
            continue
        if entry.get("expires") and is_expired(entry["expires"]):
            continue
        return True
    return False
