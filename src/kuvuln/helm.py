"""Helm chart hardening: metadata, dependency pinning and plaintext values."""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML

from .config import Config
from .models import Finding, Location
from .utils import normalize_path

LOGGER = logging.getLogger("kuvuln.helm")

_SECRET_KEY_RE = re.compile(
    r"(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth)",
    re.IGNORECASE,
)
_SKIP_VALUES = ("{{", "$", "vault:", "secretKeyRef", "ref+", "ENC[", "age1", "sops:")
_RANGE_RE = re.compile(r"[*^~>=<]")


def find_chart_dirs(roots: list[str | Path]) -> list[Path]:
    charts: list[Path] = []
    for root in roots:
        root_path = Path(root).resolve()
        for dirpath, dirnames, filenames in os.walk(root_path, followlinks=False):
            dirnames[:] = [
                name
                for name in dirnames
                if name not in {".git", "node_modules", ".venv", "venv"}
                and not name.startswith(".")
            ]
            if "Chart.yaml" in filenames or "Chart.yml" in filenames:
                charts.append(Path(dirpath))
    return sorted(set(charts))


def analyze_helm_charts(roots: list[str | Path], config: Config) -> list[Finding]:
    if not config.get("kubernetes.helm.enabled", True):
        return []
    findings: list[Finding] = []
    loader = YAML(typ="rt")
    for chart_dir in find_chart_dirs(roots):
        chart_path = chart_dir / "Chart.yaml"
        if not chart_path.exists():
            chart_path = chart_dir / "Chart.yml"
        try:
            chart = loader.load(chart_path.read_text(encoding="utf-8", errors="replace")) or {}
        except Exception as exc:  # noqa: BLE001
            LOGGER.debug("Could not parse %s: %s", chart_path, exc)
            continue
        if not isinstance(chart, dict):
            continue
        rel = _relative(chart_path, roots)
        api_version = str(chart.get("apiVersion", "v2"))
        if api_version == "v1":
            findings.append(
                Finding(
                    rule_id="KUV-HELM-001",
                    title="Helm chart uses the deprecated v1 API",
                    description="Chart.yaml apiVersion v1 targets Helm 2 and is no "
                    "longer supported.",
                    severity="LOW",
                    category="supply-chain",
                    source="kuvuln",
                    location=Location(path=rel, start_line=_line_of_key(chart, "apiVersion") or 1),
                    remediation="Set apiVersion: v2 and use Helm 3.",
                    properties={"chart": str(chart.get("name", chart_dir.name))},
                )
            )
        if config.get("kubernetes.helm.check_dependencies", True):
            findings.extend(_check_dependencies(chart, rel))
        if config.get("kubernetes.helm.check_values_secrets", True):
            findings.extend(_check_values(chart_dir, roots, config))
    return findings


def _check_dependencies(chart: dict[str, Any], rel: str) -> list[Finding]:
    findings: list[Finding] = []
    dependencies = chart.get("dependencies") or []
    if not isinstance(dependencies, list):
        return findings
    for index, dependency in enumerate(dependencies):
        if not isinstance(dependency, dict):
            continue
        name = str(dependency.get("name", f"dependency-{index}"))
        version = str(dependency.get("version", "") or "")
        repository = str(dependency.get("repository", "") or "")
        line = _line_of_key(dependency, "version") or _line_of_key(chart, "dependencies") or 1
        props = {"chart": str(chart.get("name", "")), "dependency": name}
        if not version:
            findings.append(
                Finding(
                    rule_id="KUV-HELM-002",
                    title=f"Helm dependency '{name}' has no pinned version",
                    description="A dependency without a version can resolve to a "
                    "different chart at install time, making deployments "
                    "non-reproducible and vulnerable to supply-chain attacks.",
                    severity="MEDIUM",
                    category="supply-chain",
                    source="kuvuln",
                    location=Location(path=rel, start_line=line),
                    remediation=f"Pin {name} to an exact chart version and commit "
                    "Chart.lock.",
                    properties=props,
                )
            )
        elif _RANGE_RE.search(version):
            findings.append(
                Finding(
                    rule_id="KUV-HELM-002",
                    title=f"Helm dependency '{name}' uses a mutable version range",
                    description=f"Version constraint {version} can install different "
                    "chart versions across runs.",
                    severity="MEDIUM",
                    category="supply-chain",
                    source="kuvuln",
                    location=Location(path=rel, start_line=line),
                    remediation=f"Pin {name} to an exact version (e.g. 1.2.3).",
                    properties=props,
                )
            )
        if repository.startswith("http://"):
            findings.append(
                Finding(
                    rule_id="KUV-HELM-003",
                    title=f"Helm dependency '{name}' uses an insecure repository",
                    description=f"repository {repository} is served over plain HTTP "
                    "and can be tampered with in transit.",
                    severity="HIGH",
                    category="supply-chain",
                    source="kuvuln",
                    location=Location(path=rel, start_line=line),
                    remediation="Use an HTTPS chart repository URL.",
                    properties=props,
                )
            )
    return findings


def _check_values(
    chart_dir: Path, roots: list[str | Path], config: Config
) -> list[Finding]:
    findings: list[Finding] = []
    values_files = sorted(
        [
            path
            for path in chart_dir.glob("values*.y*ml")
            if path.name not in {"values.schema.json"}
        ]
    )
    loader = YAML(typ="safe")
    for values_path in values_files:
        try:
            data = loader.load(values_path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        rel = _relative(values_path, roots)
        for key, value in _walk_values(data, str(values_path), rel):
            findings.append(
                Finding(
                    rule_id="KUV-HELM-004",
                    title=f"Helm values contain a literal secret: {key}",
                    description=f"values file {rel} stores '{key}' as a plain value. "
                    "Helm values are committed to Git and end up in release secrets.",
                    severity="HIGH",
                    category="supply-chain",
                    source="kuvuln",
                    location=Location(path=rel, start_line=1),
                    remediation="Move the value to an external secret manager and "
                    "reference it via valuesFrom/secretKeyRef or a secrets driver.",
                    properties={"chart": chart_dir.name, "key": key},
                )
            )
    return findings


def _walk_values(node: Any, path: str, rel: str, prefix: str = "") -> list[tuple[str, Any]]:
    out: list[tuple[str, Any]] = []
    if isinstance(node, dict):
        for key, value in node.items():
            label = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(value, (dict, list)):
                out.extend(_walk_values(value, path, rel, label))
                continue
            if not isinstance(value, str) or not value.strip():
                continue
            if _SECRET_KEY_RE.search(str(key)) and not value.strip().startswith(_SKIP_VALUES):
                out.append((label, value))
    elif isinstance(node, list):
        for item in node:
            if isinstance(item, (dict, list)):
                out.extend(_walk_values(item, path, rel, prefix))
    return out


def _line_of_key(node: Any, key: str) -> int | None:
    lc = getattr(node, "lc", None)
    if lc is None:
        return None
    try:
        info = lc.key(key)
        line = info[0] if isinstance(info, tuple) else None
    except Exception:
        line = getattr(lc, "line", None)
    return int(line) + 1 if isinstance(line, int) else None


def _relative(path: Path, roots: list[str | Path]) -> str:
    resolved = path.resolve()
    for root in roots:
        try:
            return normalize_path(resolved.relative_to(Path(root).resolve()))
        except ValueError:
            continue
    return normalize_path(resolved)
