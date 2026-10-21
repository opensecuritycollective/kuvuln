"""Kustomize hardening: remote resources, generators and image tags."""

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

LOGGER = logging.getLogger("kuvuln.kustomize")

KUSTOMIZATION_FILES = ("kustomization.yaml", "kustomization.yml", "Kustomization")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
_SECRET_KEY_RE = re.compile(
    r"(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret)",
    re.IGNORECASE,
)


def find_kustomization_dirs(roots: list[str | Path]) -> list[Path]:
    dirs: list[Path] = []
    for root in roots:
        root_path = Path(root).resolve()
        for dirpath, dirnames, filenames in os.walk(root_path, followlinks=False):
            dirnames[:] = [
                name
                for name in dirnames
                if name not in {".git", "node_modules", ".venv", "venv"}
                and not name.startswith(".")
            ]
            if any(name in filenames for name in KUSTOMIZATION_FILES):
                dirs.append(Path(dirpath))
    return sorted(set(dirs))


def analyze_kustomize(roots: list[str | Path], config: Config) -> list[Finding]:
    if not config.get("kubernetes.kustomize.enabled", True):
        return []
    findings: list[Finding] = []
    loader = YAML(typ="rt")
    for directory in find_kustomization_dirs(roots):
        kustomization_path = _first_file(directory, KUSTOMIZATION_FILES)
        if kustomization_path is None:
            continue
        try:
            data = loader.load(
                kustomization_path.read_text(encoding="utf-8", errors="replace")
            )
        except Exception as exc:  # noqa: BLE001
            LOGGER.debug("Could not parse %s: %s", kustomization_path, exc)
            continue
        if not isinstance(data, dict):
            continue
        rel = _relative(kustomization_path, roots)
        if config.get("kubernetes.kustomize.forbid_unpinned_remote_resources", True):
            findings.extend(_check_remote_resources(data, rel))
        findings.extend(_check_helm_charts(data, rel))
        findings.extend(_check_images(data, rel))
        if config.get("kubernetes.kustomize.forbid_secret_generator", True):
            findings.extend(_check_generators(data, rel))
    return findings


def _check_remote_resources(data: dict[str, Any], rel: str) -> list[Finding]:
    findings: list[Finding] = []
    for key in ("resources", "bases"):
        values = data.get(key) or []
        if not isinstance(values, list):
            continue
        for index, value in enumerate(values):
            if not isinstance(value, str) or not value:
                continue
            line = _line_of_value(data, key, index)
            if value.startswith("http://"):
                findings.append(
                    _finding(
                        rel,
                        "KUV-KUSTOMIZE-001",
                        "HIGH",
                        "Kustomize resource uses an insecure remote base",
                        f"Remote resource {value} is fetched over plain HTTP and can "
                        "be tampered with in transit.",
                        "Use an HTTPS remote base pinned to a commit.",
                        line,
                    )
                )
                continue
            if not _looks_remote(value):
                continue
            ref = _remote_ref(value)
            if ref is None:
                severity = "HIGH"
                title = "Kustomize remote resource is not pinned"
                remediation = (
                    "Pin the remote resource with ?ref=<commit-sha> so the rendered "
                    "manifest cannot change under you."
                )
            elif _COMMIT_RE.match(ref):
                continue
            else:
                severity = "MEDIUM"
                title = "Kustomize remote resource is pinned to a mutable tag"
                remediation = "Pin the remote resource to an immutable commit SHA."
            findings.append(
                _finding(
                    rel,
                    "KUV-KUSTOMIZE-001",
                    severity,
                    title,
                    f"Remote resource {value} can resolve to different manifests "
                    "between builds.",
                    remediation,
                    line,
                )
            )
    return findings


def _check_helm_charts(data: dict[str, Any], rel: str) -> list[Finding]:
    findings: list[Finding] = []
    charts = data.get("helmCharts") or []
    if not isinstance(charts, list):
        return findings
    for index, chart in enumerate(charts):
        if not isinstance(chart, dict):
            continue
        name = str(chart.get("name", f"chart-{index}"))
        version = str(chart.get("version", "") or "")
        repository = str(chart.get("repo", "") or "")
        line = _line_of_value(data, "helmCharts", index)
        if not version:
            findings.append(
                _finding(
                    rel,
                    "KUV-KUSTOMIZE-002",
                    "MEDIUM",
                    f"Kustomize helmChart '{name}' has no pinned version",
                    "A helmChart without a version can install different charts over "
                    "time.",
                    f"Pin {name} to an exact chart version.",
                    line,
                )
            )
        elif any(operator in version for operator in ("*", "^", "~", ">=", "<=", ">", "<")):
            findings.append(
                _finding(
                    rel,
                    "KUV-KUSTOMIZE-002",
                    "MEDIUM",
                    f"Kustomize helmChart '{name}' uses a mutable version",
                    f"Version {version} can resolve to different chart releases.",
                    f"Pin {name} to an exact version and commit a lock file.",
                    line,
                )
            )
        if repository.startswith("http://"):
            findings.append(
                _finding(
                    rel,
                    "KUV-KUSTOMIZE-003",
                    "HIGH",
                    f"Kustomize helmChart '{name}' uses an insecure repository",
                    f"repository {repository} is served over plain HTTP.",
                    "Use an HTTPS Helm repository.",
                    line,
                )
            )
    return findings


def _check_images(data: dict[str, Any], rel: str) -> list[Finding]:
    findings: list[Finding] = []
    images = data.get("images") or []
    if not isinstance(images, list):
        return findings
    for index, image in enumerate(images):
        if not isinstance(image, dict):
            continue
        new_tag = str(image.get("newTag", "") or "")
        digest = str(image.get("digest", "") or "")
        line = _line_of_value(data, "images", index)
        if new_tag.lower() == "latest":
            findings.append(
                _finding(
                    rel,
                    "KUV-KUSTOMIZE-004",
                    "MEDIUM",
                    "Kustomize image uses the latest tag",
                    "The latest tag is mutable and makes the deployment "
                    "non-reproducible.",
                    "Pin the image to an immutable digest.",
                    line,
                )
            )
        if digest and digest.lower().startswith("latest"):
            findings.append(
                _finding(
                    rel,
                    "KUV-KUSTOMIZE-004",
                    "MEDIUM",
                    "Kustomize image digest is not immutable",
                    f"digest {digest} is a mutable reference.",
                    "Use a sha256 digest.",
                    line,
                )
            )
    return findings


def _check_generators(data: dict[str, Any], rel: str) -> list[Finding]:
    findings: list[Finding] = []
    if data.get("secretGenerator"):
        findings.append(
            _finding(
                rel,
                "KUV-KUSTOMIZE-005",
                "HIGH",
                "Kustomize secretGenerator stores plaintext secrets in Git",
                "secretGenerator creates Secret objects from literal or file values "
                "that are base64-encoded, not encrypted, and are readable by anyone "
                "with repository access.",
                "Use an external secrets operator (External Secrets, Sealed Secrets, "
                "SOPS) and keep only references in Git.",
                _line_of_key(data, "secretGenerator"),
            )
        )
    generators = data.get("configMapGenerator") or []
    if isinstance(generators, list):
        for index, generator in enumerate(generators):
            if not isinstance(generator, dict):
                continue
            literals = generator.get("literals") or []
            if not isinstance(literals, list):
                continue
            for literal in literals:
                if not isinstance(literal, str) or "=" not in literal:
                    continue
                key = literal.split("=", 1)[0]
                value = literal.split("=", 1)[1]
                if _SECRET_KEY_RE.search(key) and value and not value.startswith(
                    ("{{", "$", "vault:", "ref+")
                ):
                    findings.append(
                        _finding(
                            rel,
                            "KUV-KUSTOMIZE-006",
                            "HIGH",
                            f"Kustomize configMapGenerator exposes '{key}'",
                            "A literal configMap value containing a secret-like key "
                            "is stored in Git in plain text.",
                            "Move the value to a secret generator backed by an "
                            "external secrets provider.",
                            _line_of_value(data, "configMapGenerator", index),
                        )
                    )
    return findings


def _finding(
    rel: str, rule_id: str, severity: str, title: str, description: str,
    remediation: str, line: int | None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        description=description,
        severity=severity,
        category="supply-chain",
        source="kuvuln",
        location=Location(path=rel, start_line=line or 1),
        remediation=remediation,
        properties={"control": rule_id},
    )


def _looks_remote(value: str) -> bool:
    return value.startswith(("http://", "https://", "git@", "git::", "github.com/"))


def _remote_ref(value: str) -> str | None:
    match = re.search(r"[?&]ref=([^&]+)", value)
    if match:
        return match.group(1)
    return None


def _first_file(directory: Path, names: tuple[str, ...]) -> Path | None:
    for name in names:
        candidate = directory / name
        if candidate.exists():
            return candidate
    return None


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


def _line_of_value(node: Any, key: str, index: int) -> int | None:
    lc = getattr(node, "lc", None)
    if lc is None:
        return None
    try:
        info = lc.value(key)
        line = info[0] if isinstance(info, tuple) else None
    except Exception:
        line = getattr(lc, "line", None)
    if isinstance(line, int):
        return line + 1
    return None


def _relative(path: Path, roots: list[str | Path]) -> str:
    resolved = path.resolve()
    for root in roots:
        try:
            return normalize_path(resolved.relative_to(Path(root).resolve()))
        except ValueError:
            continue
    return normalize_path(resolved)
