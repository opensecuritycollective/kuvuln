"""Go module hardening and Kubernetes component lifecycle checks."""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any

from .config import Config
from .enrich import LifecycleClient
from .models import Finding, Location
from .utils import normalize_path

LOGGER = logging.getLogger("kuvuln.gochecks")

GO_COMPONENT_IMAGES = {
    "kube-apiserver",
    "kube-controller-manager",
    "kube-scheduler",
    "kube-proxy",
    "kubelet",
    "etcd",
    "kube-state-metrics",
    "metrics-server",
    "coredns",
}

_K8S_TAG_RE = re.compile(r"^[vV]?(\d+\.\d+(?:\.\d+)?)$")


def find_go_mod_files(roots: list[str | Path], config: Config | None = None) -> list[Path]:
    files: list[Path] = []
    for root in roots:
        root_path = Path(root).resolve()
        for dirpath, dirnames, filenames in os.walk(root_path, followlinks=False):
            current = Path(dirpath)
            rel_dir = _relative(current, root_path)
            dirnames[:] = [
                name
                for name in dirnames
                if name not in {".git", "node_modules", "vendor", "__pycache__"}
                and not name.startswith(".")
            ]
            if config is not None and config.path_excluded(rel_dir):
                dirnames[:] = []
                continue
            if "go.mod" in filenames:
                files.append(current / "go.mod")
            if len(files) >= 100:
                return sorted(set(files))
    return sorted(set(files))


def analyze_go(
    roots: list[str | Path],
    config: Config,
    lifecycle_client: LifecycleClient | None,
    warnings: list[str],
) -> list[Finding]:
    if not config.get("go.enabled", True):
        return []
    findings: list[Finding] = []
    for go_mod in find_go_mod_files(roots, config):
        rel = _relative(go_mod, roots)
        try:
            text = go_mod.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            warnings.append(f"{rel}: could not read ({exc})")
            continue
        findings.extend(_analyze_go_mod(text, rel, config, lifecycle_client))
    return findings


def _analyze_go_mod(
    text: str, rel: str, config: Config, lifecycle_client: LifecycleClient | None
) -> list[Finding]:
    findings: list[Finding] = []
    go_directive = None
    toolchain = None
    replaces: list[tuple[str, str | None, str | None]] = []
    in_replace = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if in_replace:
            if line == ")":
                in_replace = False
                continue
            entry = _parse_replace(line)
            if entry:
                replaces.append(entry)
            continue
        if line.startswith("replace ("):
            in_replace = True
            continue
        if line.startswith("go "):
            go_directive = line[3:].strip()
        elif line.startswith("toolchain "):
            toolchain = line[len("toolchain ") :].strip()
        elif line.startswith("replace "):
            entry = _parse_replace(line[len("replace ") :])
            if entry:
                replaces.append(entry)

    if config.get("go.check_toolchain", True) and toolchain:
        version = toolchain.lstrip("go")
        status = (
            lifecycle_client.status("go", version)
            if lifecycle_client is not None
            else None
        )
        if status is not None and status.eol:
            findings.append(
                Finding(
                    rule_id="KUV-GO-001",
                    title=f"Go toolchain {toolchain} is end-of-life",
                    description=f"The toolchain directive {toolchain} is no longer "
                    "supported and no longer receives security fixes.",
                    severity="MEDIUM",
                    category="lifecycle",
                    source="kuvuln",
                    location=Location(path=rel, start_line=_line_of(text, "toolchain")),
                    remediation=f"Update the toolchain directive to a supported Go "
                    f"release (e.g. {status.latest or 'the current stable'}).",
                    properties={"toolchain": toolchain, "eol_date": str(status.eol_date) if status.eol_date else None},
                )
            )

    minimum = config.get("go.minimum_version")
    if go_directive and minimum:
        if _version_tuple(go_directive) < _version_tuple(minimum):
            findings.append(
                Finding(
                    rule_id="KUV-GO-002",
                    title=f"Go directive {go_directive} is older than {minimum}",
                    description="The go directive sets the minimum language version "
                    "and stdlib behavior for the module.",
                    severity="LOW",
                    category="lifecycle",
                    source="kuvuln",
                    location=Location(path=rel, start_line=_line_of(text, "go ")),
                    remediation=f"Set the go directive to at least {minimum}.",
                    properties={"go_directive": go_directive, "minimum": minimum},
                )
            )

    if config.get("go.check_replace_directives", True):
        for old, new_name, new_version in replaces:
            if not new_name:
                continue
            if new_name.startswith((".", "/", "..")):
                continue
            findings.append(
                Finding(
                    rule_id="KUV-GO-003",
                    title=f"Module {old} is replaced by a third-party fork",
                    description=f"replace {old} => {new_name} {new_version or ''} "
                    "bypasses the upstream module and its security advisories.",
                    severity="LOW",
                    category="lifecycle",
                    source="kuvuln",
                    location=Location(path=rel, start_line=_line_of(text, old)),
                    remediation="Use the upstream module when possible. If the "
                    "replace is required, pin it to an exact version and review "
                    "the fork.",
                    properties={"module": old, "replacement": new_name},
                )
            )
    return findings


def check_kubernetes_component_images(
    resources: list[Any],
    lifecycle_client: LifecycleClient | None,
) -> list[Finding]:
    if lifecycle_client is None:
        return []
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for resource in resources:
        if resource.kind not in {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob", "ReplicationController"}:
            continue
        from .kubernetes import _container_specs, _pod_spec

        pod_spec = _pod_spec(resource)
        if not pod_spec:
            continue
        for container, _ in _container_specs(pod_spec):
            image = str(container.get("image", ""))
            repository, _, tag = _image_parts(image)
            if not tag:
                continue
            component = repository.rsplit("/", 1)[-1]
            if component not in GO_COMPONENT_IMAGES:
                continue
            match = _K8S_TAG_RE.match(tag)
            if not match:
                continue
            key = (resource.identity, component, tag)
            if key in seen:
                continue
            status = lifecycle_client.status("kubernetes", match.group(1))
            if status is None or not status.eol:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    rule_id="KUV-K8S-023",
                    title=f"{component} {tag} is end-of-life",
                    description=f"Kubernetes {match.group(1)} reached end-of-life and "
                    "no longer receives security patches.",
                    severity="HIGH",
                    category="lifecycle",
                    source="kuvuln",
                    location=Location(
                        path=resource.path,
                        start_line=getattr(container, "lc", None)
                        and container.lc.line + 1
                        or resource.line,
                    ),
                    remediation=f"Upgrade {component} to a supported Kubernetes "
                    f"version (e.g. {status.latest or 'the current stable'}).",
                    properties={
                        "resource": resource.identity,
                        "component": component,
                        "version": match.group(1),
                        "eol_date": str(status.eol_date) if status.eol_date else None,
                    },
                )
            )
    return findings


def _parse_replace(line: str) -> tuple[str, str | None, str | None] | None:
    left, separator, right = line.partition("=>")
    if not separator:
        return None
    old_fields = left.split()
    new_fields = right.strip().split()
    if not old_fields:
        return None
    old = old_fields[0]
    new_name = new_fields[0] if new_fields else None
    new_version = new_fields[1] if len(new_fields) > 1 else None
    return old, new_name, new_version


def _image_parts(image: str) -> tuple[str, str, str]:
    reference = image.split("@", 1)[0]
    last_slash = reference.rfind("/")
    last_colon = reference.rfind(":")
    if last_colon > last_slash >= 0:
        return reference[:last_colon], reference[last_colon + 1 :], reference[last_colon + 1 :]
    if last_colon > last_slash and last_colon >= 0:
        return reference[:last_colon], reference[last_colon + 1 :], reference[last_colon + 1 :]
    return reference, "", ""


def _line_of(text: str, needle: str) -> int | None:
    for index, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return index
    return None


def _version_tuple(version: str) -> tuple[int, ...]:
    parts = []
    for part in str(version).strip().lstrip("go").split("."):
        digits = re.sub(r"\D", "", part)
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def _relative(path: Path, roots: str | Path | list[str | Path]) -> str:
    resolved = path.resolve()
    candidates = roots if isinstance(roots, list) else [roots]
    for root in candidates:
        try:
            return normalize_path(resolved.relative_to(Path(root).resolve()))
        except ValueError:
            continue
    return normalize_path(resolved)
