"""Container image extraction from Kubernetes manifests and Dockerfiles."""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from .config import Config
from .kubernetes import ResourceDoc, _container_specs, _pod_spec
from .utils import normalize_path

LOGGER = logging.getLogger("kuvuln.images")

DOCKERFILE_NAMES = {"dockerfile", "containerfile"}
_FROM_RE = re.compile(
    r"^\s*FROM\s+(?:--platform=\S+\s+)?([^\s]+)(?:\s+[Aa][Ss]\s+\S+)?\s*$"
)
_ARG_RE = re.compile(r"^\s*ARG\s+([A-Za-z_][A-Za-z0-9_]*)(?:=(\S*))?", re.IGNORECASE)
_IMAGE_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]+$")


@dataclass
class ImageReference:
    image: str
    path: str
    line: int
    source: str  # "kubernetes" or "dockerfile"
    resource: str | None = None

    def key(self) -> tuple[str, str]:
        return (self.image, self.source)


def collect_images(
    roots: list[str | Path],
    resources: list[ResourceDoc],
    config: Config,
) -> list[ImageReference]:
    references = extract_manifest_images(resources)
    if config.get("scan_targets.docker", True) or config.get("scan_targets.container", True):
        for dockerfile in discover_dockerfiles(roots, config):
            references.extend(parse_dockerfile(dockerfile, roots))
    unique: dict[tuple[str, str], ImageReference] = {}
    for reference in references:
        if not _is_scannable(reference.image):
            continue
        existing = unique.get(reference.key())
        if existing is None:
            unique[reference.key()] = reference
    return sorted(unique.values(), key=lambda item: (item.image, item.source))


def extract_manifest_images(resources: Iterable[ResourceDoc]) -> list[ImageReference]:
    references: list[ImageReference] = []
    for resource in resources:
        pod_spec = _pod_spec(resource)
        if not pod_spec:
            continue
        for container, _ in _container_specs(pod_spec):
            image = str(container.get("image", ""))
            if image and "{{" not in image and "$" not in image:
                references.append(
                    ImageReference(
                        image=image,
                        path=resource.path,
                        line=getattr(container, "lc", None)
                        and container.lc.line + 1
                        or resource.line,
                        source="kubernetes",
                        resource=resource.identity,
                    )
                )
    return references


def discover_dockerfiles(roots: list[str | Path], config: Config) -> list[Path]:
    files: list[Path] = []
    for root in roots:
        root_path = Path(root).resolve()
        for dirpath, dirnames, filenames in os.walk(root_path, followlinks=False):
            current = Path(dirpath)
            rel_dir = _relative(current, root_path)
            dirnames[:] = [
                name
                for name in dirnames
                if name not in {".git", "node_modules", ".venv", "venv"}
                and not name.startswith(".")
            ]
            if config.path_excluded(rel_dir):
                dirnames[:] = []
                continue
            for filename in filenames:
                lower = filename.lower()
                if lower in DOCKERFILE_NAMES or lower.endswith(".dockerfile") or lower.endswith(".containerfile"):
                    files.append(current / filename)
    return sorted(set(files))


def parse_dockerfile(path: Path, roots: list[str | Path]) -> list[ImageReference]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    rel = _relative(path, roots)
    references: list[ImageReference] = []
    arg_defaults: dict[str, str] = {}
    stages: set[str] = set()
    for index, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        arg_match = _ARG_RE.match(raw_line)
        if arg_match:
            name, default = arg_match.group(1), arg_match.group(2)
            if default is not None:
                arg_defaults[name] = default.strip('"')
            continue
        from_match = _FROM_RE.match(raw_line)
        if not from_match:
            continue
        image = from_match.group(1)
        resolved = _resolve_image(image, arg_defaults)
        if not resolved or resolved.lower() == "scratch":
            continue
        if resolved in stages:
            continue
        if "{{" in resolved or "$" in resolved:
            continue
        if not _IMAGE_REF_RE.match(resolved):
            continue
        references.append(
            ImageReference(
                image=resolved,
                path=rel,
                line=index,
                source="dockerfile",
                resource=None,
            )
        )
        stages.add(image.strip('"'))
    return references


def _resolve_image(image: str, arg_defaults: dict[str, str]) -> str:
    if image.startswith("{{"):
        return image
    def replace(match: re.Match) -> str:
        name = match.group(1) or match.group(2)
        return arg_defaults.get(name, match.group(0))

    resolved = re.sub(r"\$\{\{.*?\}\}", lambda match: match.group(0), image)
    resolved = re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", replace, resolved)
    resolved = re.sub(r"\$([A-Za-z_][A-Za-z0-9_]*)", replace, resolved)
    return resolved.strip().strip('"')


def _is_scannable(image: str) -> bool:
    if not image or image.lower() == "scratch":
        return False
    if any(token in image for token in ("{{", "$", "*", " ")):
        return False
    if image.startswith(("<", "{", "[")):
        return False
    return True


def _relative(path: Path, roots: str | Path | list[str | Path]) -> str:
    resolved = path.resolve()
    candidates = roots if isinstance(roots, list) else [roots]
    for root in candidates:
        try:
            return normalize_path(resolved.relative_to(Path(root).resolve()))
        except ValueError:
            continue
    return normalize_path(resolved)
