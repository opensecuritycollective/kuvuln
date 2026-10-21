"""CycloneDX SBOM generation for discovered dependencies."""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from typing import Any

from . import __version__
from .models import Dependency


def build_sbom(dependencies: Iterable[Dependency], metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    metadata = metadata or {}
    components: dict[str, dict[str, Any]] = {}
    for dependency in dependencies:
        purl = dependency.purl
        component = components.get(purl)
        if component is None:
            component = {
                "type": _component_type(dependency.ecosystem),
                "name": dependency.name,
                "version": dependency.version,
                "purl": purl,
                "bom-ref": purl,
                "scope": "required" if dependency.scope == "runtime" else "optional",
                "properties": [],
            }
            components[purl] = component
        else:
            component["scope"] = "required" if dependency.scope == "runtime" else component["scope"]
        paths = sorted(set(dependency.paths))
        if paths:
            component["properties"].append({"name": "kuvuln:source_paths", "value": ",".join(paths)})
        if dependency.license:
            component["licenses"] = [{"expression": dependency.license}]
        if dependency.direct:
            component["properties"].append({"name": "kuvuln:direct", "value": "true"})

    component_list = list(components.values())
    component_list.sort(key=lambda item: (item["name"].lower(), item["version"]))
    repository = metadata.get("repository") or "local-repository"
    serial = uuid.uuid5(uuid.NAMESPACE_URL, f"kuvuln:{repository}:{metadata.get('commit', '')}:{len(component_list)}")
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": metadata.get("generated_at"),
            "tools": [{"vendor": "KuVuln", "name": "KuVuln", "version": __version__}],
            "component": {
                "type": "application",
                "name": metadata.get("repository") or "repository",
                "bom-ref": f"repo:{repository}",
                "version": metadata.get("commit_short") or "unknown",
            },
        },
        "components": component_list,
    }


def _component_type(ecosystem: str) -> str:
    mapping = {
        "npm": "library",
        "pypi": "library",
        "go": "library",
        "crates.io": "library",
        "maven": "library",
        "packagist": "library",
        "rubygems": "library",
        "nuget": "library",
        "pub": "library",
        "hex": "library",
    }
    return mapping.get(ecosystem.lower(), "library")
