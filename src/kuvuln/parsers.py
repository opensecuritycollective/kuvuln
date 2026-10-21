"""Dependency file discovery and parsers.

The SCA layer is intentionally independent from external binaries so KuVuln can
produce consistent results in CI, locally and in offline mode. Go is a first
class citizen: go.mod, go list -m streams and vendor/modules.txt are supported.
"""

from __future__ import annotations

import fnmatch
import json
import logging
import os
import re
import tomllib
import xml.etree.ElementTree as ET
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML

from .config import Config
from .models import Dependency
from .utils import normalize_path, read_text

LOGGER = logging.getLogger("kuvuln.sca")

PRUNE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "__pycache__",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".terraform",
    "target",
    "dist",
    "build",
    "coverage",
    ".next",
    ".nuxt",
}

EXACT_FILES = {
    "package-lock.json": "package-lock",
    "npm-shrinkwrap.json": "package-lock",
    "yarn.lock": "yarn",
    "pnpm-lock.yaml": "pnpm",
    "pnpm-lock.yml": "pnpm",
    "poetry.lock": "toml-lock",
    "pdm.lock": "toml-lock",
    "uv.lock": "toml-lock",
    "Pipfile.lock": "pipfile-lock",
    "pyproject.toml": "pyproject",
    "go.mod": "go-mod",
    "Cargo.lock": "cargo-lock",
    "pom.xml": "maven",
    "gradle.lockfile": "gradle-lock",
    "composer.lock": "composer-lock",
    "Gemfile.lock": "gemfile-lock",
    "packages.lock.json": "nuget-lock",
    "pubspec.lock": "pubspec-lock",
    "mix.lock": "mix-lock",
    "package.json": "package-json",
}

MAX_DEPENDENCIES = 50_000
_VERSION_RE = re.compile(r"^[vV]?\d+(?:\.\d+){0,4}(?:[-+][0-9A-Za-z.+_-]+)?$")


@dataclass
class ParseResult:
    dependencies: list[Dependency] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def discover_dependency_files(root: str | Path, config: Config) -> list[Path]:
    root = Path(root).resolve()
    limit = int(config.get("sca.max_files", 5000))
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        kept_dirs = []
        for name in dirnames:
            child = current / name
            child_rel = _rel(child, root)
            if name in PRUNE_DIRS or name.startswith("."):
                continue
            if config.path_excluded(child_rel):
                continue
            kept_dirs.append(name)
        dirnames[:] = sorted(kept_dirs)

        for filename in sorted(filenames):
            path = current / filename
            if path.is_symlink():
                continue
            rel = _rel(path, root)
            if config.path_excluded(rel):
                continue
            if not _is_dependency_file(rel):
                continue
            try:
                if path.stat().st_size > int(config.get("sca.max_file_size_kb", 4096)) * 1024:
                    continue
            except OSError:
                continue
            files.append(path)
            if len(files) >= limit:
                return files
    return files


def _is_dependency_file(rel_path: str) -> bool:
    name = rel_path.rsplit("/", 1)[-1]
    if name in EXACT_FILES:
        return True
    if name.startswith(("requirements", "constraints")) and name.endswith(".txt"):
        return True
    if rel_path.endswith("vendor/modules.txt"):
        return True
    lower = name.lower()
    if lower in {"gomodules.json", "go-modules.json", "go.modules.json", "gomodules.jsonl"}:
        return True
    if lower.startswith("gomodules-") and lower.endswith((".json", ".jsonl")):
        return True
    return False


def parse_dependency_file(
    path: str | Path,
    root: str | Path,
    config: Config,
) -> ParseResult:
    root = Path(root).resolve()
    path = Path(path)
    rel = _rel(path, root)
    parser_name = _parser_name(rel)
    if not parser_name:
        return ParseResult()

    try:
        if parser_name == "package-lock":
            return parse_package_lock(path, rel)
        if parser_name == "yarn":
            return parse_yarn_lock(path, rel)
        if parser_name == "pnpm":
            return parse_pnpm_lock(path, rel)
        if parser_name == "requirements":
            return parse_requirements(path, rel, config)
        if parser_name == "toml-lock":
            return parse_toml_lock(path, rel, config)
        if parser_name == "pipfile-lock":
            return parse_pipfile_lock(path, rel, config)
        if parser_name == "pyproject":
            return parse_pyproject(path, rel, config)
        if parser_name == "go-mod":
            return parse_go_mod(path, rel, config)
        if parser_name == "go-list":
            return parse_go_list(path, rel, config)
        if parser_name == "go-vendor":
            return parse_vendor_modules(path, rel, config)
        if parser_name == "cargo-lock":
            return parse_cargo_lock(path, rel, config)
        if parser_name == "maven":
            return parse_maven_pom(path, rel, config)
        if parser_name == "gradle-lock":
            return parse_gradle_lock(path, rel, config)
        if parser_name == "composer-lock":
            return parse_composer_lock(path, rel, config)
        if parser_name == "gemfile-lock":
            return parse_gemfile_lock(path, rel, config)
        if parser_name == "nuget-lock":
            return parse_nuget_lock(path, rel, config)
        if parser_name == "pubspec-lock":
            return parse_pubspec_lock(path, rel, config)
        if parser_name == "mix-lock":
            return parse_mix_lock(path, rel, config)
        if parser_name == "package-json":
            return parse_package_json(path, rel, config)
    except Exception as exc:  # noqa: BLE001 - malformed manifests must not abort a scan
        return ParseResult(warnings=[f"{rel}: could not parse ({exc})"])
    return ParseResult()


def _parser_name(rel_path: str) -> str | None:
    name = rel_path.rsplit("/", 1)[-1]
    if rel_path.endswith("vendor/modules.txt"):
        return "go-vendor"
    if name in EXACT_FILES:
        return EXACT_FILES[name]
    if name.startswith(("requirements", "constraints")) and name.endswith(".txt"):
        return "requirements"
    lower = name.lower()
    if lower in {"gomodules.json", "go-modules.json", "go.modules.json", "gomodules.jsonl"}:
        return "go-list"
    if lower.startswith("gomodules-") and lower.endswith((".json", ".jsonl")):
        return "go-list"
    return None


def collect_dependencies(
    roots: str | Path | Iterable[str | Path],
    config: Config,
) -> tuple[list[Dependency], list[str]]:
    if isinstance(roots, (str, Path)):
        root_paths = [Path(roots).resolve()]
    else:
        root_paths = [Path(root).resolve() for root in roots]
    warnings: list[str] = []
    merged: dict[tuple[str, str, str], Dependency] = {}
    enabled_ecosystems = {eco.lower() for eco in config.get("sca.ecosystems", [])}
    include_dev = bool(config.get("sca.include_dev", True))
    include_indirect = bool(config.get("sca.include_indirect", True))
    ignore_packages = config.get("sca.ignore_packages", []) or []
    parsed_files = 0

    for root in root_paths:
        files = discover_dependency_files(root, config)
        parsed_files += len(files)
        for path in files:
            result = parse_dependency_file(path, root, config)
            warnings.extend(result.warnings)
            for dep in result.dependencies:
                if not _valid_dependency(dep):
                    continue
                if enabled_ecosystems and dep.ecosystem.lower() not in enabled_ecosystems:
                    continue
                if dep.scope == "dev" and not include_dev:
                    continue
                if dep.ecosystem == "Go" and dep.properties.get("indirect"):
                    if not include_indirect:
                        continue
                if any(
                    fnmatch.fnmatchcase(dep.name.lower(), str(pattern).lower())
                    for pattern in ignore_packages
                ):
                    continue
                key = dep.key
                existing = merged.get(key)
                if existing is None:
                    merged[key] = dep
                else:
                    for dep_path in dep.paths:
                        existing.add_path(dep_path)
                    existing.scope = (
                        "runtime"
                        if existing.scope == "runtime" or dep.scope == "runtime"
                        else "dev"
                    )
                    existing.direct = existing.direct or dep.direct
                    existing.license = existing.license or dep.license
                    existing.properties.update(
                        {
                            k: v
                            for k, v in dep.properties.items()
                            if k not in existing.properties
                        }
                    )
                if len(merged) >= MAX_DEPENDENCIES:
                    warnings.append(
                        f"Dependency limit reached ({MAX_DEPENDENCIES}); remaining files skipped"
                    )
                    return _sorted_dependencies(merged.values()), warnings
    return _sorted_dependencies(merged.values()), warnings


def _valid_dependency(dep: Dependency) -> bool:
    if not dep.name or not dep.version:
        return False
    version = dep.version.strip()
    if not version or version in {"*", "latest", "unknown"}:
        return False
    if any(token in version for token in ("{{", "$(", " ", "<", ">", "^", "~", "||")):
        return False
    if version.startswith(("file:", "link:", "workspace:", "git+", "http://", "https://")):
        return False
    return True


def _sorted_dependencies(values: Iterable[Dependency]) -> list[Dependency]:
    return sorted(
        values,
        key=lambda dep: (dep.ecosystem.lower(), dep.name.lower(), dep.version),
    )


# ---------------------------------------------------------------------------
# npm and friends
# ---------------------------------------------------------------------------


def parse_package_lock(path: Path, rel: str) -> ParseResult:
    data = json.loads(read_text(path))
    result = ParseResult()
    version = data.get("lockfileVersion", 1)
    if isinstance(version, int) and version >= 2 and isinstance(data.get("packages"), dict):
        for key, meta in data["packages"].items():
            if not key or not isinstance(meta, dict):
                continue
            if meta.get("link"):
                continue
            name = meta.get("name")
            if not name:
                if "node_modules/" not in key:
                    continue
                name = key.split("node_modules/")[-1]
            installed = meta.get("version")
            if not installed:
                continue
            if key.count("node_modules/") > 1:
                name = key.split("node_modules/")[-1]
            license_value = meta.get("license")
            if isinstance(license_value, list):
                license_value = " OR ".join(str(item) for item in license_value)
            result.dependencies.append(
                Dependency(
                    name=str(name),
                    version=str(installed),
                    ecosystem="npm",
                    path=rel,
                    scope="dev" if meta.get("dev") else "runtime",
                    direct=key.count("node_modules/") == 1,
                    license=str(license_value) if license_value else None,
                    properties={"lockfile": "package-lock"},
                )
            )
        return result

    def walk(dependencies: dict[str, Any], depth: int = 0) -> None:
        for name, meta in dependencies.items():
            if not isinstance(meta, dict):
                continue
            installed = meta.get("version")
            if installed:
                license_value = meta.get("license")
                if isinstance(license_value, list):
                    license_value = " OR ".join(str(item) for item in license_value)
                result.dependencies.append(
                    Dependency(
                        name=str(name),
                        version=str(installed),
                        ecosystem="npm",
                        path=rel,
                        scope="dev" if meta.get("dev") else "runtime",
                        direct=depth == 0,
                        license=str(license_value) if license_value else None,
                        properties={"lockfile": "package-lock-v1"},
                    )
                )
            nested = meta.get("dependencies")
            if isinstance(nested, dict):
                walk(nested, depth + 1)

    walk(data.get("dependencies", {}))
    return result


def parse_yarn_lock(path: Path, rel: str) -> ParseResult:
    text = read_text(path)
    result = ParseResult()
    selectors: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace() and line.endswith(":"):
            header = line[:-1].strip()
            selectors = _split_yarn_selectors(header)
            continue
        if selectors and re.match(r"^\s+version[:\s]", line):
            match = re.search(r'version[:\s]+"?([^"\s]+)"?', line)
            if not match:
                continue
            installed = match.group(1)
            name = _yarn_selector_name(selectors[0])
            if name and installed and not installed.startswith("0.0.0-"):
                result.dependencies.append(
                    Dependency(
                        name=name,
                        version=installed,
                        ecosystem="npm",
                        path=rel,
                        properties={"lockfile": "yarn"},
                    )
                )
            selectors = []
    return result


def _split_yarn_selectors(header: str) -> list[str]:
    items: list[str] = []
    current = ""
    quoted = False
    for char in header:
        if char == '"':
            quoted = not quoted
            current += char
        elif char == "," and not quoted:
            items.append(current.strip())
            current = ""
        else:
            current += char
    if current.strip():
        items.append(current.strip())
    return [item.strip().strip('"') for item in items if item.strip()]


def _yarn_selector_name(selector: str) -> str | None:
    selector = selector.strip().strip('"')
    if not selector or selector == "__metadata":
        return None
    if selector.startswith("@"):
        index = selector.find("@", 1)
        name = selector[:index] if index > 0 else selector
        rest = selector[index + 1 :] if index > 0 else ""
    else:
        name, _, rest = selector.partition("@")
    if rest.startswith("npm:"):
        alias = rest[4:]
        if "@" in alias:
            # Yarn alias: `foo@npm:bar@1.2.3` resolves to package `bar`.
            if alias.startswith("@"):
                index = alias.find("@", 1)
                return alias[:index] if index > 0 else alias
            return alias.rsplit("@", 1)[0]
        # Berry format: `pkg@npm:1.2.3` keeps the original package name.
        return name
    return name or None


def parse_pnpm_lock(path: Path, rel: str) -> ParseResult:
    text = read_text(path)
    result = ParseResult()
    in_packages = False
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if line.strip() == "packages:":
            in_packages = True
            continue
        if in_packages and line and not line.startswith(" "):
            break
        if not in_packages:
            continue
        match = re.match(r"^  '?([^':]+)'?:\s*$", line)
        if not match:
            continue
        key = match.group(1).strip()
        if key.startswith(("file:", "link:", "http://", "https://")):
            continue
        name, installed = _pnpm_key(key)
        if name and installed and not installed.startswith("0.0.0-"):
            result.dependencies.append(
                Dependency(
                    name=name,
                    version=installed,
                    ecosystem="npm",
                    path=rel,
                    properties={"lockfile": "pnpm"},
                )
            )
    return result


def _pnpm_key(key: str) -> tuple[str | None, str | None]:
    key = key.strip().strip("'")
    key = re.sub(r"\(.*$", "", key)
    if key.startswith("/"):
        body = key[1:]
        if body.startswith("@"):
            parts = body.split("/")
            if len(parts) < 3:
                return None, None
            name = "/".join(parts[:2])
            installed = parts[2]
        else:
            name, _, installed = body.partition("/")
        installed = re.sub(r"_.*$", "", installed)
        return name or None, installed or None
    if key.startswith("@"):
        index = key.find("@", 1)
        if index < 0:
            return None, None
        name = key[:index]
        installed = key[index + 1 :]
    else:
        name, _, installed = key.partition("@")
    installed = re.sub(r"_.*$", "", installed)
    return name or None, installed or None


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------


def parse_requirements(path: Path, rel: str, config: Config) -> ParseResult:
    text = read_text(path)
    result = ParseResult()
    buffer: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if line.endswith("\\"):
            buffer.append(line[:-1])
            continue
        line = "".join(buffer) + line
        buffer = []
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "-", "git+", "http://", "https://")):
            continue
        stripped = stripped.split(" #", 1)[0].strip()
        match = re.match(
            r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]+\])?\s*(===|==)\s*([^\s;#]+)",
            stripped,
        )
        if not match:
            continue
        name, _, installed = match.groups()
        installed = installed.strip().rstrip(",")
        if installed:
            result.dependencies.append(
                Dependency(
                    name=name,
                    version=installed,
                    ecosystem="PyPI",
                    path=rel,
                    scope="runtime",
                    properties={"lockfile": "requirements"},
                )
            )
    return result


def parse_toml_lock(path: Path, rel: str, config: Config) -> ParseResult:
    data = tomllib.loads(read_text(path))
    result = ParseResult()
    packages = data.get("package", [])
    if not isinstance(packages, list):
        return result
    for package in packages:
        if not isinstance(package, dict):
            continue
        name = package.get("name")
        installed = package.get("version")
        if not name or not installed:
            continue
        scope = "dev" if str(package.get("category", "")).lower() == "dev" else "runtime"
        if package.get("optional") and not config.get("sca.include_dev", True):
            continue
        result.dependencies.append(
            Dependency(
                name=str(name),
                version=str(installed),
                ecosystem="PyPI",
                path=rel,
                scope=scope,
                properties={"lockfile": path.name},
            )
        )
    return result


def parse_pipfile_lock(path: Path, rel: str, config: Config) -> ParseResult:
    data = json.loads(read_text(path))
    result = ParseResult()
    groups = {"default": "runtime", "develop": "dev"}
    for group, scope in groups.items():
        entries = data.get(group, {})
        if not isinstance(entries, dict):
            continue
        for name, meta in entries.items():
            if not isinstance(meta, dict):
                continue
            installed = str(meta.get("version", "")).lstrip("=")
            if installed:
                result.dependencies.append(
                    Dependency(
                        name=name,
                        version=installed,
                        ecosystem="PyPI",
                        path=rel,
                        scope=scope,
                        properties={"lockfile": "Pipfile.lock"},
                    )
                )
    return result


def parse_pyproject(path: Path, rel: str, config: Config) -> ParseResult:
    data = tomllib.loads(read_text(path))
    result = ParseResult()
    project = data.get("project", {})
    if isinstance(project, dict):
        for spec in project.get("dependencies", []) or []:
            dep = _pep508_exact(str(spec), rel, "runtime")
            if dep:
                result.dependencies.append(dep)
        optional = project.get("optional-dependencies", {})
        if isinstance(optional, dict):
            for group, specs in optional.items():
                scope = "dev" if str(group).lower() in {"dev", "test", "tests", "lint"} else "runtime"
                for spec in specs or []:
                    dep = _pep508_exact(str(spec), rel, scope)
                    if dep:
                        result.dependencies.append(dep)

    poetry = data.get("tool", {}).get("poetry", {}) if isinstance(data.get("tool"), dict) else {}
    if isinstance(poetry, dict):
        for group_name, group_value in poetry.items():
            if group_name in {"dependencies", "dev-dependencies"} and isinstance(group_value, dict):
                scope = "dev" if group_name == "dev-dependencies" else "runtime"
                _collect_poetry_deps(group_value, rel, scope, result)
            if group_name == "group" and isinstance(group_value, dict):
                for _, group_cfg in group_value.items():
                    if isinstance(group_cfg, dict) and isinstance(
                        group_cfg.get("dependencies"), dict
                    ):
                        _collect_poetry_deps(
                            group_cfg["dependencies"], rel, "dev", result
                        )
    return result


def _pep508_exact(spec: str, rel: str, scope: str) -> Dependency | None:
    match = re.match(
        r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]+\])?\s*==\s*([^\s;,]+)",
        spec.strip(),
    )
    if not match:
        return None
    return Dependency(
        name=match.group(1),
        version=match.group(2),
        ecosystem="PyPI",
        path=rel,
        scope=scope,
        direct=True,
        properties={"manifest": "pyproject.toml"},
    )


def _collect_poetry_deps(
    entries: dict[str, Any], rel: str, scope: str, result: ParseResult
) -> None:
    for name, value in entries.items():
        if name.lower() == "python":
            continue
        version = None
        if isinstance(value, str):
            version = value
        elif isinstance(value, dict):
            version = value.get("version")
        if not isinstance(version, str):
            continue
        # Poetry treats bare versions as caret ranges; only "=" / "==" are
        # exact pins and therefore safe to query.
        if not version.startswith("="):
            continue
        version = version.lstrip("=")
        if re.match(r"^\d+(?:\.\d+){0,4}(?:[-+][0-9A-Za-z.+_-]+)?$", version):
            result.dependencies.append(
                Dependency(
                    name=name,
                    version=version,
                    ecosystem="PyPI",
                    path=rel,
                    scope=scope,
                    direct=True,
                    properties={"manifest": "pyproject.toml"},
                )
            )


# ---------------------------------------------------------------------------
# Go
# ---------------------------------------------------------------------------


def parse_go_mod(path: Path, rel: str, config: Config) -> ParseResult:
    text = read_text(path)
    result = ParseResult()
    requirements: list[tuple[str, str, bool]] = []
    replacements: dict[str, tuple[str | None, str | None]] = {}
    excludes: set[tuple[str, str]] = set()
    mode: str | None = None

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("//"):
            continue
        if mode and line == ")":
            mode = None
            continue
        if "//" in line:
            line, _, comment = line.partition("//")
            line = line.strip()
            indirect = "indirect" in comment
        else:
            indirect = False
        if not line:
            continue
        if line.startswith("require ("):
            mode = "require"
            continue
        if line.startswith("replace ("):
            mode = "replace"
            continue
        if line.startswith("exclude ("):
            mode = "exclude"
            continue
        if line.startswith("require "):
            mode = "require-single"
            line = line[len("require ") :]
        elif line.startswith("replace "):
            mode = "replace-single"
            line = line[len("replace ") :]
        elif line.startswith("exclude "):
            mode = "exclude-single"
            line = line[len("exclude ") :]
        elif line.startswith("go ") or line.startswith("toolchain "):
            continue

        if mode in {"require", "require-single"}:
            fields = line.split()
            if len(fields) >= 2:
                requirements.append((fields[0], fields[1], indirect))
        elif mode in {"replace", "replace-single"}:
            left, _, right = line.partition("=>")
            left = left.strip()
            right = right.strip()
            old_fields = left.split()
            new_fields = right.split()
            if old_fields:
                old_name = old_fields[0]
                new_name = new_fields[0] if new_fields else None
                new_version = new_fields[1] if len(new_fields) > 1 else None
                replacements[old_name] = (new_name, new_version)
        elif mode in {"exclude", "exclude-single"}:
            fields = line.split()
            if len(fields) >= 2:
                excludes.add((fields[0], fields[1]))
        if mode and mode.endswith("-single"):
            mode = None

    for name, version, indirect in requirements:
        if (name, version) in excludes:
            continue
        effective_name, effective_version = name, version
        replacement = replacements.get(name) or replacements.get(f"{name}@{version}")
        if replacement:
            new_name, new_version = replacement
            if new_name and (new_name.startswith(".") or new_name.startswith("/")):
                continue
            if not new_version:
                continue
            effective_name = new_name or name
            effective_version = new_version
        result.dependencies.append(
            Dependency(
                name=effective_name,
                version=effective_version,
                ecosystem="Go",
                path=rel,
                scope="runtime",
                direct=not indirect,
                properties={
                    "indirect": indirect,
                    "manifest": "go.mod",
                    **({"replaced_from": name} if replacement else {}),
                },
            )
        )
    return result


def parse_go_list(path: Path, rel: str, config: Config) -> ParseResult:
    text = read_text(path)
    result = ParseResult()
    for module in _iter_json_stream(text):
        if not isinstance(module, dict):
            continue
        if module.get("Main"):
            continue
        name = module.get("Path")
        version = module.get("Version")
        replace = module.get("Replace")
        if isinstance(replace, dict):
            name = replace.get("Path") or name
            version = replace.get("Version") or version
            if isinstance(replace.get("Path"), str) and (
                str(replace["Path"]).startswith(".") or str(replace["Path"]).startswith("/")
            ):
                continue
        if not name or not version:
            continue
        result.dependencies.append(
            Dependency(
                name=str(name),
                version=str(version),
                ecosystem="Go",
                path=rel,
                scope="runtime",
                direct=not bool(module.get("Indirect")),
                properties={
                    "indirect": bool(module.get("Indirect")),
                    "manifest": "go list -m",
                },
            )
        )
    return result


def _iter_json_stream(text: str) -> Iterable[Any]:
    decoder = json.JSONDecoder()
    index = 0
    length = len(text)
    while index < length:
        while index < length and text[index] in " \t\r\n,":
            index += 1
        if index >= length:
            break
        try:
            value, index = decoder.raw_decode(text, index)
        except json.JSONDecodeError:
            line_end = text.find("\n", index)
            if line_end < 0:
                break
            index = line_end + 1
            continue
        if isinstance(value, list):
            yield from value
        else:
            yield value


def parse_vendor_modules(path: Path, rel: str, config: Config) -> ParseResult:
    text = read_text(path)
    result = ParseResult()
    for line in text.splitlines():
        if not line.startswith("# "):
            continue
        body = line[2:].strip()
        if "=>" in body:
            left, _, right = body.partition("=>")
            left_fields = left.split()
            right_fields = right.strip().split()
            if not left_fields:
                continue
            name = right_fields[0] if right_fields else left_fields[0]
            version = right_fields[1] if len(right_fields) > 1 else None
            if name.startswith((".", "/")):
                continue
        else:
            fields = body.split()
            if len(fields) < 2:
                continue
            name, version = fields[0], fields[1]
        if name and version:
            result.dependencies.append(
                Dependency(
                    name=name,
                    version=version,
                    ecosystem="Go",
                    path=rel,
                    scope="runtime",
                    properties={"manifest": "vendor/modules.txt"},
                )
            )
    return result


# ---------------------------------------------------------------------------
# Rust, JVM, PHP, Ruby, .NET, Dart, Elixir
# ---------------------------------------------------------------------------


def parse_cargo_lock(path: Path, rel: str, config: Config) -> ParseResult:
    data = tomllib.loads(read_text(path))
    result = ParseResult()
    for package in data.get("package", []) or []:
        if not isinstance(package, dict):
            continue
        name = package.get("name")
        installed = package.get("version")
        if not name or not installed:
            continue
        if not package.get("source"):
            continue
        result.dependencies.append(
            Dependency(
                name=str(name),
                version=str(installed),
                ecosystem="crates.io",
                path=rel,
                properties={"lockfile": "Cargo.lock"},
            )
        )
    return result


def _localname(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _xml_child(parent: ET.Element, name: str) -> ET.Element | None:
    for child in list(parent):
        if _localname(child.tag) == name:
            return child
    return None


def _xml_children(parent: ET.Element, name: str) -> list[ET.Element]:
    return [child for child in list(parent) if _localname(child.tag) == name]


def _xml_text(parent: ET.Element, name: str) -> str | None:
    child = _xml_child(parent, name)
    if child is None or child.text is None:
        return None
    return child.text.strip()


def parse_maven_pom(path: Path, rel: str, config: Config) -> ParseResult:
    root = ET.fromstring(read_text(path))
    properties: dict[str, str] = {}
    props_node = _xml_child(root, "properties")
    if props_node is not None:
        for child in list(props_node):
            if child.text:
                properties[_localname(child.tag)] = child.text.strip()
    parent = _xml_child(root, "parent")
    if parent is not None:
        parent_version = _xml_text(parent, "version")
        parent_group = _xml_text(parent, "groupId")
        if parent_version:
            properties.setdefault("project.version", parent_version)
        if parent_group:
            properties.setdefault("project.groupId", parent_group)
    own_version = _xml_text(root, "version")
    own_group = _xml_text(root, "groupId")
    if own_version:
        properties["project.version"] = own_version
    if own_group:
        properties["project.groupId"] = own_group
    properties.setdefault("project.version", "")
    properties.setdefault("project.groupId", "")

    managed: dict[tuple[str, str], str] = {}
    managed_node = _xml_child(root, "dependencyManagement")
    if managed_node is not None:
        deps_node = _xml_child(managed_node, "dependencies")
        if deps_node is not None:
            for dep in _xml_children(deps_node, "dependency"):
                group = _resolve_properties(_xml_text(dep, "groupId") or "", properties)
                artifact = _resolve_properties(_xml_text(dep, "artifactId") or "", properties)
                version = _resolve_properties(_xml_text(dep, "version") or "", properties)
                if group and artifact and version:
                    managed[(group, artifact)] = version

    result = ParseResult()
    dependencies_node = _xml_child(root, "dependencies")
    if dependencies_node is None:
        return result
    for dep in _xml_children(dependencies_node, "dependency"):
        group = _resolve_properties(_xml_text(dep, "groupId") or "", properties)
        artifact = _resolve_properties(_xml_text(dep, "artifactId") or "", properties)
        version = _resolve_properties(_xml_text(dep, "version") or "", properties)
        if not version:
            version = managed.get((group, artifact), "")
        scope = (_xml_text(dep, "scope") or "compile").lower()
        if scope in {"test", "provided", "system"} and not config.get(
            "sca.include_dev", True
        ):
            continue
        if not group or not artifact or not version:
            continue
        if not re.match(r"^[0-9]", version):
            continue
        result.dependencies.append(
            Dependency(
                name=f"{group}:{artifact}",
                version=version,
                ecosystem="Maven",
                path=rel,
                scope="dev" if scope == "test" else "runtime",
                direct=True,
                properties={"scope": scope, "manifest": "pom.xml"},
            )
        )
    return result


def _resolve_properties(value: str, properties: dict[str, str]) -> str:
    for _ in range(6):
        match = re.search(r"\$\{([^}]+)\}", value)
        if not match:
            break
        key = match.group(1)
        replacement = properties.get(key)
        if replacement is None:
            break
        value = value[: match.start()] + replacement + value[match.end() :]
    return value.strip()


def parse_gradle_lock(path: Path, rel: str, config: Config) -> ParseResult:
    result = ParseResult()
    for line in read_text(path).splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("empty="):
            continue
        coordinates = line.split("=", 1)[0]
        parts = coordinates.split(":")
        if len(parts) < 3:
            continue
        group, artifact, version = parts[0], parts[1], parts[2]
        result.dependencies.append(
            Dependency(
                name=f"{group}:{artifact}",
                version=version,
                ecosystem="Maven",
                path=rel,
                properties={"manifest": "gradle.lockfile"},
            )
        )
    return result


def parse_composer_lock(path: Path, rel: str, config: Config) -> ParseResult:
    data = json.loads(read_text(path))
    result = ParseResult()
    for key, scope in (("packages", "runtime"), ("packages-dev", "dev")):
        for package in data.get(key, []) or []:
            if not isinstance(package, dict):
                continue
            name = package.get("name")
            installed = str(package.get("version", "")).lstrip("v")
            if not name or not installed:
                continue
            licenses = package.get("license")
            if isinstance(licenses, list):
                licenses = " OR ".join(str(item) for item in licenses)
            result.dependencies.append(
                Dependency(
                    name=str(name),
                    version=installed,
                    ecosystem="Packagist",
                    path=rel,
                    scope=scope,
                    license=str(licenses) if licenses else None,
                    properties={"lockfile": "composer.lock"},
                )
            )
    return result


def parse_gemfile_lock(path: Path, rel: str, config: Config) -> ParseResult:
    text = read_text(path)
    result = ParseResult()
    section = ""
    in_specs = False
    for line in text.splitlines():
        if line and not line[0].isspace():
            section = line.strip()
            in_specs = False
            continue
        if line.strip() == "specs:":
            in_specs = True
            continue
        if section != "GEM" or not in_specs:
            continue
        match = re.match(r"^    ([A-Za-z0-9_.-]+) \(([^)]+)\)$", line)
        if match:
            result.dependencies.append(
                Dependency(
                    name=match.group(1),
                    version=match.group(2),
                    ecosystem="RubyGems",
                    path=rel,
                    properties={"lockfile": "Gemfile.lock"},
                )
            )
        elif line.startswith("  ") and not line.startswith("    "):
            in_specs = False
    return result


def parse_nuget_lock(path: Path, rel: str, config: Config) -> ParseResult:
    data = json.loads(read_text(path))
    result = ParseResult()
    dependencies = data.get("dependencies", {})
    if not isinstance(dependencies, dict):
        return result
    frameworks = dependencies.values()
    for packages in frameworks:
        if not isinstance(packages, dict):
            continue
        for name, meta in packages.items():
            if not isinstance(meta, dict):
                continue
            if str(meta.get("type", "")).lower() == "project":
                continue
            installed = meta.get("resolved")
            if installed:
                result.dependencies.append(
                    Dependency(
                        name=name,
                        version=str(installed),
                        ecosystem="NuGet",
                        path=rel,
                        properties={"lockfile": "packages.lock.json"},
                    )
                )
    return result


def parse_pubspec_lock(path: Path, rel: str, config: Config) -> ParseResult:
    data = YAML(typ="safe").load(read_text(path)) or {}
    result = ParseResult()
    packages = data.get("packages", {}) if isinstance(data, dict) else {}
    if not isinstance(packages, dict):
        return result
    for name, meta in packages.items():
        if not isinstance(meta, dict):
            continue
        if str(meta.get("source", "")).lower() not in {"hosted", ""}:
            continue
        installed = meta.get("version")
        if installed:
            result.dependencies.append(
                Dependency(
                    name=str(name),
                    version=str(installed),
                    ecosystem="Pub",
                    path=rel,
                    properties={"lockfile": "pubspec.lock"},
                )
            )
    return result


def parse_mix_lock(path: Path, rel: str, config: Config) -> ParseResult:
    text = read_text(path)
    result = ParseResult()
    pattern = re.compile(r'"([^"]+)"\s*:\s*\{:hex,\s*:[^,]+,\s*"([^"]+)"')
    for match in pattern.finditer(text):
        result.dependencies.append(
            Dependency(
                name=match.group(1),
                version=match.group(2),
                ecosystem="Hex",
                path=rel,
                properties={"lockfile": "mix.lock"},
            )
        )
    return result


def parse_package_json(path: Path, rel: str, config: Config) -> ParseResult:
    data = json.loads(read_text(path))
    # Only exact versions are useful without a lockfile; ranges are skipped to
    # avoid false positives.
    result = ParseResult()
    groups = (
        ("dependencies", "runtime"),
        ("devDependencies", "dev"),
        ("optionalDependencies", "runtime"),
    )
    for key, scope in groups:
        entries = data.get(key, {})
        if not isinstance(entries, dict):
            continue
        for name, version in entries.items():
            if not isinstance(version, str):
                continue
            text = version.strip().lstrip("=")
            if not re.match(r"^\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?$", text):
                continue
            result.dependencies.append(
                Dependency(
                    name=str(name),
                    version=text,
                    ecosystem="npm",
                    path=rel,
                    scope=scope,
                    direct=True,
                    properties={"manifest": "package.json"},
                )
            )
    return result


def _rel(path: Path, root: Path) -> str:
    try:
        return normalize_path(path.resolve().relative_to(root))
    except ValueError:
        return normalize_path(path)
