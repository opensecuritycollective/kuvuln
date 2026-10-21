"""KuVuln configuration loading, validation and exclusion matching."""

from __future__ import annotations

import fnmatch
import json
import logging
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .models import Finding, normalize_severity
from .utils import deep_merge, is_expired, normalize_path

LOGGER = logging.getLogger("kuvuln.config")

DEFAULT_CONFIG: dict[str, Any] = {
    "version": "3.0.0",
    "bot_name": "KuVuln",
    "settings": {
        "fail_on_severity": "HIGH",
        "fail_on_kev": True,
        "fail_on_epss": 0.0,
        "minimum_severity": "LOW",
        "report_minimum_severity": "LOW",
        "ignore_unfixed": False,
        "max_allowed": {},
        "baseline": None,
        "scan_targets": {
            "kubernetes": True,
            "rbac": True,
            "network_policy": True,
            "helm": True,
            "kustomize": True,
            "go": True,
            "dependencies": True,
            "container": True,
            "docker": True,
            "secrets": True,
            "sast": True,
            "licenses": True,
            "lifecycle": True,
            "ci": True,
        },
        "exclusions": {
            "directories": [],
            "paths": [],
            "vulnerabilities": [],
            "rules": [],
            "packages": [],
        },
    },
    "sca": {
        "enabled": True,
        "ecosystems": [
            "npm",
            "PyPI",
            "Go",
            "crates.io",
            "Maven",
            "Packagist",
            "RubyGems",
            "NuGet",
            "Pub",
            "Hex",
        ],
        "include_dev": True,
        "include_indirect": True,
        "max_file_size_kb": 4096,
        "max_files": 5000,
        "osv_api": "https://api.osv.dev",
        "timeout_seconds": 20,
        "retries": 3,
        "ignore_packages": [],
        "go": {
            "use_go_list": True,
            "include_vendor": True,
            "check_replace_directives": True,
        },
    },
    "kubernetes": {
        "enabled": True,
        "pod_security_standard": "restricted",
        "exclude_namespaces": ["kube-system", "kube-public", "kube-node-lease"],
        "require_resource_limits": True,
        "require_network_policy": True,
        "require_image_digest": False,
        "trusted_registries": [],
        "check_plaintext_secrets": True,
        "check_rbac": True,
        "check_admission_webhooks": True,
        "check_removed_apis": True,
        "check_control_plane_flags": True,
        "check_kubelet_config": True,
        "max_file_size_kb": 4096,
        "helm": {
            "enabled": True,
            "check_values_secrets": True,
            "check_dependencies": True,
        },
        "kustomize": {
            "enabled": True,
            "forbid_unpinned_remote_resources": True,
            "forbid_secret_generator": True,
        },
    },
    "go": {
        "enabled": True,
        "check_toolchain": True,
        "check_replace_directives": True,
        "minimum_version": None,
    },
    "enrichment": {
        "epss": True,
        "kev": True,
        "lifecycle": True,
        "offline": False,
        "cache_ttl_hours": 24,
        "timeout_seconds": 20,
    },
    "lifecycle": {
        "enabled": True,
        "online": True,
        "products": ["kubernetes", "go"],
    },
    "license": {
        "enabled": True,
        "deny": [],
        "exceptions": [],
        "severity": "HIGH",
    },
    "notifications": {
        "github_pr_comments": True,
        "security_tab_integration": True,
        "summary_level": "verbose",
        "max_findings_in_comment": 25,
    },
    "compliance_standards": ["PSS-restricted", "CIS-Kubernetes", "NSA-CISA"],
    "advanced": {
        "deep_history_scan": True,
        "ignore_unfixed": False,
        "license_check": True,
        "offline": False,
        "max_findings_in_comment": 25,
    },
}

_TARGET_CATEGORIES = {
    "kubernetes": {"kubernetes", "iac"},
    "rbac": {"rbac"},
    "network_policy": {"network"},
    "helm": {"supply-chain"},
    "kustomize": {"supply-chain"},
    "dependencies": {"sca"},
    "go": {"sca"},
    "container": {"container"},
    "docker": {"container", "iac"},
    "secrets": {"secret"},
    "sast": {"sast"},
    "licenses": {"license"},
    "license": {"license"},
    "lifecycle": {"lifecycle"},
    "ci": {"ci"},
}


class ConfigError(RuntimeError):
    pass


class Config:
    def __init__(
        self,
        data: dict[str, Any] | None = None,
        path: str | Path | None = None,
    ) -> None:
        self.path = Path(path) if path else None
        self.root = self.path.parent.resolve() if self.path else Path.cwd().resolve()
        self.warnings: list[str] = []
        raw = data or {}
        if not isinstance(raw, dict):
            raise ConfigError("The KuVuln configuration must be a JSON object")
        merged = deep_merge(DEFAULT_CONFIG, raw)
        self.data = merged
        self._apply_legacy_compatibility(raw)
        self._normalize()
        self._validate()

    @classmethod
    def load(cls, path: str | Path | None) -> Config:
        if path is None:
            path = Path("kuvuln-config.json")
        config_path = Path(path)
        if not config_path.exists():
            raise ConfigError(f"Configuration file not found: {config_path}")
        try:
            with open(config_path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except json.JSONDecodeError as exc:
            raise ConfigError(
                f"Invalid JSON in {config_path} at line {exc.lineno}: {exc.msg}"
            ) from exc
        except OSError as exc:
            raise ConfigError(f"Could not read {config_path}: {exc}") from exc
        return cls(data, config_path)

    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = self.data
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    @property
    def bot_name(self) -> str:
        return str(self.get("bot_name", "KuVuln"))

    @property
    def fail_on(self) -> str:
        value = str(self.get("settings.fail_on_severity", "HIGH")).upper()
        if value in {"NONE", "OFF", "DISABLED"}:
            return "NONE"
        return normalize_severity(value, "HIGH")

    @property
    def minimum_severity(self) -> str:
        return normalize_severity(
            self.get(
                "settings.report_minimum_severity",
                self.get("settings.minimum_severity", "LOW"),
            )
        )

    @property
    def offline(self) -> bool:
        return bool(
            self.get("enrichment.offline", False)
            or self.get("advanced.offline", False)
        )

    @property
    def exclusions(self) -> dict[str, Any]:
        return self.get("settings.exclusions", {}) or {}

    def resolve_path(self, path: str | Path) -> Path:
        candidate = Path(path)
        if candidate.is_absolute():
            return candidate
        return (self.root / candidate).resolve()

    def scan_target_enabled(self, target: str) -> bool:
        targets = self.get("settings.scan_targets", {}) or {}
        return bool(targets.get(target, True))

    def category_enabled(self, category: str) -> bool:
        category = (category or "unknown").lower()
        targets = self.get("settings.scan_targets", {}) or {}
        if category in {"kubernetes", "iac"}:
            return bool(targets.get("kubernetes", True))
        if category == "rbac":
            return bool(targets.get("kubernetes", True) and targets.get("rbac", True))
        if category == "network":
            return bool(
                targets.get("kubernetes", True)
                and targets.get("network_policy", True)
            )
        if category == "supply-chain":
            return bool(
                targets.get("kubernetes", True)
                and (
                    targets.get("helm", True)
                    or targets.get("kustomize", True)
                )
            )
        if category == "container":
            return bool(
                targets.get("container", targets.get("docker", True))
            )
        if category == "sca":
            return bool(
                targets.get("dependencies", True) or targets.get("go", True)
            )
        if category == "secret":
            return bool(targets.get("secrets", True))
        if category == "sast":
            return bool(targets.get("sast", True))
        if category == "license":
            return bool(targets.get("licenses", targets.get("license", True)))
        if category == "lifecycle":
            return bool(targets.get("lifecycle", True))
        if category == "ci":
            return bool(targets.get("ci", True))
        return True

    def path_excluded(self, path: str) -> bool:
        if not path:
            return False
        normalized = normalize_path(path)
        if normalized in {".", "./"}:
            return False
        patterns: list[str] = []
        for key in ("directories", "paths"):
            values = self.exclusions.get(key, []) or []
            if isinstance(values, str):
                values = [values]
            patterns.extend(str(item) for item in values)
        return any(_match_path(normalized, pattern) for pattern in patterns)

    def suppression_reason(self, finding: Finding) -> str | None:
        if not self.category_enabled(finding.category):
            return f"scan target for '{finding.category}' is disabled"
        if self.path_excluded(finding.location.path):
            return "path excluded by configuration"

        for entry in self._entries("rules"):
            if _rule_matches(finding, entry):
                if _entry_active(entry, self.warnings):
                    return f"rule {entry.get('id')} excluded: {entry.get('reason', 'configured')}"
        for entry in self._entries("vulnerabilities"):
            if _vulnerability_matches(finding, entry):
                if _entry_active(entry, self.warnings):
                    return (
                        f"vulnerability {entry.get('id')} excluded: "
                        f"{entry.get('reason', 'configured')}"
                    )
        for entry in self._entries("packages"):
            if _package_matches(finding, entry):
                if _entry_active(entry, self.warnings):
                    return (
                        f"package {entry.get('name')} excluded: "
                        f"{entry.get('reason', 'configured')}"
                    )
        if self.get("settings.ignore_unfixed", False) and finding.category == "sca":
            if not finding.fixed_version:
                return "unfixed vulnerability ignored by configuration"
        return None

    def _entries(self, key: str) -> list[dict[str, Any]]:
        values = self.exclusions.get(key, []) or []
        if isinstance(values, dict):
            values = [values]
        if not isinstance(values, list):
            return []
        return [entry for entry in values if isinstance(entry, dict)]

    def _apply_legacy_compatibility(self, raw: dict[str, Any]) -> None:
        advanced = raw.get("advanced", {}) if isinstance(raw.get("advanced"), dict) else {}
        settings = raw.get("settings", {}) if isinstance(raw.get("settings"), dict) else {}
        if "ignore_unfixed" not in settings and "ignore_unfixed" in advanced:
            self.data["settings"]["ignore_unfixed"] = bool(advanced["ignore_unfixed"])
        if "offline" not in (raw.get("enrichment") or {}) and "offline" in advanced:
            self.data["enrichment"]["offline"] = bool(advanced["offline"])
        if "license_check" in advanced and "enabled" not in (
            raw.get("license") or {}
        ):
            self.data["license"]["enabled"] = bool(advanced["license_check"])
        if "max_findings_in_comment" in advanced and "max_findings_in_comment" not in (
            raw.get("notifications") or {}
        ):
            self.data["notifications"]["max_findings_in_comment"] = advanced[
                "max_findings_in_comment"
            ]

        targets = self.data["settings"]["scan_targets"]
        # Map legacy Docker/kubernetes switches to the richer target set.
        if settings.get("scan_targets", {}).get("docker") is False:
            targets["container"] = False
        if settings.get("scan_targets", {}).get("kubernetes") is False:
            for key in ("kubernetes", "rbac", "network_policy", "helm", "kustomize"):
                targets[key] = False
        if settings.get("scan_targets", {}).get("dependencies") is False:
            targets["dependencies"] = False
            targets["go"] = False
        if settings.get("scan_targets", {}).get("secrets") is False:
            targets["secrets"] = False
        if settings.get("scan_targets", {}).get("sast") is False:
            targets["sast"] = False

    def _normalize(self) -> None:
        settings = self.data["settings"]
        for key in ("fail_on_severity", "minimum_severity", "report_minimum_severity"):
            if key == "fail_on_severity":
                value = str(settings.get(key, "HIGH")).upper()
                if value in {"OFF", "DISABLED", "NONE"}:
                    settings[key] = "NONE"
                else:
                    settings[key] = normalize_severity(value, "HIGH")
            else:
                settings[key] = normalize_severity(settings.get(key, "LOW"), "LOW")

        max_allowed = settings.get("max_allowed")
        if not isinstance(max_allowed, dict):
            settings["max_allowed"] = {}
        else:
            normalized: dict[str, int] = {}
            for severity, count in max_allowed.items():
                try:
                    normalized[normalize_severity(severity)] = max(0, int(count))
                except (TypeError, ValueError):
                    self.warn(f"Invalid max_allowed entry for {severity!r}; ignored")
            settings["max_allowed"] = normalized

        self._normalize_exclusions()

        sca = self.data["sca"]
        sca["ecosystems"] = [
            _canonical_ecosystem(value) for value in (sca.get("ecosystems") or [])
        ]
        try:
            sca["max_file_size_kb"] = max(64, int(sca.get("max_file_size_kb", 4096)))
            sca["max_files"] = max(10, int(sca.get("max_files", 5000)))
            sca["timeout_seconds"] = max(5, int(sca.get("timeout_seconds", 20)))
            sca["retries"] = max(0, int(sca.get("retries", 3)))
        except (TypeError, ValueError):
            raise ConfigError("sca.max_file_size_kb/max_files must be integers")

        k8s = self.data["kubernetes"]
        standard = str(k8s.get("pod_security_standard", "restricted")).lower()
        if standard not in {"restricted", "baseline", "off"}:
            self.warn(
                "kubernetes.pod_security_standard must be restricted, baseline or off; "
                "using restricted"
            )
            standard = "restricted"
        k8s["pod_security_standard"] = standard
        if isinstance(k8s.get("exclude_namespaces"), str):
            k8s["exclude_namespaces"] = [
                item.strip()
                for item in k8s["exclude_namespaces"].split(",")
                if item.strip()
            ]
        elif not isinstance(k8s.get("exclude_namespaces"), list):
            k8s["exclude_namespaces"] = []

        license_cfg = self.data["license"]
        license_cfg["severity"] = normalize_severity(
            license_cfg.get("severity", "HIGH"), "HIGH"
        )
        if isinstance(license_cfg.get("deny"), str):
            license_cfg["deny"] = [
                item.strip() for item in license_cfg["deny"].split(",") if item.strip()
            ]
        if isinstance(license_cfg.get("exceptions"), list):
            normalized_exceptions = []
            for entry in license_cfg["exceptions"]:
                if isinstance(entry, str):
                    normalized_exceptions.append({"package": entry})
                elif isinstance(entry, dict):
                    normalized_exceptions.append(entry)
            license_cfg["exceptions"] = normalized_exceptions

        notifications = self.data["notifications"]
        try:
            notifications["max_findings_in_comment"] = max(
                5, int(notifications.get("max_findings_in_comment", 25))
            )
        except (TypeError, ValueError):
            notifications["max_findings_in_comment"] = 25

        enrichment = self.data["enrichment"]
        try:
            enrichment["cache_ttl_hours"] = max(
                0.0, float(enrichment.get("cache_ttl_hours", 24))
            )
            enrichment["timeout_seconds"] = max(
                5, int(enrichment.get("timeout_seconds", 20))
            )
        except (TypeError, ValueError):
            self.warn("Invalid enrichment timeout/cache values; using defaults")
            enrichment["cache_ttl_hours"] = 24
            enrichment["timeout_seconds"] = 20

        baseline = settings.get("baseline")
        if baseline is not None and not isinstance(baseline, str):
            self.warn("settings.baseline must be a path or null; ignored")
            settings["baseline"] = None

    def _normalize_exclusions(self) -> None:
        exclusions = self.data["settings"]["exclusions"]
        if not isinstance(exclusions, dict):
            exclusions = {}
            self.data["settings"]["exclusions"] = exclusions
        for key in ("directories", "paths"):
            values = exclusions.get(key, []) or []
            if isinstance(values, str):
                values = [values]
            exclusions[key] = [
                normalize_path(str(item)).rstrip("/")
                for item in values
                if str(item).strip()
            ]
        exclusions["vulnerabilities"] = _normalize_id_entries(
            exclusions.get("vulnerabilities"), self.warn
        )
        exclusions["rules"] = _normalize_id_entries(exclusions.get("rules"), self.warn)
        packages = exclusions.get("packages", []) or []
        if isinstance(packages, (str, dict)):
            packages = [packages]
        normalized_packages = []
        for entry in packages:
            if isinstance(entry, str):
                normalized_packages.append({"name": entry})
            elif isinstance(entry, dict) and entry.get("name"):
                normalized_packages.append(
                    {
                        "name": str(entry["name"]),
                        "ecosystem": entry.get("ecosystem"),
                        "version": entry.get("version"),
                        "reason": entry.get("reason", "configured"),
                        "expires": entry.get("expires"),
                    }
                )
            else:
                self.warn(f"Invalid package exclusion ignored: {entry!r}")
        exclusions["packages"] = normalized_packages
        ignore_packages = self.data["sca"].get("ignore_packages", []) or []
        if isinstance(ignore_packages, str):
            ignore_packages = [ignore_packages]
        self.data["sca"]["ignore_packages"] = [str(item) for item in ignore_packages]

    def _validate(self) -> None:
        targets = self.data["settings"].get("scan_targets")
        if not isinstance(targets, dict):
            raise ConfigError("settings.scan_targets must be an object")
        for key, value in list(targets.items()):
            if not isinstance(value, bool):
                self.warn(f"scan_targets.{key} must be true or false; using true")
                targets[key] = True
        if not self.data["sca"].get("osv_api"):
            self.warn("sca.osv_api is empty; OSV queries will be skipped")
        if self.data["sca"].get("max_files", 0) > 20000:
            self.warn("sca.max_files is very high; scans may be slow")
        if self.get("kubernetes.enabled") and self.data["kubernetes"].get(
            "pod_security_standard"
        ) == "off":
            self.warn("Kubernetes Pod Security Standards checks are disabled")

    def warn(self, message: str) -> None:
        if message not in self.warnings:
            self.warnings.append(message)

    def summary(self) -> dict[str, Any]:
        return {
            "path": str(self.path) if self.path else None,
            "version": self.get("version"),
            "fail_on_severity": self.fail_on,
            "minimum_severity": self.minimum_severity,
            "offline": self.offline,
            "pod_security_standard": self.get(
                "kubernetes.pod_security_standard", "restricted"
            ),
            "scan_targets": self.get("settings.scan_targets", {}),
            "warnings": self.warnings,
        }


def _canonical_ecosystem(value: Any) -> str:
    text = str(value).strip().lower()
    mapping = {
        "npm": "npm",
        "pypi": "PyPI",
        "pip": "PyPI",
        "go": "Go",
        "golang": "Go",
        "crates.io": "crates.io",
        "cargo": "crates.io",
        "crates": "crates.io",
        "maven": "Maven",
        "java": "Maven",
        "packagist": "Packagist",
        "composer": "Packagist",
        "rubygems": "RubyGems",
        "gem": "RubyGems",
        "nuget": "NuGet",
        "pub": "Pub",
        "dart": "Pub",
        "hex": "Hex",
        "elixir": "Hex",
    }
    return mapping.get(text, str(value))


def _normalize_id_entries(
    values: Any, warn: Any
) -> list[dict[str, Any]]:
    if values is None:
        return []
    if isinstance(values, (str, dict)):
        values = [values]
    if not isinstance(values, list):
        warn(f"Invalid exclusion list ignored: {values!r}")
        return []
    out = []
    for entry in values:
        if isinstance(entry, str):
            out.append({"id": entry.strip(), "reason": "configured"})
        elif isinstance(entry, dict) and entry.get("id"):
            out.append(
                {
                    "id": str(entry["id"]).strip(),
                    "reason": entry.get("reason", "configured"),
                    "expires": entry.get("expires"),
                }
            )
        else:
            warn(f"Invalid exclusion entry ignored: {entry!r}")
    return out


def _entry_active(entry: dict[str, Any], warnings: list[str]) -> bool:
    if entry.get("expires") and is_expired(entry["expires"]):
        message = (
            f"Exclusion for {entry.get('id') or entry.get('name')} expired on "
            f"{entry['expires']}; it no longer applies"
        )
        if message not in warnings:
            warnings.append(message)
        return False
    return True


def _rule_matches(finding: Finding, entry: dict[str, Any]) -> bool:
    target = str(entry.get("id", "")).upper()
    if not target:
        return False
    if any(ch in target for ch in "*?["):
        return any(
            fnmatch.fnmatchcase(value.upper(), target)
            for value in finding.all_identifiers()
        )
    return target in {value.upper() for value in finding.all_identifiers()}


def _vulnerability_matches(finding: Finding, entry: dict[str, Any]) -> bool:
    target = str(entry.get("id", "")).upper()
    if not target:
        return False
    if any(ch in target for ch in "*?["):
        return any(
            fnmatch.fnmatchcase(value.upper(), target)
            for value in finding.all_identifiers()
        )
    return target in {value.upper() for value in finding.all_identifiers()}


def _package_matches(finding: Finding, entry: dict[str, Any]) -> bool:
    if not finding.package:
        return False
    name = str(entry.get("name", "")).lower()
    if not name:
        return False
    if not fnmatch.fnmatchcase(finding.package.lower(), name):
        return False
    ecosystem = entry.get("ecosystem")
    if ecosystem and (finding.ecosystem or "").lower() != str(ecosystem).lower():
        return False
    version = entry.get("version")
    if version and finding.version != str(version):
        return False
    return True


def _match_path(path: str, pattern: str) -> bool:
    path = normalize_path(path).lower()
    pattern = normalize_path(pattern).lower().rstrip("/")
    if not pattern:
        return False
    pattern = pattern.removeprefix("./")

    # "tests/**" should match the directory itself and everything below it.
    if pattern.endswith("/**"):
        base = pattern[:-3].rstrip("/")
        return path == base or path.startswith(base + "/")
    if pattern.startswith("**/") and pattern.endswith("/**"):
        middle = pattern[3:-3].strip("/")
        return f"/{middle}/" in f"/{path}/" or middle in path.split("/")

    if fnmatch.fnmatchcase(path, pattern):
        return True
    # A bare directory name should match any path segment below it.
    if "/" not in pattern and not any(ch in pattern for ch in "*?["):
        return pattern in path.split("/")
    # Match any ancestor directory (e.g. "charts/*" excludes charts/foo/templates/x).
    parts = path.split("/")
    for index in range(1, len(parts)):
        ancestor = "/".join(parts[:index])
        if fnmatch.fnmatchcase(ancestor, pattern):
            return True
    return False


def iter_exclusion_warnings(config: Config) -> Iterable[str]:
    return config.warnings
