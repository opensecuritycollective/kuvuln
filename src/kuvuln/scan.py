"""Scan orchestration: SCA, Kubernetes analysis, enrichment, policy and reports."""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import __version__
from .baseline import apply_baseline, load_baseline
from .cache import Cache
from .config import Config
from .correlate import correlate_findings
from .enrich import EpssClient, KevClient, LifecycleClient, enrich_findings
from .gochecks import analyze_go, check_kubernetes_component_images
from .govulncheck import ingest_govulncheck_file, is_govulncheck_file
from .helm import analyze_helm_charts
from .http import HttpClient
from .images import collect_images
from .kubernetes import analyze_resources, discover_resources
from .kustomize import analyze_kustomize
from .licenses import license_findings
from .models import Dependency, Finding, severity_at_least
from .osv import OsvClient, findings_from_osv
from .parsers import collect_dependencies
from .policy import apply_suppressions, evaluate_policy
from .reports import (
    render_html,
    render_json,
    render_markdown,
    render_step_summary,
)
from .risk import enrich_risk
from .sbom import build_sbom
from .utils import atomic_write_text, git_metadata, write_json

LOGGER = logging.getLogger("kuvuln.scan")


@dataclass
class ScanOptions:
    root: Path
    config: Config
    inputs: list[Path] = field(default_factory=list)
    output_dir: Path = Path("kuvuln-out")
    formats: list[str] = field(
        default_factory=lambda: ["json", "markdown", "html", "sarif", "sbom"]
    )
    fail_on: str | None = None
    offline: bool = False
    baseline_path: Path | None = None
    pr_comment: bool = False
    pr_number: int | None = None
    step_summary: bool = False
    quiet: bool = False


@dataclass
class ScanOutcome:
    findings: list[Finding]
    dependencies: list[Dependency]
    policy: Any
    warnings: list[str]
    tools: list[dict[str, Any]]
    metadata: dict[str, Any]
    outputs: list[str]
    suppressed: list[dict[str, Any]]
    exit_code: int

    @property
    def passed(self) -> bool:
        return self.policy.passed


def run_scan(options: ScanOptions) -> ScanOutcome:
    config = options.config
    root = options.root.resolve()
    warnings: list[str] = []
    tools: list[dict[str, Any]] = []
    metadata = git_metadata(root)
    metadata["kuvuln_version"] = __version__
    offline = bool(options.offline or config.offline)
    cache = Cache()
    http = HttpClient(
        timeout=float(config.get("enrichment.timeout_seconds", 20)),
        retries=int(config.get("sca.retries", 3)),
        offline=offline,
    )

    # --- SCA ---------------------------------------------------------------
    dependencies: list[Dependency] = []
    sca_enabled = bool(config.get("sca.enabled", True)) and config.category_enabled("sca")
    if sca_enabled:
        input_paths = [path.resolve() for path in options.inputs if path.exists()]
        dependencies, parse_warnings = collect_dependencies([root, *input_paths], config)
        warnings.extend(parse_warnings)
    else:
        dependencies = []

    sca_findings: list[Finding] = []
    if dependencies:
        osv_client = OsvClient(
            str(config.get("sca.osv_api", "https://api.osv.dev")),
            http,
            cache,
            timeout=float(config.get("sca.timeout_seconds", 20)),
            retries=int(config.get("sca.retries", 3)),
        )
        try:
            queries = osv_client.query_dependencies(dependencies)
            sca_findings.extend(findings_from_osv(queries))
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"OSV analysis failed: {exc}")
        tools.append(
            {
                "name": "osv",
                "version": None,
                "results": len(sca_findings),
                "dependencies": len(dependencies),
            }
        )
    elif sca_enabled:
        warnings.append("No dependency files found for SCA")

    # --- Native Kubernetes / Helm / Kustomize / Go -------------------------
    lifecycle_client = LifecycleClient(
        http,
        cache,
        products=config.get("lifecycle.products", ["kubernetes", "go"]),
    )
    native_findings: list[Finding] = []
    resources = []
    if config.category_enabled("kubernetes"):
        input_paths = [path.resolve() for path in options.inputs if path.exists()]
        resources, resource_warnings = discover_resources([root, *input_paths], config)
        warnings.extend(resource_warnings)
        if config.get("kubernetes.enabled", True):
            native_findings.extend(analyze_resources(resources, config))
        native_findings.extend(analyze_helm_charts([root, *input_paths], config))
        native_findings.extend(analyze_kustomize([root, *input_paths], config))
        native_findings.extend(
            analyze_go([root, *input_paths], config, lifecycle_client, warnings)
        )
        native_findings.extend(
            check_kubernetes_component_images(resources, lifecycle_client)
        )

    license_findings_list = license_findings(dependencies, config)

    # --- External scanners -------------------------------------------------
    all_inputs = [path for path in options.inputs if path.exists()]
    for input_path in all_inputs:
        from .sarif import ingest_sarif, sarif_files

        for sarif_path in sarif_files([input_path]):
            report = ingest_sarif(sarif_path, root=root)
            native_findings.extend(report.findings)
            tools.extend(report.tools)
            warnings.extend(report.warnings)
        for candidate in sorted(input_path.rglob("*.json")) if input_path.is_dir() else []:
            if is_govulncheck_file(candidate.name):
                findings, tool_meta = ingest_govulncheck_file(
                    candidate, str(candidate.relative_to(input_path))
                )
                native_findings.extend(findings)
                tools.append(tool_meta)
                if tool_meta.get("warning"):
                    warnings.append(tool_meta["warning"])

    # --- License findings --------------------------------------------------
    native_findings.extend(license_findings_list)

    # --- Correlation / deduplication --------------------------------------
    correlated = correlate_findings(sca_findings + native_findings)
    warnings.extend(_correlation_notes(correlated))

    # --- Enrichment --------------------------------------------------------
    epss_client = EpssClient(
        http, cache, ttl_hours=float(config.get("enrichment.cache_ttl_hours", 24))
    )
    kev_client = KevClient(
        http, cache, ttl_hours=12
    )
    enriched_cves = enrich_findings(correlated, config, epss_client, kev_client)
    if enriched_cves:
        LOGGER.debug("Enriched %s CVE identifiers", enriched_cves)
    enrich_risk(correlated)

    # --- Suppression: baseline then configuration --------------------------
    baseline_path = options.baseline_path or (
        config.resolve_path(config.get("settings.baseline"))
        if config.get("settings.baseline")
        else None
    )
    baseline = load_baseline(baseline_path) if baseline_path else None
    if baseline_path and baseline is None:
        warnings.append(f"Baseline file not found or invalid: {baseline_path}")
    kept, baseline_suppressed = apply_baseline(correlated, baseline, warnings)
    final, config_suppressed = apply_suppressions(kept, config)
    suppressed = baseline_suppressed + config_suppressed

    # --- Policy ------------------------------------------------------------
    config.data["settings"]["fail_on_severity"] = options.fail_on or config.data[
        "settings"
    ].get("fail_on_severity", "HIGH")
    policy = evaluate_policy(final, len(suppressed), config)

    compliance = _compliance_counts(final)
    tools.append(
        {
            "name": "kuvuln",
            "version": __version__,
            "results": len(final),
            "dependencies": len(dependencies),
        }
    )
    tools.append(
        {
            "name": "images",
            "results": len(collect_images([root, *all_inputs], resources, config)),
        }
    )

    outputs = _write_outputs(
        options.output_dir,
        options.formats,
        _report_findings(final, config),
        final,
        dependencies,
        policy,
        config,
        metadata,
        suppressed,
        tools,
        compliance,
    )

    exit_code = 0 if policy.passed else 1
    outcome = ScanOutcome(
        findings=final,
        dependencies=dependencies,
        policy=policy,
        warnings=warnings,
        tools=tools,
        metadata=metadata,
        outputs=outputs,
        suppressed=suppressed,
        exit_code=exit_code,
    )

    if options.pr_comment:
        from .github import GitHubClient

        try:
            client = GitHubClient(offline=offline)
            body = render_markdown(
                _report_findings(final, config),
                final,
                policy,
                config,
                metadata,
                dependencies,
                suppressed,
                compliance,
            )
            if options.pr_number:
                client.upsert_pr_comment(options.pr_number, body)
        except Exception as exc:  # noqa: BLE001 - reporting must not break the scan
            warnings.append(f"Could not post PR comment: {exc}")

    if options.step_summary:
        summary = render_step_summary(
            _report_findings(final, config),
            final,
            policy,
            config,
            metadata,
            dependencies,
        )
        from .github import write_step_summary

        write_step_summary(summary)

    return outcome


def _report_findings(findings: list[Finding], config: Config) -> list[Finding]:
    minimum = config.minimum_severity
    return [finding for finding in findings if severity_at_least(finding.severity, minimum)]


def _write_outputs(
    output_dir: Path,
    formats: list[str],
    findings: list[Finding],
    all_findings: list[Finding],
    dependencies: list[Dependency],
    policy: Any,
    config: Config,
    metadata: dict[str, Any],
    suppressed: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    compliance: dict[str, int],
) -> list[str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    outputs: list[str] = []
    requested = {item.lower() for item in formats}
    if "all" in requested:
        requested = {"json", "markdown", "html", "sarif", "sbom"}

    if "json" in requested or "all" in requested:
        path = output_dir / "kuvuln-report.json"
        write_json(
            path,
            render_json(
                findings, all_findings, policy, config, metadata, dependencies, suppressed, tools
            ),
        )
        outputs.append(str(path))
    if "markdown" in requested or "all" in requested:
        path = output_dir / "kuvuln-report.md"
        atomic_write_text(
            path,
            render_markdown(
                findings, all_findings, policy, config, metadata, dependencies, suppressed, compliance
            ),
        )
        outputs.append(str(path))
    if "html" in requested or "all" in requested:
        path = output_dir / "kuvuln-report.html"
        atomic_write_text(
            path,
            render_html(findings, all_findings, policy, config, metadata, dependencies, suppressed),
        )
        outputs.append(str(path))
    if "sarif" in requested or "all" in requested:
        from .sarif import build_sarif

        path = output_dir / "kuvuln.sarif"
        write_json(path, build_sarif(all_findings, metadata), pretty=False)
        outputs.append(str(path))
    if "sbom" in requested or "all" in requested:
        path = output_dir / "kuvuln-sbom.cdx.json"
        write_json(path, build_sbom(dependencies, metadata), pretty=True)
        outputs.append(str(path))
    return outputs


def _compliance_counts(findings: Iterable[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        standards = finding.properties.get("compliance") or []
        if isinstance(standards, str):
            standards = [standards]
        for standard in standards:
            if standard:
                counts[str(standard)] = counts.get(str(standard), 0) + 1
    return counts


def _correlation_notes(findings: list[Finding]) -> list[str]:
    notes: list[str] = []
    multi = [
        finding
        for finding in findings
        if len(finding.properties.get("reported_by", [])) > 1
    ]
    if multi:
        notes.append(
            f"Correlated {len(multi)} finding(s) reported by multiple scanners"
        )
    return notes
