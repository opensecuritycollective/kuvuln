"""Command line interface for KuVuln."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

from . import __version__
from .baseline import create_baseline_from_report
from .config import Config, ConfigError
from .gochecks import find_go_mod_files
from .images import collect_images
from .kubernetes import discover_resources
from .kustomize import find_kustomization_dirs
from .scan import ScanOptions, run_scan

LOGGER = logging.getLogger("kuvuln")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kuvuln",
        description="KuVuln: Kubernetes-native security analysis.",
    )
    parser.add_argument("--version", action="version", version=f"KuVuln {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Run a full security analysis")
    scan.add_argument("--root", default=".", help="Repository root (default: .)")
    scan.add_argument(
        "--config",
        default="kuvuln-config.json",
        help="Configuration file (default: kuvuln-config.json)",
    )
    scan.add_argument(
        "--input",
        action="append",
        default=[],
        help="Directory or file with SARIF/govulncheck results (repeatable)",
    )
    scan.add_argument("--output", default="kuvuln-out", help="Output directory")
    scan.add_argument(
        "--format",
        default="all",
        help="Comma-separated output formats: json,markdown,html,sarif,sbom,all",
    )
    scan.add_argument(
        "--fail-on",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"],
        default=None,
        help="Override settings.fail_on_severity",
    )
    scan.add_argument("--offline", action="store_true", help="Never use the network")
    scan.add_argument("--baseline", default=None, help="Baseline JSON file")
    scan.add_argument("--pr-comment", action="store_true", help="Post/update a PR comment")
    scan.add_argument("--pr-number", type=int, default=None, help="Pull request number")
    scan.add_argument("--step-summary", action="store_true", help="Write GITHUB_STEP_SUMMARY")
    scan.add_argument("--quiet", action="store_true", help="Only print the final summary")
    scan.add_argument("--verbose", "-v", action="store_true", help="Debug logging")

    baseline = subparsers.add_parser("baseline", help="Baseline management")
    baseline_sub = baseline.add_subparsers(dest="baseline_command", required=True)
    create = baseline_sub.add_parser("create", help="Create a baseline from a report")
    create.add_argument("--report", required=True, help="kuvuln-report.json")
    create.add_argument("--output", default=".kuvuln-baseline.json", help="Baseline output")
    create.add_argument("--expires-days", type=int, default=90)
    create.add_argument("--reason", default="accepted risk")

    images = subparsers.add_parser("images", help="List container images")
    images.add_argument("--root", default=".", help="Repository root")
    images.add_argument("--input", action="append", default=[], help="Extra roots")
    images.add_argument("--format", choices=["lines", "json"], default="lines")

    dockerfiles = subparsers.add_parser("dockerfiles", help="List Dockerfiles")
    dockerfiles.add_argument("--root", default=".")
    dockerfiles.add_argument("--format", choices=["lines", "json"], default="lines")

    gomodules = subparsers.add_parser("gomodules", help="List Go module files")
    gomodules.add_argument("--root", default=".")
    gomodules.add_argument("--format", choices=["lines", "json"], default="lines")

    kustomize = subparsers.add_parser("kustomize", help="List Kustomize directories")
    kustomize.add_argument("--root", default=".")
    kustomize.add_argument("--format", choices=["lines", "json"], default="lines")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if getattr(args, "verbose", False) else logging.INFO,
        format="%(levelname)s %(message)s",
        stream=sys.stderr,
    )

    try:
        if args.command == "scan":
            return _cmd_scan(args)
        if args.command == "baseline":
            return _cmd_baseline(args)
        if args.command == "images":
            return _cmd_images(args)
        if args.command == "dockerfiles":
            return _cmd_dockerfiles(args)
        if args.command == "gomodules":
            return _cmd_gomodules(args)
        if args.command == "kustomize":
            return _cmd_kustomize(args)
    except ConfigError as exc:
        LOGGER.error("Configuration error: %s", exc)
        return 2
    except KeyboardInterrupt:
        LOGGER.error("Interrupted")
        return 130
    except Exception as exc:  # noqa: BLE001 - CLI top-level guard
        LOGGER.error("Scan failed: %s", exc)
        return 2
    return 2


def _load_config(path: str, explicit: bool = False) -> Config:
    candidate = Path(path)
    if not candidate.exists():
        if explicit:
            raise ConfigError(f"Configuration file not found: {candidate}")
        LOGGER.warning(
            "Configuration file %s not found; using built-in defaults", candidate
        )
        return Config({})
    return Config.load(candidate)


def _cmd_scan(args: argparse.Namespace) -> int:
    config = _load_config(args.config, explicit=False)
    options = ScanOptions(
        root=Path(args.root),
        config=config,
        inputs=[Path(value) for value in args.input],
        output_dir=Path(args.output),
        formats=[item.strip() for item in args.format.split(",") if item.strip()],
        fail_on=args.fail_on,
        offline=args.offline,
        baseline_path=Path(args.baseline) if args.baseline else None,
        pr_comment=args.pr_comment,
        pr_number=args.pr_number or _env_pr_number(),
        step_summary=args.step_summary,
        quiet=args.quiet,
    )
    outcome = run_scan(options)
    if not args.quiet:
        for warning in outcome.warnings:
            LOGGER.warning("%s", warning)
    counts = outcome.policy.counts_by_severity
    LOGGER.info(
        "KuVuln: %s (total %s, critical %s, high %s, medium %s, low %s)",
        "PASSED" if outcome.passed else "POLICY GATE FAILED",
        outcome.policy.total,
        counts.get("CRITICAL", 0),
        counts.get("HIGH", 0),
        counts.get("MEDIUM", 0),
        counts.get("LOW", 0),
    )
    for output in outcome.outputs:
        LOGGER.info("Wrote %s", output)
    for reason in outcome.policy.reasons:
        LOGGER.info("Policy: %s", reason)
    return outcome.exit_code


def _cmd_baseline(args: argparse.Namespace) -> int:
    baseline = create_baseline_from_report(
        args.report, args.output, args.expires_days, args.reason
    )
    LOGGER.info(
        "Created baseline %s with %s entries (expires %s)",
        args.output,
        len(baseline["entries"]),
        baseline["expires"],
    )
    return 0


def _cmd_images(args: argparse.Namespace) -> int:

    roots = [Path(args.root), *[Path(value) for value in args.input]]
    config = _load_config("kuvuln-config.json")
    resources, _ = discover_resources(roots, config)
    references = collect_images(roots, resources, config)
    if args.format == "json":
        payload = [
            {
                "image": reference.image,
                "path": reference.path,
                "line": reference.line,
                "source": reference.source,
                "resource": reference.resource,
            }
            for reference in references
        ]
        print(json.dumps(payload, indent=2))
    else:
        for reference in references:
            print(reference.image)
    return 0


def _cmd_dockerfiles(args: argparse.Namespace) -> int:
    from .images import discover_dockerfiles, parse_dockerfile

    roots = [Path(args.root)]
    config = _load_config("kuvuln-config.json")
    rows = []
    for dockerfile in discover_dockerfiles(roots, config):
        for reference in parse_dockerfile(dockerfile, roots):
            rows.append(
                {
                    "image": reference.image,
                    "path": reference.path,
                    "line": reference.line,
                }
            )
    if args.format == "json":
        print(json.dumps(rows, indent=2))
    else:
        for row in rows:
            print(row["image"])
    return 0


def _cmd_gomodules(args: argparse.Namespace) -> int:
    config = _load_config("kuvuln-config.json")
    files = [str(path) for path in find_go_mod_files([Path(args.root)], config)]
    if args.format == "json":
        print(json.dumps(files, indent=2))
    else:
        for file in files:
            print(file)
    return 0


def _cmd_kustomize(args: argparse.Namespace) -> int:
    dirs = [str(path) for path in find_kustomization_dirs([Path(args.root)])]
    if args.format == "json":
        print(json.dumps(dirs, indent=2))
    else:
        for directory in dirs:
            print(directory)
    return 0


def _env_pr_number() -> int | None:
    value = os.getenv("PR_NUMBER")
    if value:
        try:
            return int(value)
        except ValueError:
            return None
    event_path = os.getenv("GITHUB_EVENT_PATH")
    if event_path and Path(event_path).exists():
        try:
            with open(event_path, "r", encoding="utf-8") as handle:
                event = json.load(handle)
            number = (
                (event.get("pull_request") or {}).get("number")
                or (event.get("issue") or {}).get("number")
            )
            if number:
                return int(number)
        except (OSError, json.JSONDecodeError, AttributeError):
            return None
    return None


if __name__ == "__main__":
    sys.exit(main())
