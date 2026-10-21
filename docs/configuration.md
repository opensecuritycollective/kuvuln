# Configuration reference

KuVuln is configured with `kuvuln-config.json` at the repository root. The file
is validated against [`kuvuln-config.schema.json`](../kuvuln-config.schema.json),
which editors can use for autocompletion.

```jsonc
{
  "$schema": "./kuvuln-config.schema.json",
  "version": "3.0.0",
  "settings": { "fail_on_severity": "HIGH" }
}
```

Unknown keys are preserved and ignored, so older and newer KuVuln versions can
share a config file.

---

## Top-level sections

| Section | Purpose |
|---|---|
| `settings` | Policy thresholds, scan targets, exclusions, baseline |
| `sca` | Dependency discovery and OSV query options |
| `kubernetes` | Native manifest, RBAC, network, Helm and Kustomize checks |
| `go` | Go toolchain and `replace` directive checks |
| `enrichment` | EPSS, CISA KEV and lifecycle lookups |
| `lifecycle` | End-of-life product configuration |
| `license` | License deny-list and exceptions |
| `notifications` | PR comments and summaries |
| `compliance_standards` | Labels shown in reports |
| `advanced` | Backwards-compatible legacy switches |

---

## Policy settings

### `settings.fail_on_severity`

`CRITICAL`, `HIGH`, `MEDIUM`, `LOW` or `NONE` (disables the severity gate).
Default: `HIGH`.

### `settings.fail_on_kev`

Fail when any finding is in the CISA Known Exploited Vulnerabilities catalog.
Default: `true`.

### `settings.fail_on_epss`

Fail when a finding's EPSS probability is greater than or equal to this value.
`0` disables the gate. Default: `0`.

### `settings.max_allowed`

Per-severity budget. Example:

```json
"max_allowed": { "CRITICAL": 0, "HIGH": 0, "MEDIUM": 5 }
```

### `settings.ignore_unfixed`

Suppress SCA findings that have no published fix. Default: `false`.

### `settings.baseline`

Path to a baseline file (relative to the config file) created with
`kuvuln baseline create`. Default: `null`.

---

## Scan targets

Every layer can be turned off independently:

```json
"scan_targets": {
  "kubernetes": true,
  "rbac": true,
  "network_policy": true,
  "helm": true,
  "kustomize": true,
  "go": true,
  "dependencies": true,
  "container": true,
  "docker": true,
  "secrets": true,
  "sast": true,
  "licenses": true,
  "lifecycle": true,
  "ci": true
}
```

Legacy `kubernetes`, `docker`, `dependencies`, `secrets` and `sast` switches are
still honoured.

---

## Exclusions

Exclusions are matched after analysis, so they do not hide findings from the
raw scanner artifacts.

```jsonc
"exclusions": {
  "directories": ["tests/**", "vendor/**", "third_party/**"],
  "paths": ["deploy/legacy.yaml"],
  "vulnerabilities": [
    "CVE-2024-0001",
    { "id": "GHSA-xxxx-yyyy-zzzz", "reason": "accepted", "expires": "2026-12-31" }
  ],
  "rules": [
    "KUV-K8S-011",
    { "id": "KSV001", "reason": "false positive", "expires": "2026-12-31" }
  ],
  "packages": [
    "lodash",
    { "name": "internal-legacy", "ecosystem": "npm", "reason": "deprecated" }
  ]
}
```

- `directories`/`paths` use glob patterns; `tests/**` matches everything below
  `tests/`.
- `vulnerabilities` match any advisory identifier or alias.
- `rules` match rule ids and support `*`/`?` wildcards.
- `packages` support `name`, `ecosystem`, `version` and `expires`.
- Entries with `expires` stop applying after the date and produce a warning.

---

## SCA

```jsonc
"sca": {
  "enabled": true,
  "ecosystems": ["Go", "npm", "PyPI", "crates.io", "Maven"],
  "include_dev": true,
  "include_indirect": true,
  "max_file_size_kb": 8192,
  "max_files": 5000,
  "osv_api": "https://api.osv.dev",
  "timeout_seconds": 20,
  "retries": 3,
  "ignore_packages": [],
  "go": {
    "use_go_list": true,
    "include_vendor": true,
    "check_replace_directives": true
  }
}
```

Supported dependency files:

| Ecosystem | Files |
|---|---|
| Go | `go.mod`, `go list -m` JSON streams, `vendor/modules.txt` |
| npm | `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `package.json` (exact pins) |
| PyPI | `requirements*.txt`, `constraints*.txt`, `poetry.lock`, `pdm.lock`, `uv.lock`, `Pipfile.lock`, `pyproject.toml` (exact pins) |
| Rust | `Cargo.lock` |
| Maven | `pom.xml`, `gradle.lockfile` |
| PHP | `composer.lock` |
| Ruby | `Gemfile.lock` |
| .NET | `packages.lock.json` |
| Dart | `pubspec.lock` |
| Elixir | `mix.lock` |

---

## Kubernetes

```jsonc
"kubernetes": {
  "pod_security_standard": "restricted",
  "exclude_namespaces": ["kube-system", "kube-public", "kube-node-lease"],
  "require_resource_limits": true,
  "require_network_policy": true,
  "require_image_digest": false,
  "trusted_registries": [],
  "check_rbac": true,
  "check_plaintext_secrets": true,
  "check_admission_webhooks": true,
  "check_removed_apis": true,
  "check_control_plane_flags": true,
  "check_kubelet_config": true
}
```

- `pod_security_standard`: `restricted` (default), `baseline` or `off`.
- `trusted_registries`: when non-empty, images from other registries are
  flagged. Example: `["registry.k8s.io", "ghcr.io"]`.
- `exclude_namespaces` is applied to workloads, RBAC and NetworkPolicy checks.
  Cluster-scoped objects are still checked unless their namespace is excluded.

---

## Licenses

```jsonc
"license": {
  "enabled": true,
  "deny": ["AGPL-3.0-only", "AGPL-3.0-or-later", "SSPL-1.0", "BUSL-1.1"],
  "exceptions": [
    { "package": "some-package", "ecosystem": "npm", "expires": "2027-01-01" }
  ],
  "severity": "HIGH"
}
```

Licenses are read from lockfiles that declare them (npm, Composer) and from
Trivy license scans.

---

## Enrichment and lifecycle

```jsonc
"enrichment": {
  "epss": true,
  "kev": true,
  "lifecycle": true,
  "offline": false,
  "cache_ttl_hours": 24,
  "timeout_seconds": 20
}
```

With `--offline` or `"offline": true`, KuVuln uses only cached advisories and
the static fallback lifecycle tables.

---

## Notifications

```jsonc
"notifications": {
  "github_pr_comments": true,
  "security_tab_integration": true,
  "summary_level": "verbose",
  "max_findings_in_comment": 25
}
```

The PR comment is sticky: KuVuln finds its own previous comment and updates it,
so a PR keeps one report instead of a growing thread.
