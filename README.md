# KuVuln 🛡️

**Kubernetes-native security analysis for manifests, Helm charts, Kustomize
overlays, Go modules, container images and supply chain.**

KuVuln is a GitHub Actions bot that runs on every push, pull request and weekly
schedule. It orchestrates best-of-breed scanners (Trivy, KubeLinter, Kubescape,
Semgrep, Checkov, Gitleaks, gosec, govulncheck), correlates their results into a
single deduplicated report, enriches advisories with CVSS/EPSS/CISA KEV data,
and enforces a policy-as-code gate.

> Built for Kubernetes and its sub-products: operators, controllers, CRDs,
> admission webhooks, service meshes, GitOps pipelines and Go-based components
> like [kubernetes/kubernetes](https://github.com/kubernetes/kubernetes).

---

## 🚀 Quick start

1. Copy `.github/workflows/kuvuln.yml` into your repository.
2. Copy `kuvuln-config.json` to your repository root (and edit thresholds).
3. Commit. KuVuln runs on the next push, pull request and weekly schedule.

Or use the composite action:

Detailed configuration lives in [`docs/configuration.md`](docs/configuration.md).

---

## 🧩 What it scans

| Layer | Coverage | Engines |
|---|---|---|
| ☸️ Kubernetes manifests | PSS baseline/restricted, privileged containers, host namespaces, hostPath, seccomp, capabilities, resource limits, image pinning, plaintext Secrets, removed APIs, admission webhooks, Ingress TLS, Kubelet/control-plane flags | KuVuln native + Trivy, KubeLinter, Kubescape, Checkov |
| 🔑 RBAC | Wildcard permissions, secret access, pod creation/exec, impersonation/bind/escalate, cluster-admin bindings, anonymous subjects, webhook management | KuVuln native + Checkov/KubeLinter |
| 🌐 Network policies | Namespaces without policies, missing default-deny ingress/egress | KuVuln native |
| 🎩 Helm | `apiVersion: v1`, mutable dependencies, HTTP repositories, literal secrets in `values*.yaml` | KuVuln native |
| 🧩 Kustomize | Unpinned remote resources, `secretGenerator`, mutable `helmCharts`, `latest` image tags | KuVuln native |
| 🐹 Go SCA | `go.mod`, `go list -m`, `vendor/modules.txt`, `replace` directives, reachable vulnerabilities with call paths | KuVuln OSV + govulncheck + Trivy |
| 📦 SCA (multi-ecosystem) | npm, PyPI, Go, crates.io, Maven, Packagist, RubyGems, NuGet, Pub, Hex | KuVuln OSV + Trivy |
| 🐳 Containers | Base images from Dockerfiles and workload images, OS/package CVEs | Trivy |
| 🔬 SAST | Go, Kubernetes, Dockerfiles, application code, GitHub Actions | gosec, Semgrep (custom + registry packs), zizmor |
| 🕵️ Secrets | Full git history, redacted output | Gitleaks |
| 📜 Licenses | Deny-list with package exceptions | KuVuln + Trivy |
| ♻️ Lifecycle | End-of-life Kubernetes components and Go toolchains | endoflife.date + static fallback |

---

## 🧠 How it works

```
┌──────────────────────────────────────────────────────────────┐
│ 1. Collect       go.mod / go list -m / vendor / lockfiles    │
│ 2. Analyze       Kubernetes, Helm, Kustomize, RBAC, network  │
│ 3. Scan          Trivy · KubeLinter · Kubescape · Checkov    │
│                  Semgrep · gosec · govulncheck · Gitleaks     │
│ 4. Correlate     dedupe across engines, keep reachability    │
│ 5. Enrich        CVSS · EPSS · CISA KEV · EOL lifecycle      │
│ 6. Score         risk score + KuVuln score + compliance      │
│ 7. Gate          severity, KEV, EPSS, budgets, licenses     │
│ 8. Report        SARIF · Markdown · HTML · JSON · SBOM       │
└──────────────────────────────────────────────────────────────┘
```

### Go is a first-class citizen

KuVuln understands the Go module graph:

- `go.mod` requirements (direct + indirect) and `replace` directives,
- `go list -m -json all` output (complete build list),
- `vendor/modules.txt`,
- **govulncheck** JSON streams, preserving the call-graph trace so a finding
  is marked **reachable** when the vulnerable symbol is actually invoked.

Reachable findings score higher and are surfaced with the calling package and
function, which removes most of the noise from transitive Go advisories.

### Correlation

The same misconfiguration is often reported by Trivy, KubeLinter, Kubescape,
Checkov, Semgrep and the native analyzer. KuVuln merges findings that share a
location and describe the same problem, keeps the highest severity, and records
every scanner that agreed in `reported_by`. SCA advisories are merged across
aliases (GHSA/CVE/GO) so one vulnerability appears once per package/version.

---

## 📊 Risk and policy

- **CVSS** base score is computed locally from CVSS v2/v3 vectors.
- **EPSS** and **CISA KEV** are fetched from first.org and CISA and cached.
- **Risk score** = severity/CVSS + EPSS + KEV + reachability + missing fix,
  capped at 100. KEV findings are always at least 90.
- **KuVuln score** = 100 minus weighted severity penalties.

Policy gate options:

| Setting | Default | Meaning |
|---|---|---|
| `settings.fail_on_severity` | `HIGH` | Fail when a finding is at least this severity |
| `settings.fail_on_kev` | `true` | Fail on any CISA KEV finding |
| `settings.fail_on_epss` | `0` | Fail when EPSS is at least this value (`0` disables) |
| `settings.max_allowed` | `{}` | Per-severity budget, e.g. `{"MEDIUM": 5}` |
| `settings.ignore_unfixed` | `false` | Suppress SCA findings without a fix |
| `license.deny` | copyleft list | Fail on denied licenses |
| `settings.baseline` | `null` | Suppress accepted findings until an expiry date |

### Baselines

Existing debt can be accepted explicitly and expires automatically:

```bash
python -m kuvuln baseline create \
  --report kuvuln-out/kuvuln-report.json \
  --output .kuvuln-baseline.json \
  --expires-days 90
```

Commit `.kuvuln-baseline.json` and KuVuln will suppress exactly those findings
(and warn when an entry expires).

---

## 📦 Outputs

| File | Purpose |
|---|---|
| `kuvuln-out/kuvuln.sarif` | Unified SARIF for the GitHub **Security** tab |
| `kuvuln-out/kuvuln-report.md` | Sticky pull request comment + step summary |
| `kuvuln-out/kuvuln-report.html` | Self-contained dashboard with filters |
| `kuvuln-out/kuvuln-report.json` | Machine-readable findings, policy and metadata |
| `kuvuln-out/kuvuln-sbom.cdx.json` | CycloneDX 1.5 SBOM with purls and licenses |
| `kuvuln-results/**` | Raw scanner reports (artifact) |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Policy passed |
| `1` | Policy gate failed (findings violate thresholds) |
| `2` | Scan error (bad config, unreadable input, internal failure) |

---

## 🧑💻 Local usage

```bash
pip install .

# Full offline scan of a repository
kuvuln scan --root . --config kuvuln-config.json --output kuvuln-out

# Scan scanner results produced by other tools
kuvuln scan --root . --input results/ --output kuvuln-out --format all

# List container images referenced by manifests and Dockerfiles
kuvuln images --root . --format lines

# Discover Go modules, Kustomize dirs and Dockerfiles
kuvuln gomodules --root .
kuvuln kustomize --root .
kuvuln dockerfiles --root .
```

`--offline` never opens a network connection: OSV/EPSS/KEV/lifecycle lookups
fall back to the local cache or static data, which makes the engine usable in
air-gapped environments.

---

## 🔐 Security of the bot itself

- GitHub Actions are pinned to **full commit SHAs**.
- Binary downloads are **SHA-256 verified**.
- Go tools are installed through the module proxy (checksum-db verified).
- Least-privilege permissions, no `pull_request_target`, `persist-credentials: false`.
- Secret findings are **redacted** before they can reach a PR comment, step
  summary, HTML report or JSON artifact.
- Config parsing never uses `eval`; malformed manifests produce warnings, not
  crashes.

See [`SECURITY.md`](SECURITY.md) for reporting vulnerabilities in KuVuln.

---

## ☸️ Scanning `kubernetes/kubernetes`\n\nKuVuln ships a dedicated workflow (`.github/workflows/kuvuln-kubernetes.yml`) that\nchecks out `kubernetes/kubernetes` and runs the complete engine against it:\n\n```bash\n# Trigger manually from the Actions tab, or wait for the weekly schedule\ngh workflow run kuvuln-kubernetes.yml \\\n  --ref main \\\n  -f ref=master \\\n  -f fail_on=HIGH \\\n  -f skip_container=true\n```\n\nThe reusable workflow (`.github/workflows/kuvuln.yml`) accepts a `repository`\ninput, so any organisation can scan its own Kubernetes components repository\nwith the same engine:\n\n```yaml\njobs:\n  scan:\n    uses: bleon-ethical/kuvuln/.github/workflows/kuvuln.yml@main\n    with:\n      repository: my-org/my-kubernetes-fork\n      ref: main\n      fail_on: HIGH\n      skip_container: true\n    secrets: inherit\n```\n\n---\n\n## 📚 Documentation

- [Configuration reference](docs/configuration.md)
- [Native rule catalog](docs/rules.md)

## 🤝 Contributing

1. Fork the repository.
2. Create a feature branch.
3. Run `python -m unittest discover -s tests -v` and
   `semgrep --config .kuvuln/rules --validate`.
4. Submit a pull request.

## 📜 License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
