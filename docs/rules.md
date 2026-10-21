# Native KuVuln rules

The native engine (`source: kuvuln`) evaluates Kubernetes objects, Helm charts,
Kustomize files, Go module metadata and container images without relying on an
external linter. Rules are grouped by category.

## Kubernetes workload hardening (`kubernetes`)

| Rule | Severity | Description |
|---|---|---|
| `KUV-K8S-001` | HIGH | Container runs `privileged: true` |
| `KUV-K8S-002` | HIGH / MEDIUM | Privilege escalation enabled or not explicitly disabled (restricted) |
| `KUV-K8S-003` | HIGH / MEDIUM | Container runs as root / `runAsNonRoot` not set (restricted) |
| `KUV-K8S-004` | HIGH | Container runs with UID 0 |
| `KUV-K8S-005` | HIGH | `hostNetwork` |
| `KUV-K8S-006` | HIGH | `hostPID` |
| `KUV-K8S-007` | HIGH | `hostIPC` |
| `KUV-K8S-008` | HIGH / CRITICAL | `hostPath` volume (critical for Docker socket and other sensitive paths) |
| `KUV-K8S-009` | HIGH | Dangerous capability added |
| `KUV-K8S-010` | MEDIUM / LOW | Capability added or `drop: [ALL]` missing (restricted) |
| `KUV-K8S-011` | HIGH / MEDIUM | seccomp disabled or not set (restricted) |
| `KUV-K8S-012` | LOW | Root filesystem not read-only (restricted) |
| `KUV-K8S-013` | MEDIUM | Container has no resource limits |
| `KUV-K8S-014` | MEDIUM | Image tag is `latest` or missing |
| `KUV-K8S-015` | LOW | Image not pinned by digest (when `require_image_digest` is enabled) |
| `KUV-K8S-016` | HIGH | Image registry not in `trusted_registries` |
| `KUV-K8S-017` | LOW | `automountServiceAccountToken: true` |
| `KUV-K8S-018` | MEDIUM | `shareProcessNamespace` |
| `KUV-K8S-019` | MEDIUM | Disallowed volume type (restricted) |
| `KUV-K8S-020` | HIGH | Unsafe sysctl |
| `KUV-K8S-021` | HIGH | `procMount: Unmasked` |
| `KUV-K8S-022` | HIGH | Windows `hostProcess` |
| `KUV-K8S-023` | HIGH | End-of-life Kubernetes component image |
| `KUV-K8S-024` | HIGH | Plaintext Secret data in Git |
| `KUV-K8S-025` | HIGH | Removed/deprecated API version |
| `KUV-K8S-026` | HIGH / CRITICAL | Insecure control-plane flags |
| `KUV-K8S-027` | HIGH / CRITICAL | Insecure Kubelet configuration |
| `KUV-K8S-028` | MEDIUM | Admission webhook `failurePolicy: Ignore` |
| `KUV-K8S-029` | MEDIUM | Ingress without TLS |

## RBAC (`rbac`)

| Rule | Severity | Description |
|---|---|---|
| `KUV-RBAC-001` | MEDIUM–CRITICAL | Wildcard, secret, pod-creation, impersonation, webhook or binding permissions |
| `KUV-RBAC-002` | HIGH | Binding a privileged role to non-system subjects |
| `KUV-RBAC-003` | CRITICAL | Binding to `system:anonymous` / `system:unauthenticated` |

## Network policies (`network`)

| Rule | Severity | Description |
|---|---|---|
| `KUV-NET-001` | MEDIUM | Namespace with workloads but no NetworkPolicy |
| `KUV-NET-002` | LOW | No default-deny ingress policy |
| `KUV-NET-003` | LOW | No default-deny egress policy |

## Helm (`supply-chain`)

| Rule | Severity | Description |
|---|---|---|
| `KUV-HELM-001` | LOW | Helm chart uses `apiVersion: v1` |
| `KUV-HELM-002` | MEDIUM | Dependency without pinned/exact version |
| `KUV-HELM-003` | HIGH | Dependency repository over HTTP |
| `KUV-HELM-004` | HIGH | Literal secret-like value in `values*.yaml` |

## Kustomize (`supply-chain`)

| Rule | Severity | Description |
|---|---|---|
| `KUV-KUSTOMIZE-001` | MEDIUM / HIGH | Unpinned or mutable remote resource |
| `KUV-KUSTOMIZE-002` | MEDIUM | Mutable or missing `helmCharts` version |
| `KUV-KUSTOMIZE-003` | HIGH | Helm repository over HTTP |
| `KUV-KUSTOMIZE-004` | MEDIUM | `latest` image tag |
| `KUV-KUSTOMIZE-005` | HIGH | `secretGenerator` |
| `KUV-KUSTOMIZE-006` | HIGH | Secret-like literal in `configMapGenerator` |

## Go (`lifecycle`)

| Rule | Severity | Description |
|---|---|---|
| `KUV-GO-001` | MEDIUM | End-of-life Go toolchain |
| `KUV-GO-002` | LOW | `go` directive below `go.minimum_version` |
| `KUV-GO-003` | LOW | Third-party `replace` fork |

## External rules

Findings imported from Trivy, KubeLinter, Kubescape, Checkov, Semgrep, gosec,
Gitleaks, govulncheck, zizmor and OSV keep their original rule ids and are
merged with native findings when they describe the same issue.
