# Security Policy

## Supported versions

KuVuln is continuously released from the `main` branch. Security fixes are
backported to the latest tagged release for at least 12 months.

## Reporting a vulnerability

Please **do not** open a public issue for security vulnerabilities in KuVuln
itself.

- Report privately through the **Security** tab of this repository
  (`Report a vulnerability`).
- For a critical, remotely exploitable issue you can also contact the maintainers
  listed in `OWNERS`.
- Include a description, affected version/commit, reproduction steps and, if
  possible, a minimal proof of concept.

We aim to acknowledge reports within 5 business days and to provide a fix or
mitigation plan within 30 days.

## What counts as a vulnerability in KuVuln?

- Command injection or arbitrary code execution via manifest, Helm/Kustomize,
  SARIF, SBOM or configuration input.
- SSRF or credential exfiltration through the OSV, EPSS, KEV or lifecycle APIs.
- Leakage of secret material into reports, PR comments, artifacts or logs.
- Bypass of the policy gate that fails to report a finding it should block.

## Supply chain and reporting

- GitHub Actions are pinned to full commit SHAs.
- Binary scanners (Trivy, Gitleaks, Helm, Kubescape) are checksum-verified.
- Go tools are installed through the Go module proxy with checksum-db
  verification.
- Reports never include captured secret values: secret findings are redacted
  before they reach the PR comment or step summary.
