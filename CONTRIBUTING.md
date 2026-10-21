# Contributing to KuVuln 🛡️

First of all, thank you for considering contributing to **KuVuln**! It is
people like you that make KuVuln a great security tool for the Kubernetes
community.

We follow the **Apache License 2.0** and the **CNCF Code of Conduct**.

---

## 📜 Developer Certificate of Origin (DCO)

To ensure the legal integrity of the project, all contributions must be
accompanied by a Developer Certificate of Origin (DCO). This is a formal way to
certify that you authored the patch or have the right to submit it.

### How to sign your work:
When you commit, use the `-s` flag to sign your commit:
`git commit -s -m "Brief description of the security fix"`

This will add a `Signed-off-by: Your Name <your-email@example.com>` line to your
commit message.

---

## 🚀 How Can I Contribute?

### 🛡️ Reporting Security Vulnerabilities
If you find a security vulnerability in KuVuln itself, please do not open a
public issue. Follow [`SECURITY.md`](SECURITY.md) and report it via the
**Security** tab of this repository.

### 💡 Proposing New Security Rules
If you want KuVuln to detect a new type of vulnerability (for example a
Kubernetes misconfiguration or a Go anti-pattern), please:

1. Check the native rule catalog in [`docs/rules.md`](docs/rules.md).
2. Open an issue labeled `enhancement` describing the rule and the risk it
   mitigates.
3. Submit a Pull Request with the updated policy or Semgrep rule and at least
   one fixture under `tests/fixtures/`.

### 🛠️ Code Contributions
1. **Fork** the repository.
2. **Create a branch** for your feature or fix.
3. **Run tests**:
   ```bash
   pip install -e .
   python -m unittest discover -s tests -v
   ruff check src tests
   semgrep --config .kuvuln/rules --validate
   ```
4. **Submit a PR**: reference any related issues and provide a clear
   explanation of the changes.

### 🧪 Adding tests
Every new parser, rule or policy should ship with a fixture under
`tests/fixtures/` and a test that fails before the change and passes after it.
Fixtures intentionally contain insecure patterns; keep them out of
`kuvuln-config.json` exclusions and out of `.gitleaks.toml` allowlists unless
the value is obviously fake.

---

## ⚖️ Governance and Review

KuVuln uses an **OWNERS** file to manage review and approval authority.

- **Approvers** can merge code.
- **Reviewers** can comment and request changes.

Your Pull Request must be approved by at least one Approver before it can be
merged.

---

## 🤝 Community Code of Conduct

We are committed to providing a welcoming and inspiring community for all.
Please be kind and respectful in all interactions. We adhere to the
[CNCF Code of Conduct](https://github.com/cncf/foundation/blob/main/code-of-conduct.md).

---

*Thank you for helping us secure the Cloud Native ecosystem!*
