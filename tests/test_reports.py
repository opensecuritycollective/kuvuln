import unittest

from kuvuln import __version__
from kuvuln.config import Config
from kuvuln.models import Dependency, Finding, Location
from kuvuln.policy import evaluate_policy
from kuvuln.reports import MARKER, render_html, render_json, render_markdown
from kuvuln.sbom import build_sbom


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.config = Config({})
        self.policy = evaluate_policy([], 0, self.config)
        self.metadata = {"commit": "abc123", "branch": "main", "generated_at": "2026-10-20"}

    def test_markdown_structure(self):
        finding = Finding(
            rule_id="KUV-K8S-001",
            title="Container 'app' runs privileged",
            category="kubernetes",
            severity="HIGH",
            source="kuvuln",
            location=Location("deploy.yaml", 20),
        )
        policy = evaluate_policy([finding], 0, self.config)
        markdown = render_markdown(
            [finding], [finding], policy, self.config, self.metadata, [], [], {}
        )
        self.assertTrue(markdown.startswith(MARKER))
        self.assertIn("Policy gate failed", markdown)
        self.assertIn("KUV-K8S-001", markdown)
        self.assertIn("`deploy.yaml`:20", markdown)

    def test_markdown_redacts_secrets(self):
        finding = Finding(
            rule_id="gitleaks-aws-key",
            title="AWS Access Key",
            description="Matched AKIAIOSFODNN7EXAMPLE",
            category="secret",
            severity="HIGH",
            source="gitleaks",
            location=Location("config.yaml", 1),
        )
        markdown = render_markdown(
            [finding], [finding], self.policy, self.config, self.metadata, [], [], {}
        )
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", markdown)

    def test_json_report(self):
        report = render_json(
            [], [], self.policy, self.config, self.metadata, [], [], []
        )
        self.assertEqual(report["schema_version"], 3)
        self.assertEqual(report["tool"]["version"], __version__)
        self.assertIn("summary", report)

    def test_html_report(self):
        html = render_html(
            [], [], self.policy, self.config, self.metadata, [], []
        )
        self.assertIn("<html", html)
        self.assertIn("KuVuln Security Report", html)

    def test_sbom_purls(self):
        dependencies = [
            Dependency("lodash", "4.17.20", "npm", "package-lock.json"),
            Dependency("golang.org/x/text", "v0.3.0", "Go", "go.mod"),
            Dependency("org.springframework:spring-core", "5.3.39", "Maven", "pom.xml"),
            Dependency("@scope/pkg", "1.0.0", "npm", "package-lock.json"),
        ]
        sbom = build_sbom(dependencies, self.metadata)
        purls = {component["purl"] for component in sbom["components"]}
        self.assertIn("pkg:npm/lodash@4.17.20", purls)
        self.assertIn("pkg:golang/golang.org/x/text@v0.3.0", purls)
        self.assertIn("pkg:maven/org.springframework/spring-core@5.3.39", purls)
        self.assertIn("pkg:npm/%40scope/pkg@1.0.0", purls)


if __name__ == "__main__":
    unittest.main()
