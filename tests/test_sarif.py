import unittest
from pathlib import Path

from kuvuln.sarif import build_sarif, ingest_sarif

FIXTURES = Path(__file__).parent / "fixtures" / "sarif"


class SarifTests(unittest.TestCase):
    def test_trivy_ingestion(self):
        report = ingest_sarif(FIXTURES / "trivy.sarif", root=".")
        self.assertEqual(len(report.findings), 3)
        by_rule = {finding.rule_id: finding for finding in report.findings}
        sca = by_rule["CVE-2021-23337"]
        self.assertEqual(sca.category, "sca")
        self.assertEqual(sca.package, "lodash")
        self.assertEqual(sca.version, "4.17.20")
        self.assertEqual(sca.fixed_version, "4.17.21")
        self.assertEqual(sca.severity, "CRITICAL")
        self.assertEqual(sca.location.path, "package-lock.json")
        self.assertEqual(sca.location.start_line, 10)

        privileged = by_rule["KSV001"]
        self.assertEqual(privileged.category, "kubernetes")
        self.assertEqual(privileged.severity, "HIGH")

        secret = by_rule["aws-access-key-id"]
        self.assertEqual(secret.category, "secret")
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", secret.description)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", secret.title)
        self.assertIn("intentionally not shown", secret.description)

    def test_semgrep_ingestion(self):
        report = ingest_sarif(FIXTURES / "semgrep.sarif", root=".")
        self.assertEqual(len(report.findings), 1)
        finding = report.findings[0]
        self.assertEqual(finding.category, "sast")
        self.assertEqual(finding.source, "semgrep")
        self.assertEqual(finding.severity, "MEDIUM")

    def test_build_sarif(self):
        report = ingest_sarif(FIXTURES / "trivy.sarif", root=".")
        output = build_sarif(report.findings, {"generated_at": "2026-10-20T00:00:00Z"})
        self.assertEqual(output["version"], "2.1.0")
        run = output["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "KuVuln")
        self.assertEqual(len(run["results"]), 3)
        self.assertEqual(run["results"][0]["partialFingerprints"]["kuvuln/v1"], report.findings[0].fingerprint)


if __name__ == "__main__":
    unittest.main()
