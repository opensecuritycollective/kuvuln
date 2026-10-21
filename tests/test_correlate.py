import unittest
from pathlib import Path

from kuvuln.correlate import correlate_findings
from kuvuln.models import Finding, Location

FIXTURES = Path(__file__).parent / "fixtures" / "go"


class CorrelateTests(unittest.TestCase):
    def test_sca_reachability_merge(self):
        osv = Finding(
            rule_id="CVE-2021-38561",
            title="Out-of-bounds read in golang.org/x/text/language",
            category="sca",
            severity="HIGH",
            source="osv",
            package="golang.org/x/text",
            version="v0.3.0",
            ecosystem="Go",
            location=Location("go.mod"),
            identifiers=["CVE-2021-38561"],
        )
        govuln = Finding(
            rule_id="CVE-2021-38561",
            title="Out-of-bounds read in golang.org/x/text/language",
            category="sca",
            severity="HIGH",
            source="govulncheck",
            package="golang.org/x/text",
            version="v0.3.0",
            ecosystem="Go",
            reachable=True,
            location=Location("main.go", 14),
            identifiers=["CVE-2021-38561"],
        )
        merged = correlate_findings([osv, govuln])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].source, "govulncheck")
        self.assertTrue(merged[0].reachable)
        self.assertEqual(
            set(merged[0].properties.get("reported_by", [])),
            {"osv", "govulncheck"},
        )

    def test_native_raw_rendered_dedupe(self):
        raw = Finding(
            rule_id="KUV-K8S-001",
            title="Container 'app' runs privileged",
            category="kubernetes",
            severity="HIGH",
            source="kuvuln",
            location=Location("deploy.yaml", 20),
            properties={"resource": "Deployment/demo/app", "container": "app", "control": "KUV-K8S-001"},
        )
        rendered = Finding(
            rule_id="KUV-K8S-001",
            title="Container 'app' runs privileged",
            category="kubernetes",
            severity="HIGH",
            source="kuvuln",
            location=Location("kuvuln-rendered/chart.yaml", 25),
            properties={"resource": "Deployment/demo/app", "container": "app", "control": "KUV-K8S-001"},
        )
        merged = correlate_findings([raw, rendered])
        self.assertEqual(len(merged), 1)

    def test_different_containers_not_merged(self):
        first = Finding(
            rule_id="KUV-K8S-001",
            title="Container 'app' runs privileged",
            category="kubernetes",
            severity="HIGH",
            source="kuvuln",
            location=Location("deploy.yaml", 20),
            properties={"resource": "Deployment/demo/app", "container": "app"},
        )
        second = Finding(
            rule_id="KUV-K8S-001",
            title="Container 'sidecar' runs privileged",
            category="kubernetes",
            severity="HIGH",
            source="kuvuln",
            location=Location("deploy.yaml", 40),
            properties={"resource": "Deployment/demo/app", "container": "sidecar"},
        )
        merged = correlate_findings([first, second])
        self.assertEqual(len(merged), 2)


if __name__ == "__main__":
    unittest.main()
