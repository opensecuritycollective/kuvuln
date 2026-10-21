import unittest
from pathlib import Path

from kuvuln.config import Config
from kuvuln.helm import analyze_helm_charts
from kuvuln.kustomize import analyze_kustomize

FIXTURES = Path(__file__).parent / "fixtures"


class HelmKustomizeTests(unittest.TestCase):
    def test_helm_checks(self):
        config = Config({})
        findings = analyze_helm_charts([FIXTURES], config)
        rules = {finding.rule_id for finding in findings}
        self.assertIn("KUV-HELM-001", rules)
        self.assertIn("KUV-HELM-002", rules)
        self.assertIn("KUV-HELM-003", rules)
        self.assertIn("KUV-HELM-004", rules)
        secrets = [f for f in findings if f.rule_id == "KUV-HELM-004"]
        self.assertTrue(any("password" in f.title for f in secrets))

    def test_kustomize_checks(self):
        config = Config({})
        findings = analyze_kustomize([FIXTURES], config)
        rules = {finding.rule_id for finding in findings}
        self.assertIn("KUV-KUSTOMIZE-001", rules)
        self.assertIn("KUV-KUSTOMIZE-002", rules)
        self.assertIn("KUV-KUSTOMIZE-003", rules)
        self.assertIn("KUV-KUSTOMIZE-004", rules)
        self.assertIn("KUV-KUSTOMIZE-005", rules)
        remote = [f for f in findings if f.rule_id == "KUV-KUSTOMIZE-001"]
        self.assertTrue(any(f.severity == "HIGH" for f in remote))

    def test_disabled_checks(self):
        config = Config(
            {"kubernetes": {"helm": {"enabled": False}, "kustomize": {"enabled": False}}}
        )
        self.assertEqual(analyze_helm_charts([FIXTURES], config), [])
        self.assertEqual(analyze_kustomize([FIXTURES], config), [])


if __name__ == "__main__":
    unittest.main()
