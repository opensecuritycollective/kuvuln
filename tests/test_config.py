import unittest
from pathlib import Path

from kuvuln.config import Config
from kuvuln.models import Finding, Location

ROOT = Path(__file__).resolve().parent.parent


class ConfigTests(unittest.TestCase):
    def test_shipped_config_loads(self):
        config = Config.load(ROOT / "kuvuln-config.json")
        self.assertEqual(config.fail_on, "HIGH")
        self.assertTrue(config.category_enabled("kubernetes"))
        self.assertTrue(config.category_enabled("rbac"))
        self.assertFalse(config.path_excluded("."))
        self.assertTrue(config.path_excluded("tests/fixtures/k8s/insecure-deployment.yaml"))

    def test_legacy_switches(self):
        config = Config(
            {
                "advanced": {"ignore_unfixed": True, "license_check": False},
                "settings": {
                    "scan_targets": {
                        "kubernetes": False,
                        "dependencies": False,
                        "secrets": False,
                    }
                },
            }
        )
        self.assertTrue(config.get("settings.ignore_unfixed"))
        self.assertFalse(config.get("license.enabled"))
        self.assertFalse(config.category_enabled("kubernetes"))
        self.assertFalse(config.category_enabled("sca"))
        self.assertFalse(config.category_enabled("secret"))

    def test_expired_exclusion_is_not_applied(self):
        config = Config(
            {
                "settings": {
                    "exclusions": {
                        "rules": [
                            {"id": "KUV-K8S-001", "reason": "accepted", "expires": "2000-01-01"}
                        ]
                    }
                }
            }
        )
        finding = Finding(
            rule_id="KUV-K8S-001",
            title="test",
            category="kubernetes",
            location=Location("deploy.yaml"),
        )
        self.assertIsNone(config.suppression_reason(finding))
        self.assertTrue(any("expired" in warning for warning in config.warnings))

    def test_package_exclusion(self):
        config = Config(
            {
                "settings": {
                    "exclusions": {"packages": [{"name": "lodash", "ecosystem": "npm"}]}
                }
            }
        )
        finding = Finding(
            rule_id="CVE-1",
            title="lodash",
            category="sca",
            package="lodash",
            version="1.0.0",
            ecosystem="npm",
            location=Location("package-lock.json"),
        )
        self.assertIsNotNone(config.suppression_reason(finding))


if __name__ == "__main__":
    unittest.main()
