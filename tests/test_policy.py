import unittest

from kuvuln.config import Config
from kuvuln.models import Finding, Location
from kuvuln.policy import apply_suppressions, evaluate_policy


def finding(
    rule_id="TEST-1",
    severity="HIGH",
    category="kubernetes",
    kev=False,
    epss=None,
    fixed=None,
    path="deploy.yaml",
    title="A finding",
):
    return Finding(
        rule_id=rule_id,
        title=title,
        category=category,
        severity=severity,
        source="kuvuln",
        location=Location(path),
        fixed_version=fixed,
        kev=kev,
        epss=epss,
    )


class PolicyTests(unittest.TestCase):
    def test_threshold_fails_on_high(self):
        config = Config({})
        policy = evaluate_policy([finding(severity="HIGH")], 0, config)
        self.assertFalse(policy.passed)
        self.assertTrue(any("fail_on_severity" in reason for reason in policy.reasons))

    def test_threshold_passes_below(self):
        config = Config({})
        policy = evaluate_policy([finding(severity="MEDIUM")], 0, config)
        self.assertTrue(policy.passed)

    def test_threshold_none_disables(self):
        config = Config({"settings": {"fail_on_severity": "NONE"}})
        policy = evaluate_policy([finding(severity="CRITICAL")], 0, config)
        self.assertTrue(policy.passed)

    def test_kev_gate(self):
        config = Config({"settings": {"fail_on_severity": "NONE"}})
        policy = evaluate_policy([finding(severity="LOW", kev=True)], 0, config)
        self.assertFalse(policy.passed)

    def test_epss_gate(self):
        config = Config(
            {"settings": {"fail_on_severity": "NONE", "fail_on_epss": 0.5}}
        )
        policy = evaluate_policy([finding(severity="LOW", epss=0.9)], 0, config)
        self.assertFalse(policy.passed)

    def test_max_allowed(self):
        config = Config(
            {
                "settings": {
                    "fail_on_severity": "NONE",
                    "max_allowed": {"MEDIUM": 1},
                }
            }
        )
        policy = evaluate_policy(
            [finding(severity="MEDIUM"), finding(severity="MEDIUM", title="Other")],
            0,
            config,
        )
        self.assertFalse(policy.passed)
        self.assertTrue(any("exceed the allowed maximum" in r for r in policy.reasons))

    def test_suppression_path(self):
        config = Config({"settings": {"exclusions": {"directories": ["tests/**"]}}})
        kept, suppressed = apply_suppressions([finding(path="tests/fixtures/a.yaml")], config)
        self.assertEqual(kept, [])
        self.assertEqual(len(suppressed), 1)

    def test_rule_suppression_and_expiry(self):
        config = Config(
            {
                "settings": {
                    "exclusions": {
                        "rules": [
                            {"id": "TEST-1", "reason": "accepted", "expires": "2000-01-01"}
                        ]
                    }
                }
            }
        )
        kept, suppressed = apply_suppressions([finding()], config)
        self.assertEqual(len(kept), 1)
        self.assertEqual(suppressed, [])
        self.assertTrue(any("expired" in warning for warning in config.warnings))

    def test_ignore_unfixed(self):
        config = Config({"settings": {"ignore_unfixed": True}})
        kept, suppressed = apply_suppressions(
            [finding(category="sca", fixed=None), finding(category="sca", fixed="1.0.0")],
            config,
        )
        self.assertEqual(len(kept), 1)
        self.assertEqual(len(suppressed), 1)


if __name__ == "__main__":
    unittest.main()
