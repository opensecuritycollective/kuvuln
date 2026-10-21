import unittest
from pathlib import Path

from kuvuln.config import Config
from kuvuln.kubernetes import analyze_resources, discover_resources

K8S = Path(__file__).parent / "fixtures" / "k8s"


class KubernetesAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.config = Config({})
        self.resources, self.warnings = discover_resources([K8S], self.config)

    def rules(self):
        return {finding.rule_id for finding in analyze_resources(self.resources, self.config)}

    def test_resources_discovered(self):
        kinds = {resource.kind for resource in self.resources}
        self.assertIn("Deployment", kinds)
        self.assertIn("ClusterRole", kinds)
        self.assertIn("ClusterRoleBinding", kinds)
        self.assertIn("Secret", kinds)
        self.assertIn("KubeletConfiguration", kinds)

    def test_workload_rules(self):
        rules = self.rules()
        for rule in (
            "KUV-K8S-001",
            "KUV-K8S-002",
            "KUV-K8S-003",
            "KUV-K8S-005",
            "KUV-K8S-008",
            "KUV-K8S-013",
            "KUV-K8S-014",
            "KUV-K8S-017",
            "KUV-K8S-024",
        ):
            self.assertIn(rule, rules, rule)

    def test_privileged_line_and_severity(self):
        findings = analyze_resources(self.resources, self.config)
        privileged = [f for f in findings if f.rule_id == "KUV-K8S-001"]
        self.assertTrue(privileged)
        self.assertTrue(all(f.severity == "HIGH" for f in privileged))
        self.assertTrue(all(f.location.start_line for f in privileged))

    def test_docker_socket_is_critical(self):
        findings = analyze_resources(self.resources, self.config)
        host_path = [f for f in findings if f.rule_id == "KUV-K8S-008"]
        self.assertTrue(any(f.severity == "CRITICAL" for f in host_path))

    def test_rbac_rules(self):
        rules = self.rules()
        self.assertIn("KUV-RBAC-001", rules)
        self.assertIn("KUV-RBAC-002", rules)

    def test_rbac_severities(self):
        findings = analyze_resources(self.resources, self.config)
        wildcard = [f for f in findings if f.rule_id == "KUV-RBAC-001" and "wildcard permissions" in f.title]
        self.assertTrue(any(f.severity == "CRITICAL" for f in wildcard))

    def test_network_policy_rules(self):
        rules = self.rules()
        self.assertIn("KUV-NET-001", rules)
        self.assertIn("KUV-NET-002", rules)
        self.assertIn("KUV-NET-003", rules)

    def test_external_secret_suppressed(self):
        findings = analyze_resources(self.resources, self.config)
        secret = [f for f in findings if f.rule_id == "KUV-K8S-024"]
        self.assertEqual(len(secret), 1)
        self.assertIn("plaintext-credentials", secret[0].properties["resource"])

    def test_removed_api(self):
        findings = analyze_resources(self.resources, self.config)
        removed = [f for f in findings if f.rule_id == "KUV-K8S-025"]
        self.assertTrue(removed)
        self.assertEqual(removed[0].properties["replacement"], "apps/v1")

    def test_kubelet_flags(self):
        findings = analyze_resources(self.resources, self.config)
        kubelet = [f for f in findings if f.rule_id == "KUV-K8S-027"]
        self.assertTrue(any(f.severity == "CRITICAL" for f in kubelet))

    def test_webhook(self):
        findings = analyze_resources(self.resources, self.config)
        webhook = [f for f in findings if f.rule_id == "KUV-K8S-028"]
        self.assertTrue(webhook)
        self.assertEqual(webhook[0].severity, "MEDIUM")

    def test_baseline_pss_skips_restricted_rules(self):
        config = Config({"kubernetes": {"pod_security_standard": "baseline"}})
        findings = analyze_resources(self.resources, config)
        rules = {f.rule_id for f in findings}
        self.assertNotIn("KUV-K8S-011", rules)
        self.assertIn("KUV-K8S-001", rules)

    def test_namespace_exclusion(self):
        config = Config(
            {"kubernetes": {"exclude_namespaces": ["demo", "kube-system", "kube-public", "kube-node-lease"]}}
        )
        findings = analyze_resources(self.resources, config)
        namespaces = {f.properties.get("namespace") for f in findings}
        self.assertNotIn("demo", namespaces)
        self.assertIn("app", namespaces)

    def test_disabled_rbac(self):
        config = Config({"kubernetes": {"check_rbac": False}})
        findings = analyze_resources(self.resources, config)
        self.assertFalse(any(f.category == "rbac" for f in findings))


if __name__ == "__main__":
    unittest.main()
