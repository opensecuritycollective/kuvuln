import unittest
from pathlib import Path

from kuvuln.config import Config
from kuvuln.enrich import LifecycleClient
from kuvuln.gochecks import analyze_go, check_kubernetes_component_images
from kuvuln.kubernetes import discover_resources

FIXTURES = Path(__file__).parent / "fixtures"


class GoCheckTests(unittest.TestCase):
    def test_go_mod_findings(self):
        config = Config({})
        lifecycle = LifecycleClient(
            http=None, cache=None, products=["go"]
        )
        findings = analyze_go([FIXTURES], config, lifecycle, [])
        rules = {finding.rule_id for finding in findings}
        self.assertIn("KUV-GO-001", rules)  # go1.25.0 is EOL (offline fallback)
        self.assertIn("KUV-GO-003", rules)  # remote replace

    def test_kubernetes_component_eol(self):
        # Build a synthetic resource set using the K8s fixture with a component image
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "component.yaml"
            path.write_text(
                "apiVersion: v1\nkind: Pod\nmetadata:\n  name: kube\nspec:\n"
                "  containers:\n  - name: apiserver\n    image: "
                "registry.k8s.io/kube-apiserver:v1.33.0\n",
                encoding="utf-8",
            )
            resources, _ = discover_resources([Path(tmp)], Config({}))
        lifecycle = LifecycleClient(http=None, cache=None, products=["kubernetes"])
        findings = check_kubernetes_component_images(resources, lifecycle)
        self.assertTrue(any(f.rule_id == "KUV-K8S-023" for f in findings))

    def test_disabled_go_checks(self):
        config = Config({"go": {"enabled": False}})
        lifecycle = LifecycleClient(http=None, cache=None, products=["go"])
        self.assertEqual(analyze_go([FIXTURES], config, lifecycle, []), [])


if __name__ == "__main__":
    unittest.main()
