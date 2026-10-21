import json
import tempfile
import unittest
from pathlib import Path

from kuvuln.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


class CliTests(unittest.TestCase):
    def test_scan_fail_then_baseline_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            config = tmp_path / "kuvuln-config.json"
            config.write_text(
                json.dumps(
                    {
                        "settings": {"fail_on_severity": "HIGH"},
                        "enrichment": {"offline": True},
                    }
                ),
                encoding="utf-8",
            )
            output = tmp_path / "out"
            first = main(
                [
                    "scan",
                    "--root",
                    str(FIXTURES),
                    "--config",
                    str(config),
                    "--input",
                    str(FIXTURES / "sarif"),
                    "--input",
                    str(FIXTURES / "go"),
                    "--output",
                    str(output),
                    "--offline",
                    "--format",
                    "json,markdown,html,sarif,sbom",
                ]
            )
            self.assertEqual(first, 1)
            self.assertTrue((output / "kuvuln-report.json").exists())
            self.assertTrue((output / "kuvuln.sarif").exists())
            self.assertTrue((output / "kuvuln-sbom.cdx.json").exists())

            report = output / "kuvuln-report.json"
            self.assertTrue(report.exists())
            baseline = tmp_path / "baseline.json"
            create = main(
                [
                    "baseline",
                    "create",
                    "--report",
                    str(report),
                    "--output",
                    str(baseline),
                    "--expires-days",
                    "30",
                ]
            )
            self.assertEqual(create, 0)
            self.assertTrue(baseline.exists())

            second = main(
                [
                    "scan",
                    "--root",
                    str(FIXTURES),
                    "--config",
                    str(config),
                    "--input",
                    str(FIXTURES / "sarif"),
                    "--input",
                    str(FIXTURES / "go"),
                    "--output",
                    str(output),
                    "--baseline",
                    str(baseline),
                    "--offline",
                    "--format",
                    "json",
                ]
            )
            self.assertEqual(second, 0, "baseline should suppress all findings")

    def test_images_command(self):
        import contextlib
        import io

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = main(["images", "--root", str(FIXTURES), "--format", "lines"])
        self.assertEqual(code, 0)
        images = buffer.getvalue().split()
        self.assertTrue(any("nginx:latest" in image for image in images))
        self.assertTrue(any("alpine:3.19" in image for image in images))
        self.assertFalse(any("builder" in image for image in images))

    def test_gomodules_command(self):
        import contextlib
        import io

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = main(["gomodules", "--root", str(FIXTURES), "--format", "lines"])
        self.assertEqual(code, 0)
        self.assertIn("go.mod", buffer.getvalue())


if __name__ == "__main__":
    unittest.main()
