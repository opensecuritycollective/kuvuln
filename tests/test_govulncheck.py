import unittest
from pathlib import Path

from kuvuln.govulncheck import govulncheck_findings, ingest_govulncheck_file

FIXTURES = Path(__file__).parent / "fixtures" / "go"


class GovulncheckTests(unittest.TestCase):
    def test_stream_parse(self):
        findings, metadata = govulncheck_findings(
            (FIXTURES / "govulncheck.json").read_text(encoding="utf-8")
        )
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.primary_id, "CVE-2021-38561")
        self.assertEqual(finding.package, "golang.org/x/text")
        self.assertEqual(finding.version, "v0.3.0")
        self.assertEqual(finding.fixed_version, "v0.3.7")
        self.assertTrue(finding.reachable)
        self.assertEqual(finding.location.path, "main.go")
        self.assertEqual(finding.location.start_line, 14)
        self.assertEqual(metadata["scan_level"], "symbol")
        self.assertEqual(metadata["go_version"], "1.25.0")

    def test_file_parse(self):
        findings, metadata = ingest_govulncheck_file(
            FIXTURES / "govulncheck.json", rel="govulncheck.json"
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(metadata["path"], "govulncheck.json")


if __name__ == "__main__":
    unittest.main()
