import unittest

from kuvuln.models import Dependency
from kuvuln.osv import OsvQuery, _version_key, findings_from_osv


class OsvTests(unittest.TestCase):
    def test_groups_aliases_and_fixed_version(self):
        dep = Dependency("lodash", "4.17.20", "npm", "package-lock.json")
        ghsa = {
            "id": "GHSA-35jh-r3h4-6jhm",
            "summary": "Command injection in lodash",
            "details": "The template function allows command injection.",
            "aliases": ["CVE-2021-23337"],
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            "affected": [
                {
                    "package": {"name": "lodash", "ecosystem": "npm"},
                    "ranges": [
                        {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}
                    ],
                }
            ],
            "references": [{"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-35jh-r3h4-6jhm"}],
        }
        cve = {
            "id": "CVE-2021-23337",
            "summary": "lodash command injection",
            "aliases": ["GHSA-35jh-r3h4-6jhm"],
            "affected": [
                {
                    "package": {"name": "lodash", "ecosystem": "npm"},
                    "ranges": [
                        {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}
                    ],
                }
            ],
        }
        findings = findings_from_osv(
            [OsvQuery(dep, ["GHSA-35jh-r3h4-6jhm", "CVE-2021-23337"], {"GHSA-35jh-r3h4-6jhm": ghsa, "CVE-2021-23337": cve})]
        )
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.primary_id, "CVE-2021-23337")
        self.assertIn("GHSA-35jh-r3h4-6jhm", finding.aliases)
        self.assertEqual(finding.fixed_version, "4.17.21")
        self.assertAlmostEqual(finding.cvss_score, 9.8)
        self.assertEqual(finding.severity, "CRITICAL")
        self.assertEqual(finding.ecosystem, "npm")

    def test_unfixed_dependency(self):
        dep = Dependency("golang.org/x/text", "v0.1.0", "Go", "go.mod")
        detail = {
            "id": "GO-2020-0015",
            "summary": "Out of bounds read",
            "aliases": [],
            "affected": [
                {
                    "package": {"name": "golang.org/x/text", "ecosystem": "Go"},
                    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
                }
            ],
        }
        findings = findings_from_osv(
            [OsvQuery(dep, ["GO-2020-0015"], {"GO-2020-0015": detail})]
        )
        self.assertEqual(len(findings), 1)
        self.assertIsNone(findings[0].fixed_version)

    def test_version_key(self):
        self.assertLess(_version_key("1.0.0"), _version_key("1.0.1"))
        self.assertLess(_version_key("1.0.0"), _version_key("1.1.0"))
        self.assertLess(_version_key("1.0.0"), _version_key("2.0.0"))
        self.assertGreater(_version_key("1.0.0"), _version_key("0.9.9"))
        self.assertGreater(_version_key("1.0.0"), _version_key("1.0.0-beta"))
        self.assertLess(_version_key("1.0.0-beta"), _version_key("1.0.0"))


if __name__ == "__main__":
    unittest.main()
