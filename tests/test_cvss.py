import unittest

from kuvuln.cvss import base_score, parse_vector, severity_from_cvss


class CvssTests(unittest.TestCase):
    def test_cvss_31_vector(self):
        score = base_score(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        )
        self.assertAlmostEqual(score, 9.8)

    def test_cvss_31_scope_changed(self):
        score = base_score(
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N"
        )
        self.assertAlmostEqual(score, 6.4)

    def test_cvss_v2(self):
        score = base_score("AV:N/AC:L/Au:N/C:C/I:C/A:C")
        self.assertAlmostEqual(score, 10.0)

    def test_invalid_vector(self):
        self.assertIsNone(base_score("not-a-vector"))
        self.assertIsNone(base_score("CVSS:3.1/AV:N"))

    def test_parse_vector(self):
        parsed = parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(parsed[0], 3)
        self.assertEqual(parsed[1]["AV"], "N")

    def test_severity_bands(self):
        self.assertEqual(severity_from_cvss(9.8), "CRITICAL")
        self.assertEqual(severity_from_cvss(7.5), "HIGH")
        self.assertEqual(severity_from_cvss(5.0), "MEDIUM")
        self.assertEqual(severity_from_cvss(2.0), "LOW")
        self.assertEqual(severity_from_cvss(0), "INFO")


if __name__ == "__main__":
    unittest.main()
