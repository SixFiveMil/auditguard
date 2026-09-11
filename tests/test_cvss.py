"""
Unit tests for AuditGuard CVSS v3.1 Scoring Engine (core/cvss.py).
Validates official FIRST.org mathematical calculation, edge cases, vector generation,
and deterministic CWE mapping.
"""

import unittest
from core.cvss import CVSS31Metrics, CVSSCalculator


class TestCVSS31Engine(unittest.TestCase):
    """Verifies FIRST.org CVSS v3.1 base score calculation."""

    def test_official_first_org_vectors(self):
        """
        Validates against official FIRST.org published test vectors.
        """
        # Vector 1: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N -> 7.5 HIGH
        m1 = CVSS31Metrics(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="H",
            integrity="N",
            availability="N",
        )
        score1 = CVSSCalculator.calculate_base_score(m1)
        self.assertEqual(score1, 7.5)
        self.assertEqual(CVSSCalculator.severity_rating(score1), "HIGH")
        self.assertEqual(m1.to_vector(), "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")

        # Vector 2: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H -> 10.0 CRITICAL
        m2 = CVSS31Metrics(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="C",
            confidentiality="H",
            integrity="H",
            availability="H",
        )
        score2 = CVSSCalculator.calculate_base_score(m2)
        self.assertEqual(score2, 10.0)
        self.assertEqual(CVSSCalculator.severity_rating(score2), "CRITICAL")

        # Vector 3: Clean zero-impact
        m3 = CVSS31Metrics(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="N",
            integrity="N",
            availability="N",
        )
        score3 = CVSSCalculator.calculate_base_score(m3)
        self.assertEqual(score3, 0.0)
        self.assertEqual(CVSSCalculator.severity_rating(score3), "NONE")

        # Vector 4: Low impact information leak
        m4 = CVSS31Metrics(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="L",
            integrity="N",
            availability="N",
        )
        score4 = CVSSCalculator.calculate_base_score(m4)
        self.assertEqual(score4, 5.3)
        self.assertEqual(CVSSCalculator.severity_rating(score4), "MEDIUM")

    def test_roundup_precision(self):
        """Verifies FIRST.org roundup function guarding against float representation."""
        self.assertEqual(CVSSCalculator._roundup(4.0), 4.0)
        self.assertEqual(CVSSCalculator._roundup(4.00001), 4.1)
        self.assertEqual(CVSSCalculator._roundup(4.02), 4.1)
        self.assertEqual(CVSSCalculator._roundup(4.100000000001), 4.1)
        self.assertEqual(CVSSCalculator._roundup(7.41), 7.5)

    def test_estimate_from_cwe(self):
        """Tests deterministic heuristic mapping from CWE IDs to CVSS scores."""
        # CORS (CWE-942) without credentials
        score_std, vector_std, _ = CVSSCalculator.estimate_from_cwe("CWE-942", "CORS Wildcard Allowed")
        self.assertGreaterEqual(score_std, 4.0)
        self.assertIn("AV:N", vector_std)

        # CORS (CWE-942) with credentials
        score_cred, vector_cred, _ = CVSSCalculator.estimate_from_cwe("CWE-942", "CORS Allowed", "Access-Control-Allow-Credentials: true")
        self.assertGreaterEqual(score_cred, 7.0)

        # Admin Auth Bypass (CWE-306)
        score, vector, _ = CVSSCalculator.estimate_from_cwe("CWE-306", "Admin Access Bypass")
        self.assertGreaterEqual(score, 7.5)
        self.assertIn("PR:N", vector)

        # Clickjacking / Missing CSP (CWE-1021)
        score, vector, _ = CVSSCalculator.estimate_from_cwe("CWE-1021", "Missing CSP")
        self.assertGreaterEqual(score, 4.0)
        self.assertIn("UI:R", vector)

        # IDOR (CWE-639)
        score, vector, _ = CVSSCalculator.estimate_from_cwe("CWE-639", "BOLA / IDOR")
        self.assertGreaterEqual(score, 6.5)


if __name__ == "__main__":
    unittest.main()
