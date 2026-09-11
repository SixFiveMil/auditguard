"""
Tests for AuditGuard Safe Harbor Legal Provisions & Proof-of-Adherence Engine.
"""

import json
import os
import tempfile
import unittest
from pathlib import Path

from core.safe_harbor import SafeHarborLedgerAuditor, SafeHarborProof, SafeHarborTerms


class TestSafeHarbor(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.log_path = os.path.join(self.temp_dir.name, "audit_log.jsonl")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_safe_harbor_terms_content(self):
        self.assertIn("good faith", SafeHarborTerms.GOOD_FAITH_RESEARCH.lower())
        self.assertIn("1030", SafeHarborTerms.CFAA_AUTHORIZATION)
        self.assertIn("1201", SafeHarborTerms.DMCA_EXEMPTION)
        self.assertIn("zero-retention", SafeHarborTerms.DATA_PROTECTION_PRIVACY.lower())
        self.assertIn("idempotent", SafeHarborTerms.NON_DESTRUCTIVE_GUARANTEE.lower())

    def test_empty_ledger_proof(self):
        proof = SafeHarborLedgerAuditor.audit_engagement(
            log_path=self.log_path,
            program_cfg={"rate_limit_per_second": 3.0, "rules_of_engagement": {"header_tag": "X-Bug-Bounty"}},
            program_key="test_prog",
        )
        self.assertEqual(proof.total_requests, 0)
        self.assertTrue(proof.rate_limit_compliant)
        self.assertTrue(proof.is_fully_compliant)
        self.assertEqual(proof.excluded_paths_dispatched, 0)

    def test_compliant_ledger_audit(self):
        entries = [
            {
                "timestamp": "2026-09-11T12:00:00Z",
                "request": {
                    "method": "GET",
                    "url": "http://localhost:3000/api/users",
                    "headers": {"X-Bug-Bounty": "AuthorizedSecurityResearcher/1.0"},
                },
                "response": {"status_code": 200},
            },
            {
                "timestamp": "2026-09-11T12:00:02Z",
                "request": {
                    "method": "GET",
                    "url": "http://localhost:3000/rest/admin",
                    "headers": {"X-Bug-Bounty": "AuthorizedSecurityResearcher/1.0"},
                },
                "response": {"status_code": 200},
            },
        ]
        with open(self.log_path, "w", encoding="utf-8") as f:
            for e in entries:
                f.write(json.dumps(e) + "\n")

        prog_cfg = {
            "rate_limit_per_second": 2.0,
            "rules_of_engagement": {"header_tag": "X-Bug-Bounty"},
            "excluded_paths": ["/api/v1/checkout"],
        }
        proof = SafeHarborLedgerAuditor.audit_engagement(
            log_path=self.log_path,
            program_cfg=prog_cfg,
            program_key="juiceshop",
        )

        self.assertEqual(proof.total_requests, 2)
        self.assertTrue(proof.rate_limit_compliant)
        self.assertEqual(proof.header_compliance_pct, 100.0)
        self.assertEqual(proof.excluded_paths_dispatched, 0)
        self.assertTrue(proof.is_fully_compliant)

        lines = proof.summary_lines()
        self.assertTrue(any("Traffic Pacing Rate" in line for line in lines))
        self.assertTrue(any("Identity Tagging Adherence" in line for line in lines))
        self.assertTrue(any("SHA-256:" in line for line in lines))

    def test_excluded_path_violation_detection(self):
        entries = [
            {
                "timestamp": "2026-09-11T12:00:00Z",
                "request": {
                    "method": "GET",
                    "url": "http://localhost:3000/api/v1/checkout/pay",
                    "headers": {"X-Bug-Bounty": "researcher"},
                },
                "response": {"status_code": 200},
            }
        ]
        with open(self.log_path, "w", encoding="utf-8") as f:
            for e in entries:
                f.write(json.dumps(e) + "\n")

        prog_cfg = {
            "rate_limit_per_second": 2.0,
            "rules_of_engagement": {"header_tag": "X-Bug-Bounty"},
            "excluded_paths": ["/api/v1/checkout*"],
        }
        proof = SafeHarborLedgerAuditor.audit_engagement(
            log_path=self.log_path,
            program_cfg=prog_cfg,
            program_key="juiceshop",
        )

        self.assertEqual(proof.excluded_paths_dispatched, 1)
        self.assertFalse(proof.is_fully_compliant)


if __name__ == "__main__":
    unittest.main()
