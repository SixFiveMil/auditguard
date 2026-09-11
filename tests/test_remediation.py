"""
Tests for AuditGuard Targeted Re-Test & Differential Remediation Tracking Engine.
"""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from core.diagnostics import DiagnosticFinding, EndpointDiagnosticReport, generate_curl_poc
from core.remediation import AuditSessionManager, RemediationAuditor, RemediationItem
from reporting.sow_report_generator import RemediationReportGenerator


class TestRemediation(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_generate_curl_poc_get(self):
        cmd = generate_curl_poc("http://example.com/api/test", method="GET")
        self.assertIn("curl -i -s", cmd)
        self.assertIn('"http://example.com/api/test"', cmd)

    def test_generate_curl_poc_with_headers_and_body(self):
        headers = {"Origin": "https://evil.attacker.com", "X-Bug-Bounty": "researcher"}
        cmd = generate_curl_poc(
            "http://example.com/api/users",
            method="POST",
            headers=headers,
            data='{"user":"admin"}',
        )
        self.assertIn("-X POST", cmd)
        self.assertIn('-H "Origin: https://evil.attacker.com"', cmd)
        self.assertIn('-H "X-Bug-Bounty: researcher"', cmd)
        self.assertIn("--data '{\"user\":\"admin\"}'", cmd)

    def test_audit_session_manager_save_and_load(self):
        session_file = os.path.join(self.temp_dir.name, "latest_findings.json")

        findings = [
            DiagnosticFinding(
                title="CORS Wildcard Allowed",
                severity="HIGH",
                cwe_id="CWE-942",
                description="Wildcard origin with credentials allowed.",
                evidence="Access-Control-Allow-Origin: *",
                remediation="Configure explicit origins.",
                affected_urls=["http://localhost:3000/api/Feedbacks"],
            )
        ]

        saved_path = AuditSessionManager.save_session(
            program_key="juiceshop",
            endpoints=["http://localhost:3000/api/Feedbacks"],
            findings=findings,
            session_file=session_file,
        )

        self.assertTrue(os.path.exists(saved_path))
        loaded = AuditSessionManager.load_session(session_file)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded["program_key"], "juiceshop")
        self.assertEqual(loaded["findings_count"], 1)
        self.assertEqual(loaded["findings"][0]["title"], "CORS Wildcard Allowed")
        self.assertIn("curl_poc", loaded["findings"][0])

    def test_remediation_auditor_differential_resolution(self):
        baseline_session = {
            "session_id": "test_sess_001",
            "program_key": "juiceshop",
            "findings_count": 2,
            "findings": [
                {
                    "title": "CORS Reflection Misconfiguration",
                    "severity": "HIGH",
                    "cwe_id": "CWE-942",
                    "description": "Origin reflected.",
                    "evidence": "Access-Control-Allow-Origin: https://evil.attacker.com",
                    "remediation": "Restrict origins.",
                    "curl_poc": 'curl -s -i -H "Origin: https://evil.attacker.com" "http://localhost:3000/api/Feedbacks"',
                    "affected_urls": ["http://localhost:3000/api/Feedbacks"],
                },
                {
                    "title": "Server Information Leak",
                    "severity": "LOW",
                    "cwe_id": "CWE-200",
                    "description": "Exposes Express banner.",
                    "evidence": "X-Powered-By: Express",
                    "remediation": "Disable X-Powered-By header.",
                    "curl_poc": 'curl -s -i "http://localhost:3000/rest/admin/application-version"',
                    "affected_urls": ["http://localhost:3000/rest/admin/application-version"],
                },
            ],
        }

        # Mock engine: /api/Feedbacks still has CORS defect, but /rest/admin/application-version is resolved (clean)
        mock_engine = MagicMock()

        rep_feedback = EndpointDiagnosticReport(
            url="http://localhost:3000/api/Feedbacks",
            status_code=200,
            elapsed_ms=12.0,
            findings=[
                DiagnosticFinding(
                    title="CORS Reflection Misconfiguration",
                    severity="HIGH",
                    cwe_id="CWE-942",
                    description="Origin reflected.",
                    evidence="Access-Control-Allow-Origin: https://evil.attacker.com",
                    remediation="Restrict origins.",
                    affected_urls=["http://localhost:3000/api/Feedbacks"],
                )
            ],
        )

        rep_version_clean = EndpointDiagnosticReport(
            url="http://localhost:3000/rest/admin/application-version",
            status_code=200,
            elapsed_ms=8.0,
            findings=[],  # Defect resolved!
        )

        mock_engine.diagnose_batch.return_value = [rep_feedback, rep_version_clean]

        retest_result = RemediationAuditor.run_retest(
            engine=mock_engine,
            baseline_session=baseline_session,
        )

        metrics = retest_result["metrics"]
        self.assertEqual(metrics["total_baseline_defects"], 2)
        self.assertEqual(metrics["resolved_count"], 1)
        self.assertEqual(metrics["unresolved_count"], 1)
        self.assertEqual(metrics["resolution_rate_pct"], 50.0)

        items = retest_result["items"]
        self.assertEqual(len(items), 2)

        # CORS finding is STILL_VULNERABLE -> UNRESOLVED
        cors_item = next(i for i in items if "CORS" in i["title"])
        self.assertEqual(cors_item["result"], "UNRESOLVED")
        self.assertEqual(cors_item["retest_status"], "STILL_VULNERABLE")

        # Version leak is RESOLVED
        leak_item = next(i for i in items if "Server Information" in i["title"])
        self.assertEqual(leak_item["result"], "RESOLVED")
        self.assertEqual(leak_item["retest_status"], "RESOLVED")

    def test_remediation_report_generator_exports(self):
        remediation_data = {
            "session_id": "test_sess_002",
            "baseline_session_id": "base_001",
            "program_key": "juiceshop",
            "retest_date": "2026-09-11 15:00:00Z",
            "endpoints_tested": 2,
            "metrics": {
                "total_baseline_defects": 2,
                "resolved_count": 1,
                "unresolved_count": 1,
                "resolution_rate_pct": 50.0,
            },
            "items": [
                {
                    "finding_id": "f01",
                    "title": "CORS Wildcard Allowed",
                    "severity": "HIGH",
                    "cwe_id": "CWE-942",
                    "affected_url": "http://localhost:3000/api/Feedbacks",
                    "baseline_status": "VULNERABLE",
                    "retest_status": "STILL_VULNERABLE",
                    "result": "UNRESOLVED",
                    "evidence": "Access-Control-Allow-Origin: *",
                    "remediation": "Restrict origins.",
                    "curl_poc": 'curl -s -i "http://localhost:3000/api/Feedbacks"',
                },
                {
                    "finding_id": "f02",
                    "title": "Application Version Leak",
                    "severity": "LOW",
                    "cwe_id": "CWE-200",
                    "affected_url": "http://localhost:3000/rest/admin/application-version",
                    "baseline_status": "VULNERABLE",
                    "retest_status": "RESOLVED",
                    "result": "RESOLVED",
                    "evidence": "Endpoint re-tested clean.",
                    "remediation": "Disable version disclosure.",
                    "curl_poc": 'curl -s -i "http://localhost:3000/rest/admin/application-version"',
                },
            ],
        }

        prog_cfg = {
            "name": "OWASP Juice Shop Test",
            "platform": "OWASP / Local Lab",
            "rate_limit_per_second": 3.0,
            "in_scope": ["http://localhost:3000"],
            "rules_of_engagement": {"header_tag": "X-Bug-Bounty"},
        }

        gen = RemediationReportGenerator(
            remediation_data=remediation_data,
            program_cfg=prog_cfg,
            assessor="Authorized Security Researcher",
        )

        # 1. Test Markdown
        md_path = os.path.join(self.temp_dir.name, "remediation.md")
        md_content = gen.export_markdown(md_path)
        self.assertIn("Remediation Verification Report", md_content)
        self.assertIn("`[RESOLVED]`", md_content)
        self.assertIn("`[UNRESOLVED]`", md_content)
        self.assertIn("Reproduction (cURL)", md_content)
        self.assertIn("Safe Harbor Legal Provisions", md_content)
        self.assertTrue(os.path.exists(md_path))

        # 2. Test HTML
        html_path = os.path.join(self.temp_dir.name, "remediation.html")
        html_content = gen.export_html(html_path)
        self.assertIn("<!DOCTYPE html>", html_content)
        self.assertIn("RE-TEST VERIFICATION COMPLETED", html_content)
        self.assertIn("RESOLVED", html_content)
        self.assertIn("UNRESOLVED", html_content)
        self.assertTrue(os.path.exists(html_path))

        # 3. Test PDF
        pdf_path = os.path.join(self.temp_dir.name, "remediation.pdf")
        gen.export_pdf(pdf_path)
        self.assertTrue(os.path.exists(pdf_path))
        with open(pdf_path, "rb") as f:
            self.assertEqual(f.read(5), b"%PDF-")


if __name__ == "__main__":
    unittest.main()
