"""
Unit tests for Statement of Work (SOW) & PDF Report Exporter.
Verifies Markdown, HTML, and vector PDF report generation, severity calculations,
scope parameters rendering, multi-format batch exports, and clear separation
between Pre-Audit Authorization SOWs and Post-Audit Assessment Reports.
"""

import os
import tempfile
import unittest
from pathlib import Path

from reporting.sow_report_generator import SOWReportGenerator


class TestSOWReporting(unittest.TestCase):
    """Test suite for SOWReportGenerator and PDF exporter."""

    def setUp(self):
        self.sample_cfg = {
            "name": "OWASP Juice Shop Test",
            "platform": "OWASP / Local Lab",
            "policy_url": "http://localhost:3000/#/privacy_security",
            "rate_limit_per_second": 5.0,
            "in_scope": ["http://localhost:3000", "http://localhost:3000/*"],
            "excluded_paths": ["/api/v1/checkout", "/logout"],
            "discovered_endpoints": [
                "http://localhost:3000/rest/user/login",
                "http://localhost:3000/api/Feedbacks",
                "http://localhost:3000/rest/admin/application-version",
            ],
            "flagged_sensitive_endpoints": [
                "http://localhost:3000/rest/admin/application-version",
            ],
            "rules_of_engagement": {
                "header_tag": "X-AuditGuard-Researcher",
            },
        }

        self.sample_findings = [
            {
                "title": "CORS Misconfiguration on Feedback API",
                "severity": "HIGH",
                "cwe_id": "CWE-942",
                "description": "Origin reflection allows arbitrary origins to read authenticated responses.",
                "evidence": "Access-Control-Allow-Origin: https://evil.attacker.com\nAccess-Control-Allow-Credentials: true",
                "remediation": "Restrict Access-Control-Allow-Origin to trusted domains.",
                "affected_urls": ["http://localhost:3000/api/Feedbacks"],
            },
            {
                "title": "Application Version Information Leak",
                "severity": "LOW",
                "cwe_id": "CWE-200",
                "description": "Endpoint exposes internal build hash and version metadata.",
                "evidence": '{"version": "14.5.1", "build": "a910bf"}',
                "remediation": "Disable verbose version disclosure in production environments.",
                "affected_urls": ["http://localhost:3000/rest/admin/application-version"],
            },
        ]

        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_report_data_consolidation_and_metrics(self):
        generator = SOWReportGenerator(
            program_key="juiceshop",
            program_cfg=self.sample_cfg,
            findings=self.sample_findings,
            assessor="Lead Assessor",
            title="Juice Shop Security Audit",
        )
        data = generator.get_report_data()

        self.assertEqual(data["sow"]["title"], "Juice Shop Security Audit")
        self.assertEqual(data["sow"]["assessor"], "Lead Assessor")
        self.assertEqual(data["program"]["name"], "OWASP Juice Shop Test")
        self.assertEqual(data["metrics"]["total_findings"], 2)
        self.assertEqual(data["metrics"]["severity_counts"]["HIGH"], 1)
        self.assertEqual(data["metrics"]["severity_counts"]["LOW"], 1)
        self.assertEqual(data["metrics"]["severity_counts"]["CRITICAL"], 0)
        self.assertEqual(data["metrics"]["endpoints_discovered"], 3)
        self.assertEqual(data["metrics"]["sensitive_endpoints"], 1)
        self.assertTrue(data["audit_executed"])

    def test_pre_audit_sow_export_omits_findings(self):
        """Pre-audit SOW must NOT contain risk posture or findings sections."""
        generator = SOWReportGenerator(
            program_key="juiceshop",
            program_cfg=self.sample_cfg,
            findings=None,
            audit_executed=False,
        )
        data = generator.get_report_data()
        self.assertFalse(data["audit_executed"])
        self.assertIn("AUTHORIZED (PENDING AUDIT EXECUTION)", data["sow"]["status"])

        # 1. Test Markdown Output
        md_path = os.path.join(self.temp_dir.name, "pre_audit_sow.md")
        md_content = generator.export_markdown(md_path)
        self.assertIn("# Statement of Work (SOW) & Scope Authorization", md_content)
        self.assertIn("AUTHORIZED (PENDING AUDIT EXECUTION)", md_content)
        self.assertIn("## 2. Attack Surface & Route Inventory", md_content)
        self.assertIn("## 3. Planned Diagnostic Methodology & Rules of Engagement", md_content)
        self.assertNotIn("## 2. Executive Risk Posture", md_content)
        self.assertNotIn("## 3. Detailed Security Findings", md_content)
        self.assertNotIn("No security hygiene defects", md_content)

        # 2. Test HTML Output
        html_path = os.path.join(self.temp_dir.name, "pre_audit_sow.html")
        html_content = generator.export_html(html_path)
        self.assertIn("STATUS: AUTHORIZED - TESTING PENDING", html_content)
        self.assertIn("Planned Testing Methodology & Rules of Engagement", html_content)
        self.assertNotIn("Executive Risk Posture", html_content)
        self.assertNotIn('<div class="finding-card">', html_content)

        # 3. Test PDF Output
        pdf_path = os.path.join(self.temp_dir.name, "pre_audit_sow.pdf")
        generator.export_pdf(pdf_path)
        self.assertTrue(os.path.exists(pdf_path))
        with open(pdf_path, "rb") as f:
            self.assertEqual(f.read(5), b"%PDF-")

    def test_export_markdown_post_audit(self):
        generator = SOWReportGenerator(
            program_key="juiceshop",
            program_cfg=self.sample_cfg,
            findings=self.sample_findings,
            audit_executed=True,
        )
        md_path = os.path.join(self.temp_dir.name, "report.md")
        content = generator.export_markdown(md_path)

        self.assertIn("Security Assessment & SOW Compliance", content)
        self.assertIn("| **In-Scope Targets** |", content)
        self.assertIn("`http://localhost:3000`", content)
        self.assertIn("## 2. Executive Risk Posture", content)
        self.assertIn("CORS Misconfiguration on Feedback API", content)
        self.assertIn("CWE-942", content)
        self.assertIn("Methodology & Compliance Attestation", content)
        self.assertTrue(os.path.exists(md_path))
        self.assertEqual(Path(md_path).read_text(encoding="utf-8"), content)

    def test_export_html_post_audit(self):
        generator = SOWReportGenerator(
            program_key="juiceshop",
            program_cfg=self.sample_cfg,
            findings=self.sample_findings,
            audit_executed=True,
        )
        html_path = os.path.join(self.temp_dir.name, "report.html")
        content = generator.export_html(html_path)

        self.assertIn("<!DOCTYPE html>", content)
        self.assertIn("@media print", content)
        self.assertIn("CORS Misconfiguration on Feedback API", content)
        self.assertIn("STATUS: AUDIT COMPLETED", content)
        self.assertIn("badge", content)
        self.assertTrue(os.path.exists(html_path))
        self.assertEqual(Path(html_path).read_text(encoding="utf-8"), content)

    def test_export_pdf_post_audit_generates_valid_pdf(self):
        generator = SOWReportGenerator(
            program_key="juiceshop",
            program_cfg=self.sample_cfg,
            findings=self.sample_findings,
            audit_executed=True,
        )
        pdf_path = os.path.join(self.temp_dir.name, "report.pdf")
        generator.export_pdf(pdf_path)

        self.assertTrue(os.path.exists(pdf_path))
        size = os.path.getsize(pdf_path)
        self.assertGreater(size, 1000)

        with open(pdf_path, "rb") as f:
            header = f.read(5)
            self.assertEqual(header, b"%PDF-")

    def test_export_pdf_with_clean_post_audit(self):
        generator = SOWReportGenerator(
            program_key="clean-target",
            program_cfg=self.sample_cfg,
            findings=[],
            audit_executed=True,
        )
        pdf_path = os.path.join(self.temp_dir.name, "clean_report.pdf")
        generator.export_pdf(pdf_path)

        self.assertTrue(os.path.exists(pdf_path))
        self.assertGreater(os.path.getsize(pdf_path), 500)

    def test_export_all(self):
        generator = SOWReportGenerator(
            program_key="juiceshop",
            program_cfg=self.sample_cfg,
            findings=self.sample_findings,
            audit_executed=True,
        )
        base = os.path.join(self.temp_dir.name, "all_reports")
        result = generator.export_all(base, ["md", "html", "pdf"])

        self.assertTrue(os.path.exists(result["markdown"]))
        self.assertTrue(os.path.exists(result["html"]))
        self.assertTrue(os.path.exists(result["pdf"]))


if __name__ == "__main__":
    unittest.main()
