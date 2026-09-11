"""
Unit tests for AuditGuard Bug Bounty & Platform Triage Exporter (reporting/triage_exporter.py).
Validates formatting for HackerOne, Bugcrowd, GitHub Issues, and Jira JSON.
"""

import json
import os
import tempfile
import unittest
from core.diagnostics import DiagnosticFinding
from reporting.triage_exporter import PlatformTriageExporter


class TestPlatformTriageExporter(unittest.TestCase):
    """Verifies generation of professional triage submission documents."""

    def setUp(self):
        self.sample_finding = DiagnosticFinding(
            title="CORS Wildcard Allowed with Credentials",
            severity="HIGH",
            cwe_id="CWE-942",
            description="The API server reflects Origin with Access-Control-Allow-Credentials: true.",
            evidence="Access-Control-Allow-Origin: https://evil.com\nAccess-Control-Allow-Credentials: true",
            remediation="Configure an explicit origin whitelist in CORS middleware.",
            affected_urls=["http://localhost:3000/api/Feedbacks"],
            cvss_score=8.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
            remediation_code="app.use(cors({ origin: ['https://app.example.com'], credentials: true }));",
            remediation_lang="javascript",
        )

    def test_export_hackerone(self):
        md = PlatformTriageExporter.export_hackerone_finding(
            self.sample_finding,
            program_name="JuiceShop VDP",
            target_scope="http://localhost:3000",
            safe_harbor_data={"Session": "test1234", "Verdict": "COMPLIANT"},
        )
        self.assertIn("# [SECURITY REPORT] CORS Wildcard Allowed", md)
        self.assertIn("CVSS v3.1: `8.1`", md)
        self.assertIn("CVSS:3.1/AV:N", md)
        self.assertIn("CWE-942", md)
        self.assertIn("Step-by-Step Reproduction Guide", md)
        self.assertIn("curl -i -s", md)
        self.assertIn("Safe Harbor & Ethical Conduct Verification", md)
        self.assertIn("app.use(cors", md)

    def test_export_bugcrowd(self):
        md = PlatformTriageExporter.export_bugcrowd_finding(
            self.sample_finding,
            program_name="JuiceShop VDP",
            target_scope="http://localhost:3000",
        )
        self.assertIn("Vulnerability Rating Taxonomy (VRT)", md)
        self.assertIn("Cross-Origin Resource Sharing", md)
        self.assertIn("curl -i -s", md)
        self.assertIn("app.use(cors", md)

    def test_export_github_issue(self):
        md = PlatformTriageExporter.export_github_issue(self.sample_finding)
        self.assertIn("## [Security] HIGH: CORS Wildcard Allowed", md)
        self.assertIn("CVSS v3.1", md)
        self.assertIn("Remediation Checklist", md)
        self.assertIn("- [ ] `http://localhost:3000/api/Feedbacks`", md)
        self.assertIn("Suggested Patch", md)

    def test_export_jira_json(self):
        data = PlatformTriageExporter.export_jira_json([self.sample_finding], project_key="APPSEC")
        self.assertIn("issueUpdates", data)
        issues = data["issueUpdates"]
        self.assertEqual(len(issues), 1)
        issue = issues[0]["fields"]
        self.assertEqual(issue["project"]["key"], "APPSEC")
        self.assertEqual(issue["priority"]["name"], "High")
        self.assertIn("[HIGH] CORS Wildcard Allowed", issue["summary"])
        self.assertIn("security", issue["labels"])

    def test_export_all_to_disk(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            paths = PlatformTriageExporter.export_all(
                [self.sample_finding],
                output_dir=tmpdir,
                base_name="test_triage",
                program_name="JuiceShop VDP",
            )
            self.assertIn("hackerone", paths)
            self.assertIn("bugcrowd", paths)
            self.assertIn("github", paths)
            self.assertIn("jira", paths)

            for key, fpath in paths.items():
                self.assertTrue(os.path.isfile(fpath))
                self.assertGreater(os.path.getsize(fpath), 100)


if __name__ == "__main__":
    unittest.main()
