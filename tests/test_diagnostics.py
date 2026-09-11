"""
Unit tests for AuditGuard Security Diagnostic Engine.
Verifies method permutation, CORS checks, header hygiene, information leaks,
scope barrier enforcement, and fault-tolerant error shielding.
"""

import unittest
from unittest.mock import MagicMock, patch

import httpx

from core.diagnostics import (
    DiagnosticFinding,
    EndpointDiagnosticReport,
    SecurityDiagnosticEngine,
)
from core.scope_validator import ScopeValidator


class TestSecurityDiagnosticEngine(unittest.TestCase):

    def setUp(self):
        self.program_config = {
            "name": "Diagnostic Test Lab",
            "in_scope": [
                "https://target.internal",
                "*.target.internal",
            ],
            "excluded_paths": [
                "/logout",
                "/delete",
                "/billing",
                "*/admin/staging/*",
            ],
            "rules_of_engagement": {
                "header_tag": "X-Bug-Bounty",
            },
        }
        self.validator = ScopeValidator(self.program_config)
        self.mock_client = MagicMock()
        self.mock_client.scope_validator = self.validator
        self.engine = SecurityDiagnosticEngine(self.mock_client)

    def test_scope_guardrail_blocks_excluded_paths(self):
        # Excluded path /billing must return skipped report without network calls
        report = self.engine.diagnose("https://target.internal/billing")
        self.assertIsNotNone(report.skipped_reason)
        self.assertIn("Excluded Path", report.skipped_reason)
        self.mock_client.get.assert_not_called()
        self.mock_client.request.assert_not_called()

        # Excluded nested path */admin/staging/* must return skipped report
        report2 = self.engine.diagnose("https://target.internal/api/admin/staging/users")
        self.assertIsNotNone(report2.skipped_reason)
        self.assertIn("Excluded Path", report2.skipped_reason)

    def test_scope_guardrail_blocks_unauthorized_domains(self):
        # Out-of-scope domain must return skipped report without network calls
        report = self.engine.diagnose("https://unauthorized-evil.com/api")
        self.assertIsNotNone(report.skipped_reason)
        self.assertIn("Out of Scope", report.skipped_reason)
        self.mock_client.get.assert_not_called()

    def test_security_headers_audit_detects_missing_defenses(self):
        report = EndpointDiagnosticReport(url="https://target.internal/api/v1")
        # Headers missing HSTS, CSP, X-Frame-Options, X-Content-Type-Options
        headers = {"server": "nginx/1.18.0"}
        self.engine._audit_security_headers(report, headers, "https://target.internal/api/v1", is_sensitive=True)

        titles = [f.title for f in report.findings]
        self.assertIn("Missing Strict-Transport-Security (HSTS) Header", titles)
        self.assertIn("Missing Content-Security-Policy (CSP)", titles)
        self.assertIn("Missing Anti-Clickjacking Defense", titles)
        self.assertIn("Missing X-Content-Type-Options Header", titles)
        self.assertIn("Sensitive Endpoint Missing 'Cache-Control: no-store'", titles)

    def test_security_headers_audit_accepts_good_hygiene(self):
        report = EndpointDiagnosticReport(url="https://target.internal/admin")
        good_headers = {
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "cache-control": "no-store, no-cache, must-revalidate",
        }
        self.engine._audit_security_headers(report, good_headers, "https://target.internal/admin", is_sensitive=True)
        self.assertEqual(len(report.findings), 0)

    def test_cors_policy_audit_detects_arbitrary_origin_with_credentials(self):
        report = EndpointDiagnosticReport(url="https://target.internal/api/profile")
        mock_resp = MagicMock()
        mock_resp.headers = {
            "access-control-allow-origin": "https://auditguard-diagnostic.internal",
            "access-control-allow-credentials": "true",
        }
        self.mock_client.request.return_value = mock_resp

        self.engine._audit_cors_policy(report, "https://target.internal/api/profile")

        self.assertEqual(len(report.findings), 1)
        finding = report.findings[0]
        self.assertEqual(finding.severity, "CRITICAL")
        self.assertIn("Arbitrary Origin Reflected with Credentials", finding.title)
        self.assertEqual(finding.cwe_id, "CWE-942")

    def test_cors_policy_audit_detects_null_origin_with_credentials(self):
        report = EndpointDiagnosticReport(url="https://target.internal/api/data")
        mock_resp = MagicMock()
        mock_resp.headers = {
            "access-control-allow-origin": "null",
            "access-control-allow-credentials": "true",
        }
        self.mock_client.request.return_value = mock_resp

        self.engine._audit_cors_policy(report, "https://target.internal/api/data")

        self.assertEqual(len(report.findings), 1)
        finding = report.findings[0]
        self.assertEqual(finding.severity, "HIGH")
        self.assertIn("'null' Origin Allowed with Credentials", finding.title)

    def test_information_leak_audit_detects_stack_traces_and_ips(self):
        report = EndpointDiagnosticReport(url="https://target.internal/api/broken")
        body_with_django_and_ips = """
        <!DOCTYPE html>
        <html>
        <head><title>DisallowedHost at /</title></head>
        <body>
            <h1>DisallowedHost at /</h1>
            <p>Traceback (most recent call last):</p>
            <p>Internal Server IP: 10.240.0.15 reached from gateway 192.168.1.5</p>
        </body>
        </html>
        """
        self.engine._audit_information_leaks(report, body_with_django_and_ips, status_code=500)

        titles = [f.title for f in report.findings]
        self.assertTrue(any("Unhandled Exception" in t or "Debug" in t for t in titles))
        self.assertIn("Internal RFC 1918 IP Address Disclosure", titles)

    def test_information_leak_audit_detects_credentials(self):
        report = EndpointDiagnosticReport(url="https://target.internal/api/config")
        leak_body = '{"status": "ok", "aws_key": "AKIAIOSFODNN7EXAMPLE", "secret": "valid"}'
        self.engine._audit_information_leaks(report, leak_body, status_code=200)

        titles = [f.title for f in report.findings]
        self.assertTrue(any("AWS Access Key" in t for t in titles))
        severities = [f.severity for f in report.findings]
        self.assertIn("CRITICAL", severities)

    def test_access_control_audit_flags_unauthenticated_admin_ok(self):
        report = EndpointDiagnosticReport(url="https://target.internal/admin/dashboard", is_sensitive=True)
        self.engine._audit_access_control(report, "https://target.internal/admin/dashboard", status_code=200, is_sensitive=True)

        self.assertEqual(len(report.findings), 1)
        finding = report.findings[0]
        self.assertEqual(finding.severity, "HIGH")
        self.assertEqual(finding.cwe_id, "CWE-306")
        self.assertIn("Unauthenticated 200 OK on Admin Route", finding.title)

    def test_http_methods_audit_flags_dangerous_methods(self):
        report = EndpointDiagnosticReport(url="https://target.internal/api/test")
        mock_resp = MagicMock()
        mock_resp.headers = {"allow": "GET, POST, OPTIONS, TRACE, DELETE"}
        self.mock_client.request.return_value = mock_resp

        self.engine._audit_http_methods(report, "https://target.internal/api/test", baseline_status=200)

        self.assertIn("TRACE", report.allowed_methods)
        self.assertIn("DELETE", report.allowed_methods)
        self.assertEqual(len(report.findings), 1)
        self.assertIn("Dangerous HTTP Methods Advertised", report.findings[0].title)

    def test_fault_tolerance_never_breaks_on_network_exceptions(self):
        # Client raises ConnectError on GET
        self.mock_client.get.side_effect = httpx.ConnectError("Connection refused by host")
        report = self.engine.diagnose("https://target.internal/api/down")

        self.assertIsNotNone(report.error)
        self.assertIn("ConnectError", report.error)
        # Did not raise exception!

        # Batch runner with mix of working and broken URLs
        urls = [
            "https://target.internal/api/down",
            "https://target.internal/billing",  # Excluded
            "https://target.internal/api/ok",
        ]
        mock_ok_resp = MagicMock()
        mock_ok_resp.status_code = 200
        mock_ok_resp.headers = {"content-type": "application/json"}
        mock_ok_resp.text = '{"status": "ok"}'
        mock_ok_resp.audit_entry = {"response": {"elapsed_ms": 15.0}}

        def get_side_effect(url, **kwargs):
            if "down" in url:
                raise httpx.TimeoutException("Read timed out")
            return mock_ok_resp

        self.mock_client.get.side_effect = get_side_effect
        self.mock_client.request.return_value = mock_ok_resp

        reports = self.engine.diagnose_batch(urls)
        self.assertEqual(len(reports), 3)
        self.assertIsNotNone(reports[0].error)  # Down
        self.assertIsNotNone(reports[1].skipped_reason)  # Excluded /billing
        self.assertEqual(reports[2].status_code, 200)  # OK


if __name__ == "__main__":
    unittest.main()
