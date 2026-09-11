"""
Unit tests for ScopedHttpClient, AuditLogger, and ReportBuilder.
"""

import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import httpx

from audit.audit_logger import AuditLogger
from core.client import ScopedHttpClient
from core.gatekeeper import Gatekeeper
from core.scope_validator import ScopeValidator, OutOfScopeDomainError
from reporting.report_builder import ReportBuilder


class TestClientAndAudit(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.log_file = os.path.join(self.temp_dir, "test_audit.jsonl")

        self.program_cfg = {
            "name": "Mock Test VDP",
            "in_scope": ["api.mocktarget.com"],
            "out_of_scope": {"domains": [], "paths": []},
            "rules_of_engagement": {"header_tag": "X-Custom-Bounty"},
        }
        self.validator = ScopeValidator(self.program_cfg)
        self.gatekeeper = Gatekeeper(
            rate_limit_per_second=20.0,
            require_interactive=False,
            approval_hook=lambda req: True,
        )
        self.logger = AuditLogger(self.log_file)
        self.client = ScopedHttpClient(
            scope_validator=self.validator,
            gatekeeper=self.gatekeeper,
            audit_logger=self.logger,
            researcher_identifier="test_researcher_handle",
        )

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch("httpx.Client.request")
    def test_end_to_end_authorized_probe(self, mock_httpx_req):
        # Mock HTTP response
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.text = '{"status": "ok", "user": "test"}'
        mock_response.json.return_value = {"status": "ok", "user": "test"}
        mock_response.url = httpx.URL("https://api.mocktarget.com/v1/status")
        mock_response.headers = {"content-type": "application/json"}
        mock_httpx_req.return_value = mock_response

        # Execute request
        res = self.client.get("https://api.mocktarget.com/v1/status", rationale="Testing status endpoint")

        # Verify response wrapper
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json(), {"status": "ok", "user": "test"})

        # Verify compliance headers were passed to httpx
        called_args, called_kwargs = mock_httpx_req.call_args
        headers = called_kwargs.get("headers", {})
        self.assertEqual(headers.get("X-Custom-Bounty"), "test_researcher_handle")
        self.assertIn("AuditGuard", headers.get("User-Agent", ""))

        # Verify audit ledger entry was written
        entries = self.logger.get_recent_entries()
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry["request"]["url"], "https://api.mocktarget.com/v1/status")
        self.assertEqual(entry["response"]["status_code"], 200)
        self.assertEqual(entry["program"], "Mock Test VDP")

        # Test ReportBuilder generating deterministic Markdown
        report = ReportBuilder.build_report(
            title="Information Disclosure in Status Route",
            severity="low",
            cwe_id="CWE-200",
            summary="Endpoint returns diagnostic user information without session checks.",
            interaction=entry,
            steps_to_reproduce=["Send GET request to /v1/status", "Inspect response JSON"],
            impact="Exposes non-sensitive testing credentials.",
            remediation="Restrict endpoint access or remove test user flag.",
            researcher_handle="test_researcher",
        )

        self.assertIn("# Information Disclosure in Status Route", report)
        self.assertIn("curl -i -X GET https://api.mocktarget.com/v1/status", report)
        self.assertIn("X-Custom-Bounty: test_researcher_handle", report)
        self.assertIn("HTTP 200", report)

    def test_out_of_scope_call_never_hits_network(self):
        with self.assertRaises(OutOfScopeDomainError):
            self.client.get("https://unauthorized.target.com/secret")

        # Confirm audit log is empty (no network call was made)
        self.assertEqual(len(self.logger.get_recent_entries()), 0)


if __name__ == "__main__":
    unittest.main()
