"""
Unit tests for AuditGuard Attack Surface Drift & Regression Monitor (core/drift_monitor.py).
Validates route drift, status transitions, header regressions, and report outputs.
"""

import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock
from core.drift_monitor import AttackSurfaceDriftMonitor, RouteDriftItem, DriftReport


class TestAttackSurfaceDriftMonitor(unittest.TestCase):
    """Verifies attack surface drift analysis and security regression tracking."""

    def setUp(self):
        self.baseline_session = {
            "session_id": "base001",
            "program_key": "juiceshop",
            "timestamp": "2026-09-10T10:00:00Z",
            "endpoints": [
                "http://localhost:3000/api/Feedbacks",
                "http://localhost:3000/rest/products",
            ],
            "findings": [
                {
                    "title": "CORS Wildcard Allowed",
                    "severity": "HIGH",
                    "cwe_id": "CWE-942",
                    "affected_urls": ["http://localhost:3000/api/Feedbacks"],
                }
            ],
        }

    def test_compare_sessions_new_routes_and_findings(self):
        current_session = {
            "session_id": "curr002",
            "program_key": "juiceshop",
            "timestamp": "2026-09-11T10:00:00Z",
            "endpoints": [
                "http://localhost:3000/api/Feedbacks",
                "http://localhost:3000/rest/products",
                "http://localhost:3000/api/Users",  # Newly discovered route
            ],
            "findings": [
                {
                    "title": "CORS Wildcard Allowed",
                    "severity": "HIGH",
                    "cwe_id": "CWE-942",
                    "affected_urls": ["http://localhost:3000/api/Feedbacks"],
                },
                {
                    "title": "User Enumeration on /api/Users",  # New vulnerability regression
                    "severity": "CRITICAL",
                    "cwe_id": "CWE-200",
                    "affected_urls": ["http://localhost:3000/api/Users"],
                },
            ],
        }

        monitor = AttackSurfaceDriftMonitor()
        report = monitor.compare_sessions(self.baseline_session, current_session)

        self.assertTrue(report.has_drift)
        self.assertEqual(report.baseline_endpoint_count, 2)
        self.assertEqual(report.current_endpoint_count, 3)

        # Check new route drift
        new_route_drifts = [d for d in report.drifts if d.drift_type == "NEW_ROUTE"]
        self.assertEqual(len(new_route_drifts), 1)
        self.assertIn("/api/Users", new_route_drifts[0].url)

        # Check security regression drift
        sec_reg_drifts = [d for d in report.drifts if d.drift_type == "SECURITY_REGRESSION"]
        self.assertEqual(len(sec_reg_drifts), 1)
        self.assertEqual(sec_reg_drifts[0].severity, "CRITICAL")
        self.assertIn("User Enumeration", sec_reg_drifts[0].description)

    def test_report_serialization(self):
        report = DriftReport(
            baseline_session_id="base001",
            current_session_id="curr002",
            program_key="juiceshop",
            timestamp="2026-09-11T12:00:00Z",
            baseline_endpoint_count=5,
            current_endpoint_count=6,
            drifts=[
                RouteDriftItem(
                    url="http://localhost:3000/admin",
                    drift_type="NEW_ROUTE",
                    severity="HIGH",
                    baseline_value=None,
                    current_value="Active",
                    description="Admin endpoint exposed",
                )
            ],
        )

        md = report.to_markdown()
        self.assertIn("# Attack Surface Drift & Regression Report", md)
        self.assertIn("`juiceshop`", md)
        self.assertIn("Admin endpoint exposed", md)

        data = report.to_dict()
        self.assertEqual(data["total_drifts"], 1)
        self.assertEqual(data["high_severity_drifts"], 1)

    def test_save_report(self):
        report = DriftReport(
            baseline_session_id="base001",
            current_session_id="curr002",
            program_key="juiceshop",
            timestamp="2026-09-11T12:00:00Z",
            baseline_endpoint_count=1,
            current_endpoint_count=1,
            drifts=[],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            md_path, json_path = AttackSurfaceDriftMonitor.save_report(report, output_dir=tmpdir, base_name="test_drift")
            self.assertTrue(os.path.isfile(md_path))
            self.assertTrue(os.path.isfile(json_path))
            with open(md_path, "r", encoding="utf-8") as fh:
                self.assertIn("No attack surface drift", fh.read())


if __name__ == "__main__":
    unittest.main()
