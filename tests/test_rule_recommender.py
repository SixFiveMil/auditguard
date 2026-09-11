"""
Unit tests for Discovery-Driven Rule Recommender.
Verifies target profiling heuristics, trait extraction, template candidate loading,
relevance scoring, rationale generation, and template importing.
"""

import os
import tempfile
import unittest
from pathlib import Path

from core.rule_engine import DiagnosticTemplate, HttpRequestStep, MatcherRule
from core.rule_recommender import DiscoveryProfiler, DiscoveryTrait, RuleRecommendation, RuleRecommender


class TestDiscoveryProfiler(unittest.TestCase):
    """Verifies reconnaissance trait extraction."""

    def test_profile_routes_heuristics(self):
        prog_cfg = {
            "discovered_endpoints": [
                "/engine.io",
                "/administration",
                "/rest/admin/users",
                "/login",
                "/wallet-web3",
            ],
            "flagged_sensitive_endpoints": ["/administration"],
            "robots_disallow_directives": ["/ftp"],
        }

        traits = DiscoveryProfiler.profile_program(prog_cfg)
        tokens = {t.token for t in traits}

        self.assertIn("websocket", tokens)
        self.assertIn("admin", tokens)
        self.assertIn("api", tokens)
        self.assertIn("auth", tokens)
        self.assertIn("web3", tokens)
        self.assertIn("ftp", tokens)
        # Universal hygiene
        self.assertIn("cors", tokens)
        self.assertIn("headers", tokens)

    def test_profile_live_headers_and_body(self):
        headers = {
            "Server": "Kestrel",
            "X-Powered-By": "Express",
        }
        body = '<!DOCTYPE html><html><body ng-version="14.2.0"><app-root></app-root></body></html>'

        traits = DiscoveryProfiler.profile_program({}, live_headers=headers, live_body=body)
        tokens = {t.token for t in traits}

        self.assertIn("express", tokens)
        self.assertIn("nodejs", tokens)
        self.assertIn("dotnet", tokens)
        self.assertIn("angular", tokens)
        self.assertIn("spa", tokens)


class TestRuleRecommender(unittest.TestCase):
    """Verifies template scoring, safety filters, and importing."""

    def setUp(self):
        self.sample_traits = [
            DiscoveryTrait(category="technology", token="angular", evidence="Detected Angular SPA marker", weight=2.5),
            DiscoveryTrait(category="technology", token="express", evidence="X-Powered-By: Express", weight=2.5),
            DiscoveryTrait(category="route", token="websocket", evidence="Discovered endpoint: /engine.io", weight=2.0),
            DiscoveryTrait(category="route", token="admin", evidence="Sensitive route: /administration", weight=2.0),
        ]

        self.sample_templates = [
            DiagnosticTemplate(
                id="angular-detect",
                name="Angular Detect",
                severity="INFO",
                description="Detects Angular version",
                cwe_id="CWE-16",
                remediation="",
                tags=["tech", "angular", "discovery"],
                http_steps=[HttpRequestStep(method="GET", path=["{{BaseURL}}"])],
                file_path="/mock/angular-detect.yaml",
            ),
            DiagnosticTemplate(
                id="switch-protocol",
                name="WebSocket Protocol Switch",
                severity="INFO",
                description="Checks WebSocket support",
                cwe_id="CWE-16",
                remediation="",
                tags=["protocol", "websocket", "tech"],
                http_steps=[HttpRequestStep(method="GET", path=["{{BaseURL}}/engine.io"])],
                file_path="/mock/switch-protocol.yaml",
            ),
            DiagnosticTemplate(
                id="unrelated-wordpress-plugin",
                name="WordPress Arbitrary Plugin",
                severity="LOW",
                description="Checks WP plugin",
                cwe_id="CWE-200",
                remediation="",
                tags=["wordpress", "wp-plugin"],
                http_steps=[HttpRequestStep(method="GET", path=["{{BaseURL}}/wp-content/plugins/xyz"])],
                file_path="/mock/wp-plugin.yaml",
            ),
            DiagnosticTemplate(
                id="dangerous-destructive-probe",
                name="Destructive Delete Probe",
                severity="HIGH",
                description="Unsafe write check",
                cwe_id="CWE-284",
                remediation="",
                tags=["admin", "dangerous"],
                http_steps=[HttpRequestStep(method="DELETE", path=["{{BaseURL}}/admin/delete"])],
                file_path="/mock/delete-probe.yaml",
            ),
        ]

    def test_recommender_scoring_and_filtering(self):
        recommender = RuleRecommender(repo_path="rules/diagnostics")
        recs = recommender.recommend(self.sample_traits, self.sample_templates, min_score=30)

        rec_ids = [r.template_id for r in recs]
        self.assertIn("angular-detect", rec_ids)
        self.assertIn("switch-protocol", rec_ids)
        self.assertNotIn("unrelated-wordpress-plugin", rec_ids)

        # Angular recommendation rationale should cite Angular marker
        ang_rec = next(r for r in recs if r.template_id == "angular-detect")
        self.assertGreaterEqual(ang_rec.relevance_score, 80)
        self.assertIn("Detected Angular SPA marker", ang_rec.rationale)

    def test_import_recommendations(self):
        with tempfile.TemporaryDirectory() as src_dir, tempfile.TemporaryDirectory() as dest_dir:
            src_file = Path(src_dir) / "test-rule.yaml"
            src_file.write_text("id: test-rule\ninfo:\n  name: Test\n", encoding="utf-8")

            rec = RuleRecommendation(
                template_id="test-rule",
                template_name="Test",
                severity="INFO",
                cwe_id="CWE-16",
                file_path=str(src_file),
                relevance_score=90,
                matched_traits=["angular"],
                rationale="Test rationale",
            )

            count = RuleRecommender.import_recommendations([rec], target_dir=dest_dir)
            self.assertEqual(count, 1)
            self.assertTrue((Path(dest_dir) / "test-rule.yaml").exists())


if __name__ == "__main__":
    unittest.main()
