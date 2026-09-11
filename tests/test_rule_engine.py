"""
Unit tests for AuditGuard Declarative Rule Engine (Nuclei Standard).
Verifies YAML template parsing, inverted index querying, matcher conditions,
placeholder resolution, and strict scope barrier enforcement.
"""

import os
import tempfile
import unittest
from unittest.mock import MagicMock

import httpx

from core.client import AuditResponse, ScopedHttpClient
from core.diagnostics import DiagnosticFinding, SecurityDiagnosticEngine
from core.rule_engine import (
    DiagnosticTemplate,
    HttpRequestStep,
    MatcherRule,
    NucleiDiagnosticRunner,
    RuleCatalog,
    TemplateMatcherEvaluator,
)
from core.scope_validator import ScopeValidator, ScopeViolationError


def make_audit_response(status_code: int = 200, headers: dict = None, text: str = "") -> AuditResponse:
    raw = httpx.Response(status_code, headers=headers or {}, text=text)
    return AuditResponse(raw, {"request_id": "test-req"})


class TestTemplateMatcherEvaluator(unittest.TestCase):
    """Verifies matcher logic for status, words, regex, negative matches, and headers."""

    def test_status_matcher(self):
        resp = make_audit_response(status_code=200, text="OK")
        matcher = MatcherRule(type="status", status=[200, 301])
        self.assertTrue(TemplateMatcherEvaluator.evaluate_matcher(matcher, resp))

        matcher_fail = MatcherRule(type="status", status=[403, 404])
        self.assertFalse(TemplateMatcherEvaluator.evaluate_matcher(matcher_fail, resp))

    def test_word_matcher_body(self):
        resp = make_audit_response(status_code=200, text="Hello World from Angular SPA")
        
        # Positive match OR
        matcher_or = MatcherRule(type="word", part="body", words=["Angular", "React"], condition="or")
        self.assertTrue(TemplateMatcherEvaluator.evaluate_matcher(matcher_or, resp))

        # Positive match AND
        matcher_and = MatcherRule(type="word", part="body", words=["Hello", "Angular"], condition="and")
        self.assertTrue(TemplateMatcherEvaluator.evaluate_matcher(matcher_and, resp))

        # Negative match
        matcher_neg = MatcherRule(type="word", part="body", words=["Vue"], negative=True)
        self.assertTrue(TemplateMatcherEvaluator.evaluate_matcher(matcher_neg, resp))

        # Case insensitive match
        matcher_ci = MatcherRule(type="word", part="body", words=["angular spa"], case_insensitive=True)
        self.assertTrue(TemplateMatcherEvaluator.evaluate_matcher(matcher_ci, resp))

    def test_word_matcher_header(self):
        headers = {
            "Access-Control-Allow-Origin": "https://evil.attacker.com",
            "Access-Control-Allow-Credentials": "true",
            "Server": "Kestrel",
        }
        resp = make_audit_response(status_code=200, headers=headers, text="{}")

        matcher_hdr = MatcherRule(
            type="word",
            part="header",
            words=["Access-Control-Allow-Origin: https://evil.attacker.com"], case_insensitive=True,
            condition="and",
        )
        self.assertTrue(TemplateMatcherEvaluator.evaluate_matcher(matcher_hdr, resp))

    def test_regex_matcher(self):
        resp = make_audit_response(status_code=200, text='{"swagger": "2.0", "info": {"version": "1.0"}}')
        matcher_regex = MatcherRule(
            type="regex",
            part="body",
            regex=[r'"swagger"\s*:\s*"2\.0"', r'"info"'],
            condition="and",
        )
        self.assertTrue(TemplateMatcherEvaluator.evaluate_matcher(matcher_regex, resp))

        matcher_regex_fail = MatcherRule(
            type="regex",
            part="body",
            regex=[r'"openapi"\s*:\s*"3\.[0-9]"'],
        )
        self.assertFalse(TemplateMatcherEvaluator.evaluate_matcher(matcher_regex_fail, resp))


class TestRuleCatalog(unittest.TestCase):
    """Verifies catalog loading, indexing, and querying."""

    def setUp(self):
        self.catalog = RuleCatalog()
        self.loaded_count = self.catalog.load_from_directory("rules/diagnostics")

    def test_catalog_loads_built_in_rules(self):
        self.assertGreaterEqual(self.loaded_count, 5)
        self.assertIn("cors-arbitrary-origin-reflection", self.catalog.templates)
        self.assertIn("angular-client-state-exposure", self.catalog.templates)
        self.assertIn("exposed-openapi-swagger-spec", self.catalog.templates)
        self.assertIn("http-verb-tampering-inconsistency", self.catalog.templates)
        self.assertIn("sensitive-cache-control-hygiene", self.catalog.templates)

    def test_query_by_tag(self):
        results = self.catalog.query(tags=["angular"])
        self.assertGreaterEqual(len(results), 1)
        self.assertTrue(any(t.id == "angular-client-state-exposure" for t in results))

        results_cors = self.catalog.query(tags=["cors"])
        self.assertGreaterEqual(len(results_cors), 1)
        self.assertEqual(results_cors[0].id, "cors-arbitrary-origin-reflection")

    def test_query_by_severity(self):
        critical_results = self.catalog.query(severities=["CRITICAL"])
        self.assertTrue(any(t.id == "cors-arbitrary-origin-reflection" for t in critical_results))

        low_results = self.catalog.query(severities=["LOW"])
        ids = [t.id for t in low_results]
        self.assertIn("exposed-openapi-swagger-spec", ids)
        self.assertIn("sensitive-cache-control-hygiene", ids)

    def test_query_by_keyword(self):
        results = self.catalog.query(keyword="swagger")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].id, "exposed-openapi-swagger-spec")

    def test_parse_malformed_yaml_returns_none(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write("invalid: yaml: mapping: error: : [unbalanced")
            temp_path = f.name
        try:
            tpl = RuleCatalog.parse_yaml_file(temp_path)
            self.assertIsNone(tpl)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)


class TestNucleiDiagnosticRunner(unittest.TestCase):
    """Verifies execution, variable substitution, and scope barriers."""

    def setUp(self):
        self.program_config = {
            "name": "Test Platform",
            "in_scope": ["https://target.internal", "*.target.internal"],
            "excluded_paths": ["/logout", "/admin/*"],
            "rules_of_engagement": {"header_tag": "X-Bug-Bounty"},
        }
        self.validator = ScopeValidator(self.program_config)
        self.mock_client = MagicMock(spec=ScopedHttpClient)
        self.mock_client.scope_validator = self.validator
        self.runner = NucleiDiagnosticRunner(self.mock_client)

    def test_run_template_matches_and_returns_finding(self):
        tpl = DiagnosticTemplate(
            id="test-rule",
            name="Test Exposure",
            severity="HIGH",
            description="Testing detection logic",
            cwe_id="CWE-200",
            remediation="Fix it",
            tags=["test"],
            http_steps=[
                HttpRequestStep(
                    method="GET",
                    path=["{{BaseURL}}/api/debug"],
                    matchers=[
                        MatcherRule(type="status", status=[200]),
                        MatcherRule(type="word", part="body", words=["DEBUG_MODE"]),
                    ],
                    matchers_condition="and",
                )
            ],
        )

        self.mock_client.request.return_value = make_audit_response(
            status_code=200,
            headers={"Content-Type": "application/json"},
            text='{"status": "ok", "env": "DEBUG_MODE"}',
        )

        finding = self.runner.run_template(tpl, "https://target.internal/some/page")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, "HIGH")
        self.assertIn("Test Exposure", finding.title)
        self.assertEqual(finding.cwe_id, "CWE-200")

        self.mock_client.request.assert_called_once()
        called_url = self.mock_client.request.call_args[1]["url"]
        self.assertEqual(called_url, "https://target.internal/api/debug")

    def test_runner_strictly_aborts_out_of_scope_target(self):
        tpl = DiagnosticTemplate(
            id="test-oos",
            name="Out of Scope Test",
            severity="LOW",
            description="Desc",
            cwe_id="CWE-200",
            remediation="",
            tags=[],
            http_steps=[
                HttpRequestStep(
                    method="GET",
                    path=["{{BaseURL}}/admin/secret"],
                    matchers=[MatcherRule(type="status", status=[200])],
                )
            ],
        )

        finding = self.runner.run_template(tpl, "https://target.internal")
        self.assertIsNone(finding)
        self.mock_client.request.assert_not_called()

    def test_runner_skips_non_safe_verbs(self):
        tpl = DiagnosticTemplate(
            id="test-post-skipped",
            name="Post Test",
            severity="LOW",
            description="Desc",
            cwe_id="CWE-16",
            remediation="",
            tags=[],
            http_steps=[
                HttpRequestStep(
                    method="POST",
                    path=["{{BaseURL}}/test"],
                    matchers=[MatcherRule(type="status", status=[200])],
                )
            ],
        )

        finding = self.runner.run_template(tpl, "https://target.internal")
        self.assertIsNone(finding)
        self.mock_client.request.assert_not_called()


if __name__ == "__main__":
    unittest.main()
