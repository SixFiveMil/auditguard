"""
Unit tests for AuditGuard Remediation Code Generator (core/remediation_snippets.py).
Validates framework-specific patch generation across Express, Nginx, and Angular.
"""

import unittest
from core.remediation_snippets import RemediationSnippetGenerator


class TestRemediationSnippets(unittest.TestCase):
    """Verifies automated remediation code generation."""

    def test_cors_snippets(self):
        # Node/Express default
        snip_node = RemediationSnippetGenerator.get_snippet("CWE-942", "CORS Wildcard Allowed", ["express"])
        self.assertIsNotNone(snip_node)
        self.assertEqual(snip_node.language, "javascript")
        self.assertIn("cors(", snip_node.code)

        # Nginx
        snip_nginx = RemediationSnippetGenerator.get_snippet("CWE-942", "CORS Wildcard Allowed", ["nginx"])
        self.assertIsNotNone(snip_nginx)
        self.assertEqual(snip_nginx.language, "nginx")
        self.assertIn("map $http_origin $cors_origin", snip_nginx.code)

    def test_csp_snippets(self):
        snip_helmet = RemediationSnippetGenerator.get_snippet("CWE-1021", "Missing CSP", ["express"])
        self.assertIsNotNone(snip_helmet)
        self.assertEqual(snip_helmet.language, "javascript")
        self.assertIn("helmet.contentSecurityPolicy", snip_helmet.code)

    def test_cache_hygiene_snippets(self):
        snip_cache = RemediationSnippetGenerator.get_snippet("CWE-524", "Missing no-store", ["express"])
        self.assertIsNotNone(snip_cache)
        self.assertIn("no-store", snip_cache.code)

    def test_access_control_snippets(self):
        # Express RBAC
        snip_rbac = RemediationSnippetGenerator.get_snippet("CWE-306", "Admin route unauthenticated", ["node"])
        self.assertIsNotNone(snip_rbac)
        self.assertIn("req.session", snip_rbac.code)

        # Angular Guard
        snip_angular = RemediationSnippetGenerator.get_snippet("CWE-306", "Admin route unauthenticated", ["angular"])
        self.assertIsNotNone(snip_angular)
        self.assertEqual(snip_angular.language, "typescript")
        self.assertIn("canActivate", snip_angular.code)

    def test_info_leak_snippets(self):
        snip_leak = RemediationSnippetGenerator.get_snippet("CWE-200", "Server version leak", ["express"])
        self.assertIsNotNone(snip_leak)
        self.assertIn("disable('x-powered-by')", snip_leak.code)


if __name__ == "__main__":
    unittest.main()
