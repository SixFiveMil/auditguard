"""
Unit tests for AuditGuard Dual-Role Authorization Matrix & IDOR Prober (core/auth_matrix.py).
Validates comparative authorization testing across identities:
- Unauthenticated access on sensitive routes (CWE-306)
- Vertical privilege escalation (CWE-269)
- Horizontal BOLA / IDOR across user accounts (CWE-639)
"""

import unittest
from unittest.mock import MagicMock
from core.auth_matrix import AuthorizationMatrixAuditor, AuthRole, AuthProbeResult
from core.client import AuditResponse


class TestAuthorizationMatrixAuditor(unittest.TestCase):
    """Verifies comparative authorization matrix auditor."""

    def setUp(self):
        self.mock_client = MagicMock()
        self.auditor = AuthorizationMatrixAuditor(client=self.mock_client)

    def test_unauthenticated_admin_access(self):
        """Detects CWE-306 when unauthenticated request reaches an admin route with 200 OK."""
        role_user = AuthRole(role_name="user_a", headers={"Authorization": "Bearer token_a"})
        self.auditor.add_role(role_user)

        # Mock unauth response returning 200 OK on /api/admin/system
        def mock_get(url, headers=None, rationale=None):
            resp = MagicMock()
            resp.status_code = 200
            resp.text = '{"admin_panel": true, "secret_key": "xyz"}'
            resp.headers = {"Content-Type": "application/json"}
            return resp

        self.mock_client.get.side_effect = mock_get

        findings = self.auditor.probe_endpoint("http://localhost:3000/api/admin/system", is_admin_endpoint=True)
        self.assertTrue(any(f.cwe_id == "CWE-306" for f in findings))
        f_306 = next(f for f in findings if f.cwe_id == "CWE-306")
        self.assertEqual(f_306.severity, "CRITICAL")
        self.assertIn("Unauthenticated Access", f_306.title)

    def test_vertical_privilege_escalation(self):
        """Detects CWE-269 when a low-privilege role successfully accesses an admin route."""
        role_standard = AuthRole(role_name="low_priv", headers={"Authorization": "Bearer low_token"}, is_admin=False)
        self.auditor.add_role(role_standard)

        def mock_get(url, headers=None, rationale=None):
            resp = MagicMock()
            if headers and "low_token" in headers.get("Authorization", ""):
                # low-priv user gets 200 OK on admin endpoint
                resp.status_code = 200
                resp.text = '{"users": ["alice", "bob"], "role": "admin"}'
                resp.headers = {"Content-Type": "application/json"}
            else:
                # unauth gets 401
                resp.status_code = 401
                resp.text = '{"error": "Unauthorized"}'
                resp.headers = {"Content-Type": "application/json"}
            return resp

        self.mock_client.get.side_effect = mock_get

        findings = self.auditor.probe_endpoint("http://localhost:3000/administration", is_admin_endpoint=True)
        self.assertTrue(any(f.cwe_id == "CWE-269" for f in findings))
        f_269 = next(f for f in findings if f.cwe_id == "CWE-269")
        self.assertEqual(f_269.severity, "HIGH")
        self.assertIn("Vertical Privilege Escalation", f_269.title)

    def test_horizontal_bola_idor(self):
        """Detects CWE-639 when Role B retrieves the identical resource as Owner Role A."""
        role_a = AuthRole(role_name="user_a", headers={"Authorization": "Bearer token_a"})
        role_b = AuthRole(role_name="user_b", headers={"Authorization": "Bearer token_b"})
        self.auditor.add_role(role_a)
        self.auditor.add_role(role_b)

        def mock_get(url, headers=None, rationale=None):
            resp = MagicMock()
            if not headers:
                resp.status_code = 401
                resp.text = '{"error": "Unauthorized"}'
                resp.headers = {}
            else:
                # Both User A and User B get 200 OK with User A's basket data
                resp.status_code = 200
                resp.text = '{"basket_id": 42, "user_id": 1, "items": [{"id": 99, "price": 10.99}]}'
                resp.headers = {"Content-Type": "application/json"}
            return resp

        self.mock_client.get.side_effect = mock_get

        findings = self.auditor.probe_endpoint("http://localhost:3000/api/BasketItems/42", owner_role_name="user_a")
        self.assertTrue(any(f.cwe_id == "CWE-639" for f in findings))
        f_639 = next(f for f in findings if f.cwe_id == "CWE-639")
        self.assertEqual(f_639.severity, "HIGH")
        self.assertIn("BOLA / IDOR", f_639.title)
        self.assertGreaterEqual(f_639.similarity_score, 0.9)


if __name__ == "__main__":
    unittest.main()
