"""
Unit tests for ScopeValidator: Verifying strict boundary enforcement.
"""

import unittest
from core.scope_validator import (
    ScopeValidator,
    OutOfScopeDomainError,
    OutOfScopePathError,
    ProhibitedTargetError,
)

SAMPLE_PROGRAM = {
    "name": "Test VDP",
    "in_scope": [
        "staging.target.com",
        "*.api.target.com",
    ],
    "out_of_scope": {
        "domains": [
            "prod.target.com",
            "target.com",
            "admin.target.com",
        ],
        "paths": [
            "*/logout*",
            "*/reset-password*",
            "*/billing/*",
        ],
    },
    "rules_of_engagement": {
        "prohibit_dos": True,
    },
}

LOCAL_PROGRAM = {
    "name": "Local Lab",
    "in_scope": [
        "localhost:3000",
        "127.0.0.1:3000",
    ],
    "out_of_scope": {"domains": [], "paths": []},
}


class TestScopeValidator(unittest.TestCase):

    def setUp(self):
        self.validator = ScopeValidator(SAMPLE_PROGRAM)
        self.local_validator = ScopeValidator(LOCAL_PROGRAM)

    def test_authorized_exact_domain_passes(self):
        # Should pass without error
        self.validator.validate_url("https://staging.target.com/v1/users")
        self.validator.validate_url("https://staging.target.com/")

    def test_authorized_wildcard_domain_passes(self):
        # Should pass
        self.validator.validate_url("https://auth.api.target.com/login")
        self.validator.validate_url("https://v2.api.target.com/items")

    def test_unauthorized_domain_fails(self):
        with self.assertRaises(OutOfScopeDomainError):
            self.validator.validate_url("https://unauthorized.target.com/dashboard")

        with self.assertRaises(OutOfScopeDomainError):
            self.validator.validate_url("https://google.com")

    def test_explicitly_excluded_domain_fails(self):
        with self.assertRaises(OutOfScopeDomainError):
            self.validator.validate_url("https://prod.target.com/index.html")

        with self.assertRaises(OutOfScopeDomainError):
            self.validator.validate_url("https://admin.target.com/console")

    def test_explicitly_excluded_path_fails(self):
        with self.assertRaises(OutOfScopePathError):
            self.validator.validate_url("https://staging.target.com/logout")

        with self.assertRaises(OutOfScopePathError):
            self.validator.validate_url("https://staging.target.com/auth/reset-password?token=123")

        with self.assertRaises(OutOfScopePathError):
            self.validator.validate_url("https://staging.target.com/billing/invoices")

    def test_cloud_metadata_service_is_blocked(self):
        with self.assertRaises(ProhibitedTargetError):
            self.validator.validate_url("http://169.254.169.254/latest/meta-data/")

    def test_ssrf_internal_ip_blocked_on_external_program(self):
        with self.assertRaises(ProhibitedTargetError):
            self.validator.validate_url("http://127.0.0.1:8080/internal")

        with self.assertRaises(ProhibitedTargetError):
            self.validator.validate_url("http://10.0.0.1/admin")

    def test_local_lab_allows_localhost(self):
        # Local program explicitly has localhost in scope
        self.local_validator.validate_url("http://localhost:3000/#/products")
        self.local_validator.validate_url("http://127.0.0.1:3000/api")

    def test_literal_path_matches_exact_and_subpath(self):
        program = {
            "name": "Literal Test",
            "in_scope": ["staging.target.com"],
            "out_of_scope": {"paths": ["/billing", "/logout"]},
        }
        val = ScopeValidator(program)
        # Exact match
        with self.assertRaises(OutOfScopePathError):
            val.validate_url("https://staging.target.com/billing")
        with self.assertRaises(OutOfScopePathError):
            val.validate_url("https://staging.target.com/billing/")
        # Direct subpaths
        with self.assertRaises(OutOfScopePathError):
            val.validate_url("https://staging.target.com/billing/invoices")
        with self.assertRaises(OutOfScopePathError):
            val.validate_url("https://staging.target.com/billing?tab=history")
        with self.assertRaises(OutOfScopePathError):
            val.validate_url("https://staging.target.com/logout/confirm")

        # Must NOT match partial names or nested segments under other prefixes
        val.validate_url("https://staging.target.com/billing-settings")
        val.validate_url("https://staging.target.com/api/v1/billing/stripe-webhook")
        val.validate_url("https://staging.target.com/auth/api/logout")

    def test_wildcard_path_matches_nested_segments(self):
        program = {
            "name": "Wildcard Test",
            "in_scope": ["staging.target.com"],
            "out_of_scope": {"paths": ["*/billing/*", "*delete*", "*/logout"]},
        }
        val = ScopeValidator(program)
        with self.assertRaises(OutOfScopePathError):
            val.validate_url("https://staging.target.com/api/v1/billing/stripe-webhook")
        with self.assertRaises(OutOfScopePathError):
            val.validate_url("https://staging.target.com/api/v2/users/delete/profile")
        with self.assertRaises(OutOfScopePathError):
            val.validate_url("https://staging.target.com/auth/api/logout")

    def test_top_level_excluded_paths_schema(self):
        # StateHunter export schema uses top-level `excluded_paths`
        program = {
            "name": "StateHunter Schema Test",
            "in_scope": ["https://target.com"],
            "excluded_paths": ["/delete", "*/sensitive/*"],
            "discovered_endpoints": ["/api/v1/users", "/admin/metrics"],
            "flagged_sensitive_endpoints": ["/admin/metrics"],
        }
        val = ScopeValidator(program)
        self.assertEqual(len(val.discovered_endpoints), 2)
        self.assertEqual(len(val.flagged_sensitive_endpoints), 1)
        with self.assertRaises(OutOfScopePathError):
            val.validate_url("https://target.com/delete/account")
        with self.assertRaises(OutOfScopePathError):
            val.validate_url("https://target.com/api/sensitive/data")
        val.validate_url("https://target.com/api/v1/users")

    def test_path_scoped_in_scope_rules(self):
        program = {
            "name": "Path-Scoped Scope Test",
            "in_scope": [
                "https://target.com/api/*",
                "/internal/*",
            ],
            "out_of_scope": {"paths": []},
        }
        val = ScopeValidator(program)
        val.validate_url("https://target.com/api/v1/test")
        val.validate_url("https://target.com/internal/flags")
        with self.assertRaises(OutOfScopeDomainError):
            val.validate_url("https://target.com/public/landing")


if __name__ == "__main__":
    unittest.main()

