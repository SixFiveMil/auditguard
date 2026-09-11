"""
Unit tests for AuditGuard Git Ignore & Data Hygiene Rules.
Verifies that client assessment reports, researcher credentials, imported scope files,
and sensitive audit traffic logs are strictly excluded from git tracking.
"""

import os
import subprocess
import unittest
from pathlib import Path


class TestGitignoreHygiene(unittest.TestCase):
    """Verifies that .gitignore prevents accidental leakage of sensitive engagement artifacts."""

    @classmethod
    def setUpClass(cls):
        cls.repo_root = Path(__file__).resolve().parent.parent
        cls.gitignore_path = cls.repo_root / ".gitignore"

    def test_gitignore_file_exists(self):
        self.assertTrue(self.gitignore_path.exists(), ".gitignore must exist in the repository root")

    def test_gitignore_contains_critical_patterns(self):
        content = self.gitignore_path.read_text(encoding="utf-8")

        # 1. Reports exclusion
        self.assertIn("reports/*.pdf", content)
        self.assertIn("reports/*.html", content)
        self.assertIn("reports/*.md", content)
        self.assertIn("!reports/.gitkeep", content)

        # 2. Local researcher environment / credentials
        self.assertIn(".env", content)
        self.assertIn("config/researcher.env", content)
        self.assertIn("config/*.local.yaml", content)

        # 3. Scope imports from StateHunter
        self.assertIn("*scope*.yaml", content)

        # 4. Audit ledger logs
        self.assertIn("audit/*.jsonl", content)
        self.assertIn("!audit/.gitkeep", content)

    def test_git_check_ignore_behavior(self):
        """Uses git check-ignore command to ensure git engine honors hygiene rules."""
        sensitive_paths = [
            "reports/engagement_sow.pdf",
            "reports/deliverable.html",
            "reports/summary.md",
            "config/researcher.env",
            "config/programs.local.yaml",
            "juiceshop_scope.yaml",
            "audit/live_audit.jsonl",
        ]

        safe_paths = [
            "reports/.gitkeep",
            "audit/.gitkeep",
            "main.py",
            "core/rule_engine.py",
            "rules/diagnostics/cors-arbitrary-origin.yaml",
        ]

        # Run git check-ignore against sensitive paths
        try:
            res_ignored = subprocess.run(
                ["git", "check-ignore"] + sensitive_paths,
                cwd=str(self.repo_root),
                capture_output=True,
                text=True,
                check=False,
            )
            ignored_lines = [line.strip().replace("\\", "/") for line in res_ignored.stdout.splitlines() if line.strip()]

            for p in sensitive_paths:
                self.assertIn(
                    p,
                    ignored_lines,
                    f"Expected sensitive path '{p}' to be ignored by Git.",
                )

            # Run git check-ignore against safe paths
            res_safe = subprocess.run(
                ["git", "check-ignore"] + safe_paths,
                cwd=str(self.repo_root),
                capture_output=True,
                text=True,
                check=False,
            )
            safe_ignored = [line.strip().replace("\\", "/") for line in res_safe.stdout.splitlines() if line.strip()]

            for sp in safe_paths:
                self.assertNotIn(
                    sp,
                    safe_ignored,
                    f"Safe path '{sp}' should NOT be ignored by Git.",
                )
        except FileNotFoundError:
            self.skipTest("git executable not found in PATH")


if __name__ == "__main__":
    unittest.main()
