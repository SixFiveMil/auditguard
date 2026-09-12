"""
AuditGuard - Compliance-first Scope Containment & Safe Harbor Engine.
Main CLI entry point for authorized security research and scope enforcement.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import List, Optional

from audit.audit_logger import AuditLogger
from cli import commands
from cli.commands import (
    cmd_audit_auth, cmd_audit_endpoints, cmd_check, cmd_diagnose,
    cmd_endpoints, cmd_export_report, cmd_export_sow, cmd_export_triage,
    cmd_harvest_scope, cmd_import_scope, cmd_logs, cmd_monitor,
    cmd_probe, cmd_recommend_rules, cmd_retest, cmd_rules,
    cmd_safe_harbor, cmd_scope, cmd_search_programs,
    get_active_validator, load_config,
)
from cli.parser import build_parser

__all__ = [
    "main", "build_parser", "load_config", "get_active_validator",
    "Path", "AuditLogger", "cmd_scope", "cmd_check", "cmd_probe",
    "cmd_logs", "cmd_search_programs", "cmd_harvest_scope",
    "cmd_import_scope", "cmd_endpoints", "cmd_export_report",
    "cmd_diagnose", "cmd_audit_endpoints", "cmd_export_sow", "cmd_rules",
    "cmd_recommend_rules", "cmd_retest", "cmd_safe_harbor",
    "cmd_export_triage", "cmd_audit_auth", "cmd_monitor",
]


def main(argv: Optional[List[str]] = None) -> int:
    """Load configuration, build parser, and execute the dispatched command."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not hasattr(args, "func"):
        parser.print_help()
        return 1

    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
