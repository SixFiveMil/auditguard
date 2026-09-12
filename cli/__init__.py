"""
AuditGuard CLI package.
Exposes argument parsing, command dispatching, and CLI handlers.
"""

from cli.commands import (
    cmd_audit_auth,
    cmd_audit_endpoints,
    cmd_check,
    cmd_diagnose,
    cmd_endpoints,
    cmd_export_report,
    cmd_export_sow,
    cmd_export_triage,
    cmd_harvest_scope,
    cmd_import_scope,
    cmd_logs,
    cmd_monitor,
    cmd_probe,
    cmd_recommend_rules,
    cmd_retest,
    cmd_rules,
    cmd_safe_harbor,
    cmd_scope,
    cmd_search_programs,
    get_active_validator,
    load_config,
)
from cli.parser import build_parser

__all__ = [
    "build_parser",
    "load_config",
    "get_active_validator",
    "cmd_scope",
    "cmd_check",
    "cmd_probe",
    "cmd_logs",
    "cmd_search_programs",
    "cmd_harvest_scope",
    "cmd_import_scope",
    "cmd_endpoints",
    "cmd_export_report",
    "cmd_diagnose",
    "cmd_audit_endpoints",
    "cmd_export_sow",
    "cmd_rules",
    "cmd_recommend_rules",
    "cmd_retest",
    "cmd_safe_harbor",
    "cmd_export_triage",
    "cmd_audit_auth",
    "cmd_monitor",
]
