"""
AuditGuard CLI Argument Parser.
Constructs and configures the argparse argument parser and subcommands.
"""

from __future__ import annotations

import argparse

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
)


def build_parser() -> argparse.ArgumentParser:
    """Build and return the top-level ArgumentParser for AuditGuard CLI."""
    parser = argparse.ArgumentParser(
        description="AuditGuard: Scope & Oversight Management for Security Researchers"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # scope command
    sub = subparsers.add_parser("scope", help="Display active program scope and boundaries")
    sub.set_defaults(func=cmd_scope)

    # check command
    sub = subparsers.add_parser("check", help="Test a target URL against scope rules without sending traffic")
    sub.add_argument("url", help="Target URL to check")
    sub.set_defaults(func=cmd_check)

    # probe command
    sub = subparsers.add_parser("probe", help="Perform a scoped, authorized, and logged HTTP request")
    sub.add_argument("url", help="Target URL")
    sub.add_argument("-X", "--method", default="GET", help="HTTP Method (default: GET)")
    sub.add_argument("-r", "--rationale", help="Reason / test hypothesis for this action")
    sub.add_argument("-y", "--yes", action="store_true", help="Pre-approve this request without interactive prompt")
    sub.set_defaults(func=cmd_probe)

    # diagnose command (Deep single-target diagnostic suite)
    sub = subparsers.add_parser(
        "diagnose",
        help="Run comprehensive security diagnostics on a single endpoint (CORS, headers, methods, leaks)",
    )
    sub.add_argument("url", help="Target URL to diagnose")
    sub.add_argument("-s", "--sensitive", action="store_true", help="Treat endpoint as sensitive / administrative")
    sub.add_argument("-y", "--yes", action="store_true", help="Pre-approve diagnostics without interactive prompt")
    sub.add_argument("-o", "--output", help="Save markdown diagnostic report to file")
    sub.add_argument("-d", "--rules-dir", default="rules/diagnostics", help="Directory containing YAML diagnostic rules (default: rules/diagnostics)")
    sub.set_defaults(func=cmd_diagnose)

    # audit-endpoints command (Batch diagnostic scan)
    sub = subparsers.add_parser(
        "audit-endpoints",
        help="Run batch security diagnostics across all discovered endpoints from StateHunter",
    )
    sub.add_argument("--flagged-only", action="store_true", help="Audit only flagged sensitive/admin endpoints")
    sub.add_argument("-y", "--yes", action="store_true", help="Pre-approve batch audit without interactive prompt")
    sub.add_argument("-o", "--output", help="Save markdown, HTML, or PDF executive report to file")
    sub.add_argument("--pdf", help="Directly export executive PDF report to specified file")
    sub.add_argument("-d", "--rules-dir", default="rules/diagnostics", help="Directory containing YAML diagnostic rules (default: rules/diagnostics)")
    sub.add_argument("--assessor", default="Authorized Security Researcher", help="Lead assessor name for SOW report")
    sub.set_defaults(func=cmd_audit_endpoints)

    # export-sow command (Formal Statement of Work & Scope Deliverable)
    sub = subparsers.add_parser(
        "export-sow",
        help="Export formal Statement of Work (SOW) & verified scope deliverable (PDF, HTML, MD)",
    )
    sub.add_argument("-o", "--output", help="Output file path (e.g. reports/sow.pdf, sow.html, sow.md)")
    sub.add_argument("--assessor", default="Authorized Security Researcher", help="Lead researcher name")
    sub.add_argument("--title", help="Custom report title")
    sub.set_defaults(func=cmd_export_sow)

    # rules command (Nuclei-compatible rule catalog inspection)
    sub = subparsers.add_parser(
        "rules",
        help="Query and inspect open-source declarative YAML diagnostic rules",
    )
    sub.add_argument("-t", "--tag", help="Filter rules by tag (e.g. angular, cors, api, cache)")
    sub.add_argument("-s", "--severity", help="Filter rules by severity (critical, high, medium, low, info)")
    sub.add_argument("-q", "--query", help="Search keyword across rule ID, name, or description")
    sub.add_argument("-d", "--dir", "--rules-dir", dest="dir", default="rules/diagnostics", help="Directory containing YAML rules (default: rules/diagnostics)")
    sub.set_defaults(func=cmd_rules)

    # recommend-rules command
    sub = subparsers.add_parser(
        "recommend-rules",
        aliases=["suggest-rules"],
        help="Analyze target discovery profile and recommend tailored diagnostic templates from local repo",
    )
    sub.add_argument("-r", "--repo", help="Path to templates repository (default: auto-detect D:/repos/nuclei-templates or rules/diagnostics)")
    sub.add_argument("-m", "--min-score", type=int, default=40, help="Minimum relevance score (0-100, default: 40)")
    sub.add_argument("-n", "--limit", type=int, default=15, help="Maximum number of recommendations to display (default: 15)")
    sub.add_argument("--import", dest="import_rules", action="store_true", help="Copy recommended templates into rules/diagnostics/")
    sub.add_argument("--import-dir", default="rules/diagnostics", help="Destination folder for imported rules (default: rules/diagnostics)")
    sub.add_argument("--all-verbs", action="store_true", help="Allow non-idempotent HTTP verbs (default: only safe GET/HEAD/OPTIONS)")
    sub.set_defaults(func=cmd_recommend_rules)

    # logs command
    sub = subparsers.add_parser("logs", help="View recent audit ledger entries")
    sub.add_argument("-n", "--limit", type=int, default=10, help="Number of entries to show")
    sub.set_defaults(func=cmd_logs)

    # search-programs command
    sub = subparsers.add_parser(
        "search-programs", help="Search the public bug bounty program index (HackerOne, Bugcrowd, etc.)"
    )
    sub.add_argument("query", help="Company name, keyword, or domain to search")
    sub.set_defaults(func=cmd_search_programs)

    # harvest-scope command
    sub = subparsers.add_parser(
        "harvest-scope",
        help="Passively gather scope from security.txt and CT logs with vendor filtering",
    )
    sub.add_argument("domain", help="Root domain (e.g. example.com)")
    sub.add_argument("-n", "--name", help="Display name for the program")
    sub.set_defaults(func=cmd_harvest_scope)

    # import-scope command (StateHunter integration)
    sub = subparsers.add_parser(
        "import-scope",
        help="Import a StateHunter YAML scope export into config/programs.yaml",
    )
    sub.add_argument("file", help="Path to scope YAML file or '-' for stdin")
    sub.add_argument("-a", "--activate", action="store_true", help="Set the imported program as active")
    sub.set_defaults(func=cmd_import_scope)

    # endpoints command (Discovered route inspection)
    sub = subparsers.add_parser(
        "endpoints",
        help="Audit endpoints discovered by StateHunter against active scope rules",
    )
    sub.add_argument("--flagged-only", action="store_true", help="Display only flagged sensitive/admin endpoints")
    sub.set_defaults(func=cmd_endpoints)

    # export-report command (Automated markdown triage reporting)
    sub = subparsers.add_parser(
        "export-report",
        help="Generate a reproducible markdown bug bounty report from an audit interaction",
    )
    sub.add_argument("-i", "--request-id", required=True, help="Audit log Request ID (e.g. hash)")
    sub.add_argument("-t", "--title", help="Vulnerability Title")
    sub.add_argument("-s", "--severity", default="Medium", help="Severity: Critical, High, Medium, Low, Info")
    sub.add_argument("-c", "--cwe", default="CWE-200", help="Common Weakness Enumeration ID")
    sub.add_argument("--summary", help="Executive summary of the vulnerability")
    sub.add_argument("--steps", help="Semicolon-separated reproduction steps")
    sub.add_argument("--impact", help="Impact assessment")
    sub.add_argument("--remediation", help="Remediation guidance")
    sub.add_argument("--reporter", default="Authorized Researcher", help="Researcher name or handle")
    sub.add_argument("-o", "--output", help="Output file path (prints to stdout if omitted)")
    sub.set_defaults(func=cmd_export_report)

    # retest command (Targeted remediation re-verification)
    sub = subparsers.add_parser(
        "retest",
        help="Run targeted diagnostic re-tests on previously flagged endpoints to verify remediation",
    )
    sub.add_argument("-s", "--session", help="Path to audit session JSON file (default: audit/latest_findings.json)")
    sub.add_argument("-y", "--yes", action="store_true", help="Pre-approve re-test audit without interactive prompt")
    sub.add_argument("-o", "--output", help="Save differential remediation report (.pdf, .html, .md) to file")
    sub.add_argument("--pdf", help="Directly export remediation report PDF to file")
    sub.add_argument("-d", "--rules-dir", default="rules/diagnostics", help="Directory containing YAML diagnostic rules (default: rules/diagnostics)")
    sub.add_argument("--assessor", default="Authorized Security Researcher", help="Lead assessor name")
    sub.set_defaults(func=cmd_retest)

    # safe-harbor command (Proof-of-adherence inspection)
    sub = subparsers.add_parser(
        "safe-harbor",
        help="Inspect and verify the active engagement's Safe Harbor Proof-of-Adherence Certificate",
    )
    sub.add_argument("--log", default="audit/audit_log.jsonl", help="Path to audit log file (default: audit/audit_log.jsonl)")
    sub.set_defaults(func=cmd_safe_harbor)

    # export-triage command (HackerOne, Bugcrowd, GitHub Issues, Jira export)
    sub = subparsers.add_parser(
        "export-triage",
        help="Export audit findings to platform triage formats (HackerOne, Bugcrowd, GitHub, Jira)",
    )
    sub.add_argument("-s", "--session", help="Path or ID of audit session JSON (default: audit/latest_findings.json)")
    sub.add_argument("-f", "--format", choices=["all", "hackerone", "bugcrowd", "github", "jira"], default="all", help="Target submission format (default: all)")
    sub.add_argument("-o", "--output-dir", default="reports/triage", help="Output directory for generated triage files (default: reports/triage)")
    sub.add_argument("-p", "--program", help="Target program key (e.g. juiceshop)")
    sub.add_argument("--scope", help="Target asset / root domain scope")
    sub.add_argument("--jira-project", default="SEC", help="Jira project key (default: SEC)")
    sub.set_defaults(func=cmd_export_triage)

    # audit-auth command (Dual-role authorization matrix / IDOR prober)
    sub = subparsers.add_parser(
        "audit-auth",
        help="Run dual-role authorization matrix probing across identities to detect BOLA/IDOR and Privilege Escalation",
    )
    sub.add_argument("-u", "--url", help="Target endpoint to probe (or specify --session to probe recorded endpoints)")
    sub.add_argument("-s", "--session", help="Load target endpoints from recorded session JSON")
    sub.add_argument("-p", "--program", help="Program key to validate against")
    sub.add_argument("--role-a-name", default="user_a", help="Role A / Owner role name (default: user_a)")
    sub.add_argument("--role-a-header", help="Role A HTTP header string (e.g. 'Authorization: Bearer token_a')")
    sub.add_argument("--role-b-name", default="user_b", help="Role B / Foreign role name (default: user_b)")
    sub.add_argument("--role-b-header", help="Role B HTTP header string (e.g. 'Authorization: Bearer token_b')")
    sub.add_argument("--admin-header", help="Admin role HTTP header string (e.g. 'Authorization: Bearer admin_token')")
    sub.add_argument("-o", "--output", help="Save authorization findings to file (.json or .md)")
    sub.add_argument("-y", "--yes", action="store_true", help="Pre-approve probes without interactive prompt")
    sub.set_defaults(func=cmd_audit_auth)

    # monitor command (Attack surface drift and regression detection)
    sub = subparsers.add_parser(
        "monitor",
        help="Continuously monitor attack surface drift and security regressions against baseline sessions",
    )
    sub.add_argument("-b", "--baseline-session", help="Baseline session ID or path (default: latest session for program)")
    sub.add_argument("-c", "--compare-session", help="Second session to compare against for offline drift analysis")
    sub.add_argument("-l", "--live", action="store_true", help="Actively probe target to detect live attack surface drift")
    sub.add_argument("-p", "--program", help="Target program key")
    sub.add_argument("-o", "--output-dir", default="reports", help="Output directory for drift reports (default: reports)")
    sub.add_argument("-y", "--yes", action="store_true", help="Pre-approve live probes without interactive prompt")
    sub.set_defaults(func=cmd_monitor)

    return parser
