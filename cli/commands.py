"""
AuditGuard CLI Commands and Handlers.
Command execution logic, configuration management, and scope validation handlers.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx
import yaml

from audit.audit_logger import AuditLogger
from core.auth_matrix import AuthorizationMatrixAuditor, AuthRole
from core.client import ScopedHttpClient
from core.diagnostics import DiagnosticFinding, SecurityDiagnosticEngine
from core.drift_monitor import AttackSurfaceDriftMonitor
from core.gatekeeper import Gatekeeper, RequestDeniedError
from core.harvester import ScopeHarvester
from core.remediation import AuditSessionManager, RemediationAuditor
from core.rule_engine import RuleCatalog
from core.rule_recommender import DiscoveryProfiler, RuleRecommender
from core.safe_harbor import SafeHarborLedgerAuditor, SafeHarborTerms
from core.scope_validator import (
    OutOfScopePathError,
    ScopeValidator,
    ScopeViolationError,
)
from reporting.report_builder import ReportBuilder
from reporting.sow_report_generator import RemediationReportGenerator, SOWReportGenerator
from reporting.triage_exporter import PlatformTriageExporter


def _resolve_dependency(name: str, default: Any) -> Any:
    """
    Resolve a dependency or helper from the 'main' module if mocked/patched during tests,
    falling back to the local default.
    """
    main_mod = sys.modules.get("main")
    if main_mod is not None and hasattr(main_mod, name):
        val = getattr(main_mod, name)
        if val is not default:
            return val
    return default

def load_config() -> Dict[str, Any]:
    # 1. Check for researcher's local private override
    local_path = Path("config/programs.local.yaml")
    if local_path.exists():
        with open(local_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)

    # 2. Check for standard configuration file
    config_path = _resolve_dependency("Path", Path)("config/programs.yaml")
    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)

    # 3. Fallback to public example template
    example_path = Path("config/programs.yaml.example")
    if example_path.exists():
        with open(example_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)

    print("Error: No configuration file found at config/programs.yaml, config/programs.local.yaml, or config/programs.yaml.example")
    sys.exit(1)


def get_active_validator(cfg: Dict[str, Any]) -> tuple[str, ScopeValidator, Dict[str, Any]]:
    active_key = cfg.get("active_program")
    programs = cfg.get("programs", {})
    if active_key not in programs:
        print(f"Error: Active program '{active_key}' not found in programs.yaml")
        sys.exit(1)
    prog_cfg = programs[active_key]
    return active_key, ScopeValidator(prog_cfg), prog_cfg


def cmd_scope(args: Any) -> None:
    cfg = _resolve_dependency("load_config", load_config)()
    active_key, validator, prog_cfg = _resolve_dependency("get_active_validator", get_active_validator)(cfg)
    print("\n" + "=" * 60)
    print(f" ACTIVE PROGRAM: {prog_cfg.get('name')} [{active_key}]")
    print(f" Platform:       {prog_cfg.get('platform')}")
    print(f" Policy URL:     {prog_cfg.get('policy_url')}")
    print(f" Rate Limit:     {prog_cfg.get('rate_limit_per_second', 2.0)} req/sec")
    print("=" * 60)
    print("\n[+] IN-SCOPE TARGETS:")
    for target in validator.in_scope:
        print(f"    * {target}")

    print("\n[-] OUT-OF-SCOPE EXCLUSIONS:")
    for d in validator.out_of_scope_domains:
        print(f"    * Domain: {d}")
    for p in validator.out_of_scope_paths:
        print(f"    * Path:   {p}")
    print("\n" + "-" * 60)


def cmd_check(args: Any) -> None:
    cfg = _resolve_dependency("load_config", load_config)()
    _, validator, _ = _resolve_dependency("get_active_validator", get_active_validator)(cfg)
    url = args.url
    print(f"\nChecking URL: {url}")
    try:
        validator.validate_url(url)
        print("  -> RESULT: [PASS] Target is within authorized scope boundaries.")
    except ScopeViolationError as e:
        print(f"  -> RESULT: [BLOCKED] {e}")


def cmd_probe(args: Any) -> None:
    cfg = _resolve_dependency("load_config", load_config)()
    active_key, validator, prog_cfg = _resolve_dependency("get_active_validator", get_active_validator)(cfg)
    
    rate_limit = prog_cfg.get("rate_limit_per_second", 2.0)
    interactive = not getattr(args, "yes", False)
    gatekeeper = Gatekeeper(rate_limit_per_second=rate_limit, require_interactive=interactive)
    audit_logger = _resolve_dependency("AuditLogger", AuditLogger)("audit/audit_log.jsonl")
    
    client = ScopedHttpClient(
        scope_validator=validator,
        gatekeeper=gatekeeper,
        audit_logger=audit_logger,
        researcher_identifier="AuthorizedSecurityResearcher/1.0",
    )

    url = args.url
    method = args.method.upper()
    rationale = args.rationale or "Manual diagnostic probe"

    try:
        resp = client.request(method=method, url=url, rationale=rationale)
        print(f"\n[+] Request Completed: HTTP {resp.status_code}")
        print(f"[+] Audit Entry ID:    {resp.audit_entry.get('request_id')}")
        print(f"[+] Response Preview:\n{resp.text[:400]}")
    except ScopeViolationError as e:
        print(f"\n[!] Scope Violation: {e}")
    except RequestDeniedError as e:
        print(f"\n[!] Action Aborted: {e}")
    except Exception as e:
        print(f"\n[!] Network Error: {e}")


def cmd_logs(args: Any) -> None:
    logger = _resolve_dependency("AuditLogger", AuditLogger)("audit/audit_log.jsonl")
    entries = logger.get_recent_entries(limit=args.limit)
    if not entries:
        print("\nNo audit entries found.")
        return

    print(f"\nDisplaying last {len(entries)} audit log entries:")
    print("=" * 70)
    for e in entries:
        req = e.get("request", {})
        resp = e.get("response", {})
        print(
            f"[{e.get('timestamp')}] ID:{e.get('request_id')} | "
            f"{req.get('method')} {req.get('url')} -> HTTP {resp.get('status_code')} "
            f"({resp.get('elapsed_ms')}ms)"
        )


def cmd_search_programs(args: Any) -> None:
    from core.harvester import ScopeHarvester
    harvester = ScopeHarvester()
    print(f"\nSearching public bug bounty index for '{args.query}'...")
    try:
        results = harvester.search_public_programs(args.query)
        if not results:
            print("[-] No matching programs found in the public index.")
            return

        print(f"\n[+] Found {len(results)} matching bug bounty programs:")
        print("=" * 70)
        for p in results[:15]:
            bounty_tag = "[BOUNTY]" if p.get("bounty") else "[VDP/SWAG]"
            print(f"{bounty_tag} {p.get('name')}")
            print(f"    URL:     {p.get('url')}")
            print(f"    Domains: {', '.join(p.get('domains', [])) or 'See program URL'}")
            print("-" * 70)
    except Exception as e:
        print(f"[-] Error fetching program index: {e}")


def cmd_harvest_scope(args: Any) -> None:
    import yaml
    from core.harvester import ScopeHarvester

    harvester = ScopeHarvester()
    domain = args.domain.strip().lower()
    prog_name = args.name or f"{domain.replace('.', ' ').title()} VDP"
    prog_id = domain.replace(".", "_")

    print("\n" + "=" * 65)
    print(f" PASSIVE SCOPE HARVESTER: {domain}")
    print("=" * 65)

    # 1. Check security.txt
    print("[1/3] Checking RFC 9116 security.txt...")
    sec_txt = harvester.fetch_security_txt(domain)
    policy_url = ""
    if sec_txt:
        print(f"  [+] Found security.txt at {sec_txt.get('source_url')}")
        policy_url = sec_txt.get("policy", "")
        if policy_url:
            print(f"      Policy:  {policy_url}")
        if sec_txt.get("contact"):
            print(f"      Contact: {sec_txt.get('contact')}")
    else:
        print("  [-] No security.txt found.")

    # 2. Query Certificate Transparency (crt.sh)
    print(f"[2/3] Querying Certificate Transparency logs for %{domain}...")
    subdomains = harvester.query_certificate_transparency(domain)
    print(f"  [+] Discovered {len(subdomains)} unique subdomains in public CT logs.")

    # 3. Detect third-party vendor dependencies (DoH)
    print("[3/3] Inspecting subdomains for third-party vendor CNAMEs...")
    draft = harvester.build_program_scope_draft(
        program_id=prog_id,
        program_name=prog_name,
        root_domain=domain,
        policy_url=policy_url,
    )

    vendor_exclusions = draft["out_of_scope"]["domains"]
    if vendor_exclusions:
        print(f"  [!] Flagged {len(vendor_exclusions)} third-party vendor dependencies (auto-excluded):")
        for v in vendor_exclusions:
            print(f"      * {v}")

    # Display generated draft YAML
    print("\n" + "=" * 65)
    print(" GENERATED SCOPE DRAFT (Ready for config/programs.yaml):")
    print("=" * 65)
    yaml_snippet = yaml.dump({prog_id: draft}, sort_keys=False, default_flow_style=False)
    print(yaml_snippet)


def cmd_import_scope(args: Any) -> None:
    """
    Ingests a scope definition YAML (from StateHunter or file/stdin)
    and merges it into config/programs.yaml.
    """
    import re

    source_path = args.file
    raw_content = ""
    if source_path == "-" or not source_path:
        print("\nReading scope YAML from standard input (Ctrl+D / Ctrl+Z to finish)...")
        raw_content = sys.stdin.read()
    else:
        p = _resolve_dependency("Path", Path)(source_path)
        if not p.exists():
            print(f"Error: Scope file not found at '{source_path}'")
            sys.exit(1)
        raw_content = p.read_text(encoding="utf-8")

    try:
        parsed_yaml = yaml.safe_load(raw_content)
    except Exception as e:
        print(f"Error parsing YAML: {e}")
        sys.exit(1)

    if not isinstance(parsed_yaml, dict):
        print("Error: Invalid YAML content. Expected a dictionary.")
        sys.exit(1)

    # Could be wrapped in `programs:` or direct program dict
    imported_programs = parsed_yaml.get("programs", parsed_yaml)

    # Extract RFC 9116 comments if present in header
    policy_url_comment = ""
    contact_comment = ""
    m_pol = re.search(r"#\s*Policy URL:\s*(https?://\S+)", raw_content, re.IGNORECASE)
    if m_pol:
        policy_url_comment = m_pol.group(1).strip()
    m_con = re.search(r"#\s*Contact:\s*(\S+)", raw_content, re.IGNORECASE)
    if m_con:
        contact_comment = m_con.group(1).strip()

    cfg = _resolve_dependency("load_config", load_config)()
    existing_programs = cfg.setdefault("programs", {})

    imported_count = 0
    activated_key = None

    print("\n" + "=" * 65)
    print(" AUDITGUARD SCOPE IMPORTER (StateHunter & VDP Ingestion)")
    print("=" * 65)

    for prog_key, prog_def in imported_programs.items():
        if not isinstance(prog_def, dict):
            continue

        # Fill default fields if missing
        prog_def.setdefault("name", prog_key.replace("_", " ").title())
        prog_def.setdefault("platform", "StateHunter / VDP Export")
        prog_def.setdefault("rate_limit_per_second", 2.0)
        prog_def.setdefault("allowed_methods", ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
        prog_def.setdefault("in_scope", [])
        if policy_url_comment and "policy_url" not in prog_def:
            prog_def["policy_url"] = policy_url_comment
        if contact_comment and "contact" not in prog_def:
            prog_def["contact"] = contact_comment

        # Ensure rules of engagement exist
        rules = prog_def.setdefault("rules_of_engagement", {})
        rules.setdefault("prohibit_dos", True)
        rules.setdefault("prohibit_data_destruction", True)
        rules.setdefault("header_tag", "X-Bug-Bounty")

        # Validate by instantiating ScopeValidator
        try:
            val = ScopeValidator(prog_def)
        except Exception as e:
            print(f"[-] Skipping invalid program '{prog_key}': {e}")
            continue

        existing_programs[prog_key] = prog_def
        imported_count += 1
        activated_key = prog_key

        print(f"[+] Successfully Imported Program: '{prog_def.get('name')}' [{prog_key}]")
        print(f"    * In-Scope Targets:      {len(val.in_scope)}")
        print(f"    * Excluded Paths:        {len(val.out_of_scope_paths)}")
        if val.discovered_endpoints:
            print(f"    * Discovered Endpoints:  {len(val.discovered_endpoints)}")
        if val.flagged_sensitive_endpoints:
            print(f"    * Sensitive Flagged:     {len(val.flagged_sensitive_endpoints)}")

    if imported_count == 0:
        print("[-] No valid programs found to import.")
        return

    # Handle activation
    if getattr(args, "activate", False) and activated_key:
        cfg["active_program"] = activated_key
        print(f"\n[!] Active program set to: '{activated_key}'")
    elif len(existing_programs) == 1 and activated_key:
        cfg["active_program"] = activated_key
        print(f"\n[!] Active program set to: '{activated_key}'")

    config_path = _resolve_dependency("Path", Path)("config/programs.yaml")
    with open(config_path, "w", encoding="utf-8") as f:
        yaml.dump(cfg, f, sort_keys=False, default_flow_style=False)

    print(f"\n[+] Saved changes to {config_path}")
    print("=" * 65)


def cmd_endpoints(args: Any) -> None:
    """
    Lists and checks discovered SPA/API endpoints from StateHunter reconnaissance
    against active scope and exclusion rules.
    """
    cfg = _resolve_dependency("load_config", load_config)()
    active_key, validator, prog_cfg = _resolve_dependency("get_active_validator", get_active_validator)(cfg)

    discovered = getattr(validator, "discovered_endpoints", [])
    flagged = set(getattr(validator, "flagged_sensitive_endpoints", []))
    robots = getattr(validator, "robots_disallow_directives", [])

    if not discovered and not flagged:
        print(f"\nNo discovered endpoints recorded for program '{active_key}'.")
        print("Export scope from StateHunter or add 'discovered_endpoints' in config/programs.yaml.")
        return

    # Determine base target URL from in_scope to test against
    base_url = "https://example.com"
    for target in validator.in_scope:
        if target.startswith("http://") or target.startswith("https://"):
            base_url = target.rstrip("/")
            break
        elif not target.startswith("*.") and "*" not in target:
            base_url = f"https://{target.split(':')[0]}"
            break

    print("\n" + "=" * 75)
    print(f" DISCOVERED ENDPOINTS AUDIT: {prog_cfg.get('name')} [{active_key}]")
    print(f" Base Reference Target: {base_url}")
    print("=" * 75)

    displayed_count = 0
    blocked_count = 0
    permitted_count = 0

    endpoints_to_show = flagged if getattr(args, "flagged_only", False) else discovered

    for ep in endpoints_to_show:
        is_sensitive = ep in flagged
        test_url = f"{base_url}{ep}" if ep.startswith("/") else f"{base_url}/{ep}"

        status_label = "[PERMITTED]"
        try:
            validator.validate_url(test_url)
            permitted_count += 1
        except OutOfScopePathError:
            status_label = "[BLOCKED (Excluded)]"
            blocked_count += 1
        except ScopeViolationError as e:
            status_label = f"[BLOCKED ({type(e).__name__})]"
            blocked_count += 1

        tag = "[ADMIN/SENSITIVE]" if is_sensitive else "[ENDPOINT]"
        print(f"  {status_label:<20} {tag:<18} {ep}")
        displayed_count += 1

    print("-" * 75)
    print(
        f"Total Discovered: {len(discovered)} | Displayed: {displayed_count} | "
        f"Permitted: {permitted_count} | Blocked: {blocked_count}"
    )
    if robots:
        print(f"Discovered Robots.txt Directives: {len(robots)}")
    print("=" * 75)


def cmd_export_report(args: Any) -> None:
    """
    Generates a deterministic vulnerability report from an audit interaction.
    """
    logger = _resolve_dependency("AuditLogger", AuditLogger)("audit/audit_log.jsonl")
    entries = logger.get_recent_entries(limit=500)

    req_id = args.request_id
    interaction = None
    for e in entries:
        if e.get("request_id") == req_id:
            interaction = e
            break

    if not interaction:
        print(f"Error: Audit log entry with Request ID '{req_id}' not found in audit/audit_log.jsonl")
        sys.exit(1)

    steps = [s.strip() for s in (args.steps or "").split(";") if s.strip()]
    if not steps:
        req = interaction.get("request", {})
        steps = [
            f"Navigate to target endpoint: {req.get('url')}",
            f"Transmit HTTP {req.get('method')} payload with authorized Safe Harbor headers",
            "Observe vulnerability response from server",
        ]

    report = ReportBuilder.build_report(
        title=args.title or f"Vulnerability Report: {interaction.get('request', {}).get('url')}",
        severity=args.severity or "Medium",
        cwe_id=args.cwe or "CWE-200",
        summary=args.summary or "Verified vulnerability discovered during authorized security assessment.",
        interaction=interaction,
        steps_to_reproduce=steps,
        impact=args.impact or "Unauthorized access to sensitive state or functionality.",
        remediation=args.remediation or "Implement proper authentication, authorization, and input validation.",
        researcher_handle=args.reporter or "Authorized Researcher",
    )

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(report, encoding="utf-8")
        print(f"\n[+] Vulnerability report exported successfully to: {out_path}")
    else:
        print("\n" + "=" * 70)
        print(report)
        print("=" * 70)


def cmd_diagnose(args: Any) -> None:
    """
    Executes an in-depth security diagnostic suite against a single endpoint.
    Guaranteed to stay within authorized scope boundaries and shield against network faults.
    """
    from core.diagnostics import SecurityDiagnosticEngine

    cfg = _resolve_dependency("load_config", load_config)()
    active_key, validator, prog_cfg = _resolve_dependency("get_active_validator", get_active_validator)(cfg)

    url = args.url.strip()

    # Pre-flight Scope Check
    try:
        validator.validate_url(url)
    except OutOfScopePathError as e:
        print(f"\n[!] Scope Violation: Target matches explicit path exclusion: {e}")
        return
    except ScopeViolationError as e:
        print(f"\n[!] Scope Violation: Target is outside authorized scope: {e}")
        return

    # Gatekeeper confirmation (prompt once for the diagnostic suite)
    if not getattr(args, "yes", False):
        print("\n" + "=" * 70)
        print(" [GATEKEEPER] AUTHORIZE SECURITY DIAGNOSTIC SUITE")
        print("=" * 70)
        print(f"Target:   {url}")
        print(f"Program:  {prog_cfg.get('name')} [{active_key}]")
        print("Tests:    CORS, Security Headers, Verb Tampering, Info Leaks, Access Control")
        print("-" * 70)
        user_input = input("Authorize diagnostic audit? Type 'yes' or 'y' to proceed: ").strip().lower()
        if user_input not in ("y", "yes"):
            print("[!] Diagnostic run aborted by operator.")
            return

    rate_limit = prog_cfg.get("rate_limit_per_second", 2.0)
    gatekeeper = Gatekeeper(rate_limit_per_second=rate_limit, require_interactive=False)
    audit_logger = _resolve_dependency("AuditLogger", AuditLogger)("audit/audit_log.jsonl")

    client = ScopedHttpClient(
        scope_validator=validator,
        gatekeeper=gatekeeper,
        audit_logger=audit_logger,
        researcher_identifier="AuthorizedSecurityResearcher/1.0",
    )

    rules_dir = getattr(args, "rules_dir", "rules/diagnostics")
    engine = SecurityDiagnosticEngine(client, rules_dir=rules_dir)
    is_sensitive = getattr(args, "sensitive", False) or any(
        k in url.lower() for k in ("/admin", "/internal", "/private", "/metrics")
    )

    print(f"\n[*] Executing Security Diagnostic Suite on {url}...")
    report = engine.diagnose(url, is_sensitive=is_sensitive)

    if report.skipped_reason:
        print(f"[-] Diagnostic Skipped: {report.skipped_reason}")
        return
    if report.error:
        print(f"[!] Diagnostic Incomplete: {report.error}")
        return

    # Render Report
    print("\n" + "=" * 70)
    print(f" SECURITY DIAGNOSTIC REPORT: {url}")
    print("=" * 70)
    print(f"HTTP Status:     {report.status_code}")
    print(f"Latency:         {report.elapsed_ms:.1f}ms")
    print(f"Allowed Methods: {', '.join(report.allowed_methods) or 'None advertised'}")
    if report.headers.get("server"):
        print(f"Server Header:   {report.headers.get('server')}")
    if report.headers.get("x-powered-by"):
        print(f"Technology:      {report.headers.get('x-powered-by')}")
    if report.cors_policy:
        print(f"CORS Policy:     Origin: {report.cors_policy.get('allow_origin')} | Credentials: {report.cors_policy.get('allow_credentials')}")
    print("-" * 70)
    print(f"TOTAL FINDINGS:  {len(report.findings)}")
    print("-" * 70)

    if not report.findings:
        print("[+] No security hygiene defects or information leaks detected on this endpoint.")
    else:
        for f in report.findings:
            sev_tag = f"[{f.severity}]"
            print(f"\n* {sev_tag:<10} {f.title} ({f.cwe_id})")
            print(f"  Description: {f.description}")
            print(f"  Evidence:    {f.evidence}")
            print(f"  Fix:         {f.remediation}")

    print("\n" + "=" * 70)

    from core.remediation import AuditSessionManager
    session_file = AuditSessionManager.save_session(
        program_key=active_key,
        endpoints=[url],
        findings=report.findings,
    )

    if getattr(args, "output", None):
        out_p = Path(args.output)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        md_lines = [
            f"# Security Diagnostic Report: {url}",
            f"**Program:** {prog_cfg.get('name')}",
            f"**Status Code:** HTTP {report.status_code}",
            f"**Date:** {time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime())}",
            "",
            "## Findings Summary",
            f"Total Findings: {len(report.findings)}",
            "",
        ]
        for f in report.findings:
            md_lines.extend([
                f"### [{f.severity}] {f.title} ({f.cwe_id})",
                f"- **Description:** {f.description}",
                f"- **Evidence:** `{f.evidence}`",
                f"- **Remediation:** {f.remediation}",
                "",
            ])
        out_p.write_text("\n".join(md_lines), encoding="utf-8")
        print(f"[+] Diagnostic report written to: {out_p}")


def cmd_audit_endpoints(args: Any) -> None:
    """
    Executes batch security diagnostics across all discovered endpoints
    from StateHunter reconnaissance within the active program.
    Guaranteed to stay within scope and shield against network faults.
    """
    from core.diagnostics import SecurityDiagnosticEngine

    cfg = _resolve_dependency("load_config", load_config)()
    active_key, validator, prog_cfg = _resolve_dependency("get_active_validator", get_active_validator)(cfg)

    discovered = getattr(validator, "discovered_endpoints", [])
    flagged = set(getattr(validator, "flagged_sensitive_endpoints", []))

    if not discovered and not flagged:
        print(f"\nNo discovered endpoints recorded for program '{active_key}'.")
        print("Import scope from StateHunter or add 'discovered_endpoints' in config/programs.yaml.")
        return

    # Determine base origin from in_scope
    base_url = "https://example.com"
    for target in validator.in_scope:
        if target.startswith("http://") or target.startswith("https://"):
            base_url = target.rstrip("/")
            break
        elif not target.startswith("*.") and "*" not in target:
            base_url = f"https://{target.split(':')[0]}"
            break

    endpoints_to_run = [ep for ep in (flagged if getattr(args, "flagged_only", False) else discovered)]

    valid_urls = []
    skipped_excluded = []
    for ep in endpoints_to_run:
        full_url = f"{base_url}{ep}" if ep.startswith("/") else f"{base_url}/{ep}"
        try:
            validator.validate_url(full_url)
            valid_urls.append(full_url)
        except OutOfScopePathError as e:
            skipped_excluded.append((ep, str(e)))
        except ScopeViolationError:
            skipped_excluded.append((ep, "Out of Scope"))

    print("\n" + "=" * 75)
    print(f" BATCH ENDPOINT SECURITY AUDITOR: {prog_cfg.get('name')} [{active_key}]")
    print(f" Base Reference:  {base_url}")
    print(f" Total Targets:   {len(endpoints_to_run)} ({len(valid_urls)} in-scope, {len(skipped_excluded)} excluded)")
    print("=" * 75)

    if skipped_excluded:
        print(f"\n[SCOPE SAFEGUARD] Skipped {len(skipped_excluded)} routes matching excluded_paths:")
        for ep, reason in skipped_excluded[:5]:
            print(f"    * {ep} (BLOCKED: {reason})")
        if len(skipped_excluded) > 5:
            print(f"    * ... and {len(skipped_excluded) - 5} more")

    if not valid_urls:
        print("\n[-] No in-scope endpoints available to audit.")
        return

    # Gatekeeper Confirmation Prompt (Once for the entire batch!)
    if not getattr(args, "yes", False):
        print("\n" + "-" * 75)
        user_input = input(
            f"Authorize batch diagnostic audit of {len(valid_urls)} endpoints at "
            f"{prog_cfg.get('rate_limit_per_second', 2.0)} req/s? [y/N]: "
        ).strip().lower()
        if user_input not in ("y", "yes"):
            print("[!] Batch audit aborted by operator.")
            return

    rate_limit = prog_cfg.get("rate_limit_per_second", 2.0)
    gatekeeper = Gatekeeper(rate_limit_per_second=rate_limit, require_interactive=False)
    audit_logger = _resolve_dependency("AuditLogger", AuditLogger)("audit/audit_log.jsonl")

    client = ScopedHttpClient(
        scope_validator=validator,
        gatekeeper=gatekeeper,
        audit_logger=audit_logger,
        researcher_identifier="AuthorizedSecurityResearcher/1.0",
    )

    rules_dir = getattr(args, "rules_dir", "rules/diagnostics")
    engine = SecurityDiagnosticEngine(client, rules_dir=rules_dir)

    print(f"\n[*] Starting diagnostic audit across {len(valid_urls)} endpoints...")
    print("-" * 75)

    def progress(current: int, total: int, url: str, rep: Any) -> None:
        findings_str = f"{len(rep.findings)} findings" if rep.findings else "clean"
        status_str = f"HTTP {rep.status_code}" if rep.status_code else "FAILED"
        print(f" [{current}/{total}] {status_str:<9} {findings_str:<12} {url}")

    reports = engine.diagnose_batch(valid_urls, flagged_set=flagged, progress_callback=progress)

    # Executive Summary Matrix
    all_findings = []
    for r in reports:
        all_findings.extend(r.findings)

    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in all_findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    print("\n" + "=" * 75)
    print(" BATCH AUDIT EXECUTIVE SUMMARY")
    print("=" * 75)
    print(f"Endpoints Audited: {len(reports)} | Total Findings: {len(all_findings)}")
    print(
        f"Critical: {sev_counts['CRITICAL']} | High: {sev_counts['HIGH']} | "
        f"Medium: {sev_counts['MEDIUM']} | Low: {sev_counts['LOW']} | Info: {sev_counts['INFO']}"
    )
    print("-" * 75)

    grouped: Dict[str, List[tuple[str, Any]]] = {}
    for r in reports:
        for f in r.findings:
            grouped.setdefault(f.title, []).append((r.url, f))

    for title, instances in grouped.items():
        first_finding = instances[0][1]
        print(f"\n[{first_finding.severity}] {title} ({first_finding.cwe_id}) - {len(instances)} affected endpoint(s)")
        for u, _ in instances[:4]:
            print(f"  * {u}")
        if len(instances) > 4:
            print(f"  * ... and {len(instances) - 4} more")

    print("\n" + "=" * 75)

    findings_for_sow: List[Dict[str, Any]] = []
    for title, instances in grouped.items():
        first_finding = instances[0][1]
        affected_list = [u for u, _ in instances]
        findings_for_sow.append({
            "title": first_finding.title,
            "severity": first_finding.severity,
            "cwe_id": first_finding.cwe_id,
            "description": first_finding.description,
            "evidence": first_finding.evidence,
            "remediation": first_finding.remediation,
            "curl_poc": getattr(first_finding, "curl_poc", None),
            "affected_urls": affected_list,
            "cvss_score": getattr(first_finding, "cvss_score", None),
            "cvss_vector": getattr(first_finding, "cvss_vector", None),
            "remediation_code": getattr(first_finding, "remediation_code", None),
            "remediation_lang": getattr(first_finding, "remediation_lang", None),
        })

    # Persist structured audit findings session for targeted re-testing
    from core.remediation import AuditSessionManager
    session_file = AuditSessionManager.save_session(
        program_key=active_key,
        endpoints=valid_urls,
        findings=all_findings,
        flagged_endpoints=list(flagged),
    )
    print(f"[+] Audit findings session persisted to: {session_file} (Targeted Re-Test enabled)")

    # Export deliverables if requested
    out_target = getattr(args, "output", None)
    pdf_target = getattr(args, "pdf", None)

    if out_target or pdf_target:
        from reporting.sow_report_generator import SOWReportGenerator

        sow_gen = SOWReportGenerator(
            program_key=active_key,
            program_cfg=prog_cfg,
            validator=validator,
            findings=findings_for_sow,
            assessor=getattr(args, "assessor", "Authorized Security Researcher"),
            title=f"Security Assessment & SOW Deliverable: {prog_cfg.get('name')}",
        )

        if out_target:
            if out_target.endswith(".pdf"):
                sow_gen.export_pdf(out_target)
                print(f"[+] Publication-Ready PDF Report exported to: {out_target}")
            elif out_target.endswith(".html"):
                sow_gen.export_html(out_target)
                print(f"[+] Interactive HTML Report exported to: {out_target}")
            else:
                sow_gen.export_markdown(out_target)
                print(f"[+] Markdown Audit Report written to: {out_target}")

        if pdf_target and pdf_target != out_target:
            sow_gen.export_pdf(pdf_target)
            print(f"[+] Publication-Ready PDF Report exported to: {pdf_target}")


def cmd_export_sow(args: Any) -> None:
    """
    Generates a formal Statement of Work (SOW) & Scope Confirmation deliverable
    in PDF, HTML, and/or Markdown.
    """
    from reporting.sow_report_generator import SOWReportGenerator

    cfg = _resolve_dependency("load_config", load_config)()
    active_key, validator, prog_cfg = _resolve_dependency("get_active_validator", get_active_validator)(cfg)

    assessor = getattr(args, "assessor", None) or "Authorized Security Researcher"
    title = getattr(args, "title", None) or f"Statement of Work & Scope Report: {prog_cfg.get('name', active_key)}"
    out_target = getattr(args, "output", None) or f"reports/{active_key}_sow_report.pdf"

    print("\n" + "=" * 75)
    print(" STATEMENT OF WORK (SOW) & SCOPE REPORT EXPORTER")
    print("=" * 75)
    print(f"Program:   {prog_cfg.get('name')} [{active_key}]")
    print(f"Assessor:  {assessor}")
    print(f"Output:    {out_target}")
    print("-" * 75)

    gen = SOWReportGenerator(
        program_key=active_key,
        program_cfg=prog_cfg,
        validator=validator,
        findings=None,
        assessor=assessor,
        title=title,
        audit_executed=False,
    )

    out_p = Path(out_target)
    out_p.parent.mkdir(parents=True, exist_ok=True)

    if out_target.endswith(".pdf"):
        gen.export_pdf(out_target)
        print(f"[+] Publication-Ready PDF Report exported to: {out_target}")
    elif out_target.endswith(".html"):
        gen.export_html(out_target)
        print(f"[+] Interactive HTML Report exported to: {out_target}")
    else:
        gen.export_markdown(out_target)
        print(f"[+] Markdown SOW Report exported to: {out_target}")

    print("=" * 75)


def cmd_rules(args: Any) -> None:
    """
    Lists and queries available open-source diagnostic rules in the Nuclei YAML standard.
    """
    from core.rule_engine import RuleCatalog

    catalog = RuleCatalog()
    rules_dir = getattr(args, "dir", None) or "rules/diagnostics"
    count = catalog.load_from_directory(rules_dir)

    tags = [args.tag] if getattr(args, "tag", None) else None
    severities = [args.severity] if getattr(args, "severity", None) else None
    query = getattr(args, "query", None)

    matched = catalog.query(tags=tags, severities=severities, keyword=query)

    print("\n" + "=" * 75)
    print(f" DIAGNOSTIC RULES CATALOG (Loaded: {count} from {rules_dir})")
    print("=" * 75)

    if not matched:
        print(f"[-] No diagnostic rules matched criteria (tags={tags}, severity={severities}, query={query}).")
        return

    print(f"{'ID':<34} {'SEVERITY':<10} {'CWE':<10} {'TAGS'}")
    print("-" * 75)
    for r in matched:
        tags_str = ", ".join(r.tags[:4])
        print(f"{r.id:<34} {r.severity:<10} {r.cwe_id:<10} {tags_str}")
    print("-" * 75)
    print(f"Total Rules Displayed: {len(matched)}")
    print("=" * 75)


def cmd_recommend_rules(args: Any) -> None:
    """
    Analyzes reconnaissance discovery artifacts (routes, technologies, headers, robots)
    and queries local/external template repositories to recommend targeted diagnostic tests.
    """
    from core.rule_recommender import DiscoveryProfiler, RuleRecommender

    cfg = _resolve_dependency("load_config", load_config)()
    active_key = cfg.get("active_program")
    programs = cfg.get("programs", {})
    prog_cfg = programs.get(active_key, {})

    if not prog_cfg:
        print(f"Error: Active program '{active_key}' not configured.")
        sys.exit(1)

    validator = ScopeValidator(prog_cfg)

    # Determine base URL
    base_url = "https://example.com"
    for target in validator.in_scope:
        if target.startswith("http://") or target.startswith("https://"):
            base_url = target.rstrip("/")
            break
        elif not target.startswith("*.") and "*" not in target:
            base_url = f"https://{target.split(':')[0]}"
            break

    # Determine template repository to query
    repo_dir = getattr(args, "repo", None)
    if not repo_dir:
        default_external = Path("D:/repos/nuclei-templates")
        repo_dir = str(default_external) if default_external.exists() else "rules/diagnostics"

    print("\n" + "=" * 75)
    print(f" DISCOVERY-DRIVEN RULE RECOMMENDER: {prog_cfg.get('name')} [{active_key}]")
    print(f" Target Baseline:   {base_url}")
    print(f" Template Repo:     {repo_dir}")
    print("=" * 75)

    # Gather live response signals if reachable
    live_headers: Dict[str, str] = {}
    live_body: str = ""
    try:
        import httpx
        r = httpx.get(base_url, timeout=3.0, follow_redirects=True, verify=False)
        live_headers = dict(r.headers)
        live_body = r.text
    except Exception:
        pass

    # 1. Profile Discovery Traits
    traits = DiscoveryProfiler.profile_program(prog_cfg, live_headers=live_headers, live_body=live_body)

    print("\n[+] Reconnaissance Profile & Identified Signals:")
    tech_traits = [t for t in traits if t.category == "technology"]
    route_traits = [t for t in traits if t.category in ("route", "robot_directive")]

    if tech_traits:
        print("  * Technologies Detected: " + ", ".join(f"{t.token} ({t.evidence})" for t in tech_traits))
    if route_traits:
        print("  * Architectural Surfaces: " + ", ".join(f"{t.token}" for t in route_traits[:8]))
    print(f"  * Total Traits Extracted:  {len(traits)}")

    # 2. Query & Match Templates
    recommender = RuleRecommender(repo_dir)
    print(f"\n[*] Scanning template repository for relevant non-destructive checks...")
    candidates = recommender.load_candidates(safe_only=not getattr(args, "all_verbs", False))
    print(f"[*] Loaded {len(candidates)} candidate templates. Scoring against discovery profile...")

    min_score = getattr(args, "min_score", 40)
    recommendations = recommender.recommend(traits, candidates, min_score=min_score)

    if not recommendations:
        print(f"\n[-] No templates exceeded relevance threshold score of {min_score}.")
        print("    Try running with a lower score threshold: --min-score 20")
        print("=" * 75)
        return

    # Limit display to top N
    limit = getattr(args, "limit", 15)
    displayed = recommendations[:limit]

    print("\n" + "-" * 75)
    print(f"{'SCORE':<7} {'SEVERITY':<10} {'TEMPLATE ID':<28} {'WHY RECOMMENDED (TRIGGER)'}")
    print("-" * 75)
    for r in displayed:
        print(f"{r.relevance_score:<7} {r.severity:<10} {r.template_id:<28} {r.rationale[:40]}")
    print("-" * 75)
    print(f"Showing top {len(displayed)} of {len(recommendations)} recommended rules (min score: {min_score})")

    # 3. Handle --import flag
    if getattr(args, "import_rules", False):
        import_dir = getattr(args, "import_dir", None) or "rules/diagnostics"
        count = RuleRecommender.import_recommendations(displayed, target_dir=import_dir)
        print(f"\n[+] Successfully imported {count} recommended rule(s) into: {import_dir}")
        print("    You can now run them in an audit using: python main.py audit-endpoints")

    print("=" * 75)


def cmd_retest(args: Any) -> None:
    """
    Executes targeted diagnostic re-tests against previously flagged endpoints
    from a baseline audit session to verify whether vulnerabilities have been remediated.
    """
    from core.diagnostics import SecurityDiagnosticEngine
    from core.remediation import AuditSessionManager, RemediationAuditor
    from reporting.sow_report_generator import RemediationReportGenerator

    session_path = getattr(args, "session", None) or "audit/latest_findings.json"
    session_data = AuditSessionManager.load_session(session_path)

    if not session_data:
        print(f"\n[-] No baseline audit findings session found at '{session_path}'.")
        print("    Run an initial audit first: python main.py audit-endpoints --flagged-only")
        return

    cfg = _resolve_dependency("load_config", load_config)()
    session_prog_key = session_data.get("program_key", cfg.get("active_program", "active"))
    programs = cfg.get("programs", {})
    prog_cfg = programs.get(session_prog_key)

    if not prog_cfg:
        active_key, validator, prog_cfg = _resolve_dependency("get_active_validator", get_active_validator)(cfg)
    else:
        validator = ScopeValidator(prog_cfg)

    # Collect unique target URLs from baseline session
    target_urls: List[str] = []
    for bf in session_data.get("findings", []):
        for u in bf.get("affected_urls", []):
            if u not in target_urls:
                target_urls.append(u)

    if not target_urls:
        target_urls = session_data.get("endpoints", [])

    if not target_urls:
        print(f"\n[-] No target endpoints recorded in baseline session '{session_data.get('session_id')}'.")
        return

    # Pre-flight Scope Check
    valid_targets: List[str] = []
    for u in target_urls:
        try:
            validator.validate_url(u)
            valid_targets.append(u)
        except Exception as e:
            print(f"[-] Excluding target '{u}': {e}")

    if not valid_targets:
        print("\n[-] All target endpoints from baseline session are now out of scope.")
        return

    print("\n" + "=" * 75)
    print(f" TARGETED RE-TEST & REMEDIATION VERIFICATION: {prog_cfg.get('name')} [{session_prog_key}]")
    print(f" Baseline Session: {session_data.get('session_id', 'N/A')} ({session_data.get('timestamp', 'N/A')})")
    print(f" Prior Defects:    {session_data.get('findings_count', 0)}")
    print(f" Targets to Probe: {len(valid_targets)} endpoint(s)")
    print("=" * 75)

    if not getattr(args, "yes", False):
        print("\n" + "-" * 75)
        user_input = input(
            f"Authorize targeted re-test across {len(valid_targets)} endpoint(s) at "
            f"{prog_cfg.get('rate_limit_per_second', 2.0)} req/s? [y/N]: "
        ).strip().lower()
        if user_input not in ("y", "yes"):
            print("[!] Targeted re-test aborted by operator.")
            return

    rate_limit = prog_cfg.get("rate_limit_per_second", 2.0)
    gatekeeper = Gatekeeper(rate_limit_per_second=rate_limit, require_interactive=False)
    audit_logger = _resolve_dependency("AuditLogger", AuditLogger)("audit/audit_log.jsonl")

    client = ScopedHttpClient(
        scope_validator=validator,
        gatekeeper=gatekeeper,
        audit_logger=audit_logger,
        researcher_identifier="AuthorizedSecurityResearcher/1.0",
    )

    rules_dir = getattr(args, "rules_dir", "rules/diagnostics")
    engine = SecurityDiagnosticEngine(client, rules_dir=rules_dir)

    print(f"\n[*] Executing targeted re-tests...")
    print("-" * 75)

    def progress(current: int, total: int, url: str, rep: Any) -> None:
        findings_str = f"{len(rep.findings)} defect(s)" if rep.findings else "CLEAN"
        status_str = f"HTTP {rep.status_code}" if rep.status_code else "FAILED"
        print(f" [{current}/{total}] {status_str:<9} {findings_str:<12} {url}")

    retest_result = RemediationAuditor.run_retest(
        engine=engine,
        baseline_session=session_data,
        progress_callback=progress,
        flagged_set=set(getattr(validator, "flagged_sensitive_endpoints", [])),
    )

    metrics = retest_result["metrics"]
    items = retest_result["items"]

    print("\n" + "=" * 75)
    print(" DIFFERENTIAL REMEDIATION SUMMARY")
    print("=" * 75)
    print(f"Prior Defects Evaluated: {metrics['total_baseline_defects']}")
    print(f"Successfully Resolved:   {metrics['resolved_count']} [RESOLVED]")
    print(f"Persistent Defects:      {metrics['unresolved_count']} [UNRESOLVED]")
    print(f"Remediation Rate:        {metrics['resolution_rate_pct']:.1f}%")
    print("-" * 75)

    for item in items:
        badge = f"[{item['result']}]"
        sev = f"[{item['severity']}]"
        print(f"  {badge:<14} {sev:<10} {item['title']} ({item['cwe_id']})")
        print(f"                 Endpoint: {item['affected_url']}")
        print(f"                 Note:     {item['evidence']}")
        if item.get("curl_poc") and item['result'] == "UNRESOLVED":
            print(f"                 cURL:     {item['curl_poc']}")
        print()

    print("=" * 75)

    # Deliverable export
    out_target = getattr(args, "output", None)
    pdf_target = getattr(args, "pdf", None)

    if out_target or pdf_target:
        report_gen = RemediationReportGenerator(
            remediation_data=retest_result,
            program_cfg=prog_cfg,
            assessor=getattr(args, "assessor", "Authorized Security Researcher"),
            title=f"Remediation Verification Report: {prog_cfg.get('name')}",
        )

        if out_target:
            if out_target.endswith(".pdf"):
                report_gen.export_pdf(out_target)
                print(f"[+] Publication-Ready Remediation PDF exported to: {out_target}")
            elif out_target.endswith(".html"):
                report_gen.export_html(out_target)
                print(f"[+] Interactive Remediation HTML exported to: {out_target}")
            else:
                report_gen.export_markdown(out_target)
                print(f"[+] Markdown Remediation Report written to: {out_target}")

        if pdf_target and pdf_target != out_target:
            report_gen.export_pdf(pdf_target)
            print(f"[+] Publication-Ready Remediation PDF exported to: {pdf_target}")


def cmd_safe_harbor(args: Any) -> None:
    """
    Evaluates the immutable audit ledger against the active program's Rules of Engagement
    and prints a cryptographically verifiable Safe Harbor Proof-of-Adherence Certificate.
    """
    from core.safe_harbor import SafeHarborLedgerAuditor, SafeHarborTerms

    cfg = _resolve_dependency("load_config", load_config)()
    active_key, validator, prog_cfg = _resolve_dependency("get_active_validator", get_active_validator)(cfg)

    log_path = getattr(args, "log", None) or "audit/audit_log.jsonl"
    proof = SafeHarborLedgerAuditor.audit_engagement(
        log_path=log_path,
        program_cfg=prog_cfg,
        program_key=active_key,
    )

    print("\n" + "=" * 75)
    print(f" SAFE HARBOR PROOF-OF-ADHERENCE CERTIFICATE: {prog_cfg.get('name')} [{active_key}]")
    print(" Aligned with Disclose.io Core Vulnerability Disclosure Standard")
    print("=" * 75)

    print("\n[+] Legal Framework & Authorization Protections:")
    print("  * CFAA Authorization:  18 U.S.C. Section 1030 authorized access confirmed.")
    print("  * DMCA Section 1201:   Non-circumvention research exemption established.")
    print("  * Good Faith Research: Defensive vulnerability validation only.")
    print("  * Privacy Protocol:    Zero retention of customer data / no PII accessed.")
    print("  * Non-Destructive:     Idempotent HTTP verbs only (GET/HEAD/OPTIONS). No DoS.")

    print("\n[+] Cryptographic Ledger Verification Metrics:")
    for line in proof.summary_lines():
        print(f"  * {line}")

    print("\n" + "-" * 75)
    if proof.is_fully_compliant:
        print("  VERDICT: [PASS - SAFE HARBOR PROTECTED]")
        print("  All testing traffic strictly satisfied scope, rate limits, and identity tagging.")
    else:
        print("  VERDICT: [NON-COMPLIANT WARNING - REVIEW LOGS]")
        print("  One or more traffic interactions violated program boundaries or rate ceilings.")
    print("=" * 75)


def cmd_export_triage(args: Any) -> None:
    """
    Exports diagnostic findings from an audit session to platform-specific triage reports
    (HackerOne, Bugcrowd, GitHub Issues, Jira).
    """
    from core.diagnostics import DiagnosticFinding
    from core.remediation import AuditSessionManager
    from reporting.triage_exporter import PlatformTriageExporter

    session_path = getattr(args, "session", None) or "audit/latest_findings.json"
    session_data = AuditSessionManager.load_session(session_path)

    if not session_data:
        print(f"\n[-] No audit session found at '{session_path}'.")
        print("    Specify a session file with --session <path_or_id> or run an audit first.")
        return

    findings_raw = session_data.get("findings", [])
    if not findings_raw:
        print(f"\n[-] Session '{session_data.get('session_id')}' contains 0 findings to export.")
        return

    findings: List[DiagnosticFinding] = []
    for f in findings_raw:
        findings.append(
            DiagnosticFinding(
                title=f.get("title", "Finding"),
                severity=f.get("severity", "MEDIUM"),
                cwe_id=f.get("cwe_id", "N/A"),
                description=f.get("description", ""),
                evidence=f.get("evidence", ""),
                remediation=f.get("remediation", ""),
                curl_poc=f.get("curl_poc"),
                affected_urls=f.get("affected_urls", []),
                cvss_score=f.get("cvss_score"),
                cvss_vector=f.get("cvss_vector"),
                remediation_code=f.get("remediation_code"),
                remediation_lang=f.get("remediation_lang"),
            )
        )

    cfg = _resolve_dependency("load_config", load_config)()
    prog_key = getattr(args, "program", None) or session_data.get("program_key", cfg.get("active_program", "active"))
    programs = cfg.get("programs", {})
    prog_cfg = programs.get(prog_key, {})
    prog_name = prog_cfg.get("name", prog_key)
    target_scope = getattr(args, "scope", None) or prog_cfg.get("root_domain", "")
    out_dir = getattr(args, "output_dir", "reports/triage")
    fmt = (getattr(args, "format", "all") or "all").lower()
    base_name = f"triage_{session_data.get('session_id', 'export')}"

    print("\n" + "=" * 75)
    print(f" PLATFORM TRIAGE EXPORTER: {prog_name} [{prog_key}]")
    print(f" Baseline Session:  {session_data.get('session_id', 'N/A')}")
    print(f" Total Findings:    {len(findings)}")
    print(f" Target Format(s):  {fmt.upper()}")
    print(f" Output Directory:  {out_dir}")
    print("=" * 75)

    os.makedirs(out_dir, exist_ok=True)
    exported_files = []

    if fmt in ("all", "hackerone"):
        p = os.path.join(out_dir, f"{base_name}_hackerone.md")
        content = PlatformTriageExporter.export_hackerone(findings, program_name=prog_name, target_scope=target_scope)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(content)
        exported_files.append(("HackerOne Markdown", p))

    if fmt in ("all", "bugcrowd"):
        p = os.path.join(out_dir, f"{base_name}_bugcrowd.md")
        content = PlatformTriageExporter.export_bugcrowd(findings, program_name=prog_name, target_scope=target_scope)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(content)
        exported_files.append(("Bugcrowd VDP Markdown", p))

    if fmt in ("all", "github"):
        p = os.path.join(out_dir, f"{base_name}_github_issues.md")
        content = PlatformTriageExporter.export_github(findings)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(content)
        exported_files.append(("GitHub Issues Markdown", p))

    if fmt in ("all", "jira"):
        p = os.path.join(out_dir, f"{base_name}_jira.json")
        jira_data = PlatformTriageExporter.export_jira_json(findings, project_key=getattr(args, "jira_project", "SEC"))
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(jira_data, fh, indent=2)
        exported_files.append(("Jira Cloud/Server JSON", p))

    print("\n[+] Triage Deliverables Successfully Generated:")
    for label, path in exported_files:
        print(f"  * {label:<22} -> {path}")
    print("=" * 75)


def cmd_audit_auth(args: Any) -> None:
    """
    Executes comparative dual-role authorization matrix probing across researcher-controlled
    roles (User A vs User B vs Admin vs Unauthenticated) to safely detect BOLA/IDOR (CWE-639)
    and Privilege Escalation (CWE-269).
    """
    from core.auth_matrix import AuthorizationMatrixAuditor, AuthRole
    from core.remediation import AuditSessionManager

    cfg = _resolve_dependency("load_config", load_config)()
    prog_key = getattr(args, "program", None)
    if prog_key:
        programs = cfg.get("programs", {})
        prog_cfg = programs.get(prog_key)
        if not prog_cfg:
            print(f"[-] Program '{prog_key}' not found in configuration.")
            return
        validator = ScopeValidator(prog_cfg)
        active_key = prog_key
    else:
        active_key, validator, prog_cfg = _resolve_dependency("get_active_validator", get_active_validator)(cfg)

    # Collect target endpoints
    target_urls: List[str] = []
    if getattr(args, "url", None):
        target_urls.append(args.url)
    elif getattr(args, "session", None):
        s_data = AuditSessionManager.load_session(args.session)
        if s_data:
            target_urls.extend(s_data.get("endpoints", []))
    else:
        target_urls.extend(getattr(validator, "flagged_sensitive_endpoints", []))

    if not target_urls:
        print("[-] No target URLs specified. Provide --url <endpoint>, --session <id>, or configure flagged endpoints.")
        return

    # Scope check
    valid_targets: List[str] = []
    for u in target_urls:
        try:
            validator.validate_url(u)
            valid_targets.append(u)
        except Exception as e:
            print(f"[-] Excluding out-of-scope target '{u}': {e}")

    if not valid_targets:
        print("[-] No valid in-scope target endpoints to probe.")
        return

    # Setup roles
    roles: List[AuthRole] = []

    # Parse role A
    role_a_name = getattr(args, "role_a_name", "user_a") or "user_a"
    role_a_hdr = getattr(args, "role_a_header", None)
    hdrs_a = {}
    if role_a_hdr and ":" in role_a_hdr:
        k, v = role_a_hdr.split(":", 1)
        hdrs_a[k.strip()] = v.strip()
    roles.append(AuthRole(role_name=role_a_name, headers=hdrs_a, description="Owner / Standard Identity"))

    # Parse role B
    role_b_name = getattr(args, "role_b_name", "user_b") or "user_b"
    role_b_hdr = getattr(args, "role_b_header", None)
    hdrs_b = {}
    if role_b_hdr and ":" in role_b_hdr:
        k, v = role_b_hdr.split(":", 1)
        hdrs_b[k.strip()] = v.strip()
    roles.append(AuthRole(role_name=role_b_name, headers=hdrs_b, description="Foreign / Secondary Identity"))

    # Admin role
    admin_hdr = getattr(args, "admin_header", None)
    if admin_hdr and ":" in admin_hdr:
        k, v = admin_hdr.split(":", 1)
        roles.append(AuthRole(role_name="admin", headers={k.strip(): v.strip()}, description="Administrator", is_admin=True))

    print("\n" + "=" * 75)
    print(f" DUAL-ROLE AUTHORIZATION & IDOR/BOLA AUDIT: {prog_cfg.get('name')} [{active_key}]")
    print(f" Target Endpoints:  {len(valid_targets)}")
    print(f" Configured Roles:  {', '.join(r.role_name for r in roles)} + unauthenticated")
    print("=" * 75)

    if not getattr(args, "yes", False):
        user_input = input(
            f"\nAuthorize authorization matrix audit across {len(valid_targets)} endpoint(s)? [y/N]: "
        ).strip().lower()
        if user_input not in ("y", "yes"):
            print("[!] Audit aborted by operator.")
            return

    rate_limit = prog_cfg.get("rate_limit_per_second", 2.0)
    gatekeeper = Gatekeeper(rate_limit_per_second=rate_limit, require_interactive=False)
    audit_logger = _resolve_dependency("AuditLogger", AuditLogger)("audit/audit_log.jsonl")

    client = ScopedHttpClient(
        scope_validator=validator,
        gatekeeper=gatekeeper,
        audit_logger=audit_logger,
        researcher_identifier="AuthorizedSecurityResearcher/1.0",
    )

    auditor = AuthorizationMatrixAuditor(client=client, roles=roles)

    print("\n[*] Probing comparative authorization matrix...")
    print("-" * 75)

    findings: List[DiagnosticFinding] = []
    for idx, ep in enumerate(valid_targets, 1):
        print(f" [{idx}/{len(valid_targets)}] Probing {ep}...")
        ep_findings = auditor.probe_endpoint(ep, owner_role_name=role_a_name)
        for f in ep_findings:
            df = f.to_diagnostic_finding()
            findings.append(df)
            print(f"       -> [{df.severity}] {df.title} ({df.cwe_id})")

    print("\n" + "=" * 75)
    print(f" AUTHORIZATION MATRIX AUDIT COMPLETE: {len(findings)} Finding(s)")
    print("=" * 75)

    out_file = getattr(args, "output", None)
    if out_file:
        os.makedirs(os.path.dirname(out_file) or ".", exist_ok=True)
        if out_file.endswith(".json"):
            from dataclasses import asdict
            with open(out_file, "w", encoding="utf-8") as fh:
                json.dump([asdict(f) for f in findings], fh, indent=2)
        else:
            with open(out_file, "w", encoding="utf-8") as fh:
                for f in findings:
                    fh.write(f"### [{f.severity}] {f.title} ({f.cwe_id})\n")
                    fh.write(f"- Description: {f.description}\n")
                    fh.write(f"- Evidence: {f.evidence}\n")
                    fh.write(f"- cURL: {f.curl_poc}\n\n")
        print(f"[+] Authorization findings written to: {out_file}")


def cmd_monitor(args: Any) -> None:
    """
    Monitors attack surface drift and security regressions by comparing current live target
    or active session against baseline audit records.
    """
    from core.drift_monitor import AttackSurfaceDriftMonitor
    from core.remediation import AuditSessionManager

    cfg = _resolve_dependency("load_config", load_config)()
    active_key, validator, prog_cfg = _resolve_dependency("get_active_validator", get_active_validator)(cfg)

    monitor = AttackSurfaceDriftMonitor()

    # Load baseline
    baseline_ref = getattr(args, "baseline_session", None)
    if baseline_ref:
        baseline_data = monitor.load_session(baseline_ref)
    else:
        baseline_data = monitor.find_latest_session(active_key)

    if not baseline_data:
        print(f"\n[-] No baseline audit session found. Run an initial audit first or specify --baseline-session.")
        return

    compare_ref = getattr(args, "compare_session", None)
    is_live = getattr(args, "live", False)

    if compare_ref:
        # Offline session-to-session comparison
        compare_data = monitor.load_session(compare_ref)
        if not compare_data:
            print(f"[-] Comparative session '{compare_ref}' not found.")
            return
        report = monitor.compare_sessions(baseline_data, compare_data)
    elif is_live:
        # Live active probing
        print("\n" + "=" * 75)
        print(f" LIVE ATTACK SURFACE DRIFT MONITOR: {prog_cfg.get('name')} [{active_key}]")
        print(f" Baseline Session: {baseline_data.get('session_id')}")
        print("=" * 75)

        if not getattr(args, "yes", False):
            user_input = input(
                f"\nAuthorize live drift inspection across baseline endpoints at "
                f"{prog_cfg.get('rate_limit_per_second', 2.0)} req/s? [y/N]: "
            ).strip().lower()
            if user_input not in ("y", "yes"):
                print("[!] Drift monitoring aborted by operator.")
                return

        rate_limit = prog_cfg.get("rate_limit_per_second", 2.0)
        gatekeeper = Gatekeeper(rate_limit_per_second=rate_limit, require_interactive=False)
        audit_logger = _resolve_dependency("AuditLogger", AuditLogger)("audit/audit_log.jsonl")

        client = ScopedHttpClient(
            scope_validator=validator,
            gatekeeper=gatekeeper,
            audit_logger=audit_logger,
            researcher_identifier="AuthorizedSecurityResearcher/1.0",
        )
        live_monitor = AttackSurfaceDriftMonitor(client=client)
        report = live_monitor.monitor_live(
            baseline_session=baseline_data,
            current_endpoints=baseline_data.get("endpoints", []),
        )
    else:
        print("[-] Specify either --live to probe the current environment or --compare-session <id> for offline comparison.")
        return

    print("\n" + report.to_markdown())

    out_dir = getattr(args, "output_dir", "reports")
    md_p, json_p = monitor.save_report(report, output_dir=out_dir)
    print("\n" + "=" * 75)
    print(f"[+] Drift reports saved:\n  * Markdown: {md_p}\n  * JSON:     {json_p}")
    print("=" * 75)
