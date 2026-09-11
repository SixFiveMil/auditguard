"""
AuditGuard Bug Bounty & Platform Triage Exporter.
Transforms security diagnostic findings into 1-click, professionally structured
submission reports for bug bounty platforms (HackerOne, Bugcrowd) and enterprise
issue trackers (GitHub Issues, Jira Cloud/Server).
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict
from typing import Any, Dict, List, Optional

from core.diagnostics import DiagnosticFinding


# Bugcrowd Vulnerability Rating Taxonomy (VRT) Mappings
VRT_MAPPINGS: Dict[str, str] = {
    "CWE-942": "Server-Side Injection > Cross-Origin Resource Sharing (CORS) > Misconfigured Access-Control-Allow-Origin",
    "CWE-1021": "Server Security Misconfiguration > Missing Security Headers > Content-Security-Policy (CSP)",
    "CWE-524": "Sensitive Data Exposure > Information Disclosure in Cache > Missing Cache-Control",
    "CWE-525": "Sensitive Data Exposure > Information Disclosure in Cache > Browser Cache Weakness",
    "CWE-306": "Broken Authentication & Session Management > Authentication Bypass > Missing Authentication for Critical Function",
    "CWE-284": "Broken Access Control > Insecure Direct Object References (IDOR) > Unauthorized Resource Access",
    "CWE-639": "Broken Access Control > Insecure Direct Object References (IDOR) > User-Controlled Key",
    "CWE-269": "Broken Access Control > Privilege Escalation > Vertical Privilege Escalation",
    "CWE-650": "Server Security Misconfiguration > Dangerous HTTP Methods Enabled",
    "CWE-200": "Information Disclosure > Sensitive Information in Response",
    "CWE-209": "Information Disclosure > Verbose Error Messages / Stack Trace Leak",
}

# Jira Priority Mapping
JIRA_PRIORITY_MAP: Dict[str, str] = {
    "CRITICAL": "Highest",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "INFO": "Lowest",
}


class PlatformTriageExporter:
    """Exports DiagnosticFinding instances to platform-specific submission formats."""

    @staticmethod
    def _cwe_name(cwe_id: str) -> str:
        """Returns readable name for common CWEs."""
        names = {
            "CWE-942": "Permissive Cross-Origin Resource Sharing (CORS)",
            "CWE-1021": "Improper Restriction of Rendered UI Layers (Clickjacking / Missing CSP)",
            "CWE-524": "Use of Cache Containing Sensitive Information",
            "CWE-525": "Use of Web Browser Cache Containing Sensitive Information",
            "CWE-306": "Missing Authentication for Critical Function",
            "CWE-284": "Improper Access Control",
            "CWE-639": "Authorization Bypass Through User-Controlled Key (IDOR/BOLA)",
            "CWE-269": "Improper Privilege Management (Privilege Escalation)",
            "CWE-650": "Trusting HTTP Permission Methods on the Server Side",
            "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
            "CWE-209": "Generation of Error Message Containing Sensitive Information",
        }
        return names.get(cwe_id.upper(), cwe_id)

    @classmethod
    def export_hackerone_finding(
        cls,
        finding: DiagnosticFinding,
        program_name: str = "Target Program",
        target_scope: str = "",
        safe_harbor_data: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Formats a single finding for HackerOne vulnerability report submission."""
        cwe_display = f"{finding.cwe_id} - {cls._cwe_name(finding.cwe_id)}"
        cvss_score_str = f"{finding.cvss_score:.1f}" if finding.cvss_score is not None else "N/A"
        cvss_vector_str = finding.cvss_vector or "N/A"
        asset = target_scope or (finding.affected_urls[0] if finding.affected_urls else "In-Scope Asset")

        md = [
            f"# [SECURITY REPORT] {finding.title}",
            "",
            "## Summary",
            f"An issue was identified in **{program_name}** where an attacker or unauthorized user can exploit {finding.title.lower()}.",
            f"{finding.description}",
            "",
            "## Weakness & Severity",
            f"- **Weakness**: `{cwe_display}`",
            f"- **Severity**: **{finding.severity}** (CVSS v3.1: `{cvss_score_str}`)",
            f"- **CVSS Vector**: `{cvss_vector_str}`",
            f"- **Asset**: `{asset}`",
            "",
            "## Technical Impact",
            f"The exploitation of this flaw undermines the security boundary of `{asset}`.",
        ]

        if finding.severity in ("CRITICAL", "HIGH"):
            md.append("This presents high risk to confidentiality and integrity of authorized data, potentially leading to cross-origin data exfiltration, bypass of tenant isolation, or unauthorized access to administrative functionality.")
        elif finding.severity == "MEDIUM":
            md.append("This misconfiguration allows attackers to compromise client-side isolation, bypass caching controls on sensitive records, or conduct clickjacking and state interaction attacks.")
        else:
            md.append("This hygiene gap exposes internal system architecture, stack traces, or facilitates reconnaissance chaining for subsequent exploitation.")

        md.extend([
            "",
            "## Step-by-Step Reproduction Guide",
            "1. Execute the following reproduction command from an authorized research terminal:",
            "",
            "```bash",
            finding.curl_poc or f"curl -i -s \"{asset}\"",
            "```",
            "",
            "2. Observe the HTTP response headers and body confirming the vulnerability.",
            "",
            "## Proof of Concept / Evidence",
            "```http",
            finding.evidence.strip() if finding.evidence else "(Evidence captured during audit run)",
            "```",
            "",
            "## Affected Endpoints",
        ])

        if finding.affected_urls:
            for url in finding.affected_urls:
                md.append(f"- `{url}`")
        else:
            md.append(f"- `{asset}`")

        md.extend([
            "",
            "## Suggested Remediation",
            finding.remediation,
        ])

        if finding.remediation_code:
            lang = finding.remediation_lang or "javascript"
            md.extend([
                "",
                f"### Production Code Fix ({lang}):",
                f"```{lang}",
                finding.remediation_code.strip(),
                "```",
            ])

        # Safe Harbor Ledger Excerpt
        md.extend([
            "",
            "## Safe Harbor & Ethical Conduct Verification",
            "This report was generated in strict compliance with the target program's Safe Harbor and Vulnerability Disclosure Policy:",
            "- **Non-Destructive Testing**: All requests utilized non-destructive methods (read-only/safe queries) adhering to zero data modification.",
            "- **Rate Limiting & Stability**: Traffic was strictly paced via Gatekeeper rate limiters to prevent availability degradation.",
            "- **Research Attribution**: In-scope requests included researcher identification headers (`X-Bug-Bounty` / Safe Harbor headers).",
        ])

        if safe_harbor_data:
            md.append("")
            md.append("### Research Session Attribution:")
            for k, v in safe_harbor_data.items():
                md.append(f"- **{k}**: `{v}`")

        return "\n".join(md)

    @classmethod
    def export_bugcrowd_finding(
        cls,
        finding: DiagnosticFinding,
        program_name: str = "Target Program",
        target_scope: str = "",
    ) -> str:
        """Formats a single finding for Bugcrowd VDP submission."""
        vrt_cat = VRT_MAPPINGS.get(finding.cwe_id.upper(), f"Server Security Misconfiguration > {finding.cwe_id}")
        cvss_score_str = f"{finding.cvss_score:.1f}" if finding.cvss_score is not None else "N/A"
        asset = target_scope or (finding.affected_urls[0] if finding.affected_urls else "In-Scope Asset")

        md = [
            f"# {finding.title}",
            "",
            "### Vulnerability Rating Taxonomy (VRT)",
            f"**Category**: `{vrt_cat}`  ",
            f"**Assessed Severity**: `{finding.severity}` (CVSS: `{cvss_score_str}`)  ",
            f"**Target**: `{asset}`  ",
            "",
            "### Description",
            finding.description,
            "",
            "### Steps to Reproduce",
            "1. Using cURL or an intercepting proxy, send the following request:",
            "```bash",
            finding.curl_poc or f"curl -i -s \"{asset}\"",
            "```",
            "2. Note the defective response parameters documented below.",
            "",
            "### HTTP Evidence",
            "```http",
            finding.evidence.strip() if finding.evidence else "(Diagnostic evidence)",
            "```",
            "",
            "### Impact",
            f"Vulnerability in {finding.title} directly weakens `{asset}` security posture and violates {finding.cwe_id} guidelines.",
            "",
            "### Recommended Solution",
            finding.remediation,
        ]

        if finding.remediation_code:
            lang = finding.remediation_lang or "javascript"
            md.extend([
                "",
                f"```{lang}",
                finding.remediation_code.strip(),
                "```",
            ])

        return "\n".join(md)

    @classmethod
    def export_github_issue(
        cls,
        finding: DiagnosticFinding,
        repository: str = "repo",
    ) -> str:
        """Formats a finding as a ready-to-file GitHub Issue in Markdown."""
        cvss_score_str = f"{finding.cvss_score:.1f}" if finding.cvss_score is not None else "N/A"
        cvss_vector_str = finding.cvss_vector or "N/A"

        md = [
            f"## [Security] {finding.severity}: {finding.title} ({finding.cwe_id})",
            "",
            f"> **Severity**: `{finding.severity}` | **CVSS v3.1**: `{cvss_score_str}` | **Vector**: `{cvss_vector_str}`",
            "",
            "### Problem Description",
            finding.description,
            "",
            "### Affected Endpoints",
        ]

        for url in finding.affected_urls or ["(Specified in report)"]:
            md.append(f"- [ ] `{url}`")

        md.extend([
            "",
            "### Steps to Reproduce / PoC",
            "```bash",
            finding.curl_poc or "# No curl PoC specified",
            "```",
            "",
            "### Evidence / Observed Response",
            "<details>",
            "<summary>View Diagnostic HTTP Output</summary>",
            "",
            "```http",
            finding.evidence.strip() if finding.evidence else "(No raw evidence attached)",
            "```",
            "",
            "</details>",
            "",
            "### Recommended Fix",
            finding.remediation,
        ])

        if finding.remediation_code:
            lang = finding.remediation_lang or "javascript"
            md.extend([
                "",
                "#### Suggested Patch:",
                f"```{lang}",
                finding.remediation_code.strip(),
                "```",
            ])

        md.extend([
            "",
            "### Remediation Checklist",
            "- [ ] Review affected routes and reproduce using cURL PoC",
            "- [ ] Implement code patch / web server configuration change",
            "- [ ] Verify via automated test or re-test audit",
            "- [ ] Deploy fix to production",
        ])

        return "\n".join(md)

    @classmethod
    def export_jira_json(
        cls,
        findings: List[DiagnosticFinding],
        project_key: str = "SEC",
        issue_type: str = "Vulnerability",
    ) -> Dict[str, Any]:
        """
        Formats findings into Jira REST API bulk create JSON payload.
        Compatible with POST /rest/api/2/issue/bulk.
        """
        issues = []
        for finding in findings:
            cvss_score_str = f"{finding.cvss_score:.1f}" if finding.cvss_score is not None else "N/A"
            cvss_vector_str = finding.cvss_vector or "N/A"
            priority_name = JIRA_PRIORITY_MAP.get(finding.severity.upper(), "Medium")

            desc_lines = [
                f"*Summary*: {finding.description}",
                "",
                f"*Severity*: {finding.severity} (CVSS: {cvss_score_str})",
                f"*CVSS Vector*: {cvss_vector_str}",
                f"*Weakness*: {finding.cwe_id}",
                "",
                "*Reproduction cURL*:",
                "{code:bash}",
                finding.curl_poc or "curl -i -s <target>",
                "{code}",
                "",
                "*Observed Evidence*:",
                "{code:http}",
                finding.evidence.strip() if finding.evidence else "(Diagnostic evidence)",
                "{code}",
                "",
                "*Remediation*:",
                finding.remediation,
            ]

            if finding.remediation_code:
                lang = finding.remediation_lang or "javascript"
                desc_lines.extend([
                    "",
                    f"*Suggested Patch ({lang})*:",
                    f"{{code:{lang}}}",
                    finding.remediation_code.strip(),
                    "{code}",
                ])

            if finding.affected_urls:
                desc_lines.extend(["", "*Affected URLs*:"])
                for url in finding.affected_urls:
                    desc_lines.append(f"* {url}")

            issue_dict = {
                "fields": {
                    "project": {"key": project_key},
                    "summary": f"[{finding.severity}] {finding.title} ({finding.cwe_id})",
                    "description": "\n".join(desc_lines),
                    "issuetype": {"name": issue_type},
                    "priority": {"name": priority_name},
                    "labels": [
                        "security",
                        "auditguard",
                        finding.severity.lower(),
                        finding.cwe_id.lower().replace("-", "_"),
                    ],
                }
            }
            issues.append(issue_dict)

        return {"issueUpdates": issues}

    @classmethod
    def export_hackerone(
        cls,
        findings: List[DiagnosticFinding],
        program_name: str = "Target Program",
        target_scope: str = "",
        safe_harbor_data: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Batch exports all findings into a combined HackerOne report document."""
        if not findings:
            return "# HackerOne Triage Report\n\nNo diagnostic findings to export."

        docs = []
        for i, f in enumerate(findings, 1):
            docs.append(f"<!-- FINDING {i} OF {len(findings)} -->\n" + cls.export_hackerone_finding(
                f, program_name=program_name, target_scope=target_scope, safe_harbor_data=safe_harbor_data
            ))

        return "\n\n---\n\n".join(docs)

    @classmethod
    def export_bugcrowd(
        cls,
        findings: List[DiagnosticFinding],
        program_name: str = "Target Program",
        target_scope: str = "",
    ) -> str:
        """Batch exports all findings into a combined Bugcrowd report document."""
        if not findings:
            return "# Bugcrowd Triage Report\n\nNo diagnostic findings to export."

        docs = []
        for i, f in enumerate(findings, 1):
            docs.append(f"<!-- FINDING {i} OF {len(findings)} -->\n" + cls.export_bugcrowd_finding(
                f, program_name=program_name, target_scope=target_scope
            ))

        return "\n\n---\n\n".join(docs)

    @classmethod
    def export_github(
        cls,
        findings: List[DiagnosticFinding],
        repository: str = "",
    ) -> str:
        """Batch exports all findings into GitHub Issues format."""
        if not findings:
            return "# GitHub Issues Export\n\nNo diagnostic findings to export."

        docs = []
        for i, f in enumerate(findings, 1):
            docs.append(f"<!-- ISSUE #{i} -->\n" + cls.export_github_issue(f, repository=repository))

        return "\n\n---\n\n".join(docs)

    @classmethod
    def export_all(
        cls,
        findings: List[DiagnosticFinding],
        output_dir: str,
        base_name: str = "audit_triage",
        program_name: str = "Target Program",
        target_scope: str = "",
        safe_harbor_data: Optional[Dict[str, Any]] = None,
        jira_project_key: str = "SEC",
    ) -> Dict[str, str]:
        """
        Exports all formats to disk and returns a dictionary of generated file paths.
        """
        os.makedirs(output_dir, exist_ok=True)
        paths = {}

        # 1. HackerOne
        h1_content = cls.export_hackerone(findings, program_name, target_scope, safe_harbor_data)
        h1_path = os.path.join(output_dir, f"{base_name}_hackerone.md")
        with open(h1_path, "w", encoding="utf-8") as fh:
            fh.write(h1_content)
        paths["hackerone"] = h1_path

        # 2. Bugcrowd
        bc_content = cls.export_bugcrowd(findings, program_name, target_scope)
        bc_path = os.path.join(output_dir, f"{base_name}_bugcrowd.md")
        with open(bc_path, "w", encoding="utf-8") as fh:
            fh.write(bc_content)
        paths["bugcrowd"] = bc_path

        # 3. GitHub Issues
        gh_content = cls.export_github(findings)
        gh_path = os.path.join(output_dir, f"{base_name}_github_issues.md")
        with open(gh_path, "w", encoding="utf-8") as fh:
            fh.write(gh_content)
        paths["github"] = gh_path

        # 4. Jira JSON
        jira_data = cls.export_jira_json(findings, project_key=jira_project_key)
        jira_path = os.path.join(output_dir, f"{base_name}_jira.json")
        with open(jira_path, "w", encoding="utf-8") as fh:
            json.dump(jira_data, fh, indent=2)
        paths["jira"] = jira_path

        return paths
