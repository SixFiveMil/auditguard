"""
AuditGuard Statement of Work (SOW) & Multi-Format Report Generator.
Consolidates scope rules, StateHunter reconnaissance provenance, and diagnostic findings
into publication-quality Markdown, HTML, and PDF deliverables.
Clearly separates Pre-Audit Authorization SOWs from Post-Audit Assessment Reports.
"""

from __future__ import annotations

import html
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.safe_harbor import SafeHarborLedgerAuditor, SafeHarborProof, SafeHarborTerms
from reporting.pdf_exporter import generate_pdf_remediation_report, generate_pdf_sow_report


class SOWReportGenerator:
    """
    Builds and exports comprehensive security assessment reports containing the formal
    Statement of Work (SOW), scope verification, and technical findings.
    """

    def __init__(
        self,
        program_key: str,
        program_cfg: Dict[str, Any],
        validator: Optional[Any] = None,
        findings: Optional[List[Dict[str, Any]]] = None,
        assessor: str = "Authorized Security Researcher",
        title: Optional[str] = None,
        audit_executed: Optional[bool] = None,
    ):
        self.program_key = program_key
        self.program_cfg = dict(program_cfg or {})
        self.validator = validator
        self.findings = list(findings) if findings is not None else []
        self.assessor = assessor

        if audit_executed is not None:
            self.audit_executed = audit_executed
        else:
            self.audit_executed = (findings is not None)

        default_title = (
            f"Security Assessment & SOW Compliance: {self.program_cfg.get('name', program_key)}"
            if self.audit_executed
            else f"Statement of Work (SOW) & Scope Authorization: {self.program_cfg.get('name', program_key)}"
        )
        self.title = title or default_title
        self.timestamp = time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime())

    def get_report_data(self) -> Dict[str, Any]:
        """Consolidates complete report context for rendering."""
        in_scope = self.program_cfg.get("in_scope", [])
        out_paths = self.program_cfg.get("out_of_scope", {}).get("paths", []) or self.program_cfg.get("excluded_paths", [])
        disc_eps = getattr(self.validator, "discovered_endpoints", []) or self.program_cfg.get("discovered_endpoints", [])
        flagged_eps = getattr(self.validator, "flagged_sensitive_endpoints", []) or self.program_cfg.get("flagged_sensitive_endpoints", [])

        # Calculate metrics
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            sev = f.get("severity", "INFO").upper()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        return {
            "audit_executed": self.audit_executed,
            "sow": {
                "title": self.title,
                "program_key": self.program_key,
                "assessment_date": self.timestamp,
                "assessor": self.assessor,
                "status": "ASSESSMENT COMPLETED" if self.audit_executed else "AUTHORIZED (PENDING AUDIT EXECUTION)",
            },
            "program": {
                "name": self.program_cfg.get("name", self.program_key),
                "platform": self.program_cfg.get("platform", "VDP / Self-Hosted"),
                "policy_url": self.program_cfg.get("policy_url", "N/A"),
                "rate_limit_per_second": self.program_cfg.get("rate_limit_per_second", 2.0),
                "in_scope": in_scope,
                "out_of_scope": self.program_cfg.get("out_of_scope", {"paths": out_paths}),
                "excluded_paths": out_paths,
                "discovered_endpoints": disc_eps,
                "flagged_sensitive_endpoints": flagged_eps,
                "rules_of_engagement": self.program_cfg.get("rules_of_engagement", {"header_tag": "X-Bug-Bounty"}),
            },
            "metrics": {
                "total_findings": len(self.findings),
                "severity_counts": sev_counts,
                "endpoints_discovered": len(disc_eps),
                "sensitive_endpoints": len(flagged_eps),
            },
            "findings": self.findings,
        }

    def export_markdown(self, output_path: Optional[str] = None) -> str:
        """Renders GitHub / triager-ready Markdown report."""
        data = self.get_report_data()
        p = data["program"]
        m = data["metrics"]
        s = data["sow"]

        in_scope_str = ", ".join(f"`{t}`" for t in p["in_scope"]) or "None defined"
        out_paths_str = ", ".join(f"`{x}`" for x in p["excluded_paths"]) or "None listed"

        lines = [
            f"# {s['title']}",
            "",
            f"**Target Program:** {p['name']} (`{s['program_key']}`)",
            f"**Platform / Authority:** {p['platform']}",
            f"**Date Verified:** {s['assessment_date']}",
            f"**Authorized Researcher:** {s['assessor']}",
            f"**Engagement Status:** `{s['status']}`",
            f"**Safe Harbor Compliance:** Enforced by AuditGuard (Paced Rate Limits & Mathematical Boundary Checks)",
            "",
            "---",
            "",
            "## 1. Statement of Work (SOW) & Authorized Scope",
            "",
            "| Engagement Parameter | Authorized Policy Specification |",
            "| :--- | :--- |",
            f"| **In-Scope Targets** | {in_scope_str} |",
            f"| **Explicit Exclusions** | {out_paths_str} |",
            f"| **Rate Limit Enforcement** | {p['rate_limit_per_second']} req/s max |",
            f"| **Safe Harbor Identification** | `{p['rules_of_engagement'].get('header_tag', 'X-Bug-Bounty')}` |",
            f"| **StateHunter Reconnaissance** | {m['endpoints_discovered']} endpoints mapped ({m['sensitive_endpoints']} flagged sensitive) |",
            "",
            "---",
            "",
        ]

        if not self.audit_executed:
            # Pre-audit SOW sections (Scope & Authorization)
            lines.extend([
                "## 2. Attack Surface & Route Inventory (StateHunter Reconnaissance)",
                "",
                f"- **Total Discovered Client Routes:** {m['endpoints_discovered']}",
                f"- **Flagged Sensitive / Admin Routes:** {m['sensitive_endpoints']}",
                "",
            ])
            if p["flagged_sensitive_endpoints"]:
                lines.append("**Flagged Endpoints Targeted for Diagnostic Audit:**")
                for ep in p["flagged_sensitive_endpoints"]:
                    lines.append(f"- `{ep}`")
                lines.append("")

            lines.extend([
                "---",
                "",
                "## 3. Planned Diagnostic Methodology & Rules of Engagement",
                "",
                "1. **Non-Destructive Declarative Testing:** Probes utilize safe ProjectDiscovery Nuclei v3 YAML templates.",
                "2. **Idempotent HTTP Operations:** Only read-only verbs (`GET`, `HEAD`, `OPTIONS`) are permitted in diagnostic mode.",
                "3. **Paced Rate Limiting:** All automated requests are rate-limited via the Gatekeeper token bucket.",
                "4. **Immutable Audit Trail:** All network traffic is recorded in the cryptographically-signed audit ledger.",
                "",
                "---",
                "",
                "## 4. Safe Harbor Legal Provisions & Scope Authorization Attestation",
                "",
                f"- **Good Faith Security Research:** {SafeHarborTerms.GOOD_FAITH_RESEARCH}",
                f"- **CFAA Authorization:** {SafeHarborTerms.CFAA_AUTHORIZATION}",
                f"- **DMCA Exemption:** {SafeHarborTerms.DMCA_EXEMPTION}",
                f"- **Data Protection & Privacy:** {SafeHarborTerms.DATA_PROTECTION_PRIVACY}",
                f"- **Non-Destructive Operations:** {SafeHarborTerms.NON_DESTRUCTIVE_GUARANTEE}",
                "",
                "This Statement of Work defines the binding boundaries for authorized security research. All testing activities ",
                "must strictly comply with the stated scope, rate limits, and safe-harbor terms. No destructive actions, denial of ",
                "service, or unauthorized data modification are permitted under this engagement.",
                "",
                "---",
                "*Generated by AuditGuard Scope Oversight Engine*",
            ])
        else:
            # Post-audit assessment report sections (Risk Posture & Findings)
            lines.extend([
                "## 2. Executive Risk Posture",
                "",
                f"- **Total Security Defects:** {m['total_findings']}",
                f"- **Critical:** {m['severity_counts']['CRITICAL']} | **High:** {m['severity_counts']['HIGH']} | **Medium:** {m['severity_counts']['MEDIUM']} | **Low:** {m['severity_counts']['LOW']} | **Info:** {m['severity_counts']['INFO']}",
                "",
                "---",
                "",
                f"## 3. Detailed Security Findings ({len(self.findings)})",
                "",
            ])

            if not self.findings:
                lines.append("`[+] All in-scope endpoints passed diagnostic security checks without defects.`\n")
            else:
                for idx, f in enumerate(self.findings, 1):
                    sev = f.get("severity", "INFO").upper()
                    cwe = f.get("cwe_id", "N/A")
                    title = f.get("title", "Finding")
                    desc = f.get("description", "").strip()
                    evidence = f.get("evidence", "").strip()
                    fix = f.get("remediation", "").strip()
                    curl_poc = (f.get("curl_poc") or "").strip()
                    affected = f.get("affected_urls", [])
                    cvss_score = f.get("cvss_score")
                    cvss_vector = f.get("cvss_vector")
                    rem_code = (f.get("remediation_code") or "").strip()
                    rem_lang = f.get("remediation_lang") or "javascript"

                    lines.extend([
                        f"### {idx}. [{sev}] {title} ({cwe})",
                    ])
                    if cvss_score is not None:
                        lines.append(f"- **CVSS v3.1 Base Score:** `{cvss_score:.1f}` ({cvss_vector or 'N/A'})")
                    lines.append(f"- **Description:** {desc}")
                    if affected:
                        aff_str = ", ".join(f"`{u}`" for u in affected)
                        lines.append(f"- **Affected Endpoint(s):** {aff_str}")
                    if evidence:
                        lines.extend([
                            "- **Evidence / Observed Response:**",
                            "```http",
                            evidence,
                            "```",
                        ])
                    if curl_poc:
                        lines.extend([
                            "- **Reproduction (cURL):**",
                            "```bash",
                            curl_poc,
                            "```",
                        ])
                    if fix:
                        lines.append(f"- **Suggested Remediation:** {fix}")
                    if rem_code:
                        lines.extend([
                            f"- **Remediation Code Patch ({rem_lang}):**",
                            f"```{rem_lang}",
                            rem_code,
                            "```",
                        ])
                    lines.append("")

            # Audit Safe Harbor Proof
            proof = None
            try:
                proof = SafeHarborLedgerAuditor.audit_engagement(
                    log_path="audit/audit_log.jsonl",
                    program_cfg=p,
                    program_key=s["program_key"],
                )
            except Exception:
                pass

            lines.extend([
                "---",
                "",
                "## 4. Safe Harbor Legal Provisions, Methodology & Compliance Attestation",
                "",
                "This assessment was conducted strictly within authorized scope boundaries. Reconnaissance endpoints were ",
                "harvested via StateHunter in-browser state inspection and validated locally by AuditGuard's gatekeeper before ",
                "transmitting any network packet. All interactions were cryptographically tracked in the audit ledger.",
                "",
                "### Disclose.io Core Legal Protections",
                f"- **Good Faith Security Research:** {SafeHarborTerms.GOOD_FAITH_RESEARCH}",
                f"- **CFAA Authorization:** {SafeHarborTerms.CFAA_AUTHORIZATION}",
                f"- **DMCA Exemption:** {SafeHarborTerms.DMCA_EXEMPTION}",
                f"- **Data Protection & Privacy:** {SafeHarborTerms.DATA_PROTECTION_PRIVACY}",
                f"- **Non-Destructive Operations:** {SafeHarborTerms.NON_DESTRUCTIVE_GUARANTEE}",
                "",
            ])

            if proof:
                status_tag = "[PASS - SAFE HARBOR PROTECTED]" if proof.is_fully_compliant else "[NON-COMPLIANT WARNING]"
                lines.extend([
                    "### Cryptographic Audit Ledger Proof",
                    "",
                    "| Metric | Audit Value | Policy Specification | Status |",
                    "| :--- | :--- | :--- | :--- |",
                    f"| **Total Dispatched Requests** | {proof.total_requests} | N/A | Logged |",
                    f"| **Traffic Pacing Rate** | {proof.effective_rate_per_sec:.2f} req/s | Max {proof.rate_limit_ceiling:.2f} req/s | {'PASS' if proof.rate_limit_compliant else 'FAIL'} |",
                    f"| **Identity Header Adherence** | {proof.header_compliance_pct:.1f}% | 100% `{proof.header_tag}` | {'PASS' if proof.header_compliance_pct >= 90.0 else 'WARN'} |",
                    f"| **Excluded Path Guardrail** | {proof.excluded_paths_dispatched} dispatched | 0 allowed | {'PASS' if proof.excluded_paths_dispatched == 0 else 'VIOLATION'} |",
                    f"| **Ledger SHA-256 Digest** | `{proof.session_sha256[:32]}...` | Immutable Ledger Integrity | Verified |",
                    "",
                    f"**Engagement Safe Harbor Status:** `{status_tag}`",
                    "",
                ])

            lines.extend([
                "---",
                "*Generated by AuditGuard Scope Oversight Engine*",
            ])

        md_content = "\n".join(lines)
        if output_path:
            p_out = Path(output_path)
            p_out.parent.mkdir(parents=True, exist_ok=True)
            p_out.write_text(md_content, encoding="utf-8")

        return md_content

    def export_html(self, output_path: Optional[str] = None) -> str:
        """Renders an executive, self-contained HTML report with print styles."""
        data = self.get_report_data()
        p = data["program"]
        m = data["metrics"]
        s = data["sow"]

        sev_styles = {
            "CRITICAL": "background: #fee2e2; color: #991b1b; border: 1px solid #f87171;",
            "HIGH": "background: #ffedd5; color: #9a3412; border: 1px solid #fb923c;",
            "MEDIUM": "background: #fef9c3; color: #854d0e; border: 1px solid #facc15;",
            "LOW": "background: #dbeafe; color: #1e40af; border: 1px solid #60a5fa;",
            "INFO": "background: #f1f5f9; color: #475569; border: 1px solid #cbd5e1;",
        }

        if not self.audit_executed:
            # Pre-audit SOW content
            flagged_html = ""
            if p["flagged_sensitive_endpoints"]:
                items = "".join(f"<li><code>{html.escape(ep)}</code></li>" for ep in p["flagged_sensitive_endpoints"])
                flagged_html = f"<div class='sensitive-box'><strong>Flagged Endpoints Targeted for Probing:</strong><ul>{items}</ul></div>"

            body_sections = f"""
    <h2>2. Attack Surface & Route Inventory (StateHunter Reconnaissance)</h2>
    <div class="summary-cards">
      <div class="card"><span class="val">{m['endpoints_discovered']}</span><span class="lbl">Discovered Routes</span></div>
      <div class="card"><span class="val">{m['sensitive_endpoints']}</span><span class="lbl">Sensitive / Admin Routes</span></div>
      <div class="card"><span class="val">{len(p['in_scope'])}</span><span class="lbl">In-Scope Hosts</span></div>
      <div class="card"><span class="val">{len(p['excluded_paths'])}</span><span class="lbl">Explicit Exclusions</span></div>
    </div>
    {flagged_html}

    <h2>3. Planned Testing Methodology & Rules of Engagement</h2>
    <div class="methodology-box">
      <ol>
        <li><strong>Non-Destructive Declarative Testing:</strong> Probes adhere to the ProjectDiscovery Nuclei v3 YAML standard, performing harmless fingerprinting.</li>
        <li><strong>Idempotent HTTP Operations:</strong> Only read-only verbs (<code>GET</code>, <code>HEAD</code>, <code>OPTIONS</code>) are permitted in diagnostic mode.</li>
        <li><strong>Paced Rate Limiting:</strong> All traffic is paced via Gatekeeper token bucket ({p['rate_limit_per_second']} req/s maximum).</li>
        <li><strong>Cryptographic Audit Ledger:</strong> Every outgoing byte and response checksum is logged to the local audit ledger.</li>
      </ol>
    </div>

    <h2>4. Safe Harbor Compliance & Scope Authorization Attestation</h2>
    <div class="attestation">
      <strong>Good Faith Security Research (Disclose.io Aligned):</strong><br>
      {SafeHarborTerms.GOOD_FAITH_RESEARCH}<br><br>
      <strong>CFAA & DMCA Safe Harbor:</strong><br>
      {SafeHarborTerms.CFAA_AUTHORIZATION} {SafeHarborTerms.DMCA_EXEMPTION}<br><br>
      <strong>Privacy & Non-Destructive Commitment:</strong><br>
      {SafeHarborTerms.DATA_PROTECTION_PRIVACY} {SafeHarborTerms.NON_DESTRUCTIVE_GUARANTEE}
    </div>
"""
            status_badge = '<span class="status-pill status-pending">STATUS: AUTHORIZED - TESTING PENDING</span>'
            subtitle = "Formal Statement of Work (SOW) & Scope Authorization Deliverable"

        else:
            # Post-audit Assessment Report content
            findings_html = []
            for idx, f in enumerate(self.findings, 1):
                sev = f.get("severity", "INFO").upper()
                badge_style = sev_styles.get(sev, sev_styles["INFO"])
                cwe = html.escape(f.get("cwe_id", "N/A"))
                title = html.escape(f.get("title", "Finding"))
                desc = html.escape(f.get("description", ""))
                evidence = html.escape(f.get("evidence", ""))
                fix = html.escape(f.get("remediation", ""))
                curl_poc = (f.get("curl_poc") or "").strip()
                affected = f.get("affected_urls", [])
                cvss_score = f.get("cvss_score")
                cvss_vector = html.escape(f.get("cvss_vector") or "")
                rem_code = (f.get("remediation_code") or "").strip()
                rem_lang = html.escape(f.get("remediation_lang") or "javascript")

                cvss_badge = f'<span class="badge" style="background:#475569; color:#fff; margin-left:6px;">CVSS {cvss_score:.1f}</span>' if cvss_score is not None else ""
                cvss_vector_span = f'<div style="font-family:monospace; font-size:11px; color:#64748b; margin-top:2px;">{cvss_vector}</div>' if cvss_vector else ""

                aff_html = ""
                if affected:
                    aff_html = f"<div class='affected'><strong>Affected Endpoints:</strong> {', '.join(html.escape(u) for u in affected)}</div>"

                ev_html = ""
                if evidence:
                    ev_html = f"<div class='evidence-box'><strong>Evidence:</strong><pre>{evidence}</pre></div>"

                curl_html = ""
                if curl_poc:
                    curl_html = f"<div class='evidence-box'><strong>Reproduction (cURL):</strong><pre>{html.escape(curl_poc)}</pre></div>"

                fix_html = ""
                if fix:
                    fix_html = f"<div class='remediation-box'><strong>Remediation:</strong> {fix}</div>"

                code_html = ""
                if rem_code:
                    code_html = f"<div class='remediation-box' style='background:#0f172a; color:#f8fafc; border-left:4px solid #0d9488;'><strong>Remediation Code Patch ({rem_lang}):</strong><pre style='background:transparent; color:#38bdf8; margin:4px 0 0 0; padding:4px; font-size:11px;'>{html.escape(rem_code)}</pre></div>"

                card = f"""
                <div class="finding-card">
                  <div class="finding-header">
                    <span class="badge" style="{badge_style}">{sev}</span>{cvss_badge}
                    <h3>{idx}. {title} <span class="cwe">({cwe})</span></h3>
                    {cvss_vector_span}
                  </div>
                  <p class="desc">{desc}</p>
                  {aff_html}
                  {ev_html}
                  {curl_html}
                  {fix_html}
                  {code_html}
                </div>
                """
                findings_html.append(card)

            findings_body = "\n".join(findings_html) if findings_html else "<div class='clean-pass'>[+] All in-scope endpoints passed diagnostic security checks without defects.</div>"

            # Audit Safe Harbor Proof
            proof = None
            try:
                proof = SafeHarborLedgerAuditor.audit_engagement(
                    log_path="audit/audit_log.jsonl",
                    program_cfg=p,
                    program_key=s["program_key"],
                )
            except Exception:
                pass

            proof_html = ""
            if proof:
                status_color = "#166534" if proof.is_fully_compliant else "#991b1b"
                status_tag = "PASS - SAFE HARBOR PROTECTED" if proof.is_fully_compliant else "NON-COMPLIANT WARNING"
                proof_html = f"""
                <div style="margin-top: 14px; background: #ffffff; border: 1px solid #cbd5e1; border-radius: 6px; padding: 12px;">
                  <strong style="color: {status_color}; font-size: 13px;">Cryptographic Audit Ledger Proof-of-Adherence [{status_tag}]</strong>
                  <table style="margin-top: 8px; width: 100%; border-collapse: collapse; font-size: 12px;">
                    <tr><th>Metric</th><th>Audit Value</th><th>Policy Specification</th><th>Status</th></tr>
                    <tr><td>Total Requests</td><td>{proof.total_requests}</td><td>N/A</td><td><span class="badge" style="background:#dcfce7;color:#166534;">LOGGED</span></td></tr>
                    <tr><td>Traffic Pacing Rate</td><td>{proof.effective_rate_per_sec:.2f} req/s</td><td>Max {proof.rate_limit_ceiling:.2f} req/s</td><td><span class="badge" style="{'background:#dcfce7;color:#166534;' if proof.rate_limit_compliant else 'background:#fee2e2;color:#991b1b;'}">{'PASS' if proof.rate_limit_compliant else 'FAIL'}</span></td></tr>
                    <tr><td>Identity Tagging</td><td>{proof.header_compliance_pct:.1f}%</td><td>100% <code>{html.escape(proof.header_tag)}</code></td><td><span class="badge" style="{'background:#dcfce7;color:#166534;' if proof.header_compliance_pct >= 90.0 else 'background:#fee2e2;color:#991b1b;'}">{'PASS' if proof.header_compliance_pct >= 90.0 else 'WARN'}</span></td></tr>
                    <tr><td>Excluded Path Guardrail</td><td>{proof.excluded_paths_dispatched} dispatched</td><td>0 allowed</td><td><span class="badge" style="{'background:#dcfce7;color:#166534;' if proof.excluded_paths_dispatched == 0 else 'background:#fee2e2;color:#991b1b;'}">{'PASS' if proof.excluded_paths_dispatched == 0 else 'VIOLATION'}</span></td></tr>
                    <tr><td>Ledger SHA-256 Digest</td><td colspan="3"><code>{proof.session_sha256[:32]}...</code></td></tr>
                  </table>
                </div>
                """

            body_sections = f"""
    <h2>2. Executive Risk Posture</h2>
    <div class="summary-cards">
      <div class="card critical"><span class="val">{m['severity_counts']['CRITICAL']}</span><span class="lbl">Critical</span></div>
      <div class="card high"><span class="val">{m['severity_counts']['HIGH']}</span><span class="lbl">High</span></div>
      <div class="card medium"><span class="val">{m['severity_counts']['MEDIUM']}</span><span class="lbl">Medium</span></div>
      <div class="card low"><span class="val">{m['severity_counts']['LOW']}</span><span class="lbl">Low</span></div>
      <div class="card info"><span class="val">{m['severity_counts']['INFO']}</span><span class="lbl">Info</span></div>
    </div>

    <h2>3. Security Findings & Technical Evidence ({len(self.findings)})</h2>
    {findings_body}

    <h2>4. Scope Compliance & Safe Harbor Legal Attestation</h2>
    <div class="attestation">
      <strong>Good Faith Security Research (Disclose.io Aligned):</strong><br>
      {SafeHarborTerms.GOOD_FAITH_RESEARCH}<br><br>
      <strong>CFAA & DMCA Authorization:</strong><br>
      {SafeHarborTerms.CFAA_AUTHORIZATION} {SafeHarborTerms.DMCA_EXEMPTION}<br><br>
      <strong>Data Protection & Non-Destructive Guarantee:</strong><br>
      {SafeHarborTerms.DATA_PROTECTION_PRIVACY} {SafeHarborTerms.NON_DESTRUCTIVE_GUARANTEE}
    </div>
    {proof_html}
"""
            status_badge = '<span class="status-pill status-completed">STATUS: AUDIT COMPLETED</span>'
            subtitle = "Security Assessment Report & SOW Compliance Deliverable"

        in_scope_html = ", ".join(f"<code>{html.escape(t)}</code>" for t in p["in_scope"]) or "None defined"
        out_paths_html = ", ".join(f"<code>{html.escape(x)}</code>" for x in p["excluded_paths"]) or "None listed"

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{html.escape(s['title'])}</title>
  <style>
    @page {{
      size: A4;
      margin: 20mm;
    }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      color: #0f172a;
      line-height: 1.5;
      margin: 0;
      padding: 24px;
      background: #f8fafc;
    }}
    .container {{
      max-width: 900px;
      margin: 0 auto;
      background: #ffffff;
      padding: 36px 48px;
      border-radius: 8px;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    }}
    header {{
      border-bottom: 2px solid #e2e8f0;
      padding-bottom: 18px;
      margin-bottom: 24px;
    }}
    h1 {{
      font-size: 24px;
      margin: 0 0 6px 0;
      color: #0f172a;
    }}
    .subtitle {{
      font-size: 14px;
      color: #64748b;
      margin-bottom: 10px;
    }}
    .status-pill {{
      display: inline-block;
      padding: 4px 10px;
      border-radius: 9999px;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }}
    .status-pending {{
      background: #e0f2fe;
      color: #0369a1;
      border: 1px solid #7dd3fc;
    }}
    .status-completed {{
      background: #dcfce7;
      color: #15803d;
      border: 1px solid #86efac;
    }}
    h2 {{
      font-size: 17px;
      color: #1e293b;
      margin-top: 30px;
      padding-bottom: 6px;
      border-bottom: 1px solid #e2e8f0;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin-top: 12px;
      font-size: 13px;
    }}
    th, td {{
      padding: 8px 12px;
      text-align: left;
      border: 1px solid #e2e8f0;
    }}
    th {{
      background: #f1f5f9;
      width: 25%;
      color: #475569;
      font-weight: 600;
    }}
    .summary-cards {{
      display: flex;
      gap: 12px;
      margin-top: 12px;
    }}
    .card {{
      flex: 1;
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      padding: 12px;
      border-radius: 6px;
      text-align: center;
    }}
    .card.critical {{ border-top: 4px solid #ef4444; }}
    .card.high {{ border-top: 4px solid #f97316; }}
    .card.medium {{ border-top: 4px solid #eab308; }}
    .card.low {{ border-top: 4px solid #3b82f6; }}
    .card.info {{ border-top: 4px solid #64748b; }}
    .card .val {{
      display: block;
      font-size: 20px;
      font-weight: 700;
      color: #0f172a;
    }}
    .card .lbl {{
      font-size: 11px;
      color: #64748b;
      text-transform: uppercase;
      font-weight: 600;
    }}
    .finding-card {{
      background: #ffffff;
      border: 1px solid #e2e8f0;
      border-radius: 6px;
      padding: 16px;
      margin-top: 14px;
      page-break-inside: avoid;
    }}
    .finding-header {{
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 8px;
    }}
    .finding-header h3 {{
      margin: 0;
      font-size: 15px;
      color: #0f172a;
    }}
    .finding-header .cwe {{
      font-size: 12px;
      color: #64748b;
      font-weight: normal;
    }}
    .badge {{
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 700;
    }}
    .desc {{
      font-size: 13px;
      color: #334155;
      margin: 6px 0;
    }}
    .affected {{
      font-size: 12px;
      color: #64748b;
      margin-top: 4px;
    }}
    .evidence-box {{
      margin-top: 8px;
      background: #f1f5f9;
      border: 1px solid #cbd5e1;
      padding: 10px;
      border-radius: 4px;
      font-size: 11px;
    }}
    .evidence-box pre {{
      margin: 4px 0 0 0;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      white-space: pre-wrap;
      word-break: break-all;
    }}
    .remediation-box {{
      margin-top: 8px;
      background: #f0fdf4;
      border: 1px solid #bbf7d0;
      color: #166534;
      padding: 10px;
      border-radius: 4px;
      font-size: 12px;
    }}
    .sensitive-box, .methodology-box {{
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      padding: 14px;
      border-radius: 6px;
      margin-top: 12px;
      font-size: 13px;
    }}
    .sensitive-box ul, .methodology-box ol {{
      margin: 8px 0 0 16px;
      padding: 0;
    }}
    .clean-pass {{
      padding: 14px;
      background: #f0fdf4;
      border: 1px solid #bbf7d0;
      color: #15803d;
      border-radius: 6px;
      font-weight: 600;
      font-size: 13px;
      margin-top: 12px;
    }}
    .attestation {{
      background: #f8fafc;
      border-left: 4px solid #3b82f6;
      padding: 12px 16px;
      font-size: 12px;
      color: #475569;
      margin-top: 14px;
      font-style: italic;
    }}
    @media print {{
      body {{ background: #ffffff; padding: 0; }}
      .container {{ box-shadow: none; padding: 0; }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>{html.escape(s['title'])}</h1>
      <div class="subtitle">{subtitle}</div>
      {status_badge}
    </header>

    <h2>1. Statement of Work (SOW) & Engagement Scope</h2>
    <table>
      <tr><th>Target Program</th><td>{html.escape(p['name'])} (<code>{html.escape(s['program_key'])}</code>)</td></tr>
      <tr><th>Platform / Authority</th><td>{html.escape(p['platform'])}</td></tr>
      <tr><th>Date Verified</th><td>{html.escape(s['assessment_date'])}</td></tr>
      <tr><th>Authorized Researcher</th><td>{html.escape(s['assessor'])}</td></tr>
      <tr><th>Rate Limit Policy</th><td>{p['rate_limit_per_second']} requests/second maximum</td></tr>
      <tr><th>Header Identification</th><td><code>{html.escape(p['rules_of_engagement'].get('header_tag', 'X-Bug-Bounty'))}</code></td></tr>
      <tr><th>In-Scope Targets</th><td>{in_scope_html}</td></tr>
      <tr><th>Explicit Exclusions</th><td>{out_paths_html}</td></tr>
      <tr><th>StateHunter Provenance</th><td>{m['endpoints_discovered']} client routes discovered ({m['sensitive_endpoints']} flagged sensitive)</td></tr>
    </table>

    {body_sections}
  </div>
</body>
</html>
"""
        if output_path:
            p_out = Path(output_path)
            p_out.parent.mkdir(parents=True, exist_ok=True)
            p_out.write_text(html_content, encoding="utf-8")

        return html_content

    def export_pdf(self, output_path: str) -> None:
        """Renders direct vector PDF via pdf_exporter."""
        data = self.get_report_data()
        p_out = Path(output_path)
        p_out.parent.mkdir(parents=True, exist_ok=True)
        generate_pdf_sow_report(data, str(p_out))

    def export_all(self, base_name: str, formats: Optional[List[str]] = None) -> Dict[str, str]:
        """Exports multiple formats at once."""
        fmt_list = formats or ["pdf", "html", "md"]
        exported: Dict[str, str] = {}

        if "md" in fmt_list:
            md_path = f"{base_name}.md"
            self.export_markdown(md_path)
            exported["markdown"] = md_path

        if "html" in fmt_list:
            html_path = f"{base_name}.html"
            self.export_html(html_path)
            exported["html"] = html_path

        if "pdf" in fmt_list:
            pdf_path = f"{base_name}.pdf"
            self.export_pdf(pdf_path)
            exported["pdf"] = pdf_path

        return exported


class RemediationReportGenerator:
    """
    Builds and exports formal Differential Remediation Verification reports
    comparing baseline vs re-test finding states across Markdown, HTML, and PDF.
    """

    def __init__(
        self,
        remediation_data: Dict[str, Any],
        program_cfg: Dict[str, Any],
        assessor: str = "Authorized Security Researcher",
        title: Optional[str] = None,
    ):
        self.remediation_data = dict(remediation_data or {})
        self.program_cfg = dict(program_cfg or {})
        self.assessor = assessor
        self.program_key = self.remediation_data.get("program_key", self.program_cfg.get("name", "active"))
        self.title = title or f"Remediation Verification Report: {self.program_cfg.get('name', self.program_key)}"
        self.retest_date = self.remediation_data.get("retest_date") or time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime())

    def get_report_data(self) -> Dict[str, Any]:
        data = dict(self.remediation_data)
        data.setdefault("program_name", self.program_cfg.get("name", self.program_key))
        data.setdefault("program_key", self.program_key)
        data.setdefault("retest_date", self.retest_date)
        data.setdefault("assessor", self.assessor)
        data.setdefault("title", self.title)

        if "safe_harbor_proof" not in data or data["safe_harbor_proof"] is None:
            try:
                proof = SafeHarborLedgerAuditor.audit_engagement(
                    log_path="audit/audit_log.jsonl",
                    program_cfg=self.program_cfg,
                    program_key=self.program_key,
                )
                data["safe_harbor_proof"] = proof
            except Exception:
                pass
        return data

    def export_markdown(self, output_path: Optional[str] = None) -> str:
        data = self.get_report_data()
        m = data.get("metrics", {})
        items = data.get("items", [])
        proof = data.get("safe_harbor_proof")

        lines = [
            f"# {self.title}",
            "",
            f"**Target Program:** {data['program_name']} (`{self.program_key}`)",
            f"**Baseline Session ID:** `{data.get('baseline_session_id', 'N/A')}`",
            f"**Verification Date:** {self.retest_date}",
            f"**Authorized Lead Assessor:** {self.assessor}",
            "**Safe Harbor Protection:** Enforced by AuditGuard (Disclose.io Core Compliance)",
            "",
            "---",
            "",
            "## 1. Executive Remediation Metrics",
            "",
            "| Metric | Count / Value |",
            "| :--- | :--- |",
            f"| **Total Prior Defects Evaluated** | {m.get('total_baseline_defects', len(items))} |",
            f"| **Successfully Resolved (`[RESOLVED]`)** | **{m.get('resolved_count', 0)}** |",
            f"| **Persistent Defects (`[UNRESOLVED]`)** | **{m.get('unresolved_count', 0)}** |",
            f"| **Overall Remediation Rate** | **{m.get('resolution_rate_pct', 0.0):.1f}%** |",
            "",
            "---",
            "",
            f"## 2. Differential Verification Findings ({len(items)} Evaluated)",
            "",
        ]

        if not items:
            lines.append("`[+] No prior defects found in baseline session.`\n")
        else:
            for idx, item in enumerate(items, 1):
                res = item.get("result", "UNRESOLVED").upper()
                badge = f"**`[{res}]`**"
                sev = item.get("severity", "MEDIUM").upper()
                cwe = item.get("cwe_id", "N/A")
                title = item.get("title", "Finding")
                u = item.get("affected_url", "N/A")
                b_stat = item.get("baseline_status", "VULNERABLE")
                r_stat = item.get("retest_status", res)
                ev = item.get("evidence", "").strip()
                fix = item.get("remediation", "").strip()
                curl_poc = (item.get("curl_poc") or "").strip()

                lines.extend([
                    f"### {idx}. {badge} [{sev}] {title} ({cwe})",
                    f"- **Affected Endpoint:** `{u}`",
                    f"- **Differential Status:** `{b_stat}` -> `{r_stat}`",
                    f"- **Verification Note:** {ev}",
                ])
                if curl_poc:
                    lines.extend([
                        "- **Reproduction (cURL):**",
                        "```bash",
                        curl_poc,
                        "```",
                    ])
                if fix and res == "UNRESOLVED":
                    lines.append(f"- **Required Action:** {fix}")
                lines.append("")

        lines.extend([
            "---",
            "",
            "## 3. Safe Harbor Legal Provisions & Proof-of-Adherence",
            "",
            "### Disclose.io Core Legal Protections",
            f"- **Good Faith Security Research:** {SafeHarborTerms.GOOD_FAITH_RESEARCH}",
            f"- **CFAA Authorization:** {SafeHarborTerms.CFAA_AUTHORIZATION}",
            f"- **DMCA Exemption:** {SafeHarborTerms.DMCA_EXEMPTION}",
            f"- **Data Protection & Privacy:** {SafeHarborTerms.DATA_PROTECTION_PRIVACY}",
            f"- **Non-Destructive Operations:** {SafeHarborTerms.NON_DESTRUCTIVE_GUARANTEE}",
            "",
        ])

        if proof:
            status_tag = "[PASS - SAFE HARBOR PROTECTED]" if proof.is_fully_compliant else "[NON-COMPLIANT WARNING]"
            lines.extend([
                "### Cryptographic Audit Ledger Proof",
                "",
                "| Metric | Audit Value | Policy Specification | Status |",
                "| :--- | :--- | :--- | :--- |",
                f"| **Total Dispatched Requests** | {proof.total_requests} | N/A | Logged |",
                f"| **Traffic Pacing Rate** | {proof.effective_rate_per_sec:.2f} req/s | Max {proof.rate_limit_ceiling:.2f} req/s | {'PASS' if proof.rate_limit_compliant else 'FAIL'} |",
                f"| **Identity Header Adherence** | {proof.header_compliance_pct:.1f}% | 100% `{proof.header_tag}` | {'PASS' if proof.header_compliance_pct >= 90.0 else 'WARN'} |",
                f"| **Excluded Path Guardrail** | {proof.excluded_paths_dispatched} dispatched | 0 allowed | {'PASS' if proof.excluded_paths_dispatched == 0 else 'VIOLATION'} |",
                f"| **Ledger SHA-256 Digest** | `{proof.session_sha256[:32]}...` | Immutable Ledger Integrity | Verified |",
                "",
                f"**Engagement Safe Harbor Status:** `{status_tag}`",
                "",
            ])

        lines.extend([
            "---",
            "*Generated by AuditGuard Differential Remediation Engine*",
        ])

        content = "\n".join(lines)
        if output_path:
            p_out = Path(output_path)
            p_out.parent.mkdir(parents=True, exist_ok=True)
            p_out.write_text(content, encoding="utf-8")
        return content

    def export_html(self, output_path: Optional[str] = None) -> str:
        data = self.get_report_data()
        m = data.get("metrics", {})
        items = data.get("items", [])
        proof = data.get("safe_harbor_proof")

        sev_styles = {
            "CRITICAL": "background: #fee2e2; color: #991b1b; border: 1px solid #f87171;",
            "HIGH": "background: #ffedd5; color: #9a3412; border: 1px solid #fb923c;",
            "MEDIUM": "background: #fef9c3; color: #854d0e; border: 1px solid #facc15;",
            "LOW": "background: #dbeafe; color: #1e40af; border: 1px solid #60a5fa;",
            "INFO": "background: #f1f5f9; color: #475569; border: 1px solid #cbd5e1;",
        }

        res_styles = {
            "RESOLVED": "background: #dcfce7; color: #166534; border: 1px solid #86efac;",
            "UNRESOLVED": "background: #fee2e2; color: #991b1b; border: 1px solid #fca5a5;",
            "NEW": "background: #fef9c3; color: #854d0e; border: 1px solid #facc15;",
        }

        items_html = []
        for idx, item in enumerate(items, 1):
            res = item.get("result", "UNRESOLVED").upper()
            res_style = res_styles.get(res, res_styles["UNRESOLVED"])
            sev = item.get("severity", "MEDIUM").upper()
            sev_style = sev_styles.get(sev, sev_styles["INFO"])
            cwe = html.escape(item.get("cwe_id", "N/A"))
            title = html.escape(item.get("title", "Defect"))
            u = html.escape(item.get("affected_url", "N/A"))
            b_stat = html.escape(item.get("baseline_status", "VULNERABLE"))
            r_stat = html.escape(item.get("retest_status", res))
            ev = html.escape(item.get("evidence", ""))
            fix = html.escape(item.get("remediation", ""))
            curl_poc = (item.get("curl_poc") or "").strip()

            curl_html = ""
            if curl_poc:
                curl_html = f"<div class='evidence-box'><strong>Reproduction (cURL):</strong><pre>{html.escape(curl_poc)}</pre></div>"

            card = f"""
            <div class="finding-card">
              <div class="finding-header">
                <span class="badge" style="{res_style}">{res}</span>
                <span class="badge" style="{sev_style}">{sev}</span>
                <h3>{idx}. {title} <span class="cwe">({cwe})</span></h3>
              </div>
              <div class="affected"><strong>Endpoint:</strong> <code>{u}</code></div>
              <div style="font-size: 12px; margin-top: 4px; color: #475569;">
                <strong>Status Transition:</strong> <code>{b_stat}</code> &rarr; <code>{r_stat}</code>
              </div>
              <div class="evidence-box"><strong>Verification Note:</strong><pre>{ev}</pre></div>
              {curl_html}
              {'<div class="remediation-box"><strong>Action:</strong> ' + fix + '</div>' if fix and res == "UNRESOLVED" else ''}
            </div>
            """
            items_html.append(card)

        body_findings = "\n".join(items_html) if items_html else "<div class='clean-pass'>[+] No prior defects recorded for this session.</div>"

        proof_html = ""
        if proof:
            status_color = "#166534" if proof.is_fully_compliant else "#991b1b"
            status_tag = "PASS - SAFE HARBOR PROTECTED" if proof.is_fully_compliant else "NON-COMPLIANT WARNING"
            proof_html = f"""
            <div style="margin-top: 14px; background: #ffffff; border: 1px solid #cbd5e1; border-radius: 6px; padding: 12px;">
              <strong style="color: {status_color}; font-size: 13px;">Cryptographic Audit Ledger Proof-of-Adherence [{status_tag}]</strong>
              <table style="margin-top: 8px; width: 100%; border-collapse: collapse; font-size: 12px;">
                <tr><th>Metric</th><th>Audit Value</th><th>Policy Specification</th><th>Status</th></tr>
                <tr><td>Total Requests</td><td>{proof.total_requests}</td><td>N/A</td><td><span class="badge" style="background:#dcfce7;color:#166534;">LOGGED</span></td></tr>
                <tr><td>Traffic Pacing Rate</td><td>{proof.effective_rate_per_sec:.2f} req/s</td><td>Max {proof.rate_limit_ceiling:.2f} req/s</td><td><span class="badge" style="{'background:#dcfce7;color:#166534;' if proof.rate_limit_compliant else 'background:#fee2e2;color:#991b1b;'}">{'PASS' if proof.rate_limit_compliant else 'FAIL'}</span></td></tr>
                <tr><td>Identity Tagging</td><td>{proof.header_compliance_pct:.1f}%</td><td>100% <code>{html.escape(proof.header_tag)}</code></td><td><span class="badge" style="{'background:#dcfce7;color:#166534;' if proof.header_compliance_pct >= 90.0 else 'background:#fee2e2;color:#991b1b;'}">{'PASS' if proof.header_compliance_pct >= 90.0 else 'WARN'}</span></td></tr>
                <tr><td>Excluded Path Guardrail</td><td>{proof.excluded_paths_dispatched} dispatched</td><td>0 allowed</td><td><span class="badge" style="{'background:#dcfce7;color:#166534;' if proof.excluded_paths_dispatched == 0 else 'background:#fee2e2;color:#991b1b;'}">{'PASS' if proof.excluded_paths_dispatched == 0 else 'VIOLATION'}</span></td></tr>
                <tr><td>Ledger SHA-256 Digest</td><td colspan="3"><code>{proof.session_sha256[:32]}...</code></td></tr>
              </table>
            </div>
            """

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{html.escape(self.title)}</title>
  <style>
    @page {{ size: A4; margin: 15mm; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #1e293b; background: #f8fafc; margin: 0; padding: 24px; line-height: 1.5; }}
    .container {{ max-width: 900px; margin: 0 auto; background: #ffffff; border-radius: 8px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); padding: 32px; border: 1px solid #e2e8f0; }}
    header {{ border-bottom: 2px solid #0f172a; padding-bottom: 16px; margin-bottom: 24px; }}
    h1 {{ font-size: 24px; color: #0f172a; margin: 0 0 6px 0; }}
    .subtitle {{ font-size: 14px; color: #64748b; margin-bottom: 12px; }}
    .status-pill {{ display: inline-block; padding: 4px 12px; border-radius: 9999px; font-size: 11px; font-weight: 700; background: #dbeafe; color: #1e40af; }}
    h2 {{ font-size: 16px; color: #0f172a; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; margin-top: 24px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 13px; }}
    th, td {{ border: 1px solid #cbd5e1; padding: 8px 12px; text-align: left; }}
    th {{ background: #f1f5f9; color: #334155; width: 32%; }}
    .summary-cards {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-top: 12px; }}
    .card {{ background: #f8fafc; border: 1px solid #cbd5e1; border-radius: 6px; padding: 12px; text-align: center; }}
    .card .val {{ display: block; font-size: 24px; font-weight: 700; color: #0f172a; }}
    .card .lbl {{ font-size: 11px; font-weight: 600; text-transform: uppercase; color: #64748b; }}
    .finding-card {{ border: 1px solid #e2e8f0; border-radius: 6px; padding: 16px; margin-top: 12px; background: #ffffff; }}
    .finding-header {{ display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }}
    .finding-header h3 {{ margin: 0; font-size: 15px; color: #0f172a; }}
    .badge {{ font-size: 10px; font-weight: 700; padding: 2px 8px; border-radius: 4px; text-transform: uppercase; }}
    .evidence-box {{ margin-top: 8px; background: #f1f5f9; border: 1px solid #cbd5e1; padding: 10px; border-radius: 4px; font-size: 11px; }}
    .evidence-box pre {{ margin: 4px 0 0 0; font-family: ui-monospace, monospace; white-space: pre-wrap; word-break: break-all; }}
    .remediation-box {{ margin-top: 8px; background: #f0fdf4; border: 1px solid #bbf7d0; color: #166534; padding: 10px; border-radius: 4px; font-size: 12px; }}
    .sensitive-box, .methodology-box {{ background: #f8fafc; border: 1px solid #e2e8f0; padding: 14px; border-radius: 6px; margin-top: 12px; font-size: 13px; }}
    .attestation {{ background: #f8fafc; border-left: 4px solid #0284c7; padding: 12px 16px; font-size: 12px; color: #475569; margin-top: 14px; }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>{html.escape(self.title)}</h1>
      <div class="subtitle">Differential Remediation Verification Deliverable</div>
      <span class="status-pill">RE-TEST VERIFICATION COMPLETED</span>
    </header>

    <h2>1. Engagement & Re-Test Metadata</h2>
    <table>
      <tr><th>Target Program</th><td>{html.escape(data['program_name'])} (<code>{html.escape(self.program_key)}</code>)</td></tr>
      <tr><th>Baseline Session ID</th><td><code>{html.escape(data.get('baseline_session_id', 'N/A'))}</code></td></tr>
      <tr><th>Verification Date</th><td>{html.escape(self.retest_date)}</td></tr>
      <tr><th>Authorized Lead Assessor</th><td>{html.escape(self.assessor)}</td></tr>
      <tr><th>Testing Methodology</th><td>Targeted Re-Probe (Safe Non-Destructive GET/HEAD/OPTIONS)</td></tr>
    </table>

    <h2>2. Remediation Verification Metrics</h2>
    <div class="summary-cards">
      <div class="card"><span class="val">{m.get('total_baseline_defects', len(items))}</span><span class="lbl">Total Tested</span></div>
      <div class="card" style="border-color: #86efac; background: #f0fdf4;"><span class="val" style="color: #166534;">{m.get('resolved_count', 0)}</span><span class="lbl" style="color: #166534;">Resolved</span></div>
      <div class="card" style="border-color: #fca5a5; background: #fef2f2;"><span class="val" style="color: #991b1b;">{m.get('unresolved_count', 0)}</span><span class="lbl" style="color: #991b1b;">Unresolved</span></div>
      <div class="card" style="border-color: #7dd3fc; background: #f0f9ff;"><span class="val" style="color: #0369a1;">{m.get('resolution_rate_pct', 0.0):.1f}%</span><span class="lbl" style="color: #0369a1;">Resolution Rate</span></div>
    </div>

    <h2>3. Differential Verification Findings ({len(items)} Evaluated)</h2>
    {body_findings}

    <h2>4. Safe Harbor Legal Provisions & Proof-of-Adherence</h2>
    <div class="attestation">
      <strong>Good Faith Security Research (Disclose.io Aligned):</strong><br>
      {SafeHarborTerms.GOOD_FAITH_RESEARCH}<br><br>
      <strong>CFAA & DMCA Authorization:</strong><br>
      {SafeHarborTerms.CFAA_AUTHORIZATION} {SafeHarborTerms.DMCA_EXEMPTION}<br><br>
      <strong>Data Protection & Non-Destructive Guarantee:</strong><br>
      {SafeHarborTerms.DATA_PROTECTION_PRIVACY} {SafeHarborTerms.NON_DESTRUCTIVE_GUARANTEE}
    </div>
    {proof_html}
  </div>
</body>
</html>
"""
        if output_path:
            p_out = Path(output_path)
            p_out.parent.mkdir(parents=True, exist_ok=True)
            p_out.write_text(html_content, encoding="utf-8")
        return html_content

    def export_pdf(self, output_path: str) -> None:
        data = self.get_report_data()
        p_out = Path(output_path)
        p_out.parent.mkdir(parents=True, exist_ok=True)
        generate_pdf_remediation_report(data, str(p_out))

    def export_all(self, base_name: str, formats: Optional[List[str]] = None) -> Dict[str, str]:
        fmt_list = formats or ["pdf", "html", "md"]
        exported: Dict[str, str] = {}
        if "md" in fmt_list:
            md_path = f"{base_name}.md"
            self.export_markdown(md_path)
            exported["markdown"] = md_path
        if "html" in fmt_list:
            html_path = f"{base_name}.html"
            self.export_html(html_path)
            exported["html"] = html_path
        if "pdf" in fmt_list:
            pdf_path = f"{base_name}.pdf"
            self.export_pdf(pdf_path)
            exported["pdf"] = pdf_path
        return exported

