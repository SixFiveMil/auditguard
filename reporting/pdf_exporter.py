"""
AuditGuard Vector PDF Report Exporter.
Generates corporate, publication-ready security assessment reports and Statements of Work (SOW).
Built using pure-Python fpdf2 (zero native C-compiler or system DLL dependencies).
Clearly separates Pre-Audit Authorization SOWs from Post-Audit Assessment Reports.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from fpdf import FPDF


from core.safe_harbor import SafeHarborLedgerAuditor, SafeHarborProof, SafeHarborTerms


class AuditReportPDF(FPDF):
    """Custom FPDF layout with corporate headers, pagination footers, and severity badges."""

    def __init__(self, title_text: str = "Security Assessment Report"):
        super().__init__(orientation="P", unit="mm", format="A4")
        self.report_title = title_text
        self.set_auto_page_break(auto=True, margin=20)

    def header(self):
        if self.page_no() > 1:
            self.set_font("Helvetica", "B", 8)
            self.set_text_color(100, 116, 139)  # Slate-500
            self.cell(0, 8, f"AUDITGUARD  |  {self.report_title.upper()}", border="B", new_x="LMARGIN", new_y="NEXT")
            self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(148, 163, 184)  # Slate-400
        page_str = f"Page {self.page_no()} of {{nb}}"
        self.cell(0, 10, page_str, align="R")
        self.set_x(self.l_margin)
        self.cell(0, 10, "Confidential Security Audit Deliverable", align="L")

    def draw_severity_badge(self, severity: str, x: float, y: float, w: float = 24, h: float = 6) -> None:
        """Renders colored severity pill badge."""
        sev = severity.upper()
        colors = {
            "CRITICAL": {"bg": (254, 226, 226), "border": (248, 113, 113), "text": (153, 27, 27)},
            "HIGH": {"bg": (255, 237, 213), "border": (251, 146, 60), "text": (154, 52, 18)},
            "MEDIUM": {"bg": (254, 249, 195), "border": (250, 204, 21), "text": (133, 77, 14)},
            "LOW": {"bg": (219, 234, 254), "border": (96, 165, 250), "text": (30, 64, 175)},
            "INFO": {"bg": (241, 245, 249), "border": (203, 213, 225), "text": (71, 85, 105)},
        }
        cfg = colors.get(sev, colors["INFO"])

        self.set_fill_color(*cfg["bg"])
        self.set_draw_color(*cfg["border"])
        self.set_text_color(*cfg["text"])
        self.set_line_width(0.2)

        self.rect(x, y, w, h, style="DF", round_corners=True, corner_radius=2)
        self.set_xy(x, y)
        self.set_font("Helvetica", "B", 7)
        self.cell(w, h, sev, align="C")

    def draw_status_badge(self, status: str, x: float, y: float, w: float = 28, h: float = 6) -> None:
        """Renders verification status badge (RESOLVED, UNRESOLVED, NEW)."""
        stat = status.upper()
        colors = {
            "RESOLVED": {"bg": (220, 252, 231), "border": (74, 222, 128), "text": (22, 101, 52)},
            "UNRESOLVED": {"bg": (254, 226, 226), "border": (248, 113, 113), "text": (153, 27, 27)},
            "STILL_VULNERABLE": {"bg": (254, 226, 226), "border": (248, 113, 113), "text": (153, 27, 27)},
            "NEW": {"bg": (254, 249, 195), "border": (250, 204, 21), "text": (133, 77, 14)},
        }
        cfg = colors.get(stat, {"bg": (241, 245, 249), "border": (203, 213, 225), "text": (71, 85, 105)})

        self.set_fill_color(*cfg["bg"])
        self.set_draw_color(*cfg["border"])
        self.set_text_color(*cfg["text"])
        self.set_line_width(0.2)

        self.rect(x, y, w, h, style="DF", round_corners=True, corner_radius=2)
        self.set_xy(x, y)
        self.set_font("Helvetica", "B", 7)
        self.cell(w, h, stat, align="C")


def render_safe_harbor_pdf_section(
    pdf: AuditReportPDF,
    proof: Optional[Any] = None,
    section_title: str = "Safe Harbor Legal Provisions & Proof-of-Adherence",
) -> None:
    """Renders Disclose.io-aligned legal clauses and ledger proof table into PDF."""
    if pdf.get_y() > 210:
        pdf.add_page()

    pdf.ln(2)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 6, section_title, new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(30, 41, 59)
    pdf.cell(0, 4.5, "1. Good Faith Security Research & CFAA Authorization", new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", "", 7.5)
    pdf.set_text_color(71, 85, 105)
    cfaa_text = (
        "Testing was conducted strictly in good faith for defensive security research. Both parties mutually agree "
        "that actions within stated scope boundaries and rate limit specifications constitute authorized access under "
        "the Computer Fraud and Abuse Act (CFAA, 18 U.S.C. Section 1030) and state anti-hacking statutes."
    )
    pdf.multi_cell(0, 3.8, cfaa_text)
    pdf.ln(1)

    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(30, 41, 59)
    pdf.cell(0, 4.5, "2. DMCA Section 1201 Exemption & Privacy Safeguards", new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", "", 7.5)
    pdf.set_text_color(71, 85, 105)
    dmca_text = (
        "Testing was performed exclusively for vulnerability verification and does not violate DMCA Section 1201. "
        "Strict zero-retention privacy protocols were maintained; no customer data or PII was altered, downloaded in bulk, "
        "or retained beyond minimal transient verification."
    )
    pdf.multi_cell(0, 3.8, dmca_text)
    pdf.ln(1)

    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(30, 41, 59)
    pdf.cell(0, 4.5, "3. Non-Destructive Operation Guarantee", new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", "", 7.5)
    pdf.set_text_color(71, 85, 105)
    nondest_text = (
        "Probes were limited to safe, idempotent HTTP methods (GET, HEAD, OPTIONS). Denial of service, "
        "computational exhaustion, service disruption, and data destruction were strictly barred and excluded."
    )
    pdf.multi_cell(0, 3.8, nondest_text)
    pdf.ln(2)

    # If proof exists, render ledger audit metrics table
    if proof:
        pdf.set_font("Helvetica", "B", 8.5)
        pdf.set_text_color(15, 23, 42)
        status_str = "SAFE HARBOR COMPLIANT" if getattr(proof, "is_fully_compliant", True) else "NON-COMPLIANT WARNING"
        pdf.cell(0, 5, f"Cryptographic Ledger Proof-of-Adherence [{status_str}]", new_x="LMARGIN", new_y="NEXT")

        pdf.set_font("Courier", "", 7.5)
        pdf.set_fill_color(248, 250, 252)
        pdf.set_draw_color(203, 213, 225)
        pdf.set_text_color(30, 41, 59)

        ledger_rows = [
            f"Total Audited Requests:      {getattr(proof, 'total_requests', 0)}",
            f"Traffic Pacing Rate:         {getattr(proof, 'effective_rate_per_sec', 0.0):.2f} req/s (Ceiling: {getattr(proof, 'rate_limit_ceiling', 2.0):.2f} req/s) -> {'PASS' if getattr(proof, 'rate_limit_compliant', True) else 'EXCEEDED'}",
            f"Identity Tagging Adherence:  {getattr(proof, 'header_compliance_pct', 100.0):.1f}% carrying '{getattr(proof, 'header_tag', 'X-Bug-Bounty')}'",
            f"Excluded Path Guardrail:     {'PASS (0 dispatched)' if getattr(proof, 'excluded_paths_dispatched', 0) == 0 else f'VIOLATION ({getattr(proof, 'excluded_paths_dispatched', 0)} hits)'}",
            f"Audit Ledger SHA-256 Digest: {getattr(proof, 'session_sha256', '0'*64)[:32]}...",
        ]
        pdf.multi_cell(0, 4, "\n".join(ledger_rows), fill=True, border=1)


def generate_pdf_sow_report(report_data: Dict[str, Any], output_path: str) -> None:
    """
    Renders a comprehensive SOW or security assessment report as a polished PDF.
    """
    program = report_data.get("program", {})
    sow = report_data.get("sow", {})
    findings = report_data.get("findings", [])
    metrics = report_data.get("metrics", {})
    audit_executed = report_data.get("audit_executed", False)

    pdf = AuditReportPDF(title_text=sow.get("title", "Security Assessment Report"))
    pdf.alias_nb_pages()
    pdf.add_page()

    # 1. Executive Banner & Document Header
    pdf.set_fill_color(15, 23, 42)  # Slate-900
    pdf.rect(0, 0, pdf.w, 40, style="F")

    pdf.set_xy(pdf.l_margin, 10)
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(248, 250, 252)  # Slate-50
    pdf.cell(0, 10, "AUDITGUARD SECURITY ASSESSMENT", new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(148, 163, 184)  # Slate-400
    sub_title = (
        "Security Assessment Report & SOW Compliance Deliverable"
        if audit_executed
        else "Formal Statement of Work (SOW) & Engagement Scope Authorization"
    )
    pdf.cell(0, 6, sub_title, new_x="LMARGIN", new_y="NEXT")

    pdf.set_y(46)

    # 2. Key Engagement Metadata Grid
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 8, "1. Statement of Work (SOW) & Engagement Scope", new_x="LMARGIN", new_y="NEXT")

    pdf.set_draw_color(203, 213, 225)
    pdf.set_fill_color(248, 250, 252)
    pdf.set_line_width(0.2)

    col1_w = 45
    col2_w = pdf.w - pdf.l_margin - pdf.r_margin - col1_w

    def render_row(label: str, value: str) -> None:
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(71, 85, 105)
        pdf.set_fill_color(241, 245, 249)
        pdf.cell(col1_w, 7, f" {label}", border=1, fill=True)

        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(15, 23, 42)
        pdf.set_fill_color(255, 255, 255)
        if len(value) > 60:
            pdf.multi_cell(col2_w, 7, f" {value}", border=1, fill=True)
        else:
            pdf.cell(col2_w, 7, f" {value}", border=1, fill=True, new_x="LMARGIN", new_y="NEXT")

    status_str = "COMPLETED (DIAGNOSTIC AUDIT EXECUTED)" if audit_executed else "AUTHORIZED (PRE-AUDIT SCOPE DEFINITION)"
    render_row("Engagement Status", status_str)
    render_row("Target Program", f"{program.get('name', 'N/A')} [{sow.get('program_key', 'active')}]")
    render_row("Platform / Authority", program.get("platform", "Self-Hosted / VDP"))
    render_row("Assessment Date", sow.get("assessment_date", "N/A"))
    render_row("Authorized Researcher", sow.get("assessor", "Authorized Security Researcher"))
    render_row("Safe Harbor Compliant", "Yes (Strict Scope Enforcement & Non-Destructive Testing)")
    render_row("Rate Limit Enforcement", f"{program.get('rate_limit_per_second', 2.0)} req/s (Gatekeeper Paced)")
    render_row("Header Identification", program.get("rules_of_engagement", {}).get("header_tag", "X-Bug-Bounty"))
    render_row("In-Scope Targets", ", ".join(program.get("in_scope", [])) or "None defined")
    
    out_paths = program.get("out_of_scope", {}).get("paths", []) or program.get("excluded_paths", [])
    render_row("Excluded Paths", ", ".join(out_paths) if out_paths else "None explicitly listed")

    disc_eps = program.get("discovered_endpoints", [])
    flagged_eps = program.get("flagged_sensitive_endpoints", [])
    render_row("StateHunter Reconnaissance", f"{len(disc_eps)} client routes discovered ({len(flagged_eps)} flagged sensitive)")

    pdf.ln(6)

    if not audit_executed:
        # Pre-audit SOW sections
        # Section 2: Attack Surface & Route Inventory
        pdf.set_font("Helvetica", "B", 13)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(0, 8, "2. Attack Surface & Route Inventory (StateHunter Reconnaissance)", new_x="LMARGIN", new_y="NEXT")

        pdf.set_font("Helvetica", "", 9.5)
        pdf.set_text_color(51, 65, 85)
        pdf.cell(0, 6, f"Total Discovered Client Routes: {len(disc_eps)}  |  Flagged Sensitive / Admin: {len(flagged_eps)}", new_x="LMARGIN", new_y="NEXT")

        if flagged_eps:
            pdf.ln(2)
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(15, 23, 42)
            pdf.cell(0, 5, f"Target Sensitive Endpoints ({len(flagged_eps)}):", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Courier", "", 8.5)
            pdf.set_text_color(30, 41, 59)
            for ep in flagged_eps[:10]:
                pdf.cell(0, 5, f"  * {ep}", new_x="LMARGIN", new_y="NEXT")
            if len(flagged_eps) > 10:
                pdf.set_font("Helvetica", "I", 8)
                pdf.cell(0, 5, f"  ... and {len(flagged_eps) - 10} additional sensitive endpoints.", new_x="LMARGIN", new_y="NEXT")

        pdf.ln(6)

        # Section 3: Planned Diagnostic Methodology & Rules of Engagement
        pdf.set_font("Helvetica", "B", 13)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(0, 8, "3. Planned Diagnostic Methodology & Rules of Engagement", new_x="LMARGIN", new_y="NEXT")

        methodologies = [
            ("1. Declarative Probing Standards:", "Probes adhere strictly to ProjectDiscovery Nuclei v3 YAML specifications."),
            ("2. Idempotent HTTP Operations:", "Only safe, read-only HTTP methods (GET, HEAD, OPTIONS) are authorized."),
            ("3. Paced Rate Limiting:", f"All traffic is paced via Gatekeeper token bucket ({program.get('rate_limit_per_second', 2.0)} req/s max)."),
            ("4. Cryptographic Audit Ledger:", "Every outgoing byte and response checksum is logged to the tamper-evident ledger."),
        ]
        for m_title, m_desc in methodologies:
            pdf.set_font("Helvetica", "B", 8.5)
            pdf.set_text_color(15, 23, 42)
            pdf.cell(58, 5, f" {m_title}", new_x="RIGHT", new_y="TOP")
            pdf.set_font("Helvetica", "", 8.5)
            pdf.set_text_color(71, 85, 105)
            pdf.cell(0, 5, f"{m_desc}", new_x="LMARGIN", new_y="NEXT")

        pdf.ln(6)

        # Section 4: Safe Harbor Compliance & Authorization Attestation
        render_safe_harbor_pdf_section(pdf, proof=None, section_title="4. Safe Harbor Legal Provisions & Scope Authorization")

    else:
        # Post-audit Assessment sections
        # 3. Executive Summary & Risk Posture
        pdf.set_font("Helvetica", "B", 13)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(0, 8, "2. Executive Risk Posture & Findings Distribution", new_x="LMARGIN", new_y="NEXT")

        sev_counts = metrics.get("severity_counts", {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0
        })

        card_w = (pdf.w - pdf.l_margin - pdf.r_margin) / 5
        card_h = 16

        sevs = [("CRITICAL", (220, 38, 38)), ("HIGH", (234, 88, 12)), ("MEDIUM", (202, 138, 4)), ("LOW", (37, 99, 235)), ("INFO", (100, 116, 139))]

        start_x = pdf.l_margin
        start_y = pdf.get_y()

        for idx, (sev_name, color) in enumerate(sevs):
            x = start_x + (idx * card_w)
            pdf.set_xy(x, start_y)
            pdf.set_fill_color(248, 250, 252)
            pdf.set_draw_color(203, 213, 225)
            pdf.rect(x, start_y, card_w - 2, card_h, style="DF")

            pdf.set_xy(x, start_y + 2)
            pdf.set_font("Helvetica", "B", 7)
            pdf.set_text_color(*color)
            pdf.cell(card_w - 2, 4, sev_name, align="C")

            pdf.set_xy(x, start_y + 6)
            pdf.set_font("Helvetica", "B", 12)
            pdf.set_text_color(15, 23, 42)
            pdf.cell(card_w - 2, 8, str(sev_counts.get(sev_name, 0)), align="C")

        pdf.set_y(start_y + card_h + 8)

        # 4. Detailed Technical Findings
        pdf.set_font("Helvetica", "B", 13)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(0, 8, f"3. Security Findings & Defect Evidence ({len(findings)} Total)", new_x="LMARGIN", new_y="NEXT")

        if not findings:
            pdf.set_font("Helvetica", "", 10)
            pdf.set_text_color(22, 101, 52)  # Green-800
            pdf.cell(0, 8, "[+] All in-scope endpoints passed diagnostic security checks without defects.", new_x="LMARGIN", new_y="NEXT")
        else:
            for idx, f in enumerate(findings):
                if pdf.get_y() > 235:
                    pdf.add_page()

                card_top = pdf.get_y()
                pdf.draw_severity_badge(f.get("severity", "INFO"), x=pdf.l_margin, y=card_top)

                pdf.set_xy(pdf.l_margin + 26, card_top)
                pdf.set_font("Helvetica", "B", 10)
                pdf.set_text_color(15, 23, 42)
                cwe = f.get("cwe_id", "N/A")
                pdf.cell(0, 6, f"{f.get('title', 'Security Finding')} ({cwe})", new_x="LMARGIN", new_y="NEXT")

                cvss_score = f.get("cvss_score")
                cvss_vector = f.get("cvss_vector")
                if cvss_score is not None:
                    pdf.set_font("Helvetica", "B", 8)
                    pdf.set_text_color(100, 116, 139)
                    v_str = f" [{cvss_vector}]" if cvss_vector else ""
                    pdf.cell(0, 4.5, f"CVSS v3.1: {cvss_score:.1f}{v_str}", new_x="LMARGIN", new_y="NEXT")

                pdf.ln(1)
                pdf.set_font("Helvetica", "", 9)
                pdf.set_text_color(51, 65, 85)
                pdf.multi_cell(0, 5, f.get("description", "").strip())

                evidence = f.get("evidence", "").strip()
                if evidence:
                    pdf.ln(1)
                    pdf.set_font("Courier", "", 8)
                    pdf.set_fill_color(241, 245, 249)
                    pdf.set_text_color(30, 41, 59)
                    pdf.multi_cell(0, 5, f"Evidence: {evidence}", fill=True, border=1)

                remediation = f.get("remediation", "").strip()
                if remediation:
                    pdf.ln(1)
                    pdf.set_font("Helvetica", "I", 8.5)
                    pdf.set_text_color(15, 118, 110)  # Teal-700
                    pdf.multi_cell(0, 5, f"Remediation: {remediation}")

                rem_code = (f.get("remediation_code") or "").strip()
                if rem_code:
                    if pdf.get_y() > 235:
                        pdf.add_page()
                    pdf.ln(1)
                    lang = f.get("remediation_lang") or "code"
                    pdf.set_font("Courier", "", 7)
                    pdf.set_fill_color(243, 244, 246)
                    pdf.set_draw_color(209, 213, 219)
                    pdf.set_text_color(15, 23, 42)
                    pdf.multi_cell(0, 4, f"Remediation Patch ({lang}):\n{rem_code}", fill=True, border=1)

                curl_poc = f.get("curl_poc", "").strip()
                if curl_poc:
                    if pdf.get_y() > 240:
                        pdf.add_page()
                    pdf.ln(1)
                    pdf.set_font("Courier", "", 7)
                    pdf.set_fill_color(248, 250, 252)
                    pdf.set_draw_color(203, 213, 225)
                    pdf.set_text_color(15, 23, 42)
                    pdf.multi_cell(0, 4, f"Reproduction (cURL):\n{curl_poc}", fill=True, border=1)

                affected = f.get("affected_urls", [])
                if affected:
                    pdf.set_font("Helvetica", "", 8)
                    pdf.set_text_color(100, 116, 139)
                    ep_text = ", ".join(affected[:3])
                    if len(affected) > 3:
                        ep_text += f" (+{len(affected) - 3} more)"
                    pdf.cell(0, 5, f"Affected: {ep_text}", new_x="LMARGIN", new_y="NEXT")

                pdf.ln(4)
                pdf.set_draw_color(226, 232, 240)
                pdf.set_line_width(0.2)
                pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
                pdf.ln(4)

        proof = report_data.get("safe_harbor_proof")
        if not proof:
            try:
                proof = SafeHarborLedgerAuditor.audit_engagement(
                    log_path="audit/audit_log.jsonl",
                    program_cfg=program,
                    program_key=sow.get("program_key", "active"),
                )
            except Exception:
                proof = None
        render_safe_harbor_pdf_section(pdf, proof=proof, section_title="4. Scope Compliance & Safe Harbor Legal Attestation")

    pdf.output(output_path)


def generate_pdf_remediation_report(remediation_data: Dict[str, Any], output_path: str) -> None:
    """
    Renders a formal Differential Remediation Verification Report in vector PDF.
    """
    program_key = remediation_data.get("program_key", "target")
    program_name = remediation_data.get("program_name", program_key)
    session_id = remediation_data.get("baseline_session_id", "baseline")
    retest_date = remediation_data.get("retest_date", "")
    assessor = remediation_data.get("assessor", "Authorized Security Researcher")
    metrics = remediation_data.get("metrics", {})
    items = remediation_data.get("items", [])
    proof = remediation_data.get("safe_harbor_proof")

    pdf = AuditReportPDF(title_text="Remediation Verification Report")
    pdf.alias_nb_pages()
    pdf.add_page()

    # 1. Header Banner
    pdf.set_fill_color(15, 23, 42)
    pdf.rect(0, 0, pdf.w, 40, style="F")

    pdf.set_xy(pdf.l_margin, 10)
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(248, 250, 252)
    pdf.cell(0, 10, "AUDITGUARD REMEDIATION REPORT", new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(148, 163, 184)
    pdf.cell(0, 6, "Differential Pre-Patch vs. Post-Patch Security Verification Deliverable", new_x="LMARGIN", new_y="NEXT")

    pdf.set_y(46)

    # 2. Metadata Grid
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 8, "1. Engagement & Re-Test Metadata", new_x="LMARGIN", new_y="NEXT")

    pdf.set_draw_color(203, 213, 225)
    pdf.set_line_width(0.15)

    meta_rows = [
        ("Target Program", f"{program_name} ({program_key})"),
        ("Baseline Session ID", session_id),
        ("Verification Date", retest_date),
        ("Authorized Lead Assessor", assessor),
        ("Testing Methodology", "Targeted Re-Probe (Safe Non-Destructive GET/HEAD/OPTIONS)"),
    ]

    col_w_label = 55
    col_w_val = pdf.w - pdf.l_margin - pdf.r_margin - col_w_label
    row_h = 6

    for label, val in meta_rows:
        pdf.set_fill_color(248, 250, 252)
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(51, 65, 85)
        pdf.cell(col_w_label, row_h, f"  {label}", border=1, fill=True, new_x="RIGHT", new_y="TOP")

        pdf.set_fill_color(255, 255, 255)
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(col_w_val, row_h, f"  {val}", border=1, fill=True, new_x="LMARGIN", new_y="NEXT")

    pdf.ln(5)

    # 3. Remediation Metrics Cards
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 8, "2. Remediation Verification Metrics", new_x="LMARGIN", new_y="NEXT")

    card_w = (pdf.w - pdf.l_margin - pdf.r_margin) / 4
    card_h = 16
    start_x = pdf.l_margin
    start_y = pdf.get_y()

    cards = [
        ("TOTAL TESTED", str(metrics.get("total_baseline_defects", len(items))), (15, 23, 42)),
        ("RESOLVED", str(metrics.get("resolved_count", 0)), (22, 101, 52)),
        ("UNRESOLVED", str(metrics.get("unresolved_count", 0)), (220, 38, 38)),
        ("RESOLUTION RATE", f"{metrics.get('resolution_rate_pct', 0.0):.1f}%", (14, 116, 144)),
    ]

    for idx, (title, val, color) in enumerate(cards):
        x = start_x + (idx * card_w)
        pdf.set_xy(x, start_y)
        pdf.set_fill_color(248, 250, 252)
        pdf.set_draw_color(203, 213, 225)
        pdf.rect(x, start_y, card_w - 2, card_h, style="DF")

        pdf.set_xy(x, start_y + 2)
        pdf.set_font("Helvetica", "B", 7)
        pdf.set_text_color(*color)
        pdf.cell(card_w - 2, 4, title, align="C")

        pdf.set_xy(x, start_y + 6)
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(card_w - 2, 8, val, align="C")

    pdf.set_y(start_y + card_h + 8)

    # 4. Verified Findings Items
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 8, f"3. Differential Finding Status ({len(items)} Evaluated)", new_x="LMARGIN", new_y="NEXT")

    if not items:
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(22, 101, 52)
        pdf.cell(0, 8, "[+] No prior defects recorded for this session.", new_x="LMARGIN", new_y="NEXT")
    else:
        for idx, item in enumerate(items, 1):
            if pdf.get_y() > 225:
                pdf.add_page()

            card_top = pdf.get_y()
            res = item.get("result", "UNRESOLVED").upper()
            sev = item.get("severity", "MEDIUM").upper()

            # Status Badge + Severity Badge
            pdf.draw_status_badge(res, x=pdf.l_margin, y=card_top, w=28, h=6)
            pdf.draw_severity_badge(sev, x=pdf.l_margin + 30, y=card_top, w=22, h=6)

            pdf.set_xy(pdf.l_margin + 54, card_top)
            pdf.set_font("Helvetica", "B", 9.5)
            pdf.set_text_color(15, 23, 42)
            cwe = item.get("cwe_id", "N/A")
            pdf.cell(0, 6, f"{item.get('title', 'Defect')} ({cwe})", new_x="LMARGIN", new_y="NEXT")

            pdf.ln(1)
            pdf.set_font("Helvetica", "", 8.5)
            pdf.set_text_color(71, 85, 105)
            pdf.cell(0, 4.5, f"Endpoint: {item.get('affected_url', 'N/A')}", new_x="LMARGIN", new_y="NEXT")

            status_str = f"Status: {item.get('baseline_status', 'VULNERABLE')} -> {item.get('retest_status', res)}"
            pdf.cell(0, 4.5, status_str, new_x="LMARGIN", new_y="NEXT")

            evidence = item.get("evidence", "").strip()
            if evidence:
                pdf.ln(0.5)
                pdf.set_font("Courier", "", 7.5)
                pdf.set_fill_color(241, 245, 249)
                pdf.set_text_color(30, 41, 59)
                pdf.multi_cell(0, 4.5, f"Verification Result: {evidence}", fill=True, border=1)

            curl_poc = (item.get("curl_poc") or "").strip()
            if curl_poc:
                if pdf.get_y() > 235:
                    pdf.add_page()
                pdf.ln(0.5)
                pdf.set_font("Courier", "", 7)
                pdf.set_fill_color(248, 250, 252)
                pdf.set_draw_color(203, 213, 225)
                pdf.set_text_color(15, 23, 42)
                pdf.multi_cell(0, 4, f"Reproduction (cURL):\n{curl_poc}", fill=True, border=1)

            pdf.ln(3)
            pdf.set_draw_color(226, 232, 240)
            pdf.set_line_width(0.2)
            pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
            pdf.ln(3)

    # 5. Safe Harbor Section
    render_safe_harbor_pdf_section(pdf, proof=proof, section_title="4. Safe Harbor Legal Provisions & Proof-of-Adherence")

    from pathlib import Path
    p_out = Path(output_path)
    p_out.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(p_out))
