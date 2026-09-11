"""
AuditGuard Reporting & Triage Export Engine.
Produces publication-ready SOW reports (PDF, HTML, Markdown), targeted remediation
differential verifications, and 1-click platform submissions (HackerOne, Bugcrowd, GitHub, Jira).
"""

from reporting.report_builder import ReportBuilder
from reporting.sow_report_generator import SOWReportGenerator, RemediationReportGenerator
from reporting.pdf_exporter import generate_pdf_sow_report, generate_pdf_remediation_report, AuditReportPDF
from reporting.triage_exporter import PlatformTriageExporter

__all__ = [
    "ReportBuilder",
    "SOWReportGenerator",
    "RemediationReportGenerator",
    "generate_pdf_sow_report",
    "generate_pdf_remediation_report",
    "AuditReportPDF",
    "PlatformTriageExporter",
]
