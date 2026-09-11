"""
Vulnerability Disclosure Report Builder.
Generates deterministic, triager-friendly Markdown reports compliant with
HackerOne, Bugcrowd, and standard VDP triage criteria.
"""

from __future__ import annotations

import shlex
from typing import Any, Dict, List, Optional


class ReportBuilder:
    """
    Constructs high-signal, proof-carrying vulnerability reports directly from
    verified audit logs, eliminating speculative AI text.
    """

    @staticmethod
    def generate_curl_poc(interaction: Dict[str, Any]) -> str:
        """
        Generates an exact, reproducible curl command from an audit entry.
        """
        req = interaction.get("request", {})
        method = req.get("method", "GET")
        url = req.get("url", "")
        headers = req.get("headers", {})

        parts = ["curl", "-i", "-X", method, shlex.quote(url)]

        for h_name, h_val in headers.items():
            if h_val != "[REDACTED_BY_AUDIT_POLICY]":
                parts.extend(["-H", shlex.quote(f"{h_name}: {h_val}")])

        body = req.get("body_preview", "")
        if body and method in ("POST", "PUT", "PATCH", "DELETE"):
            parts.extend(["--data-raw", shlex.quote(body)])

        return " ".join(parts)

    @classmethod
    def build_report(
        cls,
        title: str,
        severity: str,
        cwe_id: str,
        summary: str,
        interaction: Dict[str, Any],
        steps_to_reproduce: List[str],
        impact: str,
        remediation: str,
        researcher_handle: str = "Authorized Researcher",
    ) -> str:
        """
        Formats a complete, triage-ready vulnerability disclosure document.
        """
        curl_cmd = cls.generate_curl_poc(interaction)
        resp = interaction.get("response", {})
        req = interaction.get("request", {})
        status_code = resp.get("status_code", "N/A")
        timestamp = interaction.get("timestamp", "N/A")
        request_id = interaction.get("request_id", "N/A")

        steps_formatted = "\n".join(f"{i+1}. {step}" for i, step in enumerate(steps_to_reproduce))

        report = f"""# {title}

**Program:** {interaction.get('program', 'Target VDP')}
**Severity:** {severity.upper()}
**Weakness:** {cwe_id}
**Date Verified:** {timestamp}
**Audit Request ID:** `{request_id}`
**Reporter:** {researcher_handle}

---

## 1. Summary
{summary.strip()}

---

## 2. Steps to Reproduce
{steps_formatted}

### Proof of Concept (Deterministic Reproduction Command)
```bash
{curl_cmd}
```

### Observed Response (Status: HTTP {status_code})
```http
HTTP/1.1 {status_code}
{resp.get('body_preview', '').strip()}
```

---

## 3. Impact Assessment
{impact.strip()}

---

## 4. Suggested Remediation
{remediation.strip()}

---
*Generated with AuditGuard Scope & Compliance Engine. All tests strictly authorized and executed within program boundaries.*
"""
        return report.strip()
