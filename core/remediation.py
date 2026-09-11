"""
AuditGuard Targeted Re-Test & Differential Remediation Tracking Engine.
Enables closed-loop verification by persisting baseline audit sessions and
re-evaluating previously flagged endpoints to determine if vulnerabilities have been
successfully remediated (RESOLVED) or remain vulnerable (UNRESOLVED).
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from core.diagnostics import DiagnosticFinding, EndpointDiagnosticReport, SecurityDiagnosticEngine


@dataclass
class RemediationItem:
    """Represents a single finding's pre-patch vs post-patch verification state."""
    finding_id: str
    title: str
    severity: str
    cwe_id: str
    affected_url: str
    baseline_status: str  # e.g. "VULNERABLE"
    retest_status: str    # e.g. "RESOLVED" or "VULNERABLE"
    result: str           # "RESOLVED", "UNRESOLVED", "NEW"
    evidence: str
    remediation: str
    curl_poc: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    remediation_code: Optional[str] = None


class AuditSessionManager:
    """Persists and retrieves structured audit finding sessions for re-testing."""

    DEFAULT_SESSION_FILE = "audit/latest_findings.json"
    SESSIONS_DIR = "audit/sessions"

    @classmethod
    def save_session(
        cls,
        program_key: str,
        endpoints: List[str],
        findings: List[DiagnosticFinding],
        session_file: str = DEFAULT_SESSION_FILE,
        flagged_endpoints: Optional[List[str]] = None,
    ) -> str:
        """Saves the current audit findings to a session JSON file."""
        p_out = Path(session_file)
        p_out.parent.mkdir(parents=True, exist_ok=True)

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        session_id = hashlib.sha256(f"{program_key}:{now_iso}:{len(findings)}".encode("utf-8")).hexdigest()[:12]

        serialized_findings: List[Dict[str, Any]] = []
        for f in findings:
            serialized_findings.append({
                "title": f.title,
                "severity": f.severity,
                "cwe_id": f.cwe_id,
                "description": f.description,
                "evidence": f.evidence,
                "remediation": f.remediation,
                "curl_poc": f.curl_poc,
                "affected_urls": f.affected_urls,
                "cvss_score": getattr(f, "cvss_score", None),
                "cvss_vector": getattr(f, "cvss_vector", None),
                "remediation_code": getattr(f, "remediation_code", None),
                "remediation_lang": getattr(f, "remediation_lang", None),
            })

        session_data = {
            "session_id": session_id,
            "timestamp": now_iso,
            "program_key": program_key,
            "endpoints": endpoints,
            "flagged_endpoints": list(flagged_endpoints or []),
            "findings_count": len(findings),
            "findings": serialized_findings,
        }

        # Write latest
        p_out.write_text(json.dumps(session_data, indent=2), encoding="utf-8")

        # Write historical session archive
        hist_dir = Path(cls.SESSIONS_DIR)
        hist_dir.mkdir(parents=True, exist_ok=True)
        hist_file = hist_dir / f"session_{session_id}.json"
        hist_file.write_text(json.dumps(session_data, indent=2), encoding="utf-8")

        return str(p_out)

    @classmethod
    def load_session(cls, session_file: str = DEFAULT_SESSION_FILE) -> Optional[Dict[str, Any]]:
        """Loads an audit session from file."""
        p_in = Path(session_file)
        if not p_in.exists():
            return None
        try:
            return json.loads(p_in.read_text(encoding="utf-8"))
        except Exception:
            return None


class RemediationAuditor:
    """
    Executes targeted diagnostic re-tests against previously flagged endpoints and computes
    differential verification metrics (Resolved vs. Persistent vs. New).
    """

    @classmethod
    def run_retest(
        cls,
        engine: SecurityDiagnosticEngine,
        baseline_session: Dict[str, Any],
        progress_callback: Optional[Callable[[int, int, str, EndpointDiagnosticReport], None]] = None,
        flagged_set: Optional[Set[str]] = None,
    ) -> Dict[str, Any]:
        """Runs targeted re-tests on the endpoints that had findings in baseline_session."""
        baseline_findings = baseline_session.get("findings", [])
        program_key = baseline_session.get("program_key", "active")
        baseline_session_id = baseline_session.get("session_id", "baseline")

        # Resolve flagged sensitive endpoints to preserve sensitivity classification during re-test
        resolved_flagged = flagged_set
        if resolved_flagged is None:
            resolved_flagged = set(baseline_session.get("flagged_endpoints", []))
            if not resolved_flagged and hasattr(engine, "validator") and engine.validator:
                resolved_flagged = set(getattr(engine.validator, "flagged_sensitive_endpoints", []))

        # Gather targets that require re-testing
        target_urls: List[str] = []
        for bf in baseline_findings:
            urls = bf.get("affected_urls", [])
            for u in urls:
                if u not in target_urls:
                    target_urls.append(u)

        if not target_urls:
            # If affected_urls wasn't populated, fall back to session endpoints
            target_urls = baseline_session.get("endpoints", [])

        # Execute targeted re-diagnostics with sensitivity context preserved!
        reports = engine.diagnose_batch(
            target_urls,
            flagged_set=resolved_flagged,
            progress_callback=progress_callback,
        )

        # Collect fresh findings
        retest_findings: List[DiagnosticFinding] = []
        for r in reports:
            retest_findings.extend(r.findings)

        # Index fresh findings by (title, url) and (cwe_id, url)
        fresh_index: Set[Tuple[str, str]] = set()
        for rf in retest_findings:
            rf_url = rf.affected_urls[0] if rf.affected_urls else ""
            fresh_index.add((rf.title.strip().lower(), rf_url.strip().lower()))
            fresh_index.add((rf.cwe_id.strip().lower(), rf_url.strip().lower()))

        remediation_items: List[RemediationItem] = []
        resolved_count = 0
        unresolved_count = 0

        # Evaluate baseline findings
        for idx, bf in enumerate(baseline_findings, 1):
            b_title = bf.get("title", "")
            b_cwe = bf.get("cwe_id", "")
            b_urls = bf.get("affected_urls", ["N/A"])
            target_u = b_urls[0] if b_urls else "N/A"

            is_persistent = (
                (b_title.strip().lower(), target_u.strip().lower()) in fresh_index
                or (b_cwe.strip().lower(), target_u.strip().lower()) in fresh_index
            )

            fid = hashlib.md5(f"{b_title}:{b_cwe}:{target_u}".encode("utf-8")).hexdigest()[:8]

            if is_persistent:
                unresolved_count += 1
                remediation_items.append(
                    RemediationItem(
                        finding_id=fid,
                        title=b_title,
                        severity=bf.get("severity", "MEDIUM"),
                        cwe_id=b_cwe,
                        affected_url=target_u,
                        baseline_status="VULNERABLE",
                        retest_status="STILL_VULNERABLE",
                        result="UNRESOLVED",
                        evidence=bf.get("evidence", ""),
                        remediation=bf.get("remediation", ""),
                        curl_poc=bf.get("curl_poc"),
                    )
                )
            else:
                resolved_count += 1
                remediation_items.append(
                    RemediationItem(
                        finding_id=fid,
                        title=b_title,
                        severity=bf.get("severity", "MEDIUM"),
                        cwe_id=b_cwe,
                        affected_url=target_u,
                        baseline_status="VULNERABLE",
                        retest_status="RESOLVED",
                        result="RESOLVED",
                        evidence="Endpoint re-tested clean. Finding condition is no longer triggered.",
                        remediation=bf.get("remediation", ""),
                        curl_poc=bf.get("curl_poc"),
                    )
                )

        total_baseline = len(baseline_findings)
        resolution_rate = (resolved_count / total_baseline * 100.0) if total_baseline > 0 else 100.0

        now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")

        return {
            "program_key": program_key,
            "baseline_session_id": baseline_session_id,
            "retest_date": now_iso,
            "endpoints_tested": len(target_urls),
            "metrics": {
                "total_baseline_defects": total_baseline,
                "resolved_count": resolved_count,
                "unresolved_count": unresolved_count,
                "resolution_rate_pct": round(resolution_rate, 1),
            },
            "items": [asdict(item) for item in remediation_items],
            "raw_reports": reports,
        }
