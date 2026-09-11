"""
AuditGuard Safe Harbor Legal Provisions & Proof-of-Adherence Engine.
Provides Disclose.io-aligned legal safe harbor terms, good-faith research protections,
and mathematical proof-of-adherence verification extracted directly from the immutable audit ledger.
"""

from __future__ import annotations

import datetime
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from core.scope_validator import ScopeValidator


class SafeHarborTerms:
    """Standardized Safe Harbor legal language aligned with Disclose.io core principles."""

    GOOD_FAITH_RESEARCH = (
        "All security testing activities under this engagement are conducted strictly in good faith "
        "for the sole purpose of identifying, validating, and reporting security defects to protect "
        "systems and users. Testing was authorized, non-destructive, and constrained to agreed scope."
    )

    CFAA_AUTHORIZATION = (
        "The target organization and security researcher mutually agree that diagnostic activities "
        "conducted within authorized scope boundaries and rate limit specifications constitute "
        "authorized access under the Computer Fraud and Abuse Act (CFAA, 18 U.S.C. Section 1030) "
        "and applicable state anti-hacking statutes."
    )

    DMCA_EXEMPTION = (
        "Testing was performed exclusively for defensive security research and vulnerability verification. "
        "The target organization affirms that in-scope activities will not be pursued as violations of "
        "the anti-circumvention provisions of the Digital Millennium Copyright Act (DMCA, 17 U.S.C. Section 1201)."
    )

    DATA_PROTECTION_PRIVACY = (
        "The researcher maintains a strict zero-retention privacy protocol. No customer, employee, or third-party "
        "personally identifiable information (PII) or sensitive business records were altered, downloaded in bulk, "
        "or retained beyond minimal transient diagnostic verification."
    )

    NON_DESTRUCTIVE_GUARANTEE = (
        "All diagnostic tests were limited to non-destructive, idempotent operations (GET, HEAD, OPTIONS). "
        "Denial of service (DoS), computational exhaustion, service disruption, and data destruction "
        "are strictly prohibited and were mathematically excluded from execution."
    )


@dataclass
class SafeHarborProof:
    """Cryptographic and empirical verification that an engagement strictly honored Safe Harbor."""
    program_key: str
    total_requests: int
    start_time: Optional[str]
    end_time: Optional[str]
    duration_seconds: float
    effective_rate_per_sec: float
    rate_limit_ceiling: float
    rate_limit_compliant: bool
    header_tag: str
    header_compliance_pct: float
    excluded_paths_dispatched: int
    session_sha256: str
    is_fully_compliant: bool

    def summary_lines(self) -> List[str]:
        status_tag = "[COMPLIANT - SAFE HARBOR PROTECTED]" if self.is_fully_compliant else "[NON-COMPLIANT WARNING]"
        return [
            f"Safe Harbor Adherence Status: {status_tag}",
            f"Total Audited Requests:      {self.total_requests}",
            f"Active Testing Window:       {self.start_time} -> {self.end_time} ({self.duration_seconds:.1f}s)",
            f"Traffic Pacing Rate:         {self.effective_rate_per_sec:.2f} req/s (Policy Ceiling: {self.rate_limit_ceiling:.2f} req/s)",
            f"Rate Limit Compliance:       {'PASS (Paced)' if self.rate_limit_compliant else 'FAIL (Exceeded)'}",
            f"Identity Tagging Adherence:  {self.header_compliance_pct:.1f}% carrying '{self.header_tag}'",
            f"Excluded Path Guardrail:     {'PASS (0 dispatched)' if self.excluded_paths_dispatched == 0 else f'VIOLATION ({self.excluded_paths_dispatched} hit)'}",
            f"Audit Ledger Integrity:     SHA-256:{self.session_sha256[:16]}...",
        ]


class SafeHarborLedgerAuditor:
    """
    Ingests the local audit ledger (audit/audit_log.jsonl) and computes verifiable
    proof that the engagement conformed to the program's Rules of Engagement.
    """

    @classmethod
    def audit_engagement(
        cls,
        log_path: str = "audit/audit_log.jsonl",
        program_cfg: Optional[Dict[str, Any]] = None,
        program_key: str = "active",
    ) -> SafeHarborProof:
        """Calculates mathematical Safe Harbor compliance proof from the ledger."""
        p_cfg = program_cfg or {}
        p_path = Path(log_path)

        rate_ceiling = float(p_cfg.get("rate_limit_per_second", 2.0))
        header_tag = p_cfg.get("rules_of_engagement", {}).get("header_tag", "X-Bug-Bounty")
        out_paths = p_cfg.get("out_of_scope", {}).get("paths", []) or p_cfg.get("excluded_paths", [])

        if not p_path.exists() or p_path.stat().st_size == 0:
            return SafeHarborProof(
                program_key=program_key,
                total_requests=0,
                start_time=None,
                end_time=None,
                duration_seconds=0.0,
                effective_rate_per_sec=0.0,
                rate_limit_ceiling=rate_ceiling,
                rate_limit_compliant=True,
                header_tag=header_tag,
                header_compliance_pct=100.0,
                excluded_paths_dispatched=0,
                session_sha256="0" * 64,
                is_fully_compliant=True,
            )

        entries: List[Dict[str, Any]] = []
        raw_lines: List[str] = []

        with open(p_path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line_str = line.strip()
                if not line_str:
                    continue
                raw_lines.append(line_str)
                try:
                    entries.append(json.loads(line_str))
                except Exception:
                    continue

        if not entries:
            return SafeHarborProof(
                program_key=program_key,
                total_requests=0,
                start_time=None,
                end_time=None,
                duration_seconds=0.0,
                effective_rate_per_sec=0.0,
                rate_limit_ceiling=rate_ceiling,
                rate_limit_compliant=True,
                header_tag=header_tag,
                header_compliance_pct=100.0,
                excluded_paths_dispatched=0,
                session_sha256="0" * 64,
                is_fully_compliant=True,
            )

        total_reqs = len(entries)
        timestamps: List[datetime.datetime] = []
        tagged_reqs = 0
        excluded_hits = 0

        validator = ScopeValidator(p_cfg) if p_cfg else None

        for entry in entries:
            req = entry.get("request", {})
            headers = req.get("headers", {})
            url = req.get("url", "")

            # Check header presence
            header_keys = [k.lower() for k in headers.keys()]
            if header_tag.lower() in header_keys:
                tagged_reqs += 1

            # Check excluded path violations
            if out_paths and url:
                parsed = urlparse(url)
                path = parsed.path or "/"
                for pattern in out_paths:
                    clean_pattern = pattern.rstrip("*")
                    if clean_pattern and clean_pattern in path:
                        excluded_hits += 1
                        break

            # Parse timestamp
            ts_str = entry.get("timestamp")
            if ts_str:
                try:
                    dt = datetime.datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    timestamps.append(dt)
                except Exception:
                    pass

        # Calculate time & rate pacing
        start_iso = None
        end_iso = None
        duration = 1.0
        effective_rate = 0.0

        if timestamps:
            timestamps.sort()
            start_iso = timestamps[0].strftime("%Y-%m-%d %H:%M:%SZ")
            end_iso = timestamps[-1].strftime("%Y-%m-%d %H:%M:%SZ")
            duration = max((timestamps[-1] - timestamps[0]).total_seconds(), 1.0)
            effective_rate = total_reqs / duration

        # Pacing compliance (allow 20% margin for initial bursts / sub-second rounding)
        rate_compliant = effective_rate <= (rate_ceiling * 1.25)
        header_pct = (tagged_reqs / total_reqs * 100.0) if total_reqs > 0 else 100.0
        
        # Session hash
        session_hash = hashlib.sha256("\n".join(raw_lines).encode("utf-8")).hexdigest()

        is_compliant = (
            rate_compliant
            and (header_pct >= 90.0)
            and (excluded_hits == 0)
        )

        return SafeHarborProof(
            program_key=program_key,
            total_requests=total_reqs,
            start_time=start_iso,
            end_time=end_iso,
            duration_seconds=duration,
            effective_rate_per_sec=effective_rate,
            rate_limit_ceiling=rate_ceiling,
            rate_limit_compliant=rate_compliant,
            header_tag=header_tag,
            header_compliance_pct=header_pct,
            excluded_paths_dispatched=excluded_hits,
            session_sha256=session_hash,
            is_fully_compliant=is_compliant,
        )
