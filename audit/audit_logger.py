"""
Append-Only Audit Logging Ledger.
Maintains a verifiable, timestamped record of every outbound security request and response.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional


class AuditLogger:
    """
    Writes immutable, line-delimited JSON log entries for complete compliance
    and defensibility during bug bounty engagements.
    """

    SENSITIVE_HEADERS = {"authorization", "cookie", "x-api-key", "token", "session"}

    def __init__(self, log_path: str = "audit/audit_log.jsonl"):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def log_interaction(
        self,
        request_id: str,
        program_name: str,
        method: str,
        url: str,
        request_headers: Dict[str, str],
        request_body: Optional[str],
        status_code: int,
        response_headers: Dict[str, str],
        response_body: str,
        elapsed_ms: float,
        rationale: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Appends an interaction record to the log and returns the structured entry.
        """
        sanitized_req_headers = self._sanitize_headers(request_headers)
        sanitized_res_headers = self._sanitize_headers(response_headers)

        resp_hash = hashlib.sha256(response_body.encode("utf-8", errors="replace")).hexdigest()
        req_hash = hashlib.sha256((request_body or "").encode("utf-8", errors="replace")).hexdigest()

        entry = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "request_id": request_id,
            "program": program_name,
            "rationale": rationale or "",
            "request": {
                "method": method.upper(),
                "url": url,
                "headers": sanitized_req_headers,
                "body_sha256": req_hash,
                "body_preview": (request_body or "")[:500],
            },
            "response": {
                "status_code": status_code,
                "headers": sanitized_res_headers,
                "body_sha256": resp_hash,
                "body_preview": response_body[:1000],
                "elapsed_ms": round(elapsed_ms, 2),
            },
        }

        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

        return entry

    def get_recent_entries(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Reads and returns the most recent log entries."""
        if not self.log_path.exists():
            return []

        entries = []
        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return entries[-limit:]

    def _sanitize_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Redacts sensitive values like session cookies and bearer tokens."""
        sanitized = {}
        for k, v in headers.items():
            if k.lower() in self.SENSITIVE_HEADERS:
                sanitized[k] = "[REDACTED_BY_AUDIT_POLICY]"
            else:
                sanitized[k] = v
        return sanitized
