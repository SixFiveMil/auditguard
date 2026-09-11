"""
Scoped HTTP Client.
Wraps HTTP network calls with mandatory scope validation, operator gating,
compliance header injection, and immutable audit logging.
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, Optional

import httpx

from audit.audit_logger import AuditLogger
from core.gatekeeper import Gatekeeper
from core.scope_validator import ScopeValidator


class AuditResponse:
    """Wrapper holding both the raw HTTP response and its audit log record."""

    def __init__(self, raw_response: httpx.Response, audit_entry: Dict[str, Any]):
        self.raw = raw_response
        self.status_code = raw_response.status_code
        self.headers = raw_response.headers
        self.text = raw_response.text
        self.audit_entry = audit_entry

    def json(self) -> Any:
        return self.raw.json()

    def __repr__(self) -> str:
        return f"<AuditResponse status={self.status_code} id={self.audit_entry.get('request_id')}>"


class ScopedHttpClient:
    """
    HTTP Client with strict guardrails:
    1. Rejects any target URL outside the active program scope.
    2. Enforces operator approval via the Gatekeeper.
    3. Injects mandatory Safe-Harbor compliance identification headers.
    4. Automatically logs full request/response context to the audit ledger.
    """

    def __init__(
        self,
        scope_validator: ScopeValidator,
        gatekeeper: Gatekeeper,
        audit_logger: AuditLogger,
        researcher_identifier: str = "AuthorizedSecurityResearcher/1.0",
        default_timeout: float = 10.0,
    ):
        self.scope_validator = scope_validator
        self.gatekeeper = gatekeeper
        self.audit_logger = audit_logger
        self.researcher_identifier = researcher_identifier
        self.default_timeout = default_timeout

    def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Any] = None,
        json_data: Optional[Any] = None,
        timeout: Optional[float] = None,
        rationale: Optional[str] = None,
    ) -> AuditResponse:
        """
        Executes an authorized HTTP request through the guardrail pipeline.
        """
        # Step 1: Deterministic Scope Validation
        self.scope_validator.validate_url(url)

        # Step 2: Inject Safe Harbor Identification Headers
        merged_headers = dict(headers or {})
        header_tag = self.scope_validator.rules.get("header_tag", "X-Bug-Bounty")
        merged_headers.setdefault(header_tag, self.researcher_identifier)
        merged_headers.setdefault(
            "User-Agent", f"AuditGuard-SecurityResearch ({self.researcher_identifier})"
        )

        # Step 3: Human-in-the-Loop Operator Gatekeeper
        request_id = self.gatekeeper.authorize_request(
            method=method,
            url=url,
            headers=merged_headers,
            data=data,
            json_data=json_data,
            rationale=rationale,
        )

        # Step 4: Network Execution
        req_timeout = timeout or self.default_timeout
        start_time = time.perf_counter()
        
        request_body_str = None
        if json_data is not None:
            request_body_str = json.dumps(json_data)
        elif data is not None:
            request_body_str = str(data)

        with httpx.Client(timeout=req_timeout, follow_redirects=False) as client:
            raw_response = client.request(
                method=method.upper(),
                url=url,
                headers=merged_headers,
                params=params,
                data=data,
                json=json_data,
            )

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        # Step 5: Audit Ledger Logging
        audit_entry = self.audit_logger.log_interaction(
            request_id=request_id,
            program_name=self.scope_validator.program_name,
            method=method,
            url=str(raw_response.url),
            request_headers=merged_headers,
            request_body=request_body_str,
            status_code=raw_response.status_code,
            response_headers=dict(raw_response.headers),
            response_body=raw_response.text,
            elapsed_ms=elapsed_ms,
            rationale=rationale,
        )

        return AuditResponse(raw_response, audit_entry)

    # Convenience helper methods
    def get(self, url: str, **kwargs: Any) -> AuditResponse:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> AuditResponse:
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs: Any) -> AuditResponse:
        return self.request("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> AuditResponse:
        return self.request("DELETE", url, **kwargs)
