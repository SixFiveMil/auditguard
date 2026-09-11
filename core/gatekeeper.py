"""
Human-in-the-Loop Gatekeeper & Rate Limiter.
Enforces explicit operator approval and rate-limiting before any external request fires.
"""

from __future__ import annotations

import hashlib
import sys
import time
from typing import Any, Callable, Dict, Optional


class RequestDeniedError(Exception):
    """Raised when the operator denies authorization for an outbound request."""
    pass


class Gatekeeper:
    """
    Acts as the human co-signer and rate limiter for all outbound network actions.
    No packet may be sent without passing through this gate.
    """

    def __init__(
        self,
        rate_limit_per_second: float = 2.0,
        require_interactive: bool = True,
        approval_hook: Optional[Callable[[Dict[str, Any]], bool]] = None,
    ):
        self.rate_limit = max(0.1, rate_limit_per_second)
        self.min_interval = 1.0 / self.rate_limit
        self.last_request_time = 0.0
        self.require_interactive = require_interactive
        self.approval_hook = approval_hook

    def authorize_request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Any] = None,
        json_data: Optional[Any] = None,
        rationale: Optional[str] = None,
    ) -> str:
        """
        Presents the proposed network request to the human operator for explicit confirmation.
        Returns a verification token upon approval, or raises RequestDeniedError.
        """
        # Rate limiting check
        self._enforce_rate_limit()

        # Build human-readable audit payload
        payload_summary = ""
        if data:
            payload_str = str(data)
            payload_summary = payload_str[:300] + ("..." if len(payload_str) > 300 else "")
        elif json_data:
            payload_str = str(json_data)
            payload_summary = payload_str[:300] + ("..." if len(payload_str) > 300 else "")
        else:
            payload_summary = "<empty body>"

        req_summary = (
            f"METHOD:  {method.upper()}\n"
            f"TARGET:  {url}\n"
            f"PURPOSE: {rationale or 'Diagnostic / Conformance test'}\n"
            f"PAYLOAD: {payload_summary}\n"
        )

        req_hash = hashlib.sha256(f"{method}:{url}:{payload_summary}".encode()).hexdigest()[:12]

        # Check custom hook (useful for unit tests and programmatic approvals)
        if self.approval_hook:
            approved = self.approval_hook({
                "method": method,
                "url": url,
                "headers": headers,
                "payload": payload_summary,
                "hash": req_hash,
                "rationale": rationale,
            })
            if not approved:
                raise RequestDeniedError(f"Approval hook rejected request [{req_hash}]")
            return req_hash

        # Interactive terminal check
        if self.require_interactive:
            print("\n" + "=" * 65)
            print(f" [GATEKEEPER] OUTBOUND ACTION AUTHORIZATION REQUIRED (ID: {req_hash})")
            print("=" * 65)
            print(req_summary.strip())
            print("-" * 65)

            try:
                prompt = f"Authorize outbound request [{req_hash}]? Type 'yes' or 'y' to proceed: "
                user_input = input(prompt).strip().lower()
                if user_input not in ("y", "yes"):
                    raise RequestDeniedError(
                        f"Operator declined request [{req_hash}]. Execution aborted."
                    )
            except (KeyboardInterrupt, EOFError):
                print("\n[GATEKEEPER] Action aborted by operator signal.")
                raise RequestDeniedError("Operator interrupted authorization prompt.")

        return req_hash

    def _enforce_rate_limit(self) -> None:
        """Enforces spacing between requests to comply with program rate limits."""
        now = time.time()
        elapsed = now - self.last_request_time
        if elapsed < self.min_interval:
            sleep_time = self.min_interval - elapsed
            time.sleep(sleep_time)
        self.last_request_time = time.time()
