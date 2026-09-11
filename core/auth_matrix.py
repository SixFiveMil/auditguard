"""
AuditGuard Dual-Role Authorization Matrix & IDOR / BOLA Prober.
Performs comparative multi-identity authorization audits across researcher-controlled
roles (e.g. User A vs User B vs Admin vs Unauthenticated) to safely detect Broken
Object Level Authorization (BOLA/IDOR, CWE-639), Missing Authentication (CWE-306),
and Vertical Privilege Escalation (CWE-269).
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from core.client import AuditResponse, ScopedHttpClient
from core.diagnostics import DiagnosticFinding, generate_curl_poc


@dataclass
class AuthRole:
    """Represents a test identity controlled by the security researcher."""
    role_name: str
    headers: Dict[str, str] = field(default_factory=dict)
    description: str = ""
    is_admin: bool = False


@dataclass
class AuthProbeResult:
    """Captures the response characteristics of an authorization probe."""
    role_name: str
    status_code: int
    content_length: int
    response_body: str
    headers: Dict[str, str]
    curl_cmd: str


@dataclass
class AuthFinding:
    """Represents a verified authorization defect detected during matrix probing."""
    endpoint: str
    finding_type: str  # "BOLA_IDOR", "PRIVILEGE_ESCALATION", "UNAUTHENTICATED_ACCESS"
    severity: str
    cwe_id: str
    title: str
    description: str
    evidence: str
    curl_pocs: Dict[str, str] = field(default_factory=dict)
    status_codes: Dict[str, int] = field(default_factory=dict)
    similarity_score: Optional[float] = None

    def to_diagnostic_finding(self) -> DiagnosticFinding:
        """Converts AuthFinding to a standard DiagnosticFinding for unified reporting."""
        curl_poc = self.curl_pocs.get("foreign") or self.curl_pocs.get("unauthenticated") or list(self.curl_pocs.values())[0] if self.curl_pocs else ""
        return DiagnosticFinding(
            title=self.title,
            severity=self.severity,
            cwe_id=self.cwe_id,
            description=self.description,
            evidence=self.evidence,
            remediation=self._get_remediation(),
            curl_poc=curl_poc,
            affected_urls=[self.endpoint],
        )

    def _get_remediation(self) -> str:
        if self.finding_type == "BOLA_IDOR":
            return (
                "Implement strict object-level access control. Verify on every request that "
                "the authenticated identity owns or has explicit permission to access the requested object ID. "
                "Do not rely on client-side routing, hidden parameters, or obscurity."
            )
        elif self.finding_type == "PRIVILEGE_ESCALATION":
            return (
                "Enforce role-based access control (RBAC) server-side on all administrative routes. "
                "Validate user privileges before executing administrative logic, rejecting low-privilege tokens with HTTP 403 Forbidden."
            )
        else:
            return (
                "Require valid authentication tokens or session cookies before granting access to sensitive application data. "
                "Enforce route guards and reject unauthenticated requests with HTTP 401 Unauthorized."
            )


class AuthorizationMatrixAuditor:
    """
    Executes comparative multi-role authorization probes against candidate endpoints.
    Enforces scope validation and safe harbor headers through ScopedHttpClient.
    """

    ADMIN_PATTERNS = [
        re.compile(r"/(admin|manage|system|internal|config|root|dashboard/admin)", re.I),
        re.compile(r"/api/(admin|management|system|super)", re.I),
    ]

    LOGIN_PATTERNS = [
        re.compile(r"login|signin|register|signup|auth/oauth|forgot-password", re.I),
    ]

    def __init__(
        self,
        client: ScopedHttpClient,
        roles: Optional[List[AuthRole]] = None,
    ):
        self.client = client
        self.roles: Dict[str, AuthRole] = {r.role_name: r for r in (roles or [])}

    def add_role(self, role: AuthRole) -> None:
        """Registers a researcher test identity."""
        self.roles[role.role_name] = role

    def _execute_probe(
        self,
        url: str,
        role: Optional[AuthRole],
        role_label: str,
    ) -> Optional[AuthProbeResult]:
        """Safely issues a non-destructive GET request for a specific role identity."""
        headers = dict(role.headers) if role else {}
        curl_cmd = generate_curl_poc(url, method="GET", headers=headers)

        try:
            resp: AuditResponse = self.client.get(
                url,
                headers=headers,
                rationale=f"Dual-role authorization matrix probe for {role_label} on {url}",
            )
            body = resp.text or ""
            return AuthProbeResult(
                role_name=role_label,
                status_code=resp.status_code,
                content_length=len(body),
                response_body=body,
                headers=dict(resp.headers),
                curl_cmd=curl_cmd,
            )
        except Exception:
            return None

    def probe_endpoint(
        self,
        endpoint: str,
        owner_role_name: Optional[str] = None,
        is_admin_endpoint: bool = False,
    ) -> List[AuthFinding]:
        """
        Executes comparative multi-role probing on a single endpoint.
        Compares Owner vs Foreign vs Admin vs Unauthenticated responses.
        """
        findings: List[AuthFinding] = []

        # 1. Check if endpoint looks like an administrative route
        if not is_admin_endpoint:
            path = urlparse(endpoint).path
            is_admin_endpoint = any(p.search(path) for p in self.ADMIN_PATTERNS)

        # 2. Probe unauthenticated
        unauth_result = self._execute_probe(endpoint, role=None, role_label="unauthenticated")

        # 3. Probe all configured roles
        role_results: Dict[str, AuthProbeResult] = {}
        for r_name, r_obj in self.roles.items():
            res = self._execute_probe(endpoint, role=r_obj, role_label=r_name)
            if res:
                role_results[r_name] = res

        if not role_results and not unauth_result:
            return findings

        # -------------------------------------------------------------
        # Test 1: Unauthenticated Access to Administrative / Sensitive Route
        # -------------------------------------------------------------
        if unauth_result and unauth_result.status_code in (200, 206) and is_admin_endpoint:
            # Check it's not simply a login redirect or public page
            if not any(lp.search(unauth_result.response_body) for lp in self.LOGIN_PATTERNS):
                findings.append(
                    AuthFinding(
                        endpoint=endpoint,
                        finding_type="UNAUTHENTICATED_ACCESS",
                        severity="CRITICAL",
                        cwe_id="CWE-306",
                        title=f"Unauthenticated Access to Administrative Functionality ({endpoint})",
                        description=(
                            f"The administrative endpoint `{endpoint}` responded with HTTP {unauth_result.status_code} "
                            "when requested without any authentication headers or cookies. Critical controls must require "
                            "authenticated identity verification."
                        ),
                        evidence=(
                            f"Request: GET {endpoint} (No Auth)\n"
                            f"Response Status: HTTP {unauth_result.status_code}\n"
                            f"Content Length: {unauth_result.content_length} bytes\n"
                            f"Body Preview: {unauth_result.response_body[:200]}..."
                        ),
                        curl_pocs={"unauthenticated": unauth_result.curl_cmd},
                        status_codes={"unauthenticated": unauth_result.status_code},
                    )
                )

        # -------------------------------------------------------------
        # Test 2: Vertical Privilege Escalation (Low-Privilege -> Admin)
        # -------------------------------------------------------------
        if is_admin_endpoint:
            for r_name, r_res in role_results.items():
                role_obj = self.roles.get(r_name)
                if role_obj and not role_obj.is_admin:
                    if r_res.status_code in (200, 204, 206):
                        findings.append(
                            AuthFinding(
                                endpoint=endpoint,
                                finding_type="PRIVILEGE_ESCALATION",
                                severity="HIGH",
                                cwe_id="CWE-269",
                                title=f"Vertical Privilege Escalation on Admin Route ({endpoint})",
                                description=(
                                    f"Low-privilege role `{r_name}` successfully accessed administrative endpoint `{endpoint}` "
                                    f"with HTTP {r_res.status_code}. The server failed to enforce role-based access control."
                                ),
                                evidence=(
                                    f"Role: {r_name} (Non-admin)\n"
                                    f"HTTP Status: {r_res.status_code}\n"
                                    f"Response snippet: {r_res.response_body[:200]}..."
                                ),
                                curl_pocs={r_name: r_res.curl_cmd},
                                status_codes={r_name: r_res.status_code},
                            )
                        )

        # -------------------------------------------------------------
        # Test 3: Horizontal BOLA / IDOR (Owner Role vs Foreign Role)
        # -------------------------------------------------------------
        # If an owner role is specified or detected, compare with other non-admin roles
        owner_name = owner_role_name
        if not owner_name:
            # If we have role_a and role_b, treat first non-admin as owner
            non_admin_roles = [r for r, obj in self.roles.items() if not obj.is_admin]
            if len(non_admin_roles) >= 2:
                owner_name = non_admin_roles[0]

        if owner_name and owner_name in role_results:
            owner_res = role_results[owner_name]
            # Check if owner got 200 OK
            if owner_res.status_code in (200, 206) and owner_res.content_length > 0:
                for foreign_name, foreign_res in role_results.items():
                    if foreign_name == owner_name:
                        continue
                    foreign_obj = self.roles.get(foreign_name)
                    if foreign_obj and foreign_obj.is_admin:
                        continue  # admin accessing user data is expected

                    if foreign_res.status_code in (200, 206) and foreign_res.content_length > 0:
                        # Compute similarity between responses
                        sim_ratio = difflib.SequenceMatcher(
                            None, owner_res.response_body, foreign_res.response_body
                        ).ratio()

                        # If foreign user gets same content or high similarity on user-scoped resource
                        if sim_ratio >= 0.80:
                            findings.append(
                                AuthFinding(
                                    endpoint=endpoint,
                                    finding_type="BOLA_IDOR",
                                    severity="HIGH",
                                    cwe_id="CWE-639",
                                    title=f"BOLA / IDOR Authorization Bypass on {endpoint}",
                                    description=(
                                        f"Endpoint `{endpoint}` appears to leak user-scoped data across accounts. "
                                        f"Owner role `{owner_name}` and foreign role `{foreign_name}` both received HTTP {foreign_res.status_code} "
                                        f"with {sim_ratio * 100:.1f}% body similarity, indicating missing object-level access validation."
                                    ),
                                    evidence=(
                                        f"Owner Role: {owner_name} -> HTTP {owner_res.status_code} ({owner_res.content_length} bytes)\n"
                                        f"Foreign Role: {foreign_name} -> HTTP {foreign_res.status_code} ({foreign_res.content_length} bytes)\n"
                                        f"Body Similarity: {sim_ratio:.2f}\n"
                                        f"Foreign Response Preview: {foreign_res.response_body[:250]}..."
                                    ),
                                    curl_pocs={
                                        "owner": owner_res.curl_cmd,
                                        "foreign": foreign_res.curl_cmd,
                                    },
                                    status_codes={
                                        owner_name: owner_res.status_code,
                                        foreign_name: foreign_res.status_code,
                                    },
                                    similarity_score=sim_ratio,
                                )
                            )

        return findings

    def audit_endpoints(
        self,
        endpoints: List[str],
        owner_role_name: Optional[str] = None,
    ) -> List[DiagnosticFinding]:
        """
        Runs authorization matrix audits across a list of endpoints and returns
        standardized DiagnosticFinding instances.
        """
        findings: List[DiagnosticFinding] = []
        for ep in endpoints:
            auth_findings = self.probe_endpoint(ep, owner_role_name=owner_role_name)
            for af in auth_findings:
                findings.append(af.to_diagnostic_finding())
        return findings
