"""
AuditGuard Security Diagnostic Engine.
Performs safe, non-destructive, and strictly in-scope security diagnostics on endpoints
discovered during reconnaissance (e.g. via StateHunter).

All tests are:
1. Mathematically constrained by ScopeValidator (zero out-of-scope traffic).
2. Paced by the Gatekeeper rate limiter.
3. Fault-tolerant (network errors, timeouts, or SSL issues on one route will never abort runs).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Set
from urllib.parse import urlparse

import httpx

from core.client import AuditResponse, ScopedHttpClient
from core.scope_validator import (
    OutOfScopeDomainError,
    OutOfScopePathError,
    ProhibitedTargetError,
    ScopeViolationError,
)

if TYPE_CHECKING:
    from core.rule_engine import NucleiDiagnosticRunner, RuleCatalog


def generate_curl_poc(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    data: Optional[str] = None,
) -> str:
    """Generates a standalone, minimal, copy-pasteable curl reproduction command."""
    parts = ["curl", "-i", "-s"]
    if method.upper() != "GET":
        parts.extend(["-X", method.upper()])
    if headers:
        for k, v in headers.items():
            parts.extend(["-H", f'"{k}: {v}"'])
    if data:
        parts.extend(["--data", f"'{data}'"])
    parts.append(f'"{url}"')
    return " ".join(parts)


@dataclass
class DiagnosticFinding:
    """Represents a single security defect, hygiene gap, or configuration finding."""
    title: str
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    cwe_id: str
    description: str
    evidence: str
    remediation: str
    curl_poc: Optional[str] = None
    affected_urls: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    remediation_code: Optional[str] = None
    remediation_lang: Optional[str] = None

    def __post_init__(self):
        if not self.curl_poc and self.affected_urls:
            self.curl_poc = generate_curl_poc(self.affected_urls[0])
        if self.cvss_score is None:
            try:
                from core.cvss import CVSSCalculator
                score, vector, _ = CVSSCalculator.estimate_from_cwe(self.cwe_id, self.title, self.evidence)
                self.cvss_score = score
                self.cvss_vector = vector
            except Exception:
                pass
        if not self.remediation_code:
            try:
                from core.remediation_snippets import RemediationSnippetGenerator
                snippet = RemediationSnippetGenerator.get_snippet(self.cwe_id, self.title)
                if snippet:
                    self.remediation_code = snippet.code
                    self.remediation_lang = snippet.language
            except Exception:
                pass


@dataclass
class EndpointDiagnosticReport:
    """Comprehensive diagnostic evaluation for a single endpoint."""
    url: str
    is_sensitive: bool = False
    status_code: Optional[int] = None
    elapsed_ms: float = 0.0
    allowed_methods: List[str] = field(default_factory=list)
    findings: List[DiagnosticFinding] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    cors_policy: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    skipped_reason: Optional[str] = None


class SecurityDiagnosticEngine:
    """
    Executes in-scope diagnostic audits against web endpoints.
    """

    # Framework stack trace and error screen signatures
    FRAMEWORK_DEBUG_PATTERNS = [
        (r"Traceback \(most recent call last\):", "Python / Django / Flask Unhandled Exception Stack Trace"),
        (r"DisallowedHost at /", "Django DisallowedHost Debug Screen"),
        (r"ActionController::RoutingError", "Ruby on Rails Routing Error Page"),
        (r"Whoops, looks like something went wrong", "Laravel Debug Exception Page"),
        (r"Ignition\s*-\s*Error", "Laravel Ignition Interactive Debugger"),
        (r"(?:TypeError|ReferenceError|SyntaxError):.*\n\s+at\s+", "Node.js / Express Unhandled Exception Stack Trace"),
        (r"\bat Module\._compile\b", "Node.js Internal Stack Frame Disclosure"),
        (r"Whitelabel Error Page", "Spring Boot Whitelabel Error Page"),
        (r"\bjava\.lang\.[A-Za-z]+Exception\b", "Java / Spring Framework Unhandled Exception"),
        (r"\bFatal error\b:.*in\s+.*\.php", "PHP Fatal Error with File Path Disclosure"),
        (r"\bParse error\b:.*in\s+.*\.php", "PHP Syntax / Parse Error Disclosure"),
        (r"Server Error in '/' Application", "ASP.NET Unhandled Exception Error Screen"),
        (r"System\.Web\.HttpException", "ASP.NET HttpException Disclosure"),
    ]

    # RFC 1918 Private IP regex (excluding loopbacks and standard local docs)
    INTERNAL_IP_PATTERN = re.compile(
        r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"
    )

    # Exposed secrets & high-risk credentials in response bodies
    SENSITIVE_LEAK_PATTERNS = [
        (r"\bAKIA[0-9A-Z]{16}\b", "AWS Access Key ID Leaked in Response Body"),
        (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "Private Cryptographic Key Disclosed in Response Body"),
        (r'"(?:db_password|database_url|secret_key|client_secret)"\s*:\s*"[^"]+"', "Sensitive Configuration Secret Leaked in JSON"),
    ]

    def __init__(
        self,
        client: ScopedHttpClient,
        rule_catalog: Optional[Any] = None,
        rules_dir: Optional[str] = "rules/diagnostics",
    ):
        self.client = client
        self.validator = client.scope_validator
        self.catalog = rule_catalog
        self.runner = None
        if self.catalog is not None:
            from core.rule_engine import NucleiDiagnosticRunner
            self.runner = NucleiDiagnosticRunner(self.client, self.catalog)
        elif rules_dir and os.path.exists(rules_dir):
            self.load_rules(rules_dir)

    def load_rules(self, rules_dir: str = "rules/diagnostics") -> int:
        """Loads and indexes YAML diagnostic rules into the engine."""
        from core.rule_engine import NucleiDiagnosticRunner, RuleCatalog
        if self.catalog is None:
            self.catalog = RuleCatalog()
        loaded = self.catalog.load_from_directory(rules_dir)
        self.runner = NucleiDiagnosticRunner(self.client, self.catalog)
        return loaded

    def diagnose(
        self,
        url: str,
        is_sensitive: bool = False,
        run_rules: bool = True,
    ) -> EndpointDiagnosticReport:
        """
        Runs the complete diagnostic suite against a single endpoint.
        Guaranteed to stay within scope and shield against connection drops.
        """
        report = EndpointDiagnosticReport(url=url, is_sensitive=is_sensitive)

        # 1. Pre-flight Scope Gatekeeper Check
        try:
            self.validator.validate_url(url)
        except OutOfScopePathError as e:
            report.skipped_reason = f"Excluded Path: {e}"
            return report
        except ScopeViolationError as e:
            report.skipped_reason = f"Out of Scope: {e}"
            return report

        # 2. Baseline Probe (GET)
        base_resp: Optional[AuditResponse] = None
        try:
            base_resp = self.client.get(
                url,
                rationale="Diagnostic baseline evaluation",
                timeout=8.0,
            )
            report.status_code = base_resp.status_code
            report.elapsed_ms = base_resp.audit_entry.get("response", {}).get("elapsed_ms", 0.0)
            report.headers = dict(base_resp.headers)
        except ScopeViolationError as e:
            report.skipped_reason = f"Scope Violation: {e}"
            return report
        except Exception as e:
            report.error = f"Baseline probe failed: {type(e).__name__} - {e}"
            # Even if baseline probe fails (e.g. connection refused), return report safely
            return report

        # 3. Security Header Hygiene Analysis
        self._audit_security_headers(report, base_resp.headers, url, is_sensitive)

        # 4. Content & Information Leak Analysis
        self._audit_information_leaks(report, base_resp.text, base_resp.status_code)

        # 5. Access Control Differential Check
        self._audit_access_control(report, url, base_resp.status_code, is_sensitive)

        # 6. HTTP Methods & Verb Tampering Check
        self._audit_http_methods(report, url, base_resp.status_code)

        # 7. CORS Policy Probing
        self._audit_cors_policy(report, url)

        # 8. Declarative YAML Rules Evaluation
        if run_rules and self.runner and self.catalog:
            try:
                matched_rules = list(self.catalog.templates.values())
                existing_findings = {(f.title, f.cwe_id) for f in report.findings}
                for tpl in matched_rules:
                    rule_finding = self.runner.run_template(tpl, url)
                    if rule_finding and (rule_finding.title, rule_finding.cwe_id) not in existing_findings:
                        report.findings.append(rule_finding)
                        existing_findings.add((rule_finding.title, rule_finding.cwe_id))
            except Exception:
                pass
        for f in report.findings:
            if not f.affected_urls:
                f.affected_urls = [url]
            if not f.curl_poc:
                f.curl_poc = generate_curl_poc(url)

        return report

    def diagnose_batch(
        self,
        urls: List[str],
        flagged_set: Optional[Set[str]] = None,
        progress_callback: Optional[Callable[[int, int, str, EndpointDiagnosticReport], None]] = None,
    ) -> List[EndpointDiagnosticReport]:
        """
        Safely diagnoses a batch of endpoints with rate-limiting, error isolation,
        and scope enforcement.
        """
        flagged = flagged_set or set()
        reports: List[EndpointDiagnosticReport] = []
        total = len(urls)

        for idx, url in enumerate(urls, start=1):
            parsed = urlparse(url)
            path = parsed.path or "/"
            is_sensitive = url in flagged or path in flagged or any(
                k in path.lower() for k in ("/admin", "/internal", "/private", "/metrics", "/actuator")
            )

            try:
                rep = self.diagnose(url, is_sensitive=is_sensitive)
            except Exception as e:
                # Top-level shield: never let an unexpected exception break the batch loop
                rep = EndpointDiagnosticReport(url=url, is_sensitive=is_sensitive, error=f"Unhandled error: {e}")

            reports.append(rep)
            if progress_callback:
                progress_callback(idx, total, url, rep)

        return reports

    def _audit_security_headers(
        self,
        report: EndpointDiagnosticReport,
        headers: Any,
        url: str,
        is_sensitive: bool,
    ) -> None:
        """Inspects HTTP response headers for missing defenses and caching issues."""
        h_lower = {k.lower(): v for k, v in headers.items()}
        is_https = url.lower().startswith("https://")

        # HSTS (HTTPS only)
        if is_https and "strict-transport-security" not in h_lower:
            report.findings.append(
                DiagnosticFinding(
                    title="Missing Strict-Transport-Security (HSTS) Header",
                    severity="LOW",
                    cwe_id="CWE-319",
                    description="The server does not enforce HTTPS connections via HSTS, leaving users vulnerable to downgrade attacks.",
                    evidence="Strict-Transport-Security header was absent in response.",
                    remediation="Set 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
                )
            )

        # Content-Security-Policy
        if "content-security-policy" not in h_lower:
            report.findings.append(
                DiagnosticFinding(
                    title="Missing Content-Security-Policy (CSP)",
                    severity="LOW",
                    cwe_id="CWE-1021",
                    description="No Content-Security-Policy was provided to restrict script execution, object loading, and style injection.",
                    evidence="Content-Security-Policy header was absent in response.",
                    remediation="Configure a restrictive Content-Security-Policy header.",
                )
            )
        else:
            csp_val = h_lower["content-security-policy"]
            if "'unsafe-inline'" in csp_val and "nonce-" not in csp_val and "sha256-" not in csp_val:
                report.findings.append(
                    DiagnosticFinding(
                        title="Permissive Content-Security-Policy ('unsafe-inline')",
                        severity="LOW",
                        cwe_id="CWE-1021",
                        description="The Content-Security-Policy permits 'unsafe-inline' script execution without nonces or hashes.",
                        evidence=f"CSP: {csp_val[:120]}...",
                        remediation="Remove 'unsafe-inline' and migrate to cryptographic nonces or script hashes.",
                    )
                )

        # Clickjacking Defense (X-Frame-Options or CSP frame-ancestors)
        has_frame_options = "x-frame-options" in h_lower
        has_frame_ancestors = "content-security-policy" in h_lower and "frame-ancestors" in h_lower["content-security-policy"]
        if not has_frame_options and not has_frame_ancestors:
            report.findings.append(
                DiagnosticFinding(
                    title="Missing Anti-Clickjacking Defense",
                    severity="LOW",
                    cwe_id="CWE-1021",
                    description="Neither X-Frame-Options nor CSP frame-ancestors is present to prevent framing by malicious third-party origins.",
                    evidence="Both X-Frame-Options and CSP frame-ancestors are missing.",
                    remediation="Add 'X-Frame-Options: DENY' or 'Content-Security-Policy: frame-ancestors 'none''.",
                )
            )

        # MIME Sniffing Defense
        if h_lower.get("x-content-type-options", "").lower() != "nosniff":
            report.findings.append(
                DiagnosticFinding(
                    title="Missing X-Content-Type-Options Header",
                    severity="INFO",
                    cwe_id="CWE-16",
                    description="Missing 'X-Content-Type-Options: nosniff' header allows browsers to MIME-sniff response content.",
                    evidence=f"X-Content-Type-Options: {h_lower.get('x-content-type-options', '<missing>')}",
                    remediation="Set 'X-Content-Type-Options: nosniff'.",
                )
            )

        # Sensitive Cache Hygiene
        cache_control = h_lower.get("cache-control", "").lower()
        if is_sensitive and "no-store" not in cache_control:
            report.findings.append(
                DiagnosticFinding(
                    title="Sensitive Endpoint Missing 'Cache-Control: no-store'",
                    severity="MEDIUM",
                    cwe_id="CWE-524",
                    description="An endpoint designated as sensitive or administrative does not enforce 'no-store'. Responses may be cached by intermediate proxies or stored on local client disks.",
                    evidence=f"Cache-Control: {cache_control or '<missing>'}",
                    remediation="Set 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0' on all sensitive/admin routes.",
                )
            )

    def _audit_information_leaks(
        self,
        report: EndpointDiagnosticReport,
        body: str,
        status_code: Optional[int],
    ) -> None:
        """Scans response bodies for framework error signatures, stack traces, and internal IPs."""
        if not body:
            return

        # 1. Framework Debug Screens & Stack Traces
        for pattern, label in self.FRAMEWORK_DEBUG_PATTERNS:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                snippet = match.group(0)[:150].strip()
                report.findings.append(
                    DiagnosticFinding(
                        title=f"Verbose Information Disclosure: {label}",
                        severity="HIGH" if (status_code and status_code >= 500) else "MEDIUM",
                        cwe_id="CWE-209",
                        description="The application returned an internal framework debug error page or stack trace in its HTTP response body.",
                        evidence=f"Detected pattern '{pattern}': {snippet}",
                        remediation="Disable developer debug mode in production and configure generic customer-facing error pages.",
                    )
                )
                break  # Record highest-signal stack trace once per endpoint

        # 2. Leaked Internal RFC 1918 IPs
        ip_matches = self.INTERNAL_IP_PATTERN.findall(body)
        unique_ips = sorted(set(ip_matches))
        if unique_ips:
            report.findings.append(
                DiagnosticFinding(
                    title="Internal RFC 1918 IP Address Disclosure",
                    severity="LOW",
                    cwe_id="CWE-200",
                    description="The server response disclosed internal private IP addresses (e.g. 10.x, 172.16-31.x, 192.168.x), exposing internal network topology.",
                    evidence=f"Disclosed Internal IPs: {', '.join(unique_ips[:5])}",
                    remediation="Sanitize internal IP addresses from responses and API error messages.",
                )
            )

        # 3. Sensitive Credentials / Key Dumps
        for pattern, label in self.SENSITIVE_LEAK_PATTERNS:
            match = re.search(pattern, body)
            if match:
                report.findings.append(
                    DiagnosticFinding(
                        title=f"Critical Credential Exposure: {label}",
                        severity="CRITICAL",
                        cwe_id="CWE-312",
                        description="The response body contains plaintext cryptographic keys or API credentials.",
                        evidence=f"Matching token pattern detected: {match.group(0)[:30]}...",
                        remediation="Immediately revoke exposed keys and remove secrets from client-facing responses.",
                    )
                )

    def _audit_access_control(
        self,
        report: EndpointDiagnosticReport,
        url: str,
        status_code: Optional[int],
        is_sensitive: bool,
    ) -> None:
        """Flags administrative or sensitive routes that return unauthenticated 200 OK."""
        if not is_sensitive or status_code is None:
            return

        parsed = urlparse(url)
        path = parsed.path.lower()

        # Check if route appears to be a protected administrative endpoint
        admin_indicators = ("/admin", "/internal", "/manage", "/console", "/secret")
        if any(path.startswith(ind) for ind in admin_indicators):
            if status_code == 200:
                report.findings.append(
                    DiagnosticFinding(
                        title="Potential Broken Access Control: Unauthenticated 200 OK on Admin Route",
                        severity="HIGH",
                        cwe_id="CWE-306",
                        description="An administrative endpoint returned HTTP 200 OK without requiring authentication or session tokens.",
                        evidence=f"Unauthenticated request to '{url}' received HTTP {status_code}.",
                        remediation="Ensure all administrative and privileged endpoints require robust session authentication and role authorization.",
                    )
                )

    def _audit_http_methods(
        self,
        report: EndpointDiagnosticReport,
        url: str,
        baseline_status: Optional[int],
    ) -> None:
        """Tests safe HTTP methods (OPTIONS, HEAD) to identify allowed verbs and status differentials."""
        # 1. OPTIONS Check
        try:
            opt_resp = self.client.request(
                "OPTIONS",
                url,
                rationale="Diagnostic OPTIONS method audit",
                timeout=6.0,
            )
            allow_header = opt_resp.headers.get("allow", "") or opt_resp.headers.get("access-control-allow-methods", "")
            if allow_header:
                methods = [m.strip().upper() for m in allow_header.split(",") if m.strip()]
                report.allowed_methods = methods

                dangerous_methods = {"TRACE", "CONNECT", "DELETE", "PUT", "DEBUG"}
                exposed_dangerous = [m for m in methods if m in dangerous_methods]
                if exposed_dangerous:
                    report.findings.append(
                        DiagnosticFinding(
                            title=f"Potentially Dangerous HTTP Methods Advertised ({', '.join(exposed_dangerous)})",
                            severity="MEDIUM" if "TRACE" in exposed_dangerous else "LOW",
                            cwe_id="CWE-650",
                            description="The server's Allow header advertises dangerous or state-modifying HTTP methods.",
                            evidence=f"Allow Header: {allow_header}",
                            remediation="Disable unnecessary HTTP methods (such as TRACE and DEBUG) on production web servers.",
                        )
                    )
        except Exception:
            # Method probing failure must never break the audit
            pass

        # 2. Verb Tampering Differential Check (e.g. GET was 403, but HEAD was 200)
        if baseline_status in (401, 403):
            try:
                head_resp = self.client.request(
                    "HEAD",
                    url,
                    rationale="Diagnostic HEAD verb tampering check",
                    timeout=6.0,
                )
                if head_resp.status_code == 200:
                    report.findings.append(
                        DiagnosticFinding(
                            title="Potential HTTP Verb Tampering Bypass (GET 403 vs HEAD 200)",
                            severity="MEDIUM",
                            cwe_id="CWE-650",
                            description="The endpoint rejected GET with authorization error, but accepted HEAD with HTTP 200 OK, indicating inconsistent HTTP verb access controls.",
                            evidence=f"GET returned HTTP {baseline_status}, but HEAD returned HTTP {head_resp.status_code}.",
                            remediation="Apply authentication filters uniformly across all HTTP verbs.",
                        )
                    )
            except Exception:
                pass

    def _audit_cors_policy(self, report: EndpointDiagnosticReport, url: str) -> None:
        """Probes for insecure Cross-Origin Resource Sharing (CORS) configurations."""
        test_origin = "https://auditguard-diagnostic.internal"
        try:
            cors_resp = self.client.request(
                "GET",
                url,
                headers={"Origin": test_origin},
                rationale="Diagnostic CORS policy reflection check",
                timeout=6.0,
            )

            h_lower = {k.lower(): v for k, v in cors_resp.headers.items()}
            acao = h_lower.get("access-control-allow-origin", "").strip()
            acac = h_lower.get("access-control-allow-credentials", "").strip().lower()

            if not acao:
                return

            report.cors_policy = {
                "origin": test_origin,
                "allow_origin": acao,
                "allow_credentials": acac,
            }

            # 1. Arbitrary Origin Reflected + Credentials (CRITICAL)
            if acao == test_origin and acac == "true":
                report.findings.append(
                    DiagnosticFinding(
                        title="Critical CORS Misconfiguration: Arbitrary Origin Reflected with Credentials",
                        severity="CRITICAL",
                        cwe_id="CWE-942",
                        description="The application dynamically reflects arbitrary request Origin headers and enables 'Access-Control-Allow-Credentials: true'. Any malicious website visited by an authenticated user can read sensitive session data.",
                        evidence=f"Request Origin '{test_origin}' resulted in ACAO: '{acao}' with ACAC: '{acac}'.",
                        remediation="Never dynamically reflect untrusted Origin headers with credentials enabled. Implement an explicit domain whitelist.",
                    )
                )
            # 2. Null Origin with Credentials (HIGH)
            elif acao == "null" and acac == "true":
                report.findings.append(
                    DiagnosticFinding(
                        title="High CORS Misconfiguration: 'null' Origin Allowed with Credentials",
                        severity="HIGH",
                        cwe_id="CWE-942",
                        description="The CORS configuration permits the 'null' origin with credentials enabled, allowing exploitation via sandboxed iframes or data URIs.",
                        evidence="ACAO is set to 'null' with ACAC: 'true'.",
                        remediation="Remove 'null' from authorized CORS origins.",
                    )
                )
            # 3. Wildcard Origin with Credentials
            elif acao == "*" and acac == "true":
                report.findings.append(
                    DiagnosticFinding(
                        title="Invalid CORS Configuration: Wildcard Origin with Credentials",
                        severity="MEDIUM",
                        cwe_id="CWE-942",
                        description="The server returns 'Access-Control-Allow-Origin: *' combined with credentials. While modern browsers reject this combination, it represents a security configuration error.",
                        evidence="ACAO: '*' combined with ACAC: 'true'.",
                        remediation="Explicitly list authorized origins if credentials are required.",
                    )
                )
        except Exception:
            # CORS probing failure must never break the audit
            pass
