"""
Deterministic Scope Validation Engine.
Ensures zero outbound traffic reaches unauthorized, excluded, or dangerous targets.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
import socket
from urllib.parse import urlparse
from typing import Any, Dict, List, Optional


class ScopeViolationError(Exception):
    """Base exception for all scope violations."""
    pass


class OutOfScopeDomainError(ScopeViolationError):
    """Raised when a target domain is not authorized."""
    pass


class OutOfScopePathError(ScopeViolationError):
    """Raised when a target path matches an explicit exclusion."""
    pass


class ProhibitedTargetError(ScopeViolationError):
    """Raised when targeting internal networks, metadata services, or malformed URLs."""
    pass


class ScopeValidator:
    """
    Deterministic gatekeeper that validates target URLs against the active
    bug bounty policy rules before any network connection is attempted.
    """

    CLOUD_METADATA_IPS = {
        "169.254.169.254", # AWS / GCP / Azure metadata
        "100.100.100.200", # Alibaba Cloud
        "fd00:ec2::254",   # AWS IPv6
    }

    def __init__(self, program_config: Dict[str, Any]):
        self.program_name: str = program_config.get("name", "Unnamed Program")
        self.in_scope: List[str] = program_config.get("in_scope", [])
        
        out_of_scope_cfg = program_config.get("out_of_scope", {})
        self.out_of_scope_domains: List[str] = out_of_scope_cfg.get("domains", [])

        # Ingest exclusions from both out_of_scope.paths and top-level excluded_paths (StateHunter schema)
        paths_from_oos = out_of_scope_cfg.get("paths", [])
        paths_from_top = program_config.get("excluded_paths", [])
        seen_paths = set()
        merged_paths = []
        for p in paths_from_oos + paths_from_top:
            if p and p not in seen_paths:
                seen_paths.add(p)
                merged_paths.append(p)
        self.out_of_scope_paths: List[str] = merged_paths

        # Discovered and flagged endpoints from StateHunter reconnaissance
        self.discovered_endpoints: List[str] = program_config.get("discovered_endpoints", [])
        self.flagged_sensitive_endpoints: List[str] = program_config.get("flagged_sensitive_endpoints", [])
        self.robots_disallow_directives: List[str] = program_config.get("robots_disallow_directives", [])
        
        self.rules = program_config.get("rules_of_engagement", {})
        self.allow_local = any(
            t.startswith("localhost") or t.startswith("127.0.0.1") or "localhost" in t or "127.0.0.1" in t
            for t in self.in_scope
        )

    def validate_url(self, raw_url: str) -> None:
        """
        Validates the given URL against all active scope boundaries.
        Raises a subclass of ScopeViolationError if any rule is violated.
        """
        if not raw_url or not isinstance(raw_url, str):
            raise ProhibitedTargetError(f"Invalid or empty URL provided: {raw_url!r}")

        parsed = urlparse(raw_url.strip())
        if not parsed.scheme or parsed.scheme.lower() not in ("http", "https"):
            raise ProhibitedTargetError(
                f"Protocol '{parsed.scheme}' not allowed. Only HTTP and HTTPS are permitted."
            )

        if not parsed.netloc:
            raise ProhibitedTargetError(f"URL missing hostname/network location: {raw_url}")

        host = parsed.netloc.lower()
        # Separate hostname and port if present
        hostname = host.split(":")[0]

        # 1. SSRF & Internal IP Guardrails
        self._check_forbidden_ips(hostname)

        # 2. Check Explicit Exclusions (Out of Scope Domains)
        for excluded in self.out_of_scope_domains:
            if self._matches_pattern(host, excluded) or self._matches_pattern(hostname, excluded):
                raise OutOfScopeDomainError(
                    f"Target host '{host}' matches explicit OUT-OF-SCOPE domain exclusion: '{excluded}'"
                )

        # 3. Check Explicit Exclusions (Out of Scope Paths)
        path = parsed.path or "/"
        query = parsed.query or ""
        matched_rule = self._is_path_excluded(path, query)
        if matched_rule:
            raise OutOfScopePathError(
                f"Target path '{path}' matches explicit OUT-OF-SCOPE exclusion rule: '{matched_rule}'"
            )

        # 4. Check In-Scope Inclusion
        if not self._is_in_scope(raw_url, host, hostname, path):
            raise OutOfScopeDomainError(
                f"Host '{host}' is NOT listed in the authorized scope for '{self.program_name}'. "
                f"Permitted targets: {self.in_scope}"
            )

    def _is_path_excluded(self, path: str, query: str = "") -> Optional[str]:
        """
        Determines whether the path or path+query matches any out_of_scope path rule.
        Returns the matching rule string if excluded, or None.

        Rules:
        - Wildcard rules (containing '*'):
          Converted to regex matching across any path segment.
        - Literal rules (no '*'):
          Match exact path (/billing, /billing/) and direct subpaths rooted at that prefix
          (/billing/invoices, /billing?tab=1), but do NOT match nested segments under
          unrelated prefixes (/api/v1/billing/stripe-webhook).
        """
        if not path:
            path = "/"
        if not path.startswith("/"):
            path = "/" + path

        path_lower = path.lower()
        clean_path_lower = path_lower[:-1] if len(path_lower) > 1 and path_lower.endswith("/") else path_lower
        full_path_with_query = f"{path}?{query}".lower() if query else path_lower

        for raw_rule in self.out_of_scope_paths:
            rule = raw_rule.strip()
            if not rule:
                continue

            # 1. Wildcard rule
            if "*" in rule:
                wildcard_rule = rule
                if not wildcard_rule.startswith("/") and not wildcard_rule.startswith("*"):
                    wildcard_rule = "/" + wildcard_rule

                pattern = "^" + ".*".join(re.escape(part) for part in wildcard_rule.split("*")) + "$"
                regex = re.compile(pattern, re.IGNORECASE)
                if regex.search(path_lower) or regex.search(clean_path_lower) or regex.search(full_path_with_query):
                    return rule
                continue

            # 2. Literal rule
            norm_rule = rule
            if not norm_rule.startswith("/"):
                norm_rule = "/" + norm_rule
            if len(norm_rule) > 1 and norm_rule.endswith("/"):
                norm_rule = norm_rule[:-1]

            norm_rule_lower = norm_rule.lower()

            # Exact match (e.g. /billing or /billing/)
            if path_lower == norm_rule_lower or clean_path_lower == norm_rule_lower:
                return rule

            # Subpath prefix match (e.g. /billing/invoices, /billing?tab=1, /billing#test)
            if (
                path_lower.startswith(norm_rule_lower + "/")
                or full_path_with_query.startswith(norm_rule_lower + "?")
                or full_path_with_query.startswith(norm_rule_lower + "#")
            ):
                return rule

        return None

    def _matches_pattern(self, host: str, pattern: str) -> bool:
        """Matches a host against an exact name or wildcard pattern (e.g. *.example.com)."""
        pattern = pattern.lower()
        if pattern == host:
            return True
        if pattern.startswith("*."):
            suffix = pattern[1:]  # e.g., '.staging.example.com'
            if host.endswith(suffix) and host != pattern[2:]:
                return True
        return fnmatch.fnmatch(host, pattern)

    def _is_in_scope(self, url: str, host: str, hostname: str, path: str) -> bool:
        """
        Checks if the target URL, host, hostname, or path matches any in-scope rule.
        Supports:
        - Full origins/URLs (e.g. https://example.com, http://localhost:8080)
        - Wildcard hostnames (*.example.com)
        - Plain hostnames (api.example.com)
        - Path-scoped rules (/api/v1/*, https://example.com/api/*)
        """
        url_lower = url.lower()
        host_lower = host.lower()
        hostname_lower = hostname.lower()
        path_lower = path.lower() if path else "/"

        for raw_rule in self.in_scope:
            rule = raw_rule.strip()
            if not rule:
                continue

            rule_lower = rule.lower()

            # 1. Rule is full URL / origin (starts with http:// or https://)
            if rule_lower.startswith("http://") or rule_lower.startswith("https://"):
                try:
                    parsed_rule = urlparse(rule_lower)
                    rule_netloc = parsed_rule.netloc.lower()
                    rule_host = rule_netloc.split(":")[0]

                    # Match origin/host
                    host_matches = (
                        host_lower == rule_netloc
                        or hostname_lower == rule_host
                        or (rule_host.startswith("*.") and (hostname_lower == rule_host[2:] or hostname_lower.endswith("." + rule_host[2:])))
                    )

                    if host_matches:
                        rule_path = parsed_rule.path
                        if rule_path and rule_path != "/":
                            if "*" in rule_path:
                                pattern = "^" + ".*".join(re.escape(p) for p in rule_path.split("*")) + "$"
                                if re.match(pattern, path_lower):
                                    return True
                            elif path_lower == rule_path or path_lower.startswith(rule_path.rstrip("/") + "/"):
                                return True
                        else:
                            return True
                except Exception:
                    pass

                # Also check direct prefix match against full URL
                if url_lower.startswith(rule_lower.rstrip("/")):
                    return True
                continue

            # 2. Rule is a path prefix (e.g. /api/* or /internal)
            if rule_lower.startswith("/"):
                if "*" in rule_lower:
                    pattern = "^" + ".*".join(re.escape(p) for p in rule_lower.split("*")) + "$"
                    if re.match(pattern, path_lower):
                        return True
                elif path_lower == rule_lower or path_lower.startswith(rule_lower.rstrip("/") + "/"):
                    return True
                continue

            # 3. Rule is a wildcard hostname (*.example.com)
            if rule_lower.startswith("*."):
                base_domain = rule_lower[2:].split(":")[0]
                if hostname_lower == base_domain or hostname_lower.endswith("." + base_domain):
                    return True
                continue

            # 4. Rule contains wildcard * (general wildcard)
            if "*" in rule_lower:
                pattern = "^" + ".*".join(re.escape(p) for p in rule_lower.split("*")) + "$"
                if re.match(pattern, host_lower) or re.match(pattern, hostname_lower) or re.match(pattern, url_lower):
                    return True
                continue

            # 5. Plain hostname or hostname:port match
            if host_lower == rule_lower or hostname_lower == rule_lower.split(":")[0]:
                return True

        return False

    def _check_forbidden_ips(self, hostname: str) -> None:
        """Blocks cloud metadata, link-local, and unauthorized private addresses."""
        if hostname in self.CLOUD_METADATA_IPS:
            raise ProhibitedTargetError(
                f"Targeting cloud metadata service ({hostname}) is strictly prohibited."
            )

        try:
            ip = ipaddress.ip_address(hostname)
            if str(ip) in self.CLOUD_METADATA_IPS:
                raise ProhibitedTargetError(f"Cloud metadata IP {ip} is prohibited.")

            if not self.allow_local:
                if ip.is_private or ip.is_loopback or ip.is_link_local:
                    raise ProhibitedTargetError(
                        f"Target IP {ip} is private/loopback/link-local and not permitted for external VDP testing."
                    )
        except ValueError:
            # hostname is a domain name, not a direct IP string
            pass
