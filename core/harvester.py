"""
Passive Scope Harvesting & Vendor Detection Module.
Automates authorized scope definition using public program registries,
RFC 9116 security.txt, and Certificate Transparency (CT) logs without
sending intrusive or unauthorized packets to target infrastructure.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

import httpx


class ScopeHarvester:
    """
    Automates the discovery and classification of in-scope assets and
    out-of-scope third-party vendor dependencies using strictly passive sources.
    """

    PUBLIC_PROGRAMS_FEED = (
        "https://raw.githubusercontent.com/projectdiscovery/public-bugbounty-programs/main/dist/data.json"
    )

    DOH_RESOLVER_URL = "https://cloudflare-dns.com/dns-query"

    # Known third-party SaaS CNAME fingerprints that are typically out-of-scope
    THIRD_PARTY_VENDORS = {
        "zendesk.com": "Zendesk Support",
        "greenhouse.io": "Greenhouse Recruiting",
        "lever.co": "Lever Hiring",
        "shopify.com": "Shopify Storefront",
        "statuspage.io": "Atlassian Statuspage",
        "salesforce.com": "Salesforce Community",
        "hubspot.net": "HubSpot Marketing",
        "wpengine.com": "WP Engine Hosting",
        "intercom.help": "Intercom Knowledgebase",
        "freshdesk.com": "Freshdesk Support",
    }

    def __init__(self, timeout: float = 12.0):
        self.timeout = timeout

    def search_public_programs(self, query: str) -> List[Dict[str, Any]]:
        """
        Searches public bug bounty program registries (HackerOne, Bugcrowd, etc.)
        for programs matching the given keyword or domain.
        """
        query_lower = query.strip().lower()
        results = []

        with httpx.Client(timeout=self.timeout) as client:
            resp = client.get(self.PUBLIC_PROGRAMS_FEED)
            if resp.status_code != 200:
                raise RuntimeError(f"Failed to fetch public program index (HTTP {resp.status_code})")

            data = resp.json()
            programs = data.get("programs", [])

            for p in programs:
                name = p.get("name", "").lower()
                domains = [d.lower() for d in p.get("domains", [])]
                url = p.get("url", "").lower()

                if query_lower in name or query_lower in url or any(query_lower in d for d in domains):
                    results.append({
                        "name": p.get("name"),
                        "url": p.get("url"),
                        "bounty": p.get("bounty", False),
                        "domains": p.get("domains", []),
                    })

        return results

    def fetch_security_txt(self, domain: str) -> Optional[Dict[str, str]]:
        """
        Fetches RFC 9116 security.txt metadata from standard well-known locations.
        """
        clean_domain = domain.strip().lower()
        candidates = [
            f"https://{clean_domain}/.well-known/security.txt",
            f"https://{clean_domain}/security.txt",
        ]

        with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
            for url in candidates:
                try:
                    resp = client.get(url, headers={"User-Agent": "AuditGuard-ScopeHarvester/1.0"})
                    if resp.status_code == 200 and "Contact:" in resp.text:
                        parsed = {}
                        for line in resp.text.splitlines():
                            line = line.strip()
                            if ":" in line and not line.startswith("#"):
                                key, val = line.split(":", 1)
                                parsed[key.strip().lower()] = val.strip()
                        parsed["source_url"] = url
                        return parsed
                except Exception:
                    continue

        return None

    def query_certificate_transparency(self, root_domain: str, max_results: int = 150) -> Set[str]:
        """
        Queries crt.sh (Certificate Transparency log search engine) for subdomains.
        This queries a third-party public database and touches zero target servers.
        """
        clean_root = root_domain.strip().lower()
        ct_url = f"https://crt.sh/?q=%.{clean_root}&output=json"
        discovered: Set[str] = set()

        with httpx.Client(timeout=self.timeout) as client:
            try:
                resp = client.get(ct_url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
                if resp.status_code == 200:
                    entries = resp.json()
                    for item in entries:
                        name_val = item.get("name_value", "").lower()
                        for sub in name_val.split("\n"):
                            sub = sub.strip()
                            # Strip wildcards (*.example.com -> example.com)
                            if sub.startswith("*."):
                                sub = sub[2:]
                            if sub.endswith(clean_root) and " " not in sub and "@" not in sub:
                                discovered.add(sub)
                                if len(discovered) >= max_results:
                                    return discovered
            except Exception:
                # CT logs can occasionally time out or be rate-limited
                pass

        return discovered

    def detect_third_party_vendor(self, domain: str) -> Optional[Dict[str, str]]:
        """
        Queries public DNS-over-HTTPS (DoH) for CNAME records to identify
        third-party vendor hosting (e.g. Zendesk, Shopify, Greenhouse).
        """
        with httpx.Client(timeout=self.timeout) as client:
            try:
                resp = client.get(
                    self.DOH_RESOLVER_URL,
                    params={"name": domain, "type": "CNAME"},
                    headers={"accept": "application/dns-json"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    answers = data.get("Answer", [])
                    for ans in answers:
                        cname_target = ans.get("data", "").lower()
                        for vendor_domain, vendor_name in self.THIRD_PARTY_VENDORS.items():
                            if vendor_domain in cname_target:
                                return {
                                    "domain": domain,
                                    "cname": cname_target.rstrip("."),
                                    "vendor": vendor_name,
                                }
            except Exception:
                pass

        return None

    def build_program_scope_draft(
        self,
        program_id: str,
        program_name: str,
        root_domain: str,
        policy_url: str = "",
        platform: str = "Self-Hosted / VDP",
    ) -> Dict[str, Any]:
        """
        Coordinates CT log enumeration and vendor detection to generate a
        pre-classified draft configuration ready for review.
        """
        subdomains = self.query_certificate_transparency(root_domain)
        in_scope_candidates: List[str] = [f"*.{root_domain}", root_domain]
        out_of_scope_domains: List[str] = []

        # Check subdomains for third-party SaaS vendor traps
        vendor_keywords = ("support", "help", "careers", "jobs", "shop", "store", "status", "community", "portal")
        candidates = sorted(subdomains)
        
        # Check high-risk prefixes first, capped at 35 checks to maintain speed
        priority_subs = [s for s in candidates if any(k in s for k in vendor_keywords)]
        regular_subs = [s for s in candidates if s not in priority_subs]
        to_check = (priority_subs + regular_subs)[:35]

        for sub in candidates:
            if sub in to_check:
                vendor_info = self.detect_third_party_vendor(sub)
                if vendor_info:
                    out_of_scope_domains.append(f"{sub} # Vendor: {vendor_info['vendor']} ({vendor_info['cname']})")
                    continue
            if sub not in (root_domain, f"www.{root_domain}") and sub not in in_scope_candidates:
                in_scope_candidates.append(sub)

        return {
            "name": program_name,
            "platform": platform,
            "policy_url": policy_url or f"https://{root_domain}/.well-known/security.txt",
            "safe_harbor": True,
            "rate_limit_per_second": 2.0,
            "allowed_methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
            "in_scope": in_scope_candidates[:30], # Top 30 verified targets
            "out_of_scope": {
                "domains": out_of_scope_domains,
                "paths": [
                    "*/logout",
                    "*/reset-password*",
                    "*/delete-account*",
                ],
            },
            "rules_of_engagement": {
                "prohibit_dos": True,
                "prohibit_data_destruction": True,
                "header_tag": "X-Bug-Bounty",
            },
        }
