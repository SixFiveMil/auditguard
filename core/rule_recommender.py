"""
AuditGuard Discovery-Driven Rule Recommender.
Analyzes StateHunter reconnaissance data (routes, sensitive paths, robots directives,
and live response headers) and matches against local/external template repositories
to recommend high-value, non-destructive diagnostic tests tailored to the target.
"""

from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from core.rule_engine import DiagnosticTemplate, RuleCatalog


@dataclass
class DiscoveryTrait:
    """Represents an architectural or technological signal discovered about the target."""
    category: str  # "technology", "route", "header", "robot_directive", "auth"
    token: str     # Normalized identifier, e.g. "angular", "express", "engine.io", "ftp"
    evidence: str  # Human-readable context, e.g. "Discovered endpoint: /engine.io"
    weight: float = 1.0


@dataclass
class RuleRecommendation:
    """Represents a matched diagnostic rule recommendation with rationale."""
    template_id: str
    template_name: str
    severity: str
    cwe_id: str
    file_path: str
    relevance_score: int
    matched_traits: List[str]
    rationale: str


class DiscoveryProfiler:
    """
    Analyzes program configuration, reconnaissance artifacts, and live target metadata
    to build a comprehensive security trait profile.
    """

    ROUTE_HEURISTICS: List[Tuple[re.Pattern, str, str, float]] = [
        (re.compile(r"/(?:admin|administration|accounting|dashboard|internal|management)", re.I), "admin", "Sensitive administration / management route", 2.0),
        (re.compile(r"/(?:engine\.io|socket\.io|ws|websocket)", re.I), "websocket", "WebSocket / Realtime engine endpoint", 2.5),
        (re.compile(r"/(?:ftp|backup|dump|download|data-export)", re.I), "ftp", "File transfer / data export interface", 2.0),
        (re.compile(r"/(?:api|rest|v[0-9]|graphql|swagger|openapi|api-docs)", re.I), "api", "REST API / Swagger documentation surface", 1.8),
        (re.compile(r"/(?:login|register|auth|2fa|oauth|token|password|session)", re.I), "auth", "Authentication / identity credential flow", 1.5),
        (re.compile(r"/(?:wallet|crypto|web3|nft)", re.I), "web3", "Web3 / cryptocurrency component", 1.5),
        (re.compile(r"/(?:search|query|feedback|contact|complain)", re.I), "input", "User input / query interface", 1.2),
    ]

    @classmethod
    def profile_program(
        cls,
        program_cfg: Dict[str, Any],
        live_headers: Optional[Dict[str, str]] = None,
        live_body: Optional[str] = None,
    ) -> List[DiscoveryTrait]:
        """Profiles a program from discovery metadata and optional live response context."""
        traits: List[DiscoveryTrait] = []
        seen_tokens: Set[str] = set()

        def add_trait(category: str, token: str, evidence: str, weight: float = 1.0):
            norm_token = token.strip().lower()
            key = f"{category}:{norm_token}"
            if key not in seen_tokens and norm_token:
                seen_tokens.add(key)
                traits.append(DiscoveryTrait(category=category, token=norm_token, evidence=evidence, weight=weight))

        # 1. Base web hygiene traits (applies to all web applications)
        add_trait("hygiene", "cors", "Universal web application CORS security baseline", 1.0)
        add_trait("hygiene", "headers", "HTTP security header defense-in-depth baseline", 1.0)
        add_trait("hygiene", "cache", "Sensitive API and endpoint cache hygiene baseline", 1.0)
        add_trait("hygiene", "methods", "HTTP verb tampering and access differential baseline", 1.0)

        # 2. Analyze discovered endpoints
        endpoints = program_cfg.get("discovered_endpoints", [])
        for ep in endpoints:
            for pattern, token, desc, weight in cls.ROUTE_HEURISTICS:
                if pattern.search(ep):
                    add_trait("route", token, f"{desc} ({ep})", weight)

        # Flagged sensitive routes give higher weight to admin/auth traits
        flagged = program_cfg.get("flagged_sensitive_endpoints", [])
        for fep in flagged:
            add_trait("route", "admin", f"High-priority flagged sensitive route: {fep}", 2.5)

        # 3. Analyze robots.txt disallow directives
        robots = program_cfg.get("robots_disallow_directives", [])
        for r_path in robots:
            norm_r = r_path.strip().lower().replace("/", "")
            if norm_r:
                add_trait("robot_directive", norm_r, f"Robots.txt restricted path: {r_path}", 2.2)

        # 4. Analyze live response headers
        if live_headers:
            h_lower = {k.lower(): str(v).lower() for k, v in live_headers.items()}
            server = h_lower.get("server", "")
            if "kestrel" in server or "iis" in server or "asp.net" in server:
                add_trait("technology", "dotnet", f"Server header: {server}", 2.0)
            if "nginx" in server:
                add_trait("technology", "nginx", f"Server header: {server}", 1.5)
            if "apache" in server:
                add_trait("technology", "apache", f"Server header: {server}", 1.5)

            powered = h_lower.get("x-powered-by", "")
            if "express" in powered:
                add_trait("technology", "express", f"X-Powered-By: {powered}", 2.5)
                add_trait("technology", "nodejs", f"Node.js runtime via {powered}", 2.0)
            elif "php" in powered:
                add_trait("technology", "php", f"X-Powered-By: {powered}", 2.0)
            elif "asp.net" in powered:
                add_trait("technology", "dotnet", f"X-Powered-By: {powered}", 2.0)

        # 5. Analyze live body / SPA signatures
        if live_body:
            body_sample = live_body[:10000].lower()
            if "ng-version" in body_sample or "app-root" in body_sample or "angular" in body_sample:
                add_trait("technology", "angular", "Detected Angular SPA frontend marker (ng-version)", 2.5)
                add_trait("technology", "spa", "Single Page Application (SPA) architecture", 1.8)
            if "react" in body_sample or "__next" in body_sample:
                add_trait("technology", "react", "Detected React / Next.js frontend marker", 2.0)
                add_trait("technology", "spa", "Single Page Application (SPA) architecture", 1.8)
            if "vue" in body_sample or "__nuxt" in body_sample:
                add_trait("technology", "vue", "Detected Vue.js / Nuxt frontend marker", 2.0)

        return traits


class RuleRecommender:
    """
    Scans diagnostic template repositories and matches them against target discovery traits.
    """

    SAFE_SUBDIRS = ("technologies", "misconfiguration", "exposures", "vulnerabilities", "diagnostics")

    def __init__(self, repo_path: str = "rules/diagnostics"):
        self.repo_path = repo_path

    def load_candidates(self, safe_only: bool = True, max_rules: int = 500) -> List[DiagnosticTemplate]:
        """Loads candidate templates from the repository safely."""
        p = Path(self.repo_path)
        if not p.exists():
            return []

        templates: List[DiagnosticTemplate] = []
        yaml_files: List[Path] = []

        # If repo is a nuclei-templates root, prioritize safe diagnostic categories
        for sub in self.SAFE_SUBDIRS:
            sub_dir = p / "http" / sub if (p / "http" / sub).exists() else p / sub
            if sub_dir.exists():
                for f in sub_dir.glob("*.yaml"):
                    yaml_files.append(f)
                    if len(yaml_files) >= max_rules:
                        break

        # If no subdirs matched, just glob the folder directly
        if not yaml_files:
            for f in p.glob("**/*.yaml"):
                yaml_files.append(f)
                if len(yaml_files) >= max_rules:
                    break

        for f in yaml_files:
            try:
                tpl = RuleCatalog.parse_yaml_file(str(f))
                if not tpl:
                    continue

                if safe_only:
                    # Enforce that all HTTP steps use safe idempotent verbs
                    all_safe = all(s.method.upper() in ("GET", "HEAD", "OPTIONS") for s in tpl.http_steps)
                    if not all_safe:
                        continue
                    # Exclude intrusive/dos templates
                    if any(t in ("dos", "rce", "intrusive", "fuzz") for t in tpl.tags):
                        continue

                templates.append(tpl)
            except Exception:
                continue

        return templates

    def recommend(
        self,
        traits: List[DiscoveryTrait],
        templates: Optional[List[DiagnosticTemplate]] = None,
        min_score: int = 30,
    ) -> List[RuleRecommendation]:
        """Calculates relevance scores and produces prioritized recommendations."""
        candidate_templates = templates if templates is not None else self.load_candidates()
        recommendations: List[RuleRecommendation] = []

        # Build trait lookup map
        trait_tokens = {t.token: t for t in traits}

        for tpl in candidate_templates:
            score = 0
            matched_evidence: List[str] = []
            matched_trait_names: List[str] = []

            # 1. Match against tags
            for tag in tpl.tags:
                tag_clean = tag.strip().lower()
                if tag_clean in trait_tokens:
                    t = trait_tokens[tag_clean]
                    score += int(35 * t.weight)
                    matched_trait_names.append(tag_clean)
                    matched_evidence.append(t.evidence)

            # 2. Match against template ID or Name
            combined_id = f"{tpl.id} {tpl.name}".lower()
            for token, t in trait_tokens.items():
                if token in combined_id and token not in matched_trait_names:
                    score += int(25 * t.weight)
                    matched_trait_names.append(token)
                    matched_evidence.append(t.evidence)

            # 3. Match against request paths (e.g. {{BaseURL}}/api, /admin)
            for step in tpl.http_steps:
                for path in step.path:
                    path_lower = path.lower()
                    for token, t in trait_tokens.items():
                        if token in ("admin", "api", "auth", "ftp", "websocket") and token in path_lower:
                            if token not in matched_trait_names:
                                score += int(20 * t.weight)
                                matched_trait_names.append(token)
                                matched_evidence.append(t.evidence)

            if score >= min_score:
                # Deduplicate evidence strings
                unique_evidence = list(dict.fromkeys(matched_evidence))
                rationale = " | ".join(unique_evidence[:2]) if unique_evidence else "General security hygiene test"
                
                # Cap score at 100
                final_score = min(score, 100)

                recommendations.append(
                    RuleRecommendation(
                        template_id=tpl.id,
                        template_name=tpl.name,
                        severity=tpl.severity.upper(),
                        cwe_id=tpl.cwe_id,
                        file_path=tpl.file_path or "",
                        relevance_score=final_score,
                        matched_traits=matched_trait_names,
                        rationale=rationale,
                    )
                )

        # Sort recommendations: highest relevance score first, then severity
        sev_order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
        recommendations.sort(
            key=lambda r: (r.relevance_score, sev_order.get(r.severity, 0)),
            reverse=True,
        )

        return recommendations

    @staticmethod
    def import_recommendations(
        recommendations: List[RuleRecommendation],
        target_dir: str = "rules/diagnostics",
    ) -> int:
        """Copies selected template files into AuditGuard's diagnostic rules catalog."""
        dest_p = Path(target_dir)
        dest_p.mkdir(parents=True, exist_ok=True)
        imported = 0

        for r in recommendations:
            if not r.file_path or not os.path.exists(r.file_path):
                continue
            src = Path(r.file_path)
            # Avoid copying onto itself
            if src.parent.resolve() == dest_p.resolve():
                continue

            target_file = dest_p / src.name
            shutil.copy2(src, target_file)
            imported += 1

        return imported
