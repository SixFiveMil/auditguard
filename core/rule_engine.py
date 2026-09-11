"""
AuditGuard Declarative Vulnerability & Diagnostic Probing Engine.
Ingests and executes open-source ProjectDiscovery Nuclei-compatible YAML templates
with strict scope validation, Gatekeeper rate limits, and tamper-evident audit logging.
"""

from __future__ import annotations

import glob
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

import yaml

from core.client import AuditResponse, ScopedHttpClient
from core.diagnostics import DiagnosticFinding
from core.scope_validator import ScopeViolationError


@dataclass
class MatcherRule:
    """Represents a condition block inside a diagnostic template."""
    type: str  # "status", "word", "regex", "kval"
    part: str = "body"  # "body", "header", "status_code"
    words: List[str] = field(default_factory=list)
    regex: List[str] = field(default_factory=list)
    status: List[int] = field(default_factory=list)
    condition: str = "or"  # "and" | "or"
    negative: bool = False
    case_insensitive: bool = False


@dataclass
class HttpRequestStep:
    """Represents an HTTP request block in a template."""
    method: str = "GET"
    path: List[str] = field(default_factory=lambda: ["{{BaseURL}}"])
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    stop_at_first_match: bool = False
    matchers_condition: str = "and"  # "and" | "or"
    matchers: List[MatcherRule] = field(default_factory=list)


@dataclass
class DiagnosticTemplate:
    """Validated in-memory representation of a Nuclei-compatible YAML template."""
    id: str
    name: str
    severity: str
    description: str
    cwe_id: str
    remediation: str
    tags: List[str]
    reference: List[str] = field(default_factory=list)
    http_steps: List[HttpRequestStep] = field(default_factory=list)
    file_path: Optional[str] = None


class TemplateMatcherEvaluator:
    """Natively evaluates template matchers against an AuditResponse."""

    @staticmethod
    def evaluate_matcher(matcher: MatcherRule, response: AuditResponse) -> bool:
        part = matcher.part.lower()
        if part == "header":
            content = "\r\n".join(f"{k}: {v}" for k, v in response.headers.items())
        elif part == "status_code":
            content = str(response.status_code)
        else:
            content = response.text or ""

        if matcher.case_insensitive and isinstance(content, str):
            content = content.lower()

        # 1. Status Matcher
        if matcher.type == "status":
            matched = response.status_code in matcher.status

        # 2. Substring / Word Matcher
        elif matcher.type == "word":
            test_words = [w.lower() if matcher.case_insensitive else w for w in matcher.words]
            if not test_words:
                matched = False
            elif matcher.condition == "and":
                matched = all(w in content for w in test_words)
            else:
                matched = any(w in content for w in test_words)

        # 3. Regex Matcher
        elif matcher.type == "regex":
            flags = re.IGNORECASE if matcher.case_insensitive else 0
            if not matcher.regex:
                matched = False
            elif matcher.condition == "and":
                matched = all(re.search(p, content, flags) is not None for p in matcher.regex)
            else:
                matched = any(re.search(p, content, flags) is not None for p in matcher.regex)

        else:
            matched = False

        return not matched if matcher.negative else matched


class RuleCatalog:
    """
    Catalog and inverted index for fast querying of diagnostic templates
    by technology, domain, and severity.
    """

    def __init__(self):
        self.templates: Dict[str, DiagnosticTemplate] = {}
        self._by_tag: Dict[str, Set[str]] = {}
        self._by_severity: Dict[str, Set[str]] = {}

    def add_template(self, tpl: DiagnosticTemplate) -> None:
        self.templates[tpl.id] = tpl

        # Index by severity
        sev = tpl.severity.upper()
        self._by_severity.setdefault(sev, set()).add(tpl.id)

        # Index by tags
        for t in tpl.tags:
            tag_clean = t.strip().lower()
            if tag_clean:
                self._by_tag.setdefault(tag_clean, set()).add(tpl.id)

    def load_from_directory(self, dir_path: str) -> int:
        """Loads all YAML templates from a directory and its subdirectories."""
        p = Path(dir_path)
        if not p.exists():
            return 0

        loaded = 0
        yaml_files = list(p.glob("**/*.yaml")) + list(p.glob("**/*.yml"))

        for f in yaml_files:
            try:
                tpl = self.parse_yaml_file(str(f))
                if tpl:
                    self.add_template(tpl)
                    loaded += 1
            except Exception:
                # Malformed community rule must not break catalog initialization
                continue

        return loaded

    @classmethod
    def parse_yaml_file(cls, path_to_file: str) -> Optional[DiagnosticTemplate]:
        """Safely parses a single Nuclei-compatible YAML file."""
        try:
            with open(path_to_file, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
        except Exception:
            return None

        if not isinstance(data, dict):
            return None

        tpl_id = str(data.get("id", "")).strip()
        if not tpl_id:
            return None

        info = data.get("info", {})
        if not isinstance(info, dict):
            return None

        name = info.get("name", tpl_id)
        severity = info.get("severity", "info").upper()
        description = info.get("description", "")
        classification = info.get("classification", {}) or {}
        cwe_id = classification.get("cwe-id", "CWE-16")
        remediation = info.get("metadata", {}).get("remediation", "") or classification.get("remediation", "")

        # Extract tags
        raw_tags = info.get("tags", "")
        if isinstance(raw_tags, list):
            tags = [str(t).strip().lower() for t in raw_tags]
        elif isinstance(raw_tags, str):
            tags = [t.strip().lower() for t in raw_tags.split(",") if t.strip()]
        else:
            tags = []

        # Parse HTTP steps (modern v3 'http' or legacy 'requests')
        http_blocks = data.get("http", []) or data.get("requests", [])
        if not isinstance(http_blocks, list):
            return None

        steps: List[HttpRequestStep] = []
        for blk in http_blocks:
            if not isinstance(blk, dict):
                continue

            method = str(blk.get("method", "GET")).upper()
            # Safety Gate: Diagnostic prober only permits idempotent, non-destructive verbs
            if method not in ("GET", "HEAD", "OPTIONS"):
                continue

            path_list = blk.get("path", ["{{BaseURL}}"])
            if isinstance(path_list, str):
                path_list = [path_list]

            headers = blk.get("headers", {})
            match_cond = blk.get("matchers-condition", "and").lower()

            matchers: List[MatcherRule] = []
            for m in blk.get("matchers", []):
                if not isinstance(m, dict):
                    continue
                matchers.append(
                    MatcherRule(
                        type=str(m.get("type", "word")).lower(),
                        part=str(m.get("part", "body")).lower(),
                        words=[str(w) for w in m.get("words", [])],
                        regex=[str(r) for r in m.get("regex", [])],
                        status=[int(s) for s in m.get("status", []) if str(s).isdigit()],
                        condition=str(m.get("condition", "or")).lower(),
                        negative=bool(m.get("negative", False)),
                        case_insensitive=bool(m.get("case-insensitive", False)),
                    )
                )

            steps.append(
                HttpRequestStep(
                    method=method,
                    path=path_list,
                    headers=headers,
                    stop_at_first_match=bool(blk.get("stop-at-first-match", False)),
                    matchers_condition=match_cond,
                    matchers=matchers,
                )
            )

        if not steps:
            return None

        return DiagnosticTemplate(
            id=tpl_id,
            name=name,
            severity=severity,
            description=description,
            cwe_id=cwe_id,
            remediation=remediation,
            tags=tags,
            reference=info.get("reference", []) if isinstance(info.get("reference"), list) else [],
            http_steps=steps,
            file_path=path_to_file,
        )

    def query(
        self,
        tags: Optional[List[str]] = None,
        severities: Optional[List[str]] = None,
        keyword: Optional[str] = None,
    ) -> List[DiagnosticTemplate]:
        """Queries templates matching criteria."""
        candidates: Optional[Set[str]] = None

        # Tag filter
        if tags:
            tag_matches: Set[str] = set()
            for t in tags:
                tag_matches.update(self._by_tag.get(t.strip().lower(), set()))
            candidates = tag_matches

        # Severity filter
        if severities:
            sev_set: Set[str] = set()
            for s in severities:
                sev_set.update(self._by_severity.get(s.strip().upper(), set()))
            if candidates is None:
                candidates = sev_set
            else:
                candidates = candidates.intersection(sev_set)

        results: List[DiagnosticTemplate] = []
        target_ids = candidates if candidates is not None else set(self.templates.keys())

        for tid in target_ids:
            tpl = self.templates.get(tid)
            if not tpl:
                continue

            if keyword:
                kw = keyword.lower()
                if (
                    kw not in tpl.id.lower()
                    and kw not in tpl.name.lower()
                    and kw not in tpl.description.lower()
                    and not any(kw in t for t in tpl.tags)
                ):
                    continue

            results.append(tpl)

        return results


class NucleiDiagnosticRunner:
    """
    Executes declarative YAML templates safely through ScopedHttpClient.
    Guaranteed to respect rate limits, scope validation, and audit logging.
    """

    def __init__(self, client: ScopedHttpClient, catalog: Optional[RuleCatalog] = None):
        self.client = client
        self.catalog = catalog or RuleCatalog()
        self.evaluator = TemplateMatcherEvaluator()

    def run_template(self, template: DiagnosticTemplate, target_url: str) -> Optional[DiagnosticFinding]:
        """
        Executes a single template against target_url. Returns DiagnosticFinding on match.
        """
        parsed = urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
        root_url = base_url
        req_path = parsed.path or "/"

        for step in template.http_steps:
            for path_pattern in step.path:
                # 1. Resolve variable placeholders
                resolved_url = (
                    path_pattern
                    .replace("{{BaseURL}}", base_url)
                    .replace("{{RootURL}}", root_url)
                    .replace("{{Path}}", req_path)
                    .replace("{{Hostname}}", parsed.hostname or "")
                )

                # 2. Scope pre-flight validation
                try:
                    self.client.scope_validator.validate_url(resolved_url)
                except ScopeViolationError:
                    # Strictly abort probe if resolved path is out of scope
                    continue

                # 3. Disallow non-safe HTTP methods in diagnostic mode
                if step.method.upper() not in ("GET", "HEAD", "OPTIONS"):
                    continue

                # 4. Dispatch through ScopedHttpClient (gatekeeper + headers + audit log)
                try:
                    response = self.client.request(
                        method=step.method.upper(),
                        url=resolved_url,
                        headers=step.headers,
                        rationale=f"Diagnostic rule probe [{template.id}]",
                        timeout=8.0,
                    )
                except Exception:
                    continue  # Fault-tolerant network execution

                # 5. Evaluate matchers
                if not step.matchers:
                    continue

                results = [self.evaluator.evaluate_matcher(m, response) for m in step.matchers]
                is_hit = all(results) if step.matchers_condition == "and" else any(results)

                if is_hit:
                    from core.diagnostics import generate_curl_poc
                    curl_poc = generate_curl_poc(
                        resolved_url,
                        method=step.method.upper(),
                        headers=step.headers if step.headers else None,
                    )
                    return DiagnosticFinding(
                        title=f"{template.name} [{template.id}]",
                        severity=template.severity.upper(),
                        cwe_id=template.cwe_id,
                        description=template.description,
                        evidence=f"Matched template on {resolved_url} (HTTP {response.status_code})",
                        remediation=template.remediation or "Review configuration and enforce least-privilege access.",
                        curl_poc=curl_poc,
                        affected_urls=[resolved_url],
                    )

                if step.stop_at_first_match and is_hit:
                    break

        return None

    def run_suite(
        self,
        templates: List[DiagnosticTemplate],
        target_url: str,
    ) -> List[DiagnosticFinding]:
        """Executes a suite of templates against an endpoint."""
        findings: List[DiagnosticFinding] = []
        for tpl in templates:
            f = self.run_template(tpl, target_url)
            if f:
                findings.append(f)
        return findings
