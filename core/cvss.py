"""
AuditGuard Deterministic CVSS v3.1 Vector & Scoring Engine.
Implements the official FIRST.org Common Vulnerability Scoring System (CVSS) v3.1 specification.
Provides mathematical base score calculation, vector generation, and deterministic
mapping from finding characteristics and CWE identifiers.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class CVSS31Metrics:
    """Represents the FIRST.org CVSS v3.1 Base Metric Group."""
    # Exploitability Metrics
    attack_vector: str = "N"          # N (Network), A (Adjacent), L (Local), P (Physical)
    attack_complexity: str = "L"      # L (Low), H (High)
    privileges_required: str = "N"    # N (None), L (Low), H (High)
    user_interaction: str = "N"       # N (None), R (Required)
    scope: str = "U"                  # U (Unchanged), C (Changed)

    # Impact Metrics
    confidentiality: str = "N"        # N (None), L (Low), H (High)
    integrity: str = "N"              # N (None), L (Low), H (High)
    availability: str = "N"           # N (None), L (Low), H (High)

    def to_vector(self) -> str:
        """Returns the RFC-compliant CVSS:3.1 vector string."""
        return (
            f"CVSS:3.1/AV:{self.attack_vector}/AC:{self.attack_complexity}/"
            f"PR:{self.privileges_required}/UI:{self.user_interaction}/"
            f"S:{self.scope}/C:{self.confidentiality}/"
            f"I:{self.integrity}/A:{self.availability}"
        )


class CVSSCalculator:
    """Official FIRST.org CVSS v3.1 mathematical calculation engine."""

    # Metric Weight Lookups
    AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    AC_WEIGHTS = {"L": 0.77, "H": 0.44}
    UI_WEIGHTS = {"N": 0.85, "R": 0.62}

    # PR weights depend on Scope
    PR_WEIGHTS = {
        "U": {"N": 0.85, "L": 0.62, "H": 0.27},
        "C": {"N": 0.85, "L": 0.68, "H": 0.50},
    }

    IMPACT_WEIGHTS = {"N": 0.0, "L": 0.22, "H": 0.56}

    @staticmethod
    def _roundup(val: float) -> float:
        """
        Official FIRST.org CVSS v3.1 Roundup function.
        Rounds up to one decimal place while guarding against floating point inaccuracies.
        """
        int_input = round(val * 100000)
        if int_input % 10000 == 0:
            return round(int_input / 100000.0, 1)
        else:
            return round((math.floor(int_input / 10000) + 1) / 10.0, 1)

    @classmethod
    def calculate_base_score(cls, metrics: CVSS31Metrics) -> float:
        """Calculates CVSS v3.1 Base Score based on FIRST.org specification."""
        c_weight = cls.IMPACT_WEIGHTS.get(metrics.confidentiality.upper(), 0.0)
        i_weight = cls.IMPACT_WEIGHTS.get(metrics.integrity.upper(), 0.0)
        a_weight = cls.IMPACT_WEIGHTS.get(metrics.availability.upper(), 0.0)

        # 1. Calculate Impact Sub-Score (ISS)
        iss = 1.0 - ((1.0 - c_weight) * (1.0 - i_weight) * (1.0 - a_weight))
        if iss <= 0:
            return 0.0

        # 2. Calculate Impact
        scope = metrics.scope.upper()
        if scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * math.pow((iss - 0.02), 15)

        # 3. Calculate Exploitability
        av = cls.AV_WEIGHTS.get(metrics.attack_vector.upper(), 0.85)
        ac = cls.AC_WEIGHTS.get(metrics.attack_complexity.upper(), 0.77)
        pr = cls.PR_WEIGHTS.get(scope, cls.PR_WEIGHTS["U"]).get(metrics.privileges_required.upper(), 0.85)
        ui = cls.UI_WEIGHTS.get(metrics.user_interaction.upper(), 0.85)

        exploitability = 8.22 * av * ac * pr * ui

        # 4. Calculate Base Score
        if scope == "U":
            raw_score = min(impact + exploitability, 10.0)
        else:
            raw_score = min(1.08 * (impact + exploitability), 10.0)

        return cls._roundup(raw_score)

    @staticmethod
    def get_severity_rating(score: float) -> str:
        """Returns qualitative severity rating based on CVSS v3.1 thresholds."""
        if score == 0.0:
            return "NONE"
        elif score <= 3.9:
            return "LOW"
        elif score <= 6.9:
            return "MEDIUM"
        elif score <= 8.9:
            return "HIGH"
        else:
            return "CRITICAL"

    severity_rating = get_severity_rating

    @classmethod
    def from_vector(cls, vector_str: str) -> tuple[CVSS31Metrics, float, str]:
        """Parses a CVSS:3.1 vector string, returns (metrics, score, rating)."""
        metrics = CVSS31Metrics()
        parts = vector_str.strip().split("/")
        for p in parts:
            if ":" not in p:
                continue
            key, val = p.split(":", 1)
            key = key.upper()
            val = val.upper()
            if key == "AV":
                metrics.attack_vector = val
            elif key == "AC":
                metrics.attack_complexity = val
            elif key == "PR":
                metrics.privileges_required = val
            elif key == "UI":
                metrics.user_interaction = val
            elif key == "S":
                metrics.scope = val
            elif key == "C":
                metrics.confidentiality = val
            elif key == "I":
                metrics.integrity = val
            elif key == "A":
                metrics.availability = val

        score = cls.calculate_base_score(metrics)
        rating = cls.get_severity_rating(score)
        return metrics, score, rating

    @classmethod
    def estimate_from_cwe(
        cls,
        cwe_id: str,
        title: str = "",
        evidence: str = "",
        is_sensitive: bool = False,
    ) -> tuple[float, str, str]:
        """
        Deterministically estimates standard CVSS v3.1 metrics from vulnerability signatures.
        Returns: (base_score, vector_string, severity_rating)
        """
        cwe = (cwe_id or "").lower().strip()
        title_lower = (title or "").lower()

        # Defaults: Network reachable, Low complexity, None privileges, No user interaction, Scope Unchanged
        metrics = CVSS31Metrics(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="N",
            integrity="N",
            availability="N",
        )

        if "cwe-306" in cwe:
            # Missing Authentication for Critical Function
            metrics.confidentiality = "H"
            metrics.integrity = "L" if is_sensitive else "N"
            metrics.availability = "N"
            metrics.scope = "U"
        elif "cwe-942" in cwe:
            # CORS Misconfiguration / Origin Reflection
            if "credentials: true" in evidence.lower() or "allow-credentials" in evidence.lower():
                # Authenticated session cross-origin read
                metrics.user_interaction = "R"  # victim visits evil site
                metrics.confidentiality = "H"
                metrics.integrity = "L"
            else:
                metrics.user_interaction = "R"
                metrics.confidentiality = "L"
        elif "cwe-639" in cwe or "cwe-284" in cwe:
            # Broken Object-Level Authorization (BOLA) / IDOR / Access Control
            metrics.privileges_required = "L"  # Authenticated attacker
            metrics.confidentiality = "H"
            metrics.integrity = "L"
        elif "cwe-269" in cwe or "privilege escalation" in title_lower:
            # Vertical Privilege Escalation
            metrics.privileges_required = "L"
            metrics.confidentiality = "H"
            metrics.integrity = "H"
            metrics.scope = "U"
        elif "cwe-524" in cwe or "cwe-525" in cwe:
            # Sensitive Cache Control Hygiene
            metrics.attack_vector = "L" if "cwe-524" in cwe else "N"  # Local/proxy cache
            metrics.confidentiality = "L"
        elif "cwe-1021" in cwe:
            # Clickjacking / Missing CSP / Missing Frame-Options
            metrics.user_interaction = "R"
            metrics.integrity = "L"
        elif "cwe-650" in cwe:
            # HTTP Verb Tampering / Dangerous Methods Advertised
            metrics.confidentiality = "L"
            metrics.integrity = "L"
        elif "cwe-200" in cwe or "cwe-209" in cwe:
            # Information Disclosure / Stack Trace / Version Leak
            metrics.confidentiality = "L"
        elif "cwe-319" in cwe:
            # Missing HSTS
            metrics.attack_vector = "A"  # Adjacent network / MitM
            metrics.confidentiality = "L"
            metrics.integrity = "L"
            metrics.user_interaction = "R"
        else:
            # Generic fallback
            metrics.confidentiality = "L"

        score = cls.calculate_base_score(metrics)
        vector = metrics.to_vector()
        rating = cls.get_severity_rating(score)
        return score, vector, rating
