"""
AuditGuard Core Framework Engine.
Provides deterministic scope validation, rate-limited gatekeeping,
diagnostic rule parsing, CVSS v3.1 scoring, remediation generation,
comparative authorization matrix probing, and continuous drift monitoring.
"""

from core.scope_validator import ScopeValidator, ScopeViolationError
from core.gatekeeper import Gatekeeper, RequestDeniedError
from core.client import ScopedHttpClient, AuditResponse
from core.diagnostics import DiagnosticFinding, SecurityDiagnosticEngine
from core.rule_engine import DiagnosticTemplate, RuleCatalog, NucleiDiagnosticRunner
from core.rule_recommender import RuleRecommender
from core.cvss import CVSS31Metrics, CVSSCalculator
from core.remediation_snippets import RemediationSnippet, RemediationSnippetGenerator
from core.remediation import AuditSessionManager, RemediationAuditor
from core.auth_matrix import AuthRole, AuthorizationMatrixAuditor
from core.drift_monitor import AttackSurfaceDriftMonitor, DriftReport
from core.safe_harbor import SafeHarborLedgerAuditor, SafeHarborProof

__all__ = [
    "ScopeValidator",
    "ScopeViolationError",
    "Gatekeeper",
    "RequestDeniedError",
    "ScopedHttpClient",
    "AuditResponse",
    "DiagnosticFinding",
    "SecurityDiagnosticEngine",
    "DiagnosticTemplate",
    "RuleCatalog",
    "NucleiDiagnosticRunner",
    "RuleRecommender",
    "CVSS31Metrics",
    "CVSSCalculator",
    "RemediationSnippet",
    "RemediationSnippetGenerator",
    "AuditSessionManager",
    "RemediationAuditor",
    "AuthRole",
    "AuthorizationMatrixAuditor",
    "AttackSurfaceDriftMonitor",
    "DriftReport",
    "SafeHarborLedgerAuditor",
    "SafeHarborProof",
]
