"""
AuditGuard Continuous Attack Surface Drift & Regression Monitor.
Detects route expansion, HTTP status transitions, and security defense header regressions
against baseline audit sessions to enforce continuous security hygiene.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from core.client import AuditResponse, ScopedHttpClient


@dataclass
class RouteDriftItem:
    """Represents a detected drift event on an endpoint."""
    url: str
    drift_type: str  # "NEW_ROUTE", "STATUS_CHANGE", "REMOVED_ROUTE", "HEADER_REGRESSION"
    severity: str    # "HIGH", "MEDIUM", "LOW", "INFO"
    baseline_value: Optional[Any]
    current_value: Optional[Any]
    description: str


@dataclass
class DriftReport:
    """Consolidated attack surface drift and security regression report."""
    baseline_session_id: str
    current_session_id: Optional[str]
    program_key: str
    timestamp: str
    baseline_endpoint_count: int
    current_endpoint_count: int
    drifts: List[RouteDriftItem] = field(default_factory=list)

    @property
    def has_drift(self) -> bool:
        return len(self.drifts) > 0

    @property
    def high_severity_count(self) -> int:
        return sum(1 for d in self.drifts if d.severity in ("CRITICAL", "HIGH"))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "baseline_session_id": self.baseline_session_id,
            "current_session_id": self.current_session_id,
            "program_key": self.program_key,
            "timestamp": self.timestamp,
            "baseline_endpoint_count": self.baseline_endpoint_count,
            "current_endpoint_count": self.current_endpoint_count,
            "total_drifts": len(self.drifts),
            "high_severity_drifts": self.high_severity_count,
            "drifts": [asdict(d) for d in self.drifts],
        }

    def to_markdown(self) -> str:
        md = [
            "# Attack Surface Drift & Regression Report",
            "",
            f"- **Target Program**: `{self.program_key}`",
            f"- **Timestamp**: `{self.timestamp}`",
            f"- **Baseline Session**: `{self.baseline_session_id}`",
            f"- **Baseline Route Count**: `{self.baseline_endpoint_count}`",
            f"- **Current Route Count**: `{self.current_endpoint_count}`",
            f"- **Total Drifts Detected**: **{len(self.drifts)}**",
            f"- **High-Risk Regressions**: **{self.high_severity_count}**",
            "",
        ]

        if not self.drifts:
            md.append("✅ **No attack surface drift or security regressions detected.** The environment matches the baseline.")
            return "\n".join(md)

        md.extend([
            "## Detected Drift Items",
            "",
            "| Severity | Type | Endpoint | Baseline | Current | Description |",
            "|:---:|:---:|:---|:---|:---|:---|",
        ])

        for d in self.drifts:
            b_val = str(d.baseline_value) if d.baseline_value is not None else "-"
            c_val = str(d.current_value) if d.current_value is not None else "-"
            md.append(f"| **{d.severity}** | `{d.drift_type}` | `{d.url}` | `{b_val}` | `{c_val}` | {d.description} |")

        md.extend([
            "",
            "## Recommended Operational Actions",
            "1. **Investigate New Routes**: Ensure all newly active endpoints are within authorized scope and protected by authentication.",
            "2. **Verify Status Transitions**: If administrative endpoints transitioned from `403/401` to `200`, verify route guard integrity.",
            "3. **Remediate Header Regressions**: Restore any dropped defense headers (CSP, HSTS, Cache-Control) immediately.",
        ])

        return "\n".join(md)


class AttackSurfaceDriftMonitor:
    """
    Compares target attack surface and security posture against baseline audit sessions.
    Identifies route additions, status changes, and defensive regressions.
    """

    CRITICAL_SECURITY_HEADERS = [
        "content-security-policy",
        "strict-transport-security",
        "cache-control",
        "x-content-type-options",
        "x-frame-options",
    ]

    def __init__(
        self,
        session_store_dir: str = "audit/sessions",
        client: Optional[ScopedHttpClient] = None,
    ):
        self.session_store_dir = session_store_dir
        self.client = client

    def load_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Loads a session JSON file by session_id or path."""
        if os.path.isfile(session_id):
            target_path = session_id
        else:
            filename = f"session_{session_id}.json" if not session_id.endswith(".json") else session_id
            target_path = os.path.join(self.session_store_dir, filename)

        if not os.path.exists(target_path):
            return None

        with open(target_path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def find_latest_session(self, program_key: str) -> Optional[Dict[str, Any]]:
        """Finds the most recent session for a given program key."""
        if not os.path.exists(self.session_store_dir):
            return None

        candidates = []
        for fname in os.listdir(self.session_store_dir):
            if fname.startswith("session_") and fname.endswith(".json"):
                fpath = os.path.join(self.session_store_dir, fname)
                try:
                    with open(fpath, "r", encoding="utf-8") as fh:
                        data = json.load(fh)
                    if data.get("program_key") == program_key:
                        mtime = os.path.getmtime(fpath)
                        candidates.append((mtime, data))
                except Exception:
                    continue

        if not candidates:
            return None

        candidates.sort(key=lambda x: x[0], reverse=True)
        return candidates[0][1]

    def compare_sessions(
        self,
        baseline_session: Dict[str, Any],
        current_session: Dict[str, Any],
    ) -> DriftReport:
        """Compares two recorded audit sessions offline."""
        base_id = baseline_session.get("session_id", "baseline")
        curr_id = current_session.get("session_id", "current")
        prog_key = baseline_session.get("program_key", "unknown")

        base_endpoints: Set[str] = set(baseline_session.get("endpoints", []))
        curr_endpoints: Set[str] = set(current_session.get("endpoints", []))

        drifts: List[RouteDriftItem] = []

        # 1. New routes discovered
        new_routes = sorted(curr_endpoints - base_endpoints)
        for r in new_routes:
            drifts.append(
                RouteDriftItem(
                    url=r,
                    drift_type="NEW_ROUTE",
                    severity="MEDIUM",
                    baseline_value=None,
                    current_value="Active",
                    description=f"New endpoint exposed since baseline session {base_id}.",
                )
            )

        # 2. Removed or unreached routes
        removed_routes = sorted(base_endpoints - curr_endpoints)
        for r in removed_routes:
            drifts.append(
                RouteDriftItem(
                    url=r,
                    drift_type="REMOVED_ROUTE",
                    severity="INFO",
                    baseline_value="Active",
                    current_value=None,
                    description=f"Endpoint was active in baseline {base_id} but not detected in current run.",
                )
            )

        # 3. New Vulnerability / Regression in findings
        base_finding_keys = {
            f"{f.get('title')}:{f.get('cwe_id')}" for f in baseline_session.get("findings", [])
        }
        for curr_f in current_session.get("findings", []):
            f_key = f"{curr_f.get('title')}:{curr_f.get('cwe_id')}"
            if f_key not in base_finding_keys:
                drifts.append(
                    RouteDriftItem(
                        url=", ".join(curr_f.get("affected_urls", ["Target"])),
                        drift_type="SECURITY_REGRESSION",
                        severity=curr_f.get("severity", "MEDIUM"),
                        baseline_value="Clean / Not Found",
                        current_value=curr_f.get("title"),
                        description=f"New vulnerability introduced: {curr_f.get('title')} ({curr_f.get('cwe_id')}).",
                    )
                )

        now_str = datetime.now(timezone.utc).isoformat()
        return DriftReport(
            baseline_session_id=base_id,
            current_session_id=curr_id,
            program_key=prog_key,
            timestamp=now_str,
            baseline_endpoint_count=len(base_endpoints),
            current_endpoint_count=len(curr_endpoints),
            drifts=drifts,
        )

    def monitor_live(
        self,
        baseline_session: Dict[str, Any],
        current_endpoints: List[str],
    ) -> DriftReport:
        """
        Actively probes endpoints and compares against the baseline session.
        Checks for new routes, status changes, and header hygiene regressions.
        """
        if not self.client:
            raise ValueError("ScopedHttpClient must be provided for live drift monitoring.")

        base_id = baseline_session.get("session_id", "baseline")
        prog_key = baseline_session.get("program_key", "unknown")
        base_endpoints: Set[str] = set(baseline_session.get("endpoints", []))
        all_to_probe = sorted(set(current_endpoints) | base_endpoints)

        drifts: List[RouteDriftItem] = []

        for ep in all_to_probe:
            try:
                resp = self.client.get(ep, rationale=f"Attack surface drift check for {ep}")
                status = resp.status_code
                headers = {k.lower(): v for k, v in resp.headers.items()}
            except Exception as e:
                # Connection or network failure
                if ep in base_endpoints:
                    drifts.append(
                        RouteDriftItem(
                            url=ep,
                            drift_type="STATUS_CHANGE",
                            severity="LOW",
                            baseline_value="200 OK",
                            current_value="Unreachable",
                            description=f"Endpoint failed to respond during drift probe: {e}",
                        )
                    )
                continue

            # Check 1: New Route
            if ep not in base_endpoints:
                drifts.append(
                    RouteDriftItem(
                        url=ep,
                        drift_type="NEW_ROUTE",
                        severity="MEDIUM" if status in (200, 206) else "INFO",
                        baseline_value=None,
                        current_value=f"HTTP {status}",
                        description="New endpoint detected outside baseline session.",
                    )
                )

            # Check 2: Header Regressions
            # E.g. Missing CSP
            if "content-security-policy" not in headers and "html" in headers.get("content-type", ""):
                drifts.append(
                    RouteDriftItem(
                        url=ep,
                        drift_type="HEADER_REGRESSION",
                        severity="LOW",
                        baseline_value="Enforced",
                        current_value="Missing CSP",
                        description="Content-Security-Policy header is absent on HTML response.",
                    )
                )

            # Check 3: Cache-Control on admin/sensitive routes
            if any(s in ep.lower() for s in ("admin", "account", "user", "basket", "feedbacks")):
                cc = headers.get("cache-control", "")
                if "no-store" not in cc:
                    drifts.append(
                        RouteDriftItem(
                            url=ep,
                            drift_type="HEADER_REGRESSION",
                            severity="MEDIUM",
                            baseline_value="no-store",
                            current_value=cc or "Missing",
                            description="Sensitive endpoint does not enforce 'Cache-Control: no-store'.",
                        )
                    )

        now_str = datetime.now(timezone.utc).isoformat()
        return DriftReport(
            baseline_session_id=base_id,
            current_session_id=None,
            program_key=prog_key,
            timestamp=now_str,
            baseline_endpoint_count=len(base_endpoints),
            current_endpoint_count=len(current_endpoints),
            drifts=drifts,
        )

    @staticmethod
    def save_report(
        report: DriftReport,
        output_dir: str = "reports",
        base_name: str = "drift_report",
    ) -> Tuple[str, str]:
        """Saves drift report in Markdown and JSON formats."""
        os.makedirs(output_dir, exist_ok=True)

        md_path = os.path.join(output_dir, f"{base_name}.md")
        with open(md_path, "w", encoding="utf-8") as fh:
            fh.write(report.to_markdown())

        json_path = os.path.join(output_dir, f"{base_name}.json")
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(report.to_dict(), fh, indent=2)

        return md_path, json_path
