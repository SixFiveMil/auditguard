# AuditGuard CLI Command Reference

Comprehensive manual for the AuditGuard command-line interface (`auditguard` / `python main.py`).

---

## Command Index

| Command | Category | Description |
|:---|:---:|:---|
| [`scope`](#1-scope) | Scope & Policy | Display active program scope boundaries, rules, and rate limits |
| [`check`](#2-check) | Scope & Policy | Test a target URL against scope rules without sending traffic |
| [`search-programs`](#3-search-programs) | Program Discovery | Search the 800+ public bug bounty program registry |
| [`harvest-scope`](#4-harvest-scope) | Scope Harvesting | Passively harvest scope from security.txt and CT logs |
| [`import-scope`](#5-import-scope) | Scope Ingestion | Ingest a StateHunter YAML scope export into configuration |
| [`endpoints`](#6-endpoints) | Route Inventory | Inspect discovered routes against active scope rules |
| [`probe`](#7-probe) | Active Auditing | Execute an authorized, rate-limited HTTP probe |
| [`diagnose`](#8-diagnose) | Active Auditing | Run deep security diagnostics on a single endpoint |
| [`audit-endpoints`](#9-audit-endpoints) | Active Auditing | Run batch security diagnostics across all discovered routes |
| [`audit-auth`](#10-audit-auth) | Active Auditing | Execute dual-role authorization matrix & IDOR / BOLA prober |
| [`rules`](#11-rules) | Rules Engine | Query and inspect declarative Nuclei-compatible YAML rules |
| [`recommend-rules`](#12-recommend-rules) | Rules Engine | Auto-match 3rd-party rules based on detected technology |
| [`retest`](#13-retest) | Remediation | Run targeted differential re-tests on prior defects |
| [`monitor`](#14-monitor) | Continuous Monitoring | Monitor attack surface drift and security regressions |
| [`export-sow`](#15-export-sow) | Deliverables | Export Statement of Work (SOW) deliverable (PDF, HTML, MD) |
| [`export-report`](#16-export-report) | Deliverables | Generate a reproducible bug bounty report from an interaction |
| [`export-triage`](#17-export-triage) | Deliverables | Export 1-click reports for HackerOne, Bugcrowd, GitHub, Jira |
| [`safe-harbor`](#18-safe-harbor) | Compliance | Inspect and verify Safe Harbor Proof-of-Adherence Certificate |
| [`logs`](#19-logs) | Compliance | Inspect recent entries in the immutable audit ledger |

---

## 1. `scope`
Displays active program scope, authorized in-scope targets, excluded paths, and rules of engagement.

```powershell
auditguard scope
```

---

## 2. `check`
Tests whether a target URL is permitted under active scope rules without dispatching network traffic.

```powershell
auditguard check <url>
```
- **Example**: `auditguard check http://localhost:3000/administration`

---

## 3. `search-programs`
Searches the public directory of 800+ bug bounty programs (HackerOne, Bugcrowd, etc.).

```powershell
auditguard search-programs <query>
```
- **Example**: `auditguard search-programs gitlab`

---

## 4. `harvest-scope`
Passively discovers scope targets via `security.txt` and Certificate Transparency logs.

```powershell
auditguard harvest-scope <domain> [-n NAME]
```

---

## 5. `import-scope`
Ingests a StateHunter YAML scope export into `config/programs.yaml`.

```powershell
auditguard import-scope <file> [-a]
```
- `-a, --activate`: Set the newly imported program as active.

---

## 6. `endpoints`
Audits endpoints discovered during reconnaissance against active scope rules.

```powershell
auditguard endpoints [--flagged-only]
```
- `--flagged-only`: Display only sensitive/administrative endpoints.

---

## 7. `probe`
Performs a scoped, logged HTTP request with operator approval.

```powershell
auditguard probe <url> [-X METHOD] [-r RATIONALE] [-y]
```
- `-X, --method`: HTTP verb (`GET`, `HEAD`, `OPTIONS`, etc. Default: `GET`).
- `-r, --rationale`: Stated testing hypothesis.
- `-y, --yes`: Pre-approve request without interactive confirmation.

---

## 8. `diagnose`
Runs comprehensive security diagnostics (CORS, security headers, verb tampering, cache hygiene) on a single endpoint.

```powershell
auditguard diagnose <url> [-o OUTPUT]
```

---

## 9. `audit-endpoints`
Executes batch security diagnostics across all discovered routes from StateHunter.

```powershell
auditguard audit-endpoints [--flagged-only] [-o OUTPUT] [--pdf PDF] [-y]
```
- `--flagged-only`: Run diagnostics only on flagged sensitive routes.
- `-o, --output`: Export assessment report (`.html` or `.md`).
- `--pdf`: Export publication-ready vector PDF report.
- `-y, --yes`: Pre-approve execution without interactive prompts.

---

## 10. `audit-auth`
Executes comparative multi-identity authorization matrix probing across researcher-controlled accounts to safely detect BOLA/IDOR (`CWE-639`) and vertical privilege escalation (`CWE-269`).

```powershell
auditguard audit-auth [-u URL] [-s SESSION] [--role-a-name NAME] [--role-a-header HDR] [--role-b-name NAME] [--role-b-header HDR] [--admin-header HDR] [-o OUTPUT] [-y]
```
- `-u, --url`: Single target endpoint.
- `-s, --session`: Path/ID of audit session to probe all recorded endpoints.
- `--role-a-name`: Owner role label (default: `user_a`).
- `--role-a-header`: Header for Role A (e.g. `'Authorization: Bearer token_a'`).
- `--role-b-name`: Foreign role label (default: `user_b`).
- `--role-b-header`: Header for Role B (e.g. `'Authorization: Bearer token_b'`).
- `--admin-header`: Header for Administrator role.
- `-o, --output`: Save findings to `.json` or `.md`.
- `-y, --yes`: Pre-approve probes without interactive confirmation.

---

## 11. `rules`
Queries and inspects declarative Nuclei-compatible YAML diagnostic rules.

```powershell
auditguard rules [--rules-dir DIR] [--tag TAG] [--severity SEV] [--inspect RULE_ID]
```

---

## 12. `recommend-rules` (alias: `suggest-rules`)
Analyzes the target's discovered technology markers and recommends matching diagnostic rules from an external repository.

```powershell
auditguard recommend-rules --repo <path> [--import] [--import-dir DIR] [--all-verbs]
```
- `--repo`: Path to 3rd-party template repository (e.g. `D:/repos/nuclei-templates/http`).
- `--import`: Automatically copy recommended safe rules into `rules/diagnostics/`.
- `--import-dir`: Target folder for imported templates.
- `--all-verbs`: Allow state-changing HTTP verbs (`POST`, `PUT`).

---

## 13. `retest`
Executes targeted differential re-tests on previously flagged endpoints from a baseline session to verify whether vulnerabilities have been remediated.

```powershell
auditguard retest [-s SESSION] [-o OUTPUT] [--pdf PDF] [-y]
```
- `-s, --session`: Path to audit session JSON (default: `audit/latest_findings.json`).
- `-o, --output`: Save differential remediation report (`.html` or `.md`).
- `--pdf`: Export publication-ready differential PDF report.

---

## 14. `monitor`
Monitors attack surface drift, status transitions, and security header regressions.

```powershell
auditguard monitor [-b BASELINE] [-c COMPARE] [-l] [-o OUTPUT_DIR] [-y]
```
- `-b, --baseline-session`: Baseline session ID or path.
- `-c, --compare-session`: Second session for offline comparison.
- `-l, --live`: Actively probe target to detect live attack surface drift.
- `-o, --output-dir`: Output folder for drift reports (default: `reports`).

---

## 15. `export-sow`
Exports a formal Statement of Work (SOW) deliverable documenting authorized scope boundaries.

```powershell
auditguard export-sow [-o OUTPUT] [--assessor ASSESSOR] [--title TITLE]
```

---

## 16. `export-report`
Generates a reproducible bug bounty report markdown file from an interaction in the audit ledger.

```powershell
auditguard export-report -i <request-id> -t <title> [-s SEVERITY] [-c CWE] [-o OUTPUT]
```

---

## 17. `export-triage`
Exports audit findings into 1-click platform submission reports.

```powershell
auditguard export-triage [-s SESSION] [-f FORMAT] [-o OUTPUT_DIR] [-p PROGRAM] [--scope SCOPE] [--jira-project KEY]
```
- `-s, --session`: Session ID or file path.
- `-f, --format`: `all`, `hackerone`, `bugcrowd`, `github`, `jira` (default: `all`).
- `-o, --output-dir`: Output directory (default: `reports/triage`).
- `--jira-project`: Jira project key (default: `SEC`).

---

## 18. `safe-harbor`
Inspects and prints a cryptographically verified Safe Harbor Proof-of-Adherence Certificate.

```powershell
auditguard safe-harbor [--log PATH]
```

---

## 19. `logs`
Displays recent audit ledger entries.

```powershell
auditguard logs [-n LIMIT]
```
- `-n, --limit`: Number of entries to display (default: 10).
