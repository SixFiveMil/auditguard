# Incorporating 3rd-Party & Community YAML Rules in AuditGuard

AuditGuard features a native, declarative vulnerability diagnostic engine that is compatible with open-source **ProjectDiscovery Nuclei YAML templates** without requiring external binaries (`nuclei`, Go toolchains, etc.).

This guide explains how to acquire community rule repositories, automatically discover and match tests based on reconnaissance, enforce Safe Harbor guardrails, and safely import rules into AuditGuard.

---

## Table of Contents
- [1. Understanding the Declarative Rule Engine](#1-understanding-the-declarative-rule-engine)
- [2. Cloning 3rd-Party Rule Repositories](#2-cloning-3rd-party-rule-repositories)
- [3. Automated Discovery-Driven Rule Recommendations](#3-automated-discovery-driven-rule-recommendations)
- [4. Inspecting & Querying Rules Locally](#4-inspecting--querying-rules-locally)
- [5. Safe Harbor Compliance & Non-Destructive Filtering](#5-safe-harbor-compliance--non-destructive-filtering)
- [6. Antivirus & False-Positive Handling on Windows](#6-antivirus--false-positive-handling-on-windows)
- [7. Importing Templates into AuditGuard](#7-importing-templates-into-auditguard)
- [8. Authoring Custom YAML Diagnostic Rules](#8-authoring-custom-yaml-diagnostic-rules)

---

## 1. Understanding the Declarative Rule Engine

AuditGuard parses declarative YAML templates (`rules/diagnostics/*.yaml`) and executes them through its strictly controlled, rate-limited, and audited network layer ([`ScopedHttpClient`](../core/client.py)):

```
┌────────────────────────────────────────────────────────┐
│  3rd-Party YAML Templates (e.g. Nuclei, Custom Repo)  │
└──────────────────────────┬─────────────────────────────┘
                           │ Ingest / Query
                           ▼
┌────────────────────────────────────────────────────────┐
│   RuleRecommender (Filter by Tech Markers & Safe Verbs)│
└──────────────────────────┬─────────────────────────────┘
                           │ Import to rules/diagnostics/
                           ▼
┌────────────────────────────────────────────────────────┐
│  SecurityDiagnosticEngine -> ScopedHttpClient          │
│   * Enforces in-scope URL boundaries                   │
│   * Enforces Gatekeeper rate limits (e.g. 2 req/s)     │
│   * Injects Safe Harbor headers (X-Bug-Bounty)         │
│   * Logs raw requests/responses to audit_log.jsonl     │
└────────────────────────────────────────────────────────┘
```

---

## 2. Cloning 3rd-Party Rule Repositories

You can clone public community rules (such as the official Nuclei community templates) or your team's internal private repository into any local directory:

```powershell
# Create a local directory for external templates
mkdir D:\repos\nuclei-templates
git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git D:\repos\nuclei-templates
```

> [!NOTE]
> AuditGuard only requires the HTTP templates directory (e.g. `D:/repos/nuclei-templates/http`). It does not execute or evaluate non-HTTP templates (DNS, TCP, SSL, Code).

---

## 3. Automated Discovery-Driven Rule Recommendations

Rather than manually guessing which rules apply, AuditGuard analyzes the target's discovered technology markers (e.g., Angular, Express, Node.js, Spring Boot, Nginx, CORS) and queries the external repository for tailored tests:

```powershell
# Analyze active program and find matching rules in the external repo
auditguard recommend-rules --repo "D:/repos/nuclei-templates/http"
```

### Example Command Output
```
===========================================================================
 DIAGNOSTIC RULE RECOMMENDER: OWASP Juice Shop [localhost]
 External Repository: D:/repos/nuclei-templates/http
 Discovered Technologies: angular, express, nodejs, cors
===========================================================================

[+] Discovered 6 Recommended Safe Diagnostic Templates:

  * angular-detect.yaml
    - Name:     Angular Client-Side Application Detection
    - Severity: INFO
    - CWE:      CWE-200
    - Tags:     tech, angular, discovery
    - File:     D:/repos/nuclei-templates/http/technologies/angular-detect.yaml

  * express-session-secret.yaml
    - Name:     Express.js Default Session Secret Exposure
    - Severity: HIGH
    - CWE:      CWE-798
    - Tags:     cve, express, nodejs, auth
    - File:     D:/repos/nuclei-templates/http/cves/2022/express-session-secret.yaml
```

---

## 4. Inspecting & Querying Rules Locally

You can query, filter, and inspect rules from any local repository directly using the `rules` command:

```powershell
# List all rules in an external repository matching 'cors'
auditguard rules --rules-dir "D:/repos/nuclei-templates/http" --tag cors

# Filter by severity
auditguard rules --rules-dir "D:/repos/nuclei-templates/http" --severity high

# Inspect a specific rule definition
auditguard rules --rules-dir "D:/repos/nuclei-templates/http" --inspect angular-detect
```

---

## 5. Safe Harbor Compliance & Non-Destructive Filtering

Under Bug Bounty Safe Harbor and Vulnerability Disclosure Policies (VDP), security testing must be strictly **non-destructive** (read-only queries without state alterations or denial-of-service).

When evaluating 3rd-party rules, AuditGuard enforces:

1. **Idempotent HTTP Verbs Only**: By default, AuditGuard only imports and executes rules using safe HTTP verbs (`GET`, `HEAD`, `OPTIONS`).
2. **Payload Fuzzing Exclusion**: Rules that attempt SQL injection payloads, memory corruption fuzzing, or credential brute-forcing are filtered out.
3. **Overriding Safe Verbs**: If you have explicit authorization to execute state-changing diagnostic probes (e.g. testing `PUT`/`POST` handling on administrative routes), pass the `--all-verbs` flag:
   ```powershell
   auditguard recommend-rules --repo "D:/repos/nuclei-templates/http" --all-verbs
   ```

---

## 6. Antivirus & False-Positive Handling on Windows

Some 3rd-party CVE templates contain known exploit strings, malicious shellcode PoCs, or webshell signatures in their matcher definitions. On Windows, **Windows Defender** or endpoint EDR software may trigger a signature alert when reading these files:

```
Select-String : The file .../CVE-2017-12615.yaml cannot be read:
Operation did not complete successfully because the file contains a virus or potentially unwanted software.
```

### Best Practices & Fixes
1. **Exclude the Templates Directory in Windows Defender**:
   If you are an authorized security researcher using community templates, add an exclusion for your templates directory:
   ```powershell
   # Run in an elevated PowerShell window:
   Add-MpPreference -ExclusionPath "D:\repos\nuclei-templates"
   ```
2. **AuditGuard's Fault-Tolerant Parser**:
   AuditGuard's `RuleCatalog` gracefully skips unreadable, locked, or antivirus-quarantined files without aborting execution. The scan proceeds across all available clean rules.

---

## 7. Importing Templates into AuditGuard

Once you identify the diagnostic templates suited for your engagement, import them directly into AuditGuard's active diagnostic directory (`rules/diagnostics/`):

```powershell
# 1-Click import of recommended safe templates:
auditguard recommend-rules --repo "D:/repos/nuclei-templates/http" --import

# Custom destination directory:
auditguard recommend-rules --repo "D:/repos/nuclei-templates/http" --import --import-dir "rules/custom"
```

### Running Ingested Rules
Imported templates are automatically discovered during endpoint audits:
```powershell
# Run batch diagnostics incorporating imported rules:
auditguard audit-endpoints --flagged-only --yes
```

---

## 8. Authoring Custom YAML Diagnostic Rules

You can easily author custom diagnostic templates tailored to your target application. Place your `.yaml` file in `rules/diagnostics/`:

### Example: Custom Angular State Exposure Probe (`rules/diagnostics/custom-angular-route.yaml`)
```yaml
id: custom-angular-route-leak
info:
  name: Angular Exposed Administrative Client Routes
  author: Authorized Security Researcher
  severity: low
  description: Detected client-side routing definitions exposing unauthenticated admin views.
  classification:
    cwe-id: CWE-200
  tags:
    - angular
    - routing
    - discovery
  remediation: Implement server-side authorization checks and lazy-load sensitive route modules behind authentication guards.

requests:
  - method: GET
    path:
      - "{{BaseURL}}/main.js"
      - "{{BaseURL}}/runtime.js"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "path:\"administration\""
          - "path:\"accounting\""
        condition: or
```

### Supported Matcher Types
- **`status`**: Match one or more HTTP response status codes (e.g. `[200, 204]`).
- **`word`**: Match literal string keywords in `body` or `header`.
- **`regex`**: Evaluate regular expression patterns against body or headers.
- **`condition`**: Set `and` or `or` for multiple word/regex checks.
- **`negative: true`**: Invert condition (e.g. alert if security header is *absent*).
