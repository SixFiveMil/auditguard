# AuditGuard Technical Architecture & Design Specification

AuditGuard is an enterprise-grade security research automation framework designed to mathematically prevent unauthorized out-of-scope traffic while delivering production-quality triage artifacts, CVSS v3.1 scoring, and developer remediation code.

---

## 1. High-Level Architecture

```
                                  ┌────────────────────────────────┐
                                  │      StateHunter / Recon       │
                                  └───────────────┬────────────────┘
                                                  │ Discovered Routes & Scope
                                                  ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                    AUDITGUARD CORE                                     │
│                                                                                        │
│  ┌───────────────────────┐   ┌──────────────────────┐   ┌───────────────────────────┐  │
│  │    ScopeValidator     │──▶│      Gatekeeper      │──▶│     ScopedHttpClient      │  │
│  │ (Regex / CIDR / SSRF) │   │(Token-Bucket Rate Lmt)│  │ (Header Injection & HTTP) │  │
│  └───────────────────────┘   └──────────────────────┘   └─────────────┬─────────────┘  │
│                                                                       │                │
│                                                                       ▼                │
│                                                         ┌───────────────────────────┐  │
│                                                         │    AuditLogger (JSONL)    │  │
│                                                         │   (SHA-256 Tamper Proof)  │  │
│                                                         └───────────────────────────┘  │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │ Audited Findings
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                ADVANCED CAPABILITY ENGINES                             │
│                                                                                        │
│  ┌─────────────────────────┐  ┌──────────────────────────┐  ┌───────────────────────┐  │
│  │  CVSS v3.1 Calculator   │  │ Remediation Code Gen     │  │  Platform Exporter    │  │
│  │(FIRST.org Mathematical) │  │ (Express / Nginx / Ng)   │  │(H1 / Bugcrowd / Jira) │  │
│  └─────────────────────────┘  └──────────────────────────┘  └───────────────────────┘  │
│                                                                                        │
│  ┌─────────────────────────┐  ┌──────────────────────────┐  ┌───────────────────────┐  │
│  │   Auth Matrix Prober    │  │   Surface Drift Monitor  │  │ Safe Harbor Auditor   │  │
│  │ (BOLA / IDOR / CWE-639) │  │ (Route / Status / Hdr)   │  │(Disclose.io Standards)│  │
│  └─────────────────────────┘  └──────────────────────────┘  └───────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. The Zero-Fault Guardrail Pipeline

All outbound network requests dispatched by AuditGuard are strictly constrained by a 4-stage pipeline before a single packet is emitted:

### Stage 1: Deterministic Scope Validation ([`core/scope_validator.py`](../core/scope_validator.py))
- **Wildcard Expansion**: Expands `*.example.com` while strictly prohibiting root-domain collisions (`notexample.com`).
- **Path Exclusion Guardrails**: Verifies path boundaries against program rules (e.g. immediate block of `/logout`, `/billing`, `/delete-account`).
- **Prohibited Target Shielding**: Deterministically blocks internal IP ranges (`127.0.0.1`, `10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12`) and cloud metadata endpoints (`169.254.169.254`).

### Stage 2: Safe Harbor Compliance Header Injection ([`core/client.py`](../core/client.py))
- Injects mandatory researcher attribution headers (`X-Bug-Bounty` or program-configured header tag).
- Sets defensive user agent string (`AuditGuard-SecurityResearch (<researcher_handle>)`).

### Stage 3: Human-in-the-Loop Gatekeeper & Rate Limiting ([`core/gatekeeper.py`](../core/gatekeeper.py))
- **Token-Bucket Rate Limiter**: Enforces strict requests-per-second ceilings (default `2.0 req/s`), preventing accidental denial-of-service.
- **Interactive Prompting**: In interactive mode, prompts operator with target URL, method, and test hypothesis.

### Stage 4: Tamper-Evident Audit Logging ([`audit/audit_logger.py`](../audit/audit_logger.py))
- Every interaction produces an append-only JSONL record:
  - Timestamp (UTC ISO 8601)
  - Method, target URL, and request headers
  - Latency in milliseconds
  - HTTP response status and headers
  - Request body hash and response body SHA-256 digest

---

## 3. Deterministic CVSS v3.1 Scoring Engine

Located in [`core/cvss.py`](../core/cvss.py), the engine implements the official FIRST.org specification:

### Mathematical Formulas
1. **Impact Sub-Score (ISS)**:
   \[
   \text{ISS} = 1.0 - \big[(1.0 - C) \times (1.0 - I) \times (1.0 - A)\big]
   \]
2. **Impact (Scope = Unchanged)**:
   \[
   \text{Impact} = 6.42 \times \text{ISS}
   \]
3. **Impact (Scope = Changed)**:
   \[
   \text{Impact} = 7.52 \times (\text{ISS} - 0.029) - 3.25 \times (\text{ISS} - 0.02)^{15}
   \]
4. **Exploitability**:
   \[
   \text{Exploitability} = 8.22 \times \text{AV} \times \text{AC} \times \text{PR} \times \text{UI}
   \]
5. **Roundup Function**:
   Prevents floating-point rounding errors using the official formula:
   ```python
   int_input = round(val * 100000)
   if int_input % 10000 == 0:
       return round(int_input / 100000.0, 1)
   else:
       return round((math.floor(int_input / 10000) + 1) / 10.0, 1)
   ```

---

## 4. Dual-Role Authorization Matrix Prober

Located in [`core/auth_matrix.py`](../core/auth_matrix.py), the prober tests access control models across researcher-controlled identities:

### Probing Matrix
| Target Endpoint Type | Role A (Owner) | Role B (Foreign) | Unauthenticated | Detected Vulnerability |
|:---|:---:|:---:|:---:|:---|
| **Administrative Route** | HTTP 200 | HTTP 200 | HTTP 200 | **Unauthenticated Access (`CWE-306`)** |
| **Administrative Route** | HTTP 403 | HTTP 200 (Low-Priv) | HTTP 401 | **Vertical Privilege Escalation (`CWE-269`)** |
| **User Object Resource** | HTTP 200 | HTTP 200 (Identical Data) | HTTP 401 | **Horizontal BOLA / IDOR (`CWE-639`)** |

### Body Similarity Analysis
To differentiate genuine access control violations from generic error messages, the prober computes sequence similarity:
```python
sim_ratio = difflib.SequenceMatcher(None, owner_body, foreign_body).ratio()
```
If `sim_ratio >= 0.80` on user-scoped resources when queried by a foreign token, BOLA/IDOR is flagged.

---

## 5. Continuous Attack Surface Drift Monitor

Located in [`core/drift_monitor.py`](../core/drift_monitor.py), the monitor tracks changes between audit sessions:

- **Route Expansion**: Set difference $E_{\text{current}} \setminus E_{\text{baseline}}$.
- **Status Drift**: Tracks transitions like `HTTP 403` $\rightarrow$ `HTTP 200`.
- **Security Regressions**: Evaluates critical defense headers (`Content-Security-Policy`, `Cache-Control: no-store`, `Strict-Transport-Security`, `X-Frame-Options`).
