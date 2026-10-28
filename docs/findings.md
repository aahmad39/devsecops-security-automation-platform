# Security Assessment Findings — VulnTracker

This document records the security findings identified during Static Application Security Testing (SAST), Software Composition Analysis (SCA), Container Security Scanning, Infrastructure-as-Code (IaC) Scanning, and contextual manual code review.

Each finding is contextualized for **VulnTracker**, a sensitive security vulnerability tracking platform where confidentiality, integrity, and tenant isolation are critical.

---

## 1. Summary of Assessment Findings

| Finding ID | Title | Detection Source / Category | Severity (Contextual) | Affected Component | Scope / Origin | Exploitability & Prerequisites | Remediation Status | Plan / Reference |
|---|---|---|---|---|---|---|---|---|
| **VT-SEC-01** | JWT 'none' Algorithm Signature Bypass | Manual Review / SAST | **CRITICAL** | `app/auth.py` (`decode_token`) | Starter Code | High; Attacker sends JWT with `"alg": "none"` and empty signature to impersonate any user. | **REMEDIATED** | Fixed in `auth.py`; regression test added |
| **VT-SEC-02** | SQL Injection in Vulnerability Search Endpoint | Bandit (B608) / Manual Review | **HIGH** | `app/database.py` (`search_scans_by_query`) | Starter Code | High; Query parameter `q` formatted directly into raw SQL string; allows data exfiltration. | **REMEDIATED** | Fixed via SQLAlchemy parameterized query (`text(:pattern)`) |
| **VT-SEC-03** | Broken Object Level Authorization (IDOR) on Scans | Manual Review | **HIGH** | `app/main.py` (`get_scan`, `search_scans`) | Starter Code | Medium; Direct scan retrieval and search lacked owner scoping, exposing all tenants' private scans. | **REMEDIATED** | Fixed in `main.py` & `database.py`; owner filtering enforced |
| **VT-SEC-04** | Weak Password Protection in Report Sharing Feature | Feature Security Review | **HIGH** | `app/main.py` (`create_share_link`) | New Feature | Medium; Sharing allowed trivial 1-character passwords vulnerable to automated guessing. | **REMEDIATED** | Fixed in `main.py`; minimum 8-char password enforced |
| **VT-SEC-05** | Overly Permissive Wildcard CORS with Credentials | Manual Review | **MEDIUM** | `app/main.py` (`cors_middleware`) | Starter Code | Medium; Dynamic origin reflection (`Origin: *` with credentials) allowed cross-site data theft. | **REMEDIATED** | Fixed in `main.py`; explicit allowed origin whitelist |
| **VT-SEC-06** | Plaintext Password and Credential Logging | Manual Review | **MEDIUM** | `app/main.py` (`login`) | Starter Code | Low-Medium; Login handler logged plaintext passwords into application logs. | **REMEDIATED** | Fixed in `main.py`; passwords stripped from logs |
| **VT-SEC-07** | Detailed Stack Trace Leaks on Unhandled Errors | Manual Review | **LOW** | `app/main.py` (`global_exception_handler`) | Starter Code | Low; Uncaught exceptions returned full Python tracebacks and internal file paths. | **REMEDIATED** | Fixed in `main.py`; generic sanitized 500 error returned |
| **VT-SEC-08** | Unauthenticated SSRF via Internal Notification Webhook | Manual Review | **HIGH** | `notify/src/index.js`, `dispatcher.js` | Starter Code | High; `/notify` and `/webhooks` lack authentication and egress IP filtering (private IP probing). | **UNRESOLVED (Deferred)** | Documented in `remediation-plan.md` (VT-PLAN-01) |
| **VT-SEC-09** | Outdated Third-Party Dependencies with Known CVEs | pip-audit / Trivy (SCA) | **HIGH** | `requirements.txt` (FastAPI, Cryptography, etc.) | Starter Code | Low-Medium; Multiple dependencies contain published CVEs (e.g. cryptography, starlette). | **UNRESOLVED (Deferred)** | Documented in `remediation-plan.md` (VT-PLAN-02) |
| **VT-SEC-10** | Hardcoded Development Credentials in Configuration Files | Bandit (B105) / Manual Review | **MEDIUM** | `app/config.py`, `notify/src/config.js` | Starter Code | Low in container/cloud; defaults are overridden by Azure Key Vault CSI Secrets. | **UNRESOLVED (Compensated)** | Documented in `remediation-plan.md` (VT-PLAN-03) |
| **VT-SEC-11** | Container Image Vulnerabilities in Debian Base | Trivy (Container) | **MEDIUM** | `python:3.11-slim-bookworm` | Deployment Base | Low; Low-severity OS packages in upstream base image without public weaponized exploit. | **UNRESOLVED (Deferred)** | Tracked upstream in distro patching cycle |

---

## 2. Detailed Findings and Contextual Analysis

### VT-SEC-01: JWT 'none' Algorithm Signature Bypass
- **Detection**: Manual Code Review (verified against `app/auth.py`).
- **Severity**: **CRITICAL** (CVSS 9.8).
- **Component**: `app/auth.py`, function `decode_token`.
- **Description**: The starter codebase called `jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM, "none"])`. By accepting algorithm `"none"`, python-jose permitted attackers to forge arbitrary tokens (e.g., claiming `sub: "admin"`) without possessing the HMAC secret key.
- **Business Impact**: Complete authentication bypass across the entire VulnTracker application. An external adversary could access, modify, or delete any organization's vulnerability records.
- **Remediation**: Removed `"none"` algorithm acceptance and strictly bound verification to `algorithms=[ALGORITHM]`. Added automated regression test `test_jwt_none_algorithm_rejected`.

### VT-SEC-02: SQL Injection in Vulnerability Search Endpoint
- **Detection**: Bandit (Test ID B608) and Manual Review.
- **Severity**: **HIGH** (CVSS 8.5).
- **Component**: `app/database.py`, function `search_scans_by_query`.
- **Description**: The query string `q` was interpolated directly into raw SQL string formatting: `f"... WHERE title LIKE '%{query}%' ..."`.
- **Business Impact**: An authenticated attacker could inject SQL syntax to bypass query constraints, dump foreign database tables, or extract confidential scan notes and password hashes.
- **Remediation**: Converted the raw SQL execution to SQLAlchemy parameterized bind variables using `text(...)` and `:pattern` parameter mapping. Added automated test `test_search_scans_sql_injection_defense`.

### VT-SEC-03: Broken Object Level Authorization (IDOR)
- **Detection**: Manual Review.
- **Severity**: **HIGH** (CVSS 8.1).
- **Component**: `app/main.py` (`get_scan`) and `database.py` (`search_scans_by_query`).
- **Description**: `GET /scans/{scan_id}` fetched the scan result matching `scan_id` without validating whether `current_user.id == scan.owner_id`. Similarly, search queried all records across all owners.
- **Business Impact**: Any registered user could view other organizations' sensitive vulnerability findings simply by enumerating sequential scan IDs.
- **Remediation**: Added explicit tenancy filters checking `models.ScanResult.owner_id == current_user.id` on single-record retrieval and search. Added regression tests `test_idor_get_scan_prevented` and `test_idor_search_scans_prevented`.

### VT-SEC-04: Weak Password Protection in Report Sharing Feature
- **Detection**: Feature Security Review (Task 1 Implementation).
- **Severity**: **HIGH** (CVSS 7.4).
- **Component**: `app/main.py` (`create_share_link`).
- **Description**: The shared report link feature permitted users to specify arbitrary short passwords (e.g., 1 to 4 characters) to protect shared reports.
- **Business Impact**: Publicly shared audit links could be brute-forced easily if users chose trivial passwords like "123".
- **Remediation**: Enforced a minimum password length of 8 characters for share links, salted bcrypt hashing, and safe error messages. Added automated test `test_share_link_weak_password_rejected`.

### VT-SEC-05: Permissive CORS Configuration with Credential Reflection
- **Detection**: Manual Review.
- **Severity**: **MEDIUM** (CVSS 6.5).
- **Component**: `app/main.py` (`cors_middleware`).
- **Description**: The custom CORS middleware echoed back any caller-supplied `Origin` header and set `Access-Control-Allow-Credentials: true`.
- **Business Impact**: Malicious websites visited by an authenticated VulnTracker user could make cross-origin authenticated requests and exfiltrate vulnerability data.
- **Remediation**: Restricted CORS headers to a strict whitelist of approved origins (`ALLOWED_ORIGINS`). Added regression test `test_cors_origin_restriction`.

### VT-SEC-06: Plaintext Password Logging
- **Detection**: Manual Review.
- **Severity**: **MEDIUM** (CVSS 5.3).
- **Component**: `app/main.py` (`login`).
- **Description**: Both successful and failed login attempts logged the raw user-supplied password in server log streams.
- **Business Impact**: Sensitive user passwords leaked into log files, application monitoring dashboards, and SIEM storage.
- **Remediation**: Sanitized log statements to record only usernames and authentication outcomes.

---

## 3. Tool Scan Reproducibility and Locations

All raw scan outputs are stored in `reports/`:
- **SAST**: `reports/sast.bandit.json` (`bandit -r app/ -f json`)
- **SCA**: `reports/sca.pip-audit.json` (`pip-audit -r requirements.txt -f json`)
- **Container**: `reports/container.trivy.json` (`trivy image --format json vulntracker-api:local`)
- **IaC**: `reports/iac.checkov.json` (`checkov -d terraform/ -o json`)

