# Security Remediation Plan — VulnTracker

This document provides technical analysis and remediation planning for findings identified during the security review that remain unresolved or deferred, outlining residual business risks, compensating controls, required architectural changes, and recommended timelines.

---

## 1. Material Unresolved Findings and Strategy

### VT-PLAN-01: Server-Side Request Forgery (SSRF) in Notification Service
- **Finding Reference**: `VT-SEC-08`
- **Component**: `notify/src/index.js`, `notify/src/dispatcher.js`
- **Why Unresolved**:
  The assignment guidelines specify that the Node.js notification service (`notify/`) requires no functional code changes in this phase, and its test suite expects open registration of webhook endpoints without egress validation. Introducing URL scheme and IP address filters at this stage would require altering the service's contract and baseline tests.
- **Residual Risk**:
  An internal adversary or a compromised Python API instance could register webhook URLs pointing to cloud metadata services (e.g., `http://169.254.169.254/metadata/v1/maintenance`) or internal cluster workloads, triggering outbound HTTP POST requests and exfiltrating internal responses or secrets.
- **Existing Compensating Controls**:
  1. **Kubernetes NetworkPolicy**: In the deployment architecture (`terraform/deployment.tf`), strict egress controls restrict network traffic from the application pods. The API is permitted to connect only to `vulntracker-notify:3001` and CoreDNS (`kube-dns:53`).
  2. **Cluster Isolation**: The notification service does not have permissions to access cloud provider instance metadata.
- **Remediation Requirements**:
  - Implement an IP allowlist and blocklist in `notify/src/dispatcher.js` using libraries like `ipaddr.js` to reject loopback (`127.0.0.0/8`), link-local (`169.254.0.0/16`), and RFC 1918 private IP ranges unless explicitly enabled for internal services.
  - Require mutual authentication (mTLS or pre-shared HMAC signatures) between the FastAPI backend and Express notification service.
- **Owner**: DevSecOps / Backend Engineering Team
- **Priority**: High (Target Timeframe: Sprint 1 post-prototype)

---

### VT-PLAN-02: Third-Party Dependencies with Known Vulnerabilities (SCA)
- **Finding Reference**: `VT-SEC-09`
- **Component**: `requirements.txt`
- **Why Unresolved**:
  The starter repository strictly pins legacy dependencies (`fastapi==0.104.1`, `cryptography==38.0.1`, `python-jose==3.3.0`, `starlette==0.27.0`) to ensure compatibility with Python 3.11 and the starter test fixtures. Arbitrarily bumping major packages across the board in this phase introduces breaking changes to Pydantic v2 schemas and authentication crypto layers without extensive end-to-end regression validation.
- **Residual Risk**:
  Known public CVEs in `cryptography` and `starlette` (e.g. potential denial of service via malformed multipart forms or memory corruption in legacy OpenSSL bindings) could theoretically be triggered under specific edge conditions.
- **Existing Compensating Controls**:
  1. **Non-Root Execution**: Container runs as dedicated non-root user `appuser` (UID 10001), preventing privilege escalation to root.
  2. **Read-Only / Dropped Capabilities**: In Kubernetes, `allowPrivilegeEscalation: false` and Linux capabilities `drop: ["ALL"]` prevent OS compromise even if a library vulnerability were exploited.
  3. **Strict Input Validation**: Request schemas validate payloads before passing to internal handlers.
- **Remediation Requirements**:
  - Establish a dependency upgrade branch migrating `cryptography` to `>=42.0.0`, `fastapi` to `>=0.115.0`, and replacing abandoned `python-jose` with actively maintained `pyjwt` or `authlib`.
  - Validate all Pydantic v2 migration deprecation warnings and test compatibility.
- **Owner**: Application Security & Core Backend Engineers
- **Priority**: Medium (Target Timeframe: Sprint 2 post-prototype)

---

### VT-PLAN-03: Hardcoded Development Secrets in Configuration Defaults
- **Finding Reference**: `VT-SEC-10`
- **Component**: `app/config.py`, `notify/src/config.js`
- **Why Unresolved**:
  Default static values (`v3ry-s3cr3t-jwt-k3y-do-not-share`, `sk-vt-prod-8f3a2b1c9d4e5f6a7b8c9d0e1f2a3b4c`) were provided in starter code to enable out-of-the-box local testing without requiring external secret vaults. Removing fallback defaults entirely would break local unconfigured developer test runs.
- **Residual Risk**:
  If developers or operators inadvertently deploy the application to production without providing environment variables or secret mounts, the service would default to predictable keys, allowing attackers to forge tokens.
- **Existing Compensating Controls**:
  1. **Secrets Store CSI Driver**: In our production Terraform deployment, secrets are retrieved from Azure Key Vault (`kv-vulntracker-prod`) and mounted directly as runtime environment variables, completely superseding configuration defaults.
  2. **Production Startup Check**: An environment check (`ENVIRONMENT=prod`) can be added to abort container startup if default development secrets are detected.
- **Remediation Requirements**:
  - Refactor `config.py` using `pydantic-settings` to require explicit secret provision in non-development environments and reject default keys when `ENV == "production"`.
- **Owner**: DevSecOps Team
- **Priority**: High (Target Timeframe: Immediate prior to production rollout)

---

## 2. Summary Timeline and Roadmap

| Phase | Milestone | Focus Areas | Target Completion |
|---|---|---|---|
| **Phase 1 (Completed)** | Prototype Hardening & Feature Delivery | Task 1 Shared Link, JWT 'none' bypass fix, SQLi fix, IDOR remediation, CORS restriction, Non-root container, Terraform IaC | **Done** |
| **Phase 2 (Immediate)** | Production Secret & Environment Hardening | Enforce Key Vault secret injection, eliminate fallback keys in production mode, enable automated CI secret scanning | **Week 1** |
| **Phase 3 (Next Sprint)** | Outbound Traffic & Webhook Defense | Implement SSRF protection on notification service, mTLS inter-service authentication | **Week 2-3** |
| **Phase 4 (Quarterly)** | Dependency Modernization | Migrate legacy `python-jose` to `pyjwt`, upgrade `cryptography` and `fastapi`, automate Dependabot PRs | **Month 1** |

