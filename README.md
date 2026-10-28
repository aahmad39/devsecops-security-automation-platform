# VulnTracker — Security Automation Engineer Take-Home Solution

VulnTracker is a multi-tier vulnerability management system consisting of a FastAPI REST backend (`app/`) and an Express event notification service (`notify/`).

This repository contains the complete implementation of the **Shared Report Link** feature, comprehensive security analysis across 4 categories (SAST, SCA, Container, and IaC), remediation of critical and high severity vulnerabilities, production-grade containerization, hardened Terraform deployment definitions, and executive reporting.

---

## Architecture & Directory Layout

```text
/
├── app/                        # Python/FastAPI REST API
├── notify/                     # Node.js/Express notification service
├── Dockerfile                  # Multi-stage, non-root Python 3.11 Dockerfile
├── .dockerignore               # Optimized Docker build context filter
├── reports/                    # Genuine raw scanner JSON reports
│   ├── sast.bandit.json        # Bandit SAST report
│   ├── sca.pip-audit.json      # pip-audit dependency SCA report
│   ├── container.trivy.json    # Trivy container image scan report
│   └── iac.checkov.json        # Checkov Terraform IaC scan report
├── terraform/                  # Production-grade Kubernetes deployment on Azure
│   ├── main.tf                 # Terraform & provider configuration
│   ├── variables.tf            # Configurable deployment inputs
│   └── deployment.tf           # Hardened Deployment, NetPol, SA, SecretProviderClass
├── docs/                       # Technical & executive documentation
│   ├── findings.md             # Prioritized findings table & analysis
│   ├── remediation-plan.md     # Deferred risk analysis & compensating controls
│   └── executive-summary.md    # Plain-English briefing for CISO
├── tests/                      # Pytest automated test suite (33 tests)
│   └── test_api.py             # Baseline, feature, and remediation regression tests
└── README.md                   # System operations, build, and scan documentation
```

---

## 1. Prerequisites & Supported Versions

- **Python**: `3.11` (strictly required for CI environment compatibility)
- **Node.js**: `>= 20.0.0` (active LTS)
- **Docker Engine**: `>= 24.0.0` (with Buildx support)
- **Terraform**: `>= 1.5.0, < 2.0.0`
- **Security Tools**:
  - `bandit` 1.9.4
  - `pip-audit` 2.10.1
  - `trivy` 0.76.1
  - `checkov` 3.3.8

---

## 2. Local Setup & Execution

### 2.1 Python API (`app/`)

```bash
# From repository root
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows:
.venv\Scripts\activate

pip install -r requirements.txt

# Run from inside the app/ directory (required for bare import resolution)
cd app
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```
Interactive OpenAPI documentation will be accessible at `http://localhost:8000/docs`.

### 2.2 Notification Service (`notify/`)

```bash
cd notify
npm install
npm start
```
Service runs on `http://localhost:3001`.

---

## 3. Running Test Suites

### 3.1 Python Automated Tests

Run the complete test suite (baseline + shared links + remediation regression tests) from the repository root:

```bash
pytest tests/ -v
```
*Current test result: 33 passed.*

### 3.2 Node.js Automated Tests

```bash
cd notify
npm test
```
*Current test result: 8 passed.*

---

## 4. Shared Report Link Feature (Task 1)

Allows authorized VulnTracker users to generate time-limited, optionally password-protected report links for external auditors or stakeholders.

### Endpoints

#### 1. Create Share Link
- **Method**: `POST /scans/{scan_id}/share`
- **Auth**: `Bearer <jwt_token>` (Requires scan ownership)
- **Request Body (Optional password)**:
  ```json
  {
    "password": "OptionalStrongPassword123!"
  }
  ```
- **Response (`200 OK`)**:
  ```json
  {
    "share_url": "http://localhost:8000/share/vU0_k_19XQv_8E1_..."
  }
  ```

#### 2. Access Shared Report
- **Method**: `GET /share/{token}`
- **Auth**: None (Public)
- **Query Parameter**: `?password=OptionalStrongPassword123!` (required if protected)
- **Response (`200 OK`)**: Returns sanitized vulnerability report without internal database metadata, credentials, or ownership IDs.

### Security Properties
1. **Cryptographic Entropy**: 256-bit secure random tokens generated via `secrets.token_urlsafe(32)`.
2. **One-Way Token Hashing**: Raw tokens are never stored in the database. Only SHA-256 hashes (`token_hash`) are persisted.
3. **Strict Expiry**: Strict maximum lifetime of 24 hours enforced on database write and validated on every retrieval request.
4. **Password Protection**: Passwords hashed using bcrypt; passwords shorter than 8 characters are rejected.
5. **Data Minimization**: The response schema (`SharedScanOut`) strips `owner_id`, `created_by_user_id`, and internal system fields.

---

## 5. Docker Build, Run, and Health Verification (Task 4)

A multi-stage, non-root `Dockerfile` containerizes the FastAPI backend:

```bash
# 1. Build the production image
docker build -t vulntracker-api:local .

# 2. Run the container
docker run -d --name vulntracker-api -p 8000:8000 vulntracker-api:local

# 3. Verify health status
curl -f http://localhost:8000/health
# Or on Windows PowerShell:
Invoke-RestMethod -Uri "http://localhost:8000/health"

# 4. Check container health status
docker inspect --format='{{json .State.Health.Status}}' vulntracker-api

# 5. Clean up
docker stop vulntracker-api
docker rm vulntracker-api
```

---

## 6. Infrastructure-as-Code Deployment (Terraform)

Located in `terraform/`, defining a production Kubernetes deployment on Azure AKS.

### Key Security Controls
- **External Secret Management**: Integrates Azure Key Vault via Secrets Store CSI Driver (`SecretProviderClass`) and Azure Workload Identity (`azure.workload.identity/use: true`).
- **Least Privilege Security Context**:
  - `runAsNonRoot: true` (UID: 10001, GID: 10001)
  - `allowPrivilegeEscalation: false`
  - Linux capabilities dropped: `capabilities { drop = ["ALL"] }`
  - `seccompProfile { type = "RuntimeDefault" }`
- **Network Isolation**: `kubernetes_network_policy` restricts pod ingress to approved ingress controllers and egress to CoreDNS and the internal notification service.
- **Resource Limits**: Configured CPU/Memory requests and limits preventing noisy-neighbor DoS.

### Local IaC Validation

```bash
cd terraform
terraform init -backend=false
terraform validate
```

---

## 7. Security Scans & Report Files (Task 2 & 3)

All four security scans were executed against real application code, dependencies, containers, and deployment manifests. Raw outputs are stored in `reports/`:

| Scan Category | Tool | Command Used | Generated Report Path |
|---|---|---|---|
| **SAST** | Bandit | `bandit -r app/ -f json -o reports/sast.bandit.json` | `reports/sast.bandit.json` |
| **SCA** | pip-audit | `pip-audit -r requirements.txt -f json -o reports/sca.pip-audit.json` | `reports/sca.pip-audit.json` |
| **Container** | Trivy | `trivy image --format json --output reports/container.trivy.json vulntracker-api:local` | `reports/container.trivy.json` |
| **IaC** | Checkov | `checkov -d terraform/ -o json > reports/iac.checkov.json` | `reports/iac.checkov.json` |

---

## 8. Summary of Remediated Vulnerabilities

1. **JWT Algorithm Confusion (`VT-SEC-01` - Critical)**: Eliminated `"none"` algorithm acceptance in `app/auth.py`.
2. **SQL Injection (`VT-SEC-02` - High)**: Converted raw string interpolation in `app/database.py` to SQLAlchemy bind parameters.
3. **Broken Object Level Authorization / IDOR (`VT-SEC-03` - High)**: Enforced ownership scoping on single scan lookup and search in `app/main.py`.
4. **Weak Shared Report Password (`VT-SEC-04` - High)**: Enforced minimum 8-character password policy for shared report links.
5. **Permissive CORS Policy (`VT-SEC-05` - Medium)**: Replaced reflection with an explicit origin whitelist in `app/main.py`.
6. **Plaintext Credential Logging (`VT-SEC-06` - Medium)**: Removed raw passwords from login log messages.
7. **Stack Trace Information Leakage (`VT-SEC-07` - Low)**: Sanitized global exception responses to prevent internal path leaks.

---

## 9. Documentation References

- Detailed Findings & Analysis: [docs/findings.md](docs/findings.md)
- Remediation Plan & Residual Risks: [docs/remediation-plan.md](docs/remediation-plan.md)
- Executive Briefing for CISO: [docs/executive-summary.md](docs/executive-summary.md)

---

## 10. Statement of Testing & Known Limitations

- **Validated Locally**: Python unit & integration test suites (33 tests passing), Node.js test suite (8 tests passing), multi-stage Docker build and live container HTTP execution, Terraform provider validation (`terraform validate`), and all 4 security scanner executions.
- **Not Tested Against Live Cloud**: Terraform manifests were validated using local schema validation and Checkov policy scanning; no live paid Azure cloud infrastructure or Kubernetes clusters were provisioned.
