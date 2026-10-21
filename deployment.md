# Automated CI/CD & Cloud Deployment Architecture

A comprehensive, production-grade guide for building, testing, containerizing, and deploying the Centralized Authentication Microservice using **GitHub Actions**, **Docker**, and **Render Cloud Platform**.

---

## Table of Contents
1. [Architecture Overview & Workflow Pipeline](#1-architecture-overview--workflow-pipeline)
2. [Render Cloud Infrastructure & Mechanics](#2-render-cloud-infrastructure--mechanics)
3. [Render Setup Walkthrough (Step-by-Step)](#3-render-setup-walkthrough-step-by-step)
4. [Continuous Integration (CI): Test Containerization & Automation](#4-continuous-integration-ci-test-containerization--automation)
5. [Continuous Deployment (CD): Webhook Gating](#5-continuous-deployment-cd-webhook-gating)
6. [GitHub Repository Secrets Configuration](#6-github-repository-secrets-configuration)
7. [Production Docker Packaging (`Dockerfile` & `.dockerignore`)](#7-production-docker-packaging-dockerfile--dockerignore)
8. [End-to-End Operational Lifecycle](#8-end-to-end-operational-lifecycle)
9. [Production Troubleshooting & Diagnostic Guide](#9-production-troubleshooting--diagnostic-guide)

---

## 1. Architecture Overview & Workflow Pipeline

The deployment architecture decouples code testing from production hosting. Code pushed to GitHub undergoes automated validation inside an isolated ephemeral environment before deployment to production.

```
+-----------------------------------------------------------------------------------+
|                                  LOCAL MACHINE                                    |
|  - Feature development on local branch (dev / master)                             |
|  - Local configuration read from .env (never committed to Git)                    |
+-----------------------------------------------------------------------------------+
                                         |
                                         | git push origin master
                                         v
+-----------------------------------------------------------------------------------+
|                            GITHUB ACTIONS RUNNER (CI)                             |
|                                                                                   |
|  1. Spin up ephemeral PostgreSQL 15 Docker service container                     |
|  2. Inject test environment variables directly into memory (os.environ)           |
|  3. Run code linting & style enforcement (Ruff)                                   |
|  4. Execute Pytest suite against the isolated database container                  |
|  5. Build production Docker image to verify container recipe                      |
|  6. AUTOMATIC CONTAINER DESTRUCTION: PostgreSQL container deleted on job finish   |
+-----------------------------------------------------------------------------------+
                      |                                         |
             ❌ Tests Fail                             ✅ Tests Pass
                      |                                         |
                      v                                         v
         Pipeline halted immediately.             +---------------------------+
         Production remains untouched.            | GITHUB ACTIONS (CD)       |
                                                  | - workflow_run triggers   |
                                                  | - Fires Render Webhook    |
                                                  +---------------------------+
                                                                |
                                                                | POST Deploy Hook
                                                                v
                                                  +---------------------------+
                                                  |   RENDER CLOUD PLATFORM   |
                                                  | - Pulls latest commit     |
                                                  | - Builds Dockerfile       |
                                                  | - Injects production env  |
                                                  | - Binds to 0.0.0.0:$PORT  |
                                                  | - Live on public domain   |
                                                  +---------------------------+
```

---

## 2. Render Cloud Infrastructure & Mechanics

Render functions as a Platform-as-a-Service (PaaS). It manages underlying compute instances, reverse proxies, TLS termination, and health monitoring.

### Core Mechanics
1. **Managed Web Services**:
   - Executes the application inside isolated Linux cgroups.
   - Routes inbound HTTPS requests via an automated Cloudflare/Render edge proxy to the container port defined by `$PORT`.
2. **Dynamic Port Binding**:
   - Render dynamically allocates a port for each container instance via the `$PORT` environment variable (typically port 10000).
   - Inbound servers must bind to `0.0.0.0` (all network interfaces), not `127.0.0.1` (localhost), to allow Render's reverse proxy to route traffic.
3. **Managed PostgreSQL**:
   - Provisioned as an independent instance within Render's private cloud network.
   - Provides an **Internal Database URL** accessible with low latency by other Render services in the same region without leaving the private network.
4. **Deploy Hooks**:
   - Unique HTTPS endpoints that accept `POST` requests to trigger automated builds and rollouts.
   - Allows external CI runners (such as GitHub Actions) to act as deployment controllers.

---

## 3. Render Setup Walkthrough (Step-by-Step)

### Step 1: Provisioning the PostgreSQL Database
1. Log in to the Render Dashboard.
2. Click **New +** (top navigation bar) -> select **PostgreSQL**.
3. Configure the database parameters:
   - **Name**: `auth-database`
   - **Database**: `auth_methods`
   - **User**: `postgres` (or keep default generated username)
   - **Region**: Select the region closest to users (e.g., `Oregon (US West)` or `Frankfurt (EU Central)`).
   - **Plan**: Select **Free**.
4. Click **Create Database**.
5. Once status displays **Available**, scroll down to the **Connections** panel.
6. Copy the **Internal Database URL**:
   ```text
   postgresql://postgres:<PASSWORD>@dpg-<ID>-a/auth_methods
   ```

### Step 2: Provisioning the Web Service
1. Click **New +** -> select **Web Service**.
2. Select **Build and deploy from a Git repository**.
3. Connect the GitHub account and choose the repository `fastapi-authentican-methods`.
4. Configure service settings:
   - **Name**: `authentican-methods` (determines domain: `authentican-methods.onrender.com`)
   - **Region**: Must match the PostgreSQL database region selected in Step 1.
   - **Branch**: `master` (or `main`)
   - **Root Directory**: Leave blank (defaults to root).
   - **Runtime / Environment**: Select **Docker**.
     *(Render automatically detects `Dockerfile` in the root of the repository).*
   - **Plan**: Select **Free**.
5. Expand **Advanced** -> locate **Auto-Deploy**:
   - **Set Auto-Deploy to `No`**.
   - *Rationale*: If Auto-Deploy is set to `Yes`, Render automatically deploys on every raw Git commit, bypassing the GitHub Actions test suite. Disabling it ensures deployment occurs only after automated tests pass.

### Step 3: Injecting Production Environment Variables
In the service configuration under the **Environment Variables** section, add the required production keys:

| Key | Example Value | Description |
| :--- | :--- | :--- |
| `DATABASE_URL` | `postgresql://...` | Internal PostgreSQL connection string from Step 1 |
| `JWT_SECRET_KEY` | `<STRONG_HEX_SECRET>` | 32+ byte cryptographic secret for HMAC-SHA256 signing |
| `GOOGLE_CLIENT_ID` | `<CLIENT_ID>.apps.googleusercontent.com` | Google Cloud Console OAuth Client ID |
| `GOOGLE_CLIENT_SECRET` | `<CLIENT_SECRET>` | Google Cloud Console OAuth Client Secret |
| `GOOGLE_REDIRECT_URI` | `https://authentican-methods.onrender.com/oauth/google/callback` | Authorized production callback endpoint |

Click **Save Changes**.

### Step 4: Extracting the Deploy Hook URL
1. Navigate to the Web Service page -> click **Settings** in the left sidebar.
2. Scroll to the **Deploy Hook** card.
3. Click **Add Deploy Hook** (or copy the existing URL).
4. Save the generated URL:
   ```text
   https://api.render.com/deploy/srv-<SERVICE_ID>?key=<SECRET_KEY>
   ```

---

## 4. Continuous Integration (CI): Test Containerization & Automation

The CI workflow is configured in [`.github/workflows/ci.yml`](file:///d:/Learning/Python/networking/Auth-playground/.github/workflows/ci.yml). It provisions an isolated testing environment, verifies dependencies, enforces lint standards, runs the integration test suite, and tests the Docker build.

### Ephemeral Container Lifecycle
- **Step 1 - Startup**: When a commit is pushed to `master`, GitHub Actions starts a fresh, clean `postgres:15` Docker container on the runner's internal bridge network.
- **Step 2 - Health Check**: The runner executes `pg_isready` at 10-second intervals until the database engine is confirmed ready to accept TCP connections.
- **Step 3 - Execution**: Test runs connect directly to `localhost:5432`. Tables are created dynamically in memory via SQLAlchemy metadata fixtures.
- **Step 4 - Teardown**: Upon step completion (pass or fail), GitHub Actions stops and deletes the container. All stored test records, users, and tokens are eliminated. Zero persistent state leaks between CI runs.

### Configuration File: `.github/workflows/ci.yml`
```yaml
name: CI

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]

jobs:
  test:
    runs-on: ubuntu-latest

    # 1. Ephemeral PostgreSQL Service Container
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_USER: postgres
          POSTGRES_PASSWORD: root
          POSTGRES_DB: auth_methods
        ports:
          - 5432:5432
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    # 2. In-Memory Test Environment Variables
    env:
      JWT_SECRET_KEY: ci_cd_test_jwt_secret_key_123456789
      DATABASE_URL: postgresql+psycopg://postgres:root@localhost:5432/auth_methods
      GOOGLE_CLIENT_ID: mock_google_client_id
      GOOGLE_CLIENT_SECRET: mock_google_client_secret
      GOOGLE_REDIRECT_URI: http://localhost:8000/oauth/google/callback

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up Python runtime
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          cache: pip

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt

      - name: Run code linter (Ruff)
        run: ruff check --fix --extend-ignore=B008

      - name: Execute automated Pytest suite
        run: pytest -v

      - name: Validate Docker image build
        run: docker build -t auth-service:ci-test .
```

### Linter Configuration (`ruff.toml`)
FastAPI utilizes function parameter defaults for dependency injection (`db: DbSession = Depends(get_db)`). Standard Python linters flag this under rule `B008`. Rule `B008` is excluded via [`ruff.toml`](file:///d:/Learning/Python/networking/Auth-playground/ruff.toml):

```toml
[lint]
ignore = [
    "B008",  # Permit Depends() in FastAPI route argument defaults
]
```

### In-Memory Test Variables & Mock OAuth Mechanics

A critical design pattern in the CI pipeline is the strict separation between testing variables and production credentials.

#### 1. Environment Value Sources Comparison
- **During Testing (GitHub Actions CI)**: Values defined under `env:` in `ci.yml` are injected directly into the runner process memory (`os.environ`). No physical `.env` file exists on the runner's disk, and no communication occurs with Render.
- **During Production (Render Web Service)**: Values configured within the Render Dashboard Environment tab are injected into the production container upon deployment. Render does not read `ci.yml` or GitHub test variables.

| Variable | CI Test Value (`ci.yml`) | Render Production Value |
| :--- | :--- | :--- |
| `DATABASE_URL` | `postgresql+psycopg://postgres:root@localhost:5432/auth_methods` | Internal Database URL from managed Render PostgreSQL |
| `JWT_SECRET_KEY` | `ci_cd_test_jwt_secret_key_123456789` | Strong cryptographic production secret |
| `GOOGLE_CLIENT_ID` | `mock_google_client_id` | Live Google Cloud Console Client ID |
| `GOOGLE_CLIENT_SECRET` | `mock_google_client_secret` | Live Google Cloud Console Client Secret |
| `GOOGLE_REDIRECT_URI` | `http://localhost:8000/oauth/google/callback` | `https://authentican-methods.onrender.com/oauth/google/callback` |

#### 2. Purpose of Mock Google OAuth Values in CI
The values `mock_google_client_id`, `mock_google_client_secret`, and `http://localhost:8000/oauth/google/callback` serve four architectural purposes:
1. **Application Startup Fulfillment**:
   `settings.py` reads `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and `GOOGLE_REDIRECT_URI` during initialization. Supplying non-empty mock strings satisfies configuration loading without raising missing-variable errors.
2. **Headless Execution Compatibility**:
   Real Google OAuth requires interactive human intervention via a web browser ("Sign in with Google"). Headless CI runners cannot perform interactive user browser logins.
3. **Third-Party Isolation & Reliability**:
   Live HTTP calls to Google servers during automated test execution introduce external network dependencies, latency, and rate-limiting failures. Tests in `tests/test_oauth.py` validate application logic (database record creation, `OauthAccount` table associations, JWT issuance) completely in-memory without contacting external Google servers.
4. **Credential Security**:
   Real Google client secrets are never committed to version control or printed to public CI workflow logs. Real credentials reside exclusively within the encrypted Render Dashboard.

---

## 5. Continuous Deployment (CD): Webhook Gating

The CD pipeline is configured in [`.github/workflows/cd.yml`](file:///d:/Learning/Python/networking/Auth-playground/.github/workflows/cd.yml). It activates using GitHub's `workflow_run` event to ensure production updates happen only after the `CI` workflow completes with status `success`.

### Configuration File: `.github/workflows/cd.yml`
```yaml
name: CD

on:
  workflow_run:
    workflows: ["CI"]
    types: [completed]
    branches: [main, master]

jobs:
  deploy:
    # Deployment is triggered strictly if the CI workflow concluded successfully
    if: github.event.workflow_run.conclusion == 'success'
    runs-on: ubuntu-latest
    environment: production

    steps:
      - name: Trigger Render deployment webhook
        run: curl -fsS -X POST "${{ secrets.RENDER_DEPLOY_HOOK_URL }}"
```

### Pipeline Gating Logic:
- If a linter error or a broken unit test fails in `CI`, `workflow_run.conclusion` evaluates to `failure`.
- The `deploy` job is skipped.
- Render receives no webhook request, and the running production container remains on the previous stable release.

---

## 6. GitHub Repository Secrets Configuration

To authenticate deployment requests without publishing secrets in version control, the Render Deploy Hook URL must be stored in GitHub Secrets.

### Storage Procedure
1. Open the GitHub repository in a browser (`https://github.com/harish-AK/fastapi-authentican-methods`).
2. Click **Settings** (top repository tab bar).
3. In the left menu, expand **Secrets and variables** -> select **Actions**.
4. In the **Repository secrets** pane, click **New repository secret**.
5. Set the values:
   - **Name**: `RENDER_DEPLOY_HOOK_URL`
   - **Secret**: Paste the full deploy hook URL generated in Section 3, Step 4 (`https://api.render.com/deploy/srv-...?key=...`).
6. Click **Add secret**.

---

## 7. Production Docker Packaging (`Dockerfile` & `.dockerignore`)

Containerization bundles application code, Python 3.12, and third-party libraries into an immutable Linux image.

### Production `Dockerfile`
```dockerfile
FROM python:3.12-slim

# Prevent Python from writing .pyc bytecode and ensure real-time logging output
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000

WORKDIR /app

# Install system utilities for container healthchecks
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Layer 1: Dependency installation (cached until requirements.txt changes)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Layer 2: Copy application source tree
COPY . .

# Expose HTTP port
EXPOSE 8000

# Execute server bound to all interfaces on dynamic cloud $PORT
CMD ["sh", "-c", "python -m uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
```

### Exclusion Manifest (`.dockerignore`)
Prevents sensitive files, local environments, tests, and temporary caches from being copied into the production container image:

```gitignore
# Git version control
.git
.github
.gitignore

# Environment configurations and secrets
.env
.env.*
!.env.example

# Bytecode and execution caches
__pycache__
*.pyc
*.pyo
*.pyd

# Local virtual environments
.venv
venv/
ENV/
env/

# Test suites and test caches
.pytest_cache
.coverage
htmlcov/
tests/

# Documentation and editor configurations
*.md
.vscode/
.idea/
.postman/
postman/
```

---

## 8. End-to-End Operational Lifecycle

The operational cycle follows a predictable, fully automated progression:

```
Step 1: Code Edit & Commit
        Developer commits code changes locally:
        $ git commit -m "Add feature"
        $ git push origin master
                           │
                           ▼
Step 2: CI Triggered on GitHub Actions
        - Spins up ephemeral PostgreSQL 15 container
        - Lints with Ruff (ignores B008)
        - Executes all test files in tests/
        - Verifies Dockerfile compiles cleanly
                           │
             ┌─────────────┴─────────────┐
             │                           │
          ❌ Fail                     ✅ Pass
             │                           │
             ▼                           ▼
        Build halts.            Step 3: CD Triggered
        Alert sent.             - workflow_run receives success event
        Render untouched.       - Sends POST to Render Deploy Hook
                                         │
                                         ▼
                                Step 4: Render Deployment
                                - Clones master commit
                                - Executes Dockerfile build
                                - Starts container with production env
                                - Live on https://authentican-methods.onrender.com
```

---

## 9. Production Troubleshooting & Diagnostic Guide

### Issue 1: `NameError: name 'DATABASE_URL' is not defined`
- **Cause**: Missing import statement in [`database.py`](file:///d:/Learning/Python/networking/Auth-playground/database.py).
- **Resolution**: Ensure `from settings import DATABASE_URL` is declared before assigning `db_url = DATABASE_URL`.

### Issue 2: `ValueError: JWT_SECRET_KEY is not set`
- **Cause**: Application booted without `.env` present and without environment variable injection in the cloud hosting provider.
- **Resolution**: Open Render Dashboard -> Web Service -> **Environment** tab. Add `JWT_SECRET_KEY` with a non-empty string.

### Issue 3: `OperationalError: connection to server at "localhost", port 5432 failed`
- **Cause**: Cloud application attempted to connect to `localhost:5432`. Localhost inside a cloud container references the container itself, not the developer's laptop.
- **Resolution**: Create a managed PostgreSQL database in Render. Copy the **Internal Database URL** and set it as `DATABASE_URL` in the Web Service Environment tab.

### Issue 4: `bash: line 1: uvicorn: command not found (exit status 127)`
- **Cause**: In native Python runtime mode, `uvicorn` was not installed or binary path was excluded from `$PATH`.
- **Resolution**: Use the Docker runtime mode via [`Dockerfile`](file:///d:/Learning/Python/networking/Auth-playground/Dockerfile). If using native Python, configure the start command as `python -m uvicorn app.main:app --host 0.0.0.0 --port $PORT`.

### Issue 5: `Error 400: redirect_uri_mismatch` (Google OAuth)
- **Cause**: Callback URL in Google Cloud Console does not match the production redirect URI.
- **Resolution**: Add `https://authentican-methods.onrender.com/oauth/google/callback` to the **Authorized redirect URIs** list in the Google Cloud Console credentials page.

### Issue 6: Ruff Linter Fails with `B008`
- **Cause**: Flake8 bugbear flags function calls in default arguments.
- **Resolution**: Add rule `B008` to the ignore list in [`ruff.toml`](file:///d:/Learning/Python/networking/Auth-playground/ruff.toml) or pass `--extend-ignore=B008` to the `ruff check` invocation in CI.