# Centralized Authentication Service

A multi-tenant authentication microservice built with **FastAPI**, **PostgreSQL**, **SQLAlchemy**, and **Argon2**. This service acts as a centralized identity provider, allowing client web applications to offload user registration, login, session management, token issuance, and social logins.

---

## Auth Service Overview

Modern web applications need reliable, secure authentication. Instead of re-implementing user tables, password hashing, and token flows inside every project, this microservice centralizes all authentication operations behind clean REST endpoints.

### Key Features

* **Multi-Tenant Architecture**: Client applications register once to obtain a dedicated `API Key` (`ak_live_...`). All users, sessions, and tokens are strictly isolated per registered application.
* **4 Authentication Methods**:
  1. **Basic Auth**: Classic username and password authentication secured with state-of-the-art **Argon2** hashing.
  2. **Session-Based Auth**: Cryptographically random 32-byte tokens saved as SHA-256 hashes in PostgreSQL, returned via secure `HttpOnly` cookies.
  3. **JWT Authentication**: Short-lived access tokens (15–60 min) with long-lived refresh tokens (7 days). Includes **Refresh Token Rotation** and **Token Family Revocation** to detect and neutralize replay attacks.
  4. **Google OAuth 2.0**: Interactive browser login redirect flow and callback verification for seamless social sign-in.
* **Token & Session (`GET /verify`)**: A single verification route that validates either Bearer JWTs or session cookies for client microservices and gateways.
* **Centralized Logout**: Immediately purges active database sessions, revokes refresh token families, and invalidates JWT tokens across all devices.
* **Automatic Migrations**: Powered by **Alembic**, database schemas and tables are automatically created and upgraded on server startup.

### Tech Stack

| Component | Technology |
| :--- | :--- |
| **Framework** | FastAPI (Python 3.12) |
| **Database** | PostgreSQL 15+ (via SQLAlchemy 2.0 & Psycopg 3) |
| **Schema Migrations** | Alembic |
| **Password Hashing** | Argon2 (via `argon2-cffi`) |
| **Token Standards** | PyJWT (HMAC-SHA256) |
| **Containerization** | Docker |
| **Hosting & CI/CD** | Render + GitHub Actions |

---

## Setup

Follow the steps below to set up, configure, and run the service locally or in the cloud.

### 1. Clone & Local Environment

Clone the repository to your machine and prepare a Python virtual environment:

```bash
# Clone the repository
git clone https://github.com/harish-AK/fastapi-authentican-methods.git
cd fastapi-authentican-methods

# Install dependencies
pip install -r requirements.txt
```

---

### 2. Create Google OAuth Credentials

If you plan to use Google Social Login (`/oauth/google/login`), configure OAuth credentials in the Google Cloud Console:

1. **Open Google Cloud Console**:
   * Visit [console.cloud.google.com](https://console.cloud.google.com/) and select or create a new project.
2. **Configure OAuth Consent Screen**:
   * Navigate to **APIs & Services** $\rightarrow$ **OAuth consent screen**.
   * Select **External** user type and click **Create**.
   * Enter your **App Name** (e.g. `Centralized Auth Service`), **User support email**, and **Developer contact email**.
   * In the **Scopes** step, add:
     - `.../auth/userinfo.email`
     - `.../auth/userinfo.profile`
     - `openid`
   * In the **Test users** step, add the Gmail address you will use for testing.
3. **Create OAuth Client ID**:
   * Go to **APIs & Services** $\rightarrow$ **Credentials**.
   * Click **+ Create Credentials** $\rightarrow$ **OAuth client ID**.
   * Choose **Application type**: `Web application`.
   * Under **Authorized redirect URIs**, add:
     - Local testing: `http://localhost:8000/oauth/google/callback`
     - Production: `https://<your-render-domain>.onrender.com/oauth/google/callback`
   * Click **Create**.
4. **Save Your Secrets**:
   * Copy the **Client ID** and **Client Secret**.
   * These correspond to `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` in your environment variables.

---

### 3. Launch on Render

To run the authentication service in production on [Render](https://render.com):

#### Step A: Create a PostgreSQL Database
1. In your **Render Dashboard**, click **New +** $\rightarrow$ **PostgreSQL**.
2. Set a **Name** (e.g. `auth-methods-db`).
3. Select your preferred region and free/starter instance tier.
4. Once provisioned, note the **Internal Database URL** (used by services on Render) and **External Database URL** (for remote tools like DBeaver).

#### Step B: Create the Web Service
1. In the **Render Dashboard**, click **New +** $\rightarrow$ **Web Service**.
2. Connect your GitHub repository.
3. Choose your configuration:
   * **Runtime**: Python 3 (or Docker)
   * **Build Command**: `pip install -r requirements.txt`
   * **Start Command**: `python -m uvicorn app.main:app --host 0.0.0.0 --port $PORT`
4. Proceed to configure the environment variables below before deploying.

---

### 4. Configure Environment Variables

Create a `.env` file in the project root for local development, or add these variables in your **Render Web Service $\rightarrow$ Environment**:

| Variable | Description | Example / Default |
| :--- | :--- | :--- |
| `DATABASE_URL` | PostgreSQL connection string | `postgresql+psycopg://user:password@localhost:5432/auth_methods` |
| `JWT_SECRET_KEY` | Secret key used to sign and verify JWTs | Generate using `openssl rand -hex 32` |
| `GOOGLE_CLIENT_ID` | *(Optional)* Google OAuth Client ID | `602894...apps.googleusercontent.com` |
| `GOOGLE_CLIENT_SECRET`| *(Optional)* Google OAuth Client Secret | `GOCSPX-...` |
| `GOOGLE_REDIRECT_URI` | Google OAuth Callback URL | `https://<your-render-domain>.onrender.com/oauth/google/callback` |

> [!NOTE]
> **Zero Manual Migrations**: You do not need to run `alembic upgrade head` manually. The application automatically applies all schema migrations on startup through its lifespan event.

---

### 5. Deploy

#### Automated CI/CD Pipeline
The repository includes automated GitHub Actions workflows located in `.github/workflows/`:

* **Continuous Integration (`ci.yml`)**: Triggers on every push or pull request to `main`/`master`. It spins up an ephemeral PostgreSQL container, runs code linting with **Ruff**, executes the full **Pytest** test suite, and validates Docker image packaging.
* **Continuous Deployment (`cd.yml`)**: Once the CI checks pass successfully, it automatically calls Render's deploy webhook to trigger a fresh production deployment.

#### Setting up the Deploy Webhook
1. In your Render Web Service dashboard, navigate to **Settings** $\rightarrow$ **Deploy Hook**.
2. Copy the Webhook URL.
3. In your GitHub repository, go to **Settings** $\rightarrow$ **Secrets and variables** $\rightarrow$ **Actions**.
4. Add a repository secret named **`RENDER_DEPLOY_HOOK_URL`** and paste the webhook URL.

Every successful push to your main branch will now automatically test and deploy your live service!

---

## Use the Auth Service

Integrating a client application into this authentication service takes two simple steps:

```
+-----------------------------------------------------------------------------------+
|  1. ONE-TIME APP REGISTRATION                                                     |
|     Client App Developer calls POST /apps/register                                |
|     ==> Receives X-API-Key: ak_live_... (Saved in Client .env)                    |
+-----------------------------------------------------------------------------------+
                                       |
                                       v
+-----------------------------------------------------------------------------------+
|  2. AUTHENTICATE USERS WITH X-API-KEY                                             |
|     Client calls /basic-auth, /session-auth, /jwt-auth, or /oauth                 |
|     Headers: { "X-API-Key": "ak_live_..." }                                       |
|     Body:    { "username": "alice", "password": "...", "email": "..." }           |
+-----------------------------------------------------------------------------------+
```

For complete endpoint references, curl commands, JSON payloads, and response schemas for all 4 authentication methods:

**See the full integration guide in [Implementation.md](Implementation.md)**