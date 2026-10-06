# Centralized Authentication Service: Complete Architecture & Guide

  

A comprehensive, production-grade guide to building a centralized multi-tenant authentication microservice using **FastAPI**, **PostgreSQL**, **SQLAlchemy**, **Alembic**, and **Pytest**.

  

---

  

## Table of Contents

1. [Project Overview & Directory Structure](#1-project-overview--directory-structure)

2. [Configuration & Database Connection](#2-configuration--database-connection)

3. [Database Models & Multi-Tenant Architecture](#3-database-models--multi-tenant-architecture)

4. [Database Migrations with Alembic](#4-database-migrations-with-alembic)

5. [Password Hashing & Security](#5-password-hashing--security)

6. [Core Authentication Methods](#6-core-authentication-methods)

   - [Method 1: Basic Authentication](#method-1-basic-authentication)

   - [Method 2: Stateful Session Authentication](#method-2-stateful-session-authentication)

   - [Method 3: Stateless JWT & Refresh Tokens](#method-3-stateless-jwt--refresh-tokens)

   - [Method 4: OAuth 2.0 & OpenID Connect (Google)](#method-4-oauth-20--openid-connect-google)

7. [Centralized Universal Logout](#7-centralized-universal-logout)

8. [Introspection Endpoint (`GET /verify`)](#8-introspection-endpoint-get-verify)

9. [Master Unified Route (`POST /auth`)](#9-master-unified-route-post-auth)

10. [Automated Testing with Pytest (In-Memory Execution)](#10-automated-testing-with-pytest-in-memory-execution)

11. [CI/CD Pipeline with GitHub Actions](#11-cicd-pipeline-with-github-actions)

12. [Comprehensive Parameter & Module Glossary](#12-comprehensive-parameter--module-glossary)

  

---

  

## 1. Project Overview & Directory Structure

  

```

Auth-playground/

├── app/

│   ├── __init__.py

│   ├── main.py              # Streamlined FastAPI endpoints & business logic

│   └── security.py          # Password hashing and verification utilities

├── tests/

│   ├── __init__.py          # Marks tests as a Python package

│   ├── conftest.py          # Global Pytest fixtures (DB creation, TestClient)

│   ├── utils.py             # Unique string generator for isolated tests

│   ├── test_health.py       # API liveness check

│   ├── test_basic_auth.py   # Basic auth endpoint tests

│   ├── test_session.py      # Session auth & cookie tests

│   ├── test_jwt.py          # JWT, refresh rotation, & revocation tests

│   └── test_oauth.py        # OAuth provisioning tests

├── alembic/                 # Alembic migration scripts and versions

├── .github/workflows/

│   └── ci.yml               # GitHub Actions automated CI/CD pipeline

├── .env                     # Local environment variables (gitignored)

├── .env.test                # Test environment variables (gitignored)

├── .gitignore               # Ignored files (.env, __pycache__, etc.)

├── alembic.ini              # Alembic migration configuration

├── database.py              # Database engine & sessionmaker

├── models.py                # SQLAlchemy table models

├── pytest.ini               # Pytest configuration (pythonpath, testpaths)

├── requirements.txt         # Pinned project dependencies

├── settings.py              # Application settings & environment loader

└── Authentication app.md    # Master documentation

```

  

---

  

## 2. Configuration & Database Connection

  

### Settings (`settings.py`)

Loads environment variables from `.env` (or `.env.test`) using `python-dotenv`:

  

```python

import os

from pathlib import Path

from dotenv import load_dotenv

  

BASE_DIR = Path(__file__).resolve().parent

load_dotenv(BASE_DIR / ".env.test", override=True)

  

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")

DATABASE_URL = os.getenv("DATABASE_URL")

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")

GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")

GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")

ORIGINS = ["http://localhost:3000", "http://localhost:5173", "http://localhost:8000"]

```

  

### Database Connection (`database.py`)

Establishes connection pooling and scoped session management:

  

```python

from sqlalchemy import create_engine

from sqlalchemy.orm import declarative_base, sessionmaker

from settings import DATABASE_URL

  

engine = create_engine(DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

  

def get_db():

    """FastAPI dependency yielding a thread-local DB session, closing it on completion."""

    db = SessionLocal()

    try:

        yield db

    finally:

        db.close()

```

  

#### Why `get_db` Uses `try / finally`

- `yield db`: Injects the active session into the FastAPI endpoint route handler.

- `finally: db.close()`: Guarantees the database connection is returned to the pool after the response is sent, even if an unhandled exception occurs.

  

---

  

## 3. Database Models & Multi-Tenant Architecture

  

The system is built as a **multi-tenant Identity Provider**. External client applications register in the `applications` table, and all users, sessions, refresh tokens, and OAuth accounts belong to an `app_id`.

  

```mermaid

erDiagram

    APPLICATION ||--o{ USER : "owns"

    APPLICATION ||--o{ SESSION : "owns"

    APPLICATION ||--o{ REFRESH_TOKEN : "owns"

    APPLICATION ||--o{ OAUTH_ACCOUNT : "owns"

    USER ||--o{ SESSION : "has"

    USER ||--o{ REFRESH_TOKEN : "has"

    USER ||--o{ OAUTH_ACCOUNT : "links"

```

  

### Core Schema Highlights (`models.py`)

  

```python

class Application(Base):

    __tablename__ = "applications"

    id = Column(Integer, primary_key=True, index=True)

    app_name = Column(String, nullable=False)

    api_key_hash = Column(String(64), nullable=False, unique=True)

    users = relationship("UserDatabase", back_populates="application", cascade="all, delete-orphan")

    sessions = relationship("Session", back_populates="application", cascade="all, delete-orphan")

    refresh_tokens = relationship("RefreshToken", back_populates="application", cascade="all, delete-orphan")

    oauth_accounts = relationship("OauthAccount", back_populates="application", cascade="all, delete-orphan")

  

class UserDatabase(Base):

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)

    app_id = Column(Integer, ForeignKey("applications.id", ondelete="CASCADE"), nullable=False)

    username = Column(String, nullable=False, unique=True)

    password_hash = Column(String, nullable=False)

    email = Column(String, nullable=False, unique=True)

    is_active = Column(Boolean, default=True, nullable=False)

  

class Session(Base):

    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True)

    session_id_hash = Column(String(64), nullable=False, unique=True)

    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)

    app_id = Column(Integer, ForeignKey("applications.id", ondelete="CASCADE"), nullable=False)

    expires_at = Column(DateTime(timezone=True), nullable=False)

  

class RefreshToken(Base):

    __tablename__ = "refresh_tokens"

    id = Column(Integer, primary_key=True)

    refresh_token_hash = Column(String(64), nullable=False, unique=True)

    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)

    app_id = Column(Integer, ForeignKey("applications.id", ondelete="CASCADE"), nullable=False)

    family_id = Column(String(64), nullable=False, index=True)

    revoked = Column(Boolean, default=False, nullable=False)

    expires_at = Column(DateTime(timezone=True), nullable=False)

  

class OauthAccount(Base):

    __tablename__ = "oauth_accounts"

    id = Column(Integer, primary_key=True)

    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)

    app_id = Column(Integer, ForeignKey("applications.id", ondelete="CASCADE"), nullable=False)

    provider = Column(String, nullable=False)

    provider_user_id = Column(String, nullable=False)

    __table_args__ = (UniqueConstraint("provider", "provider_user_id", name="unique_provider_user_id"),)

```

  

#### Important Database Parameters 

- **`cascade="all, delete-orphan"`**: If an application is deleted, SQLAlchemy automatically deletes all associated users, sessions, refresh tokens, and OAuth accounts.

- **`ondelete="CASCADE"`**: Database-level foreign key constraint enforcing cascading deletes directly within PostgreSQL if rows are modified via raw SQL.

- **`UniqueConstraint("provider", "provider_user_id")`**: Prevents a single external Google account from being bound multiple times under the same provider.

  

---

  

## 4. Database Migrations with Alembic

  

Alembic detects changes in SQLAlchemy models and applies version-controlled database schema migrations.

  

```

SQLAlchemy Models (models.py) ──> Alembic autogenerate ──> Migration Script ──> PostgreSQL

```

  

### Essential Alembic Commands

```bash

# 1. Initialize Alembic (creates alembic/ folder and alembic.ini)

alembic init alembic

  

# 2. Generate a new migration script based on model changes

alembic revision --autogenerate -m "create auth tables"

  

# 3. Apply all pending migrations to the database

alembic upgrade head

  

# 4. Stamp the database to a specific version without running DDL

alembic stamp head
# The `alembic stamp` command manually updates the **alembic_version** table to record a specific revision as applied, without executing any migration scripts.
```

  

---

  

## 5. Password Hashing & Security

  

Plaintext passwords must never be stored in a database. Passwords are hashed using one-way cryptographic algorithms with automatic salting (Argon2 / Bcrypt).

  

```python

# app/security.py

from argon2 import PasswordHasher

hasher = PasswordHasher()

  

def hash_password(password: str) -> str:

    """Produces a secure one-way hash with unique salt."""

    return hasher.hash(password)

  

def verify_password(password: str, hashed_password: str) -> bool:

    """Verifies candidate password against stored hash."""

    try:

        return hasher.verify(hashed_password, password)

    except Exception:

        return False

```

  

---

  

## 6. Core Authentication Methods

  

The service exposes dedicated endpoints for each authentication mechanism, plus a master dispatcher.

  

### Method 1: Basic Authentication

**Endpoint**: `POST /basic`

  

- **Concept**: User sends `username`, `password`, and `app_name`.

- **Behavior**: If the user does not exist, they are registered (`status: "registered"`). If they exist, credentials are authenticated (`status: "verified"`).

  

```python

@app.post("/basic", response_model=AuthResponse)

def basic_auth(payload: AuthRequest, response: Response, db: DbSession = Depends(get_db)):

    return execute_authentication(payload, "basic", response, db)

```

  

---

  

### Method 2: Stateful Session Authentication

**Endpoint**: `POST /session`

  

- **Concept**: Server creates a secure random token (`secrets.token_urlsafe(32)`), saves the SHA-256 hash in the `sessions` table, and sets an HTTP cookie in the browser response.

- **Statefulness**: State resides in the database. When the user visits subsequent pages, the browser transmits the cookie, and the server validates it against `sessions.expires_at`.

  

```python

session_id = secrets.token_urlsafe(32)

session_hash = hashlib.sha256(session_id.encode()).hexdigest()

# Save session_hash into PostgreSQL...

  

response.set_cookie(

    key="session_id",

    value=session_id,

    httponly=True,

    samesite="lax",

    secure=False,      # Set True in production HTTPS

    max_age=86400,     # Valid for 24 hours (in seconds)

    path="/",

)

```

  

#### Detailed Cookie Flags Explained

- **`httponly=True`**: Prevents client-side JavaScript (`document.cookie`) from reading the cookie, neutralizing Cross-Site Scripting (XSS) token theft.

- **`samesite="lax"`**: Restricts cookie transmission to first-party requests and safe top-level navigations (GET), neutralizing Cross-Site Request Forgery (CSRF).

- **`secure=True`**: Instructs browsers to send the cookie ONLY over encrypted HTTPS connections (set `False` for local `http://localhost` testing).

- **`max_age=86400`**: Defines cookie lifetime in seconds (86,400s = 24 hours).

- **`path="/"`**: Scopes cookie availability to the entire host domain.

  

---

  

### Method 3: Stateless JWT & Refresh Tokens

**Endpoint**: `POST /jwt`

  

- **Concept**: Server cryptographically signs a JSON payload containing user identity. The client transmits the token via `Authorization: Bearer <access_token>`.

- **Lifecycle**:

  - **Access Token (Short-Lived, e.g. 60m)**: Authorizes API requests without querying the database for user authentication.

  - **Refresh Token (Long-Lived, e.g. 7 days)**: Opaque token stored in PostgreSQL used to request fresh access tokens.

  

#### Refresh Token Rotation (RTR) & Reuse Detection

To prevent compromised refresh tokens from granting indefinite access:

1. Every time a refresh token is exchanged via `POST /jwt/refresh`, the server **revokes the old token** and issues a brand-new refresh token under the same `family_id`.

2. If an attacker attempts to replay an already-revoked refresh token, **reuse detection triggers**: the server immediately revokes all tokens belonging to that `family_id`, logging the attacker and legitimate user out.

  

```python

# Reuse Detection Trigger

if stored_token.revoked:

    db.query(RefreshToken).filter(

        RefreshToken.family_id == stored_token.family_id

    ).update({"revoked": True})

    db.commit()

    raise HTTPException(

        status_code=401,

        detail="Revoked refresh token reused. All tokens in this family have been invalidated."

    )

```

  

---

  

### Method 4: OAuth 2.0 & OpenID Connect (Google)

**Endpoint**: `POST /oauth`

  

Allows external applications and service instances to authenticate users using their verified Google identity.

  

```python

@app.post("/oauth", response_model=AuthResponse)

def oauth_auth_endpoint(payload: AuthRequest, response: Response, db: DbSession = Depends(get_db)):

    return execute_authentication(payload, "oauth", response, db)

```

  

#### Essential OAuth Parameters Explained

- **`client_id`**: Public identifier assigned to your application in Google Cloud Console.

- **`client_secret`**: Confidential secret known only to your backend server and Google, used during authorization code exchange.

- **`redirect_uri`**: Authorized callback URL where Google returns users after authentication. Must match the Google Cloud Console exactly.

- **`response_type="code"`**: Tells Google to return a one-time Authorization Code (Authorization Code Flow).

- **`scope="openid email profile"`**: Permissions requested from the user:

  - `openid`: Enables OpenID Connect, requesting an ID token.

  - `email`: Grants access to user's verified email address.

  - `profile`: Grants access to basic profile attributes (name, picture).

- **`state`**: Cryptographically secure random token generated by the server. Passed to Google and returned in callback to prevent CSRF.

- **`nonce`**: Cryptographically secure random value embedded in the Google ID Token payload to prevent replay attacks.

- **`id_token`**: Cryptographically signed JWT issued by Google verifying user identity.

- **`clock_skew_in_seconds=10`**: Tolerates up to 10 seconds of time drift between Google's servers and local server clock during verification.

  

---

  

## 7. Centralized Universal Logout

  

### The Challenge of JWT Logout

Traditional session logout simply deletes the database row. However, **JWT access tokens are stateless**: because their signature is cryptographically valid until expiration (`exp`), deleting client cookies does not invalidate an access token if someone still holds the token string!

  

### The 3-Pillar Solution

  

```mermaid

flowchart TD

    Client["Client POST /logout {'username': '...'}"] --> LogoutHandler["Centralized Logout Endpoint"]

    LogoutHandler --> P1["1. Delete all DB rows in `sessions` table"]

    LogoutHandler --> P2["2. Delete all DB rows in `refresh_tokens` table"]

    LogoutHandler --> P3["3. Increment `USER_TOKEN_VERSIONS[user.id] += 1`"]

    LogoutHandler --> P4["4. Set response headers to wipe all client cookies"]

  

    P1 --> CheckSession{"Old Session calls GET /verify"}

    CheckSession -->|Session not found in DB| 401A["401 Invalid session"]

  

    P2 --> CheckRefresh{"Old Refresh Token calls POST /jwt/refresh"}

    CheckRefresh -->|Token not found in DB| 401B["401 Invalid refresh token"]

  

    P3 --> CheckJWT{"Old Access Token calls GET /verify"}

    CheckJWT -->|Token version mismatch| 401C["401 Token revoked"]

```

  

#### Endpoint Code (`POST /logout`)

```python

USER_TOKEN_VERSIONS: dict[int, int] = {}

  

@app.post("/logout")

def logout(payload: LogoutRequest, response: Response, db: DbSession = Depends(get_db)):

    user = db.query(UserDatabase).filter(UserDatabase.username == payload.username).first()

    if not user:

        raise HTTPException(status_code=404, detail="User not found")

  

    # 1. Invalidate all DB sessions

    db.query(Session).filter(Session.user_id == user.id).delete()

  

    # 2. Invalidate all DB refresh tokens

    db.query(RefreshToken).filter(RefreshToken.user_id == user.id).delete()

  

    # 3. Bump user token version (kills all active access tokens immediately)

    USER_TOKEN_VERSIONS[user.id] = USER_TOKEN_VERSIONS.get(user.id, 1) + 1

  

    db.commit()

  

    # 4. Wipe client cookies

    response.delete_cookie("session_id", path="/")

    response.delete_cookie("access_token", path="/")

    response.delete_cookie("refresh_token", path="/")

  

    return {"status": "success", "message": f"User '{user.username}' logged out successfully."}

```

  

---

  

## 8. Introspection Endpoint (`GET /verify`)

  

Deployed microservices need a single endpoint to verify whether an incoming request from a user is authenticated. `GET /verify` introspects **either a Bearer JWT or a Session Cookie**:

  

```python

@app.get("/verify")

def verify_token_or_session(

    bearer: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),

    session_id: str | None = Cookie(default=None),

    db: DbSession = Depends(get_db),

):

    # 1. Bearer JWT Introspection

    if bearer and bearer.credentials:

        payload = decode_jwt(bearer.credentials)

        user_id = int(payload.get("sub"))

        user = db.query(UserDatabase).filter(UserDatabase.id == user_id).first()

  

        if not user or not user.is_active:

            raise HTTPException(status_code=401, detail="User not found or inactive")

  

        # Verify token version hasn't been revoked via logout

        expected_version = USER_TOKEN_VERSIONS.get(user.id, 1)

        if payload.get("token_version") != expected_version:

            raise HTTPException(status_code=401, detail="Token has been revoked")

  

        return {"valid": True, "auth_type": "jwt", "user_id": user.id, "username": user.username}

  

    # 2. Session Cookie Introspection

    if session_id:

        session_hash = hashlib.sha256(session_id.encode()).hexdigest()

        session_record = db.query(Session).filter(

            Session.session_id_hash == session_hash,

            Session.expires_at > datetime.now(timezone.utc),

        ).first()

  

        if session_record and session_record.user and session_record.user.is_active:

            return {"valid": True, "auth_type": "session", "user_id": session_record.user.id, "username": session_record.user.username}

  

        raise HTTPException(status_code=401, detail="Invalid session")

  

    raise HTTPException(status_code=401, detail="No authentication credentials provided")

```

  

---

  

## 9. Master Unified Route (`POST /auth`)

  

For deployed instances that want a single entry point, `POST /auth` accepts `username`, `password`, `auth_type`, and `app_name`:

  

```python

@app.post("/auth", response_model=AuthResponse)

def unified_auth_endpoint(payload: AuthRequest, response: Response, db: DbSession = Depends(get_db)):

    target_type = (payload.auth_type or "jwt").lower()

    return execute_authentication(payload, target_type, response, db)

```

  

---

  

## 10. Automated Testing with Pytest (In-Memory Execution)

  

### How Pytest Runs Without Uvicorn Running

A common point of confusion is whether Uvicorn (`uvicorn app.main:app`) must be running before executing `pytest`. **It does NOT.**

  

```mermaid

flowchart LR

    subgraph Browser / Postman

        Client1["Browser / Postman"] -->|TCP Network Socket :8000| Server["Uvicorn Server"]

        Server -->|ASGI Protocol| App1["FastAPI Application"]

    end

  

    subgraph Pytest In-Memory

        PytestRunner["Pytest Test Function"] -->|Direct Python Call| TestClient["fastapi.testclient.TestClient"]

        TestClient -->|In-Memory Call| App2["FastAPI Application"]

    end

```

  

#### Why TestClient is In-Memory

1. `TestClient` (built on `httpx`) imports the ASGI `app` object directly into memory in the **same Python process**.

2. Calling `client.get(...)` passes the ASGI request scope dictionary directly to `app(scope, receive, send)` as an internal Python function call.

3. No network sockets are bound, no ports are opened, and execution runs at hundreds of requests per second with zero port conflict risk.

4. **What DOES need to be running**: The database (PostgreSQL) must be running, because SQLAlchemy database queries are real.

  

### Test Isolation via `unique_string()`

To ensure tests are idempotent and can be run repeatedly without database unique constraint collisions, dynamic test strings are generated:

  

```python

# tests/utils.py

import uuid

def unique_string(prefix: str = "test") -> str:

    return f"{prefix}_{uuid.uuid4().hex[:8]}"

```

  

### The Test Tasks

  

| Test File | Key Test Tasks |

| :--- | :--- |

| **`test_health.py`** | Validates `GET /health` returns `200` with `{"status": "Healthy"}`. |

| **`test_basic_auth.py`** | Tests registration and login via `POST /basic` and master `POST /auth`. Rejects invalid passwords with `401`. |

| **`test_session.py`** | Tests session creation, `session_id` cookie setting, introspection on `GET /verify`, and asserts old session fails after `POST /logout`. |

| **`test_jwt.py`** | Tests `POST /jwt`, token introspection on `GET /verify`, refresh token rotation, reuse detection family revocation, and instant token invalidation upon `POST /logout`. |

| **`test_oauth.py`** | Tests direct OAuth provisioning via `POST /oauth` with `email` and `app_name`, and verifies token on `GET /verify`. |

  

---

  

## 11. CI/CD Pipeline with GitHub Actions

  

Automated continuous integration pipeline configured in [`.github/workflows/ci.yml`](file:///d:/Learning/Python/networking/Auth-playground/.github/workflows/ci.yml).

  

```mermaid

sequenceDiagram

    autonumber

    actor Dev as Developer

    participant Git as GitHub Actions

    participant Docker as PostgreSQL Container

    participant Py as Pytest Runner

  

    Dev->>Git: git push origin dev/main

    Git->>Docker: Start postgres:15 container on port 5432

    Docker-->>Git: Container healthy (pg_isready)

    Git->>Git: Install dependencies from requirements.txt

    Git->>Py: Execute `pytest -v`

    Py->>Docker: Initialize tables & run tests

    Py-->>Git: All tests pass

    Git-->>Dev: Green Checkmark

```

  

### Workflow Configuration (`.github/workflows/ci.yml`)

```yaml

name: CI/CD Pipeline

  

on:

  push:

    branches: [ main, master, dev ]

  pull_request:

    branches: [ main, master, dev ]

  

jobs:

  test:

    runs-on: ubuntu-latest

  

    services:

      postgres:

        image: postgres:15

        env:

          POSTGRES_USER: postgres

          POSTGRES_PASSWORD: root

          POSTGRES_DB: auth_methods_test

        ports:

          - 5432:5432

        options: >-

          --health-cmd pg_isready

          --health-interval 10s

          --health-timeout 5s

          --health-retries 5

  

    env:

      JWT_SECRET_KEY: ci_cd_test_jwt_secret_key_123456789

      GOOGLE_CLIENT_ID: mock_google_client_id

      GOOGLE_CLIENT_SECRET: mock_google_client_secret

      GOOGLE_REDIRECT_URI: http://localhost:8000/oauth/google/callback

      DATABASE_URL: postgresql+psycopg://postgres:root@localhost:5432/auth_methods_test

  

    steps:

      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5

        with:

          python-version: "3.11"

          cache: "pip"

      - run: pip install -r requirements.txt

      - run: pytest -v

```

  
