# Centralized Authentication Service - API Reference & Integration Guide

This document provides complete technical specifications for integrating client web applications with the Centralized Authentication microservice hosted on Render.

---

## 1. Important Infrastructure Notice: Render Cold Starts

> **Render Free Tier Spin-Down Behavior:**
> Render instances spin down into an inactive/sleep state after periods of inactivity.
> When an instance is sleeping, the first incoming HTTP request triggers a cold-start container initialization, which typically incurs a latency of **30 to 60 seconds**.
> 
> **Integration Best Practice:**
> Before executing critical user-facing requests (such as registration or login), client applications should send an initial warm-up ping to the health endpoint (`GET /health`). Once a `200 OK` response is received, the service is fully awake and ready to handle authentication requests with minimal latency.

### Health Check (Cold-Start Wake-Up)

* **Method:** `GET`
* **Path:** `/health`
* **Headers:** None required

#### Example cURL
```bash
curl -X GET "https://<your-render-domain>.onrender.com/health"
```

#### Successful Response (`200 OK`)
```json
{
  "status": "Healthy"
}
```

---

## 2. Core Architecture: Application Provisioning & API Keys

Client applications follow a two-tier model:

1. **App Registration (Done Once by Developer):**
   * Register the consuming application via `POST /apps/register` with an `app_name`.
   * The service creates the application record, generates an API key (`ak_live_<token>`), stores its SHA-256 hash in PostgreSQL, and returns the raw key.
   * **This API key is displayed only once. Store it securely in the client application's configuration or `.env` file.**

2. **User Authentication (Ongoing API Calls):**
   * Pass the application's API key in the `X-API-Key` HTTP header on all authentication requests.
   * The server hashes the incoming key, resolves the application record, and scopes all user operations (register, login, sessions, tokens) to that application.
   * Client request bodies only need user credentials (`username`, `password`, `email`). There is no need to pass `app_name` or `app_id`.
   * API keys are not echoed back in user authentication responses.

---

## 3. Application Registration Endpoint

### Register an Application

* **Method:** `POST`
* **Path:** `/apps/register`
* **Headers:**
  ```http
  Content-Type: application/json
  ```

#### Request Payload
```json
{
  "app_name": "EcommercePlatform"
}
```

#### Example cURL
```bash
curl -X POST "https://<your-render-domain>.onrender.com/apps/register" \
  -H "Content-Type: application/json" \
  -d '{
    "app_name": "EcommercePlatform"
  }'
```

#### Successful Response (`201 Created`)
```json
{
  "app_id": 1,
  "app_name": "EcommercePlatform",
  "api_key": "ak_live_7xK89sP3u4Bv9Q2e1mZ..."
}
```

---

## 4. User Authentication Endpoints

---

### Endpoint A: Unified Authentication Dispatcher

A single consolidated endpoint capable of handling all four authentication schemes dynamically via the `auth_type` parameter.

* **Method:** `POST`
* **Path:** `/auth`
* **Headers:**
  ```http
  Content-Type: application/json
  X-API-Key: ak_live_...
  ```

#### Request Payload
```json
{
  "username": "alice",
  "password": "SecurePassword123!",
  "email": "alice@example.com",
  "auth_type": "jwt"
}
```

* Supported `auth_type` values: `"basic"`, `"session"`, `"jwt"`, `"oauth"` (Defaults to `"jwt"` if omitted).

---

### Endpoint B: Basic Authentication

Traditional credential authentication. Registers a new user on first attempt or validates credentials against stored Argon2 password hashes on subsequent calls.

* **Method:** `POST`
* **Path:** `/basic-auth`
* **Headers:**
  ```http
  Content-Type: application/json
  X-API-Key: ak_live_...
  ```

#### Request Payload
```json
{
  "username": "developer_dan",
  "password": "dan_password_456",
  "email": "dan@example.com"
}
```

#### Example cURL
```bash
curl -X POST "https://<your-render-domain>.onrender.com/basic-auth" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ak_live_7xK89sP3u4Bv9Q2e1mZ..." \
  -d '{
    "username": "developer_dan",
    "password": "dan_password_456",
    "email": "dan@example.com"
  }'
```

#### Successful Registration Response (`200 OK`)
```json
{
  "status": "registered",
  "message": "New user registered successfully",
  "auth_type": "basic",
  "app_name": "EcommercePlatform",
  "app_id": 1,
  "user_id": 10,
  "username": "developer_dan",
  "email": "dan@example.com",
  "session_id": null,
  "access_token": null,
  "token_type": null,
  "refresh_token": null
}
```

#### Successful Login / Verification Response (`200 OK`)
```json
{
  "status": "verified",
  "message": "User credentials verified successfully",
  "auth_type": "basic",
  "app_name": "EcommercePlatform",
  "app_id": 1,
  "user_id": 10,
  "username": "developer_dan",
  "email": "dan@example.com"
}
```

---

### Endpoint C: Session-Based Authentication

Generates a secure cryptographically random session token stored in PostgreSQL as a SHA-256 hash. Returns both a JSON `session_id` and an `HttpOnly` cookie.

* **Method:** `POST`
* **Path:** `/session-auth`
* **Headers:**
  ```http
  Content-Type: application/json
  X-API-Key: ak_live_...
  ```

#### Request Payload
```json
{
  "username": "session_user",
  "password": "session_password_789"
}
```

#### Example cURL
```bash
curl -i -X POST "https://<your-render-domain>.onrender.com/session-auth" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ak_live_7xK89sP3u4Bv9Q2e1mZ..." \
  -d '{
    "username": "session_user",
    "password": "session_password_789"
  }'
```

#### Response Headers
```http
Set-Cookie: session_id=s_xyz123...; Max-Age=86400; Path=/; HttpOnly; SameSite=lax
```

#### Response Body (`200 OK`)
```json
{
  "status": "verified",
  "message": "User credentials verified successfully",
  "auth_type": "session",
  "app_name": "EcommercePlatform",
  "app_id": 1,
  "user_id": 11,
  "username": "session_user",
  "email": "session_user@ecommerceplatform.com",
  "session_id": "s_xyz123..."
}
```

---

### Endpoint D: JWT Authentication (Access + Refresh Token)

Issues short-lived JWT access tokens (15-minute expiration) with claims (`sub`, `app_id`, `token_version`, `iat`, `exp`) and long-lived refresh tokens (7-day expiration) supporting reuse detection and token family revocation.

* **Method:** `POST`
* **Path:** `/jwt-auth`
* **Headers:**
  ```http
  Content-Type: application/json
  X-API-Key: ak_live_...
  ```

#### Request Payload
```json
{
  "username": "jwt_client",
  "password": "jwt_password_321"
}
```

#### Example cURL
```bash
curl -X POST "https://<your-render-domain>.onrender.com/jwt-auth" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ak_live_7xK89sP3u4Bv9Q2e1mZ..." \
  -d '{
    "username": "jwt_client",
    "password": "jwt_password_321"
  }'
```

#### Response Body (`200 OK`)
```json
{
  "status": "verified",
  "message": "User credentials verified successfully",
  "auth_type": "jwt",
  "app_name": "EcommercePlatform",
  "app_id": 1,
  "user_id": 12,
  "username": "jwt_client",
  "email": "jwt_client@ecommerceplatform.com",
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "refresh_token": "rt_89a7f01c..."
}
```

---

### Endpoint E: JWT Token Refresh (Rotation)

Rotates an active refresh token: marks the existing token as revoked, issues a new refresh token within the same token family, and produces a fresh access token. If a revoked refresh token is reused, all tokens in the entire family are immediately invalidated.

* **Method:** `POST`
* **Path:** `/jwt-auth/refresh`
* **Headers:**
  ```http
  Content-Type: application/json
  ```

#### Request Payload
```json
{
  "refresh_token": "rt_89a7f01c..."
}
```

#### Example cURL
```bash
curl -X POST "https://<your-render-domain>.onrender.com/jwt-auth/refresh" \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "rt_89a7f01c..."
  }'
```

#### Response Body (`200 OK`)
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...new",
  "token_type": "bearer",
  "refresh_token": "rt_new_family_token...",
  "app_id": 1,
  "user_id": 12
}
```

---

### Endpoint F: OAuth Authentication

Handles social authentication provisioning. Links external identities (e.g. Google OAuth) to application users and returns JWT access and refresh tokens.

* **Method:** `POST`
* **Path:** `/oauth`
* **Headers:**
  ```http
  Content-Type: application/json
  X-API-Key: ak_live_...
  ```

#### Request Payload
```json
{
  "email": "user@gmail.com",
  "username": "google_user"
}
```

#### Example cURL
```bash
curl -X POST "https://<your-render-domain>.onrender.com/oauth" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ak_live_7xK89sP3u4Bv9Q2e1mZ..." \
  -d '{
    "email": "user@gmail.com",
    "username": "google_user"
  }'
```

#### Response Body (`200 OK`)
```json
{
  "status": "authenticated",
  "message": "User authenticated successfully",
  "auth_type": "oauth",
  "app_name": "EcommercePlatform",
  "app_id": 1,
  "user_id": 13,
  "username": "google_user",
  "email": "user@gmail.com",
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "refresh_token": "rt_social_token..."
}
```

---

## 5. Verification & Logout Endpoints

---

### Endpoint G: Token & Session Introspection

Unified verification endpoint for client microservices, gateways, or reverse proxies. Inspects either an incoming Bearer JWT or an active `session_id` cookie.

* **Method:** `GET`
* **Path:** `/verify`

#### Verification via JWT (Bearer)
```bash
curl -X GET "https://<your-render-domain>.onrender.com/verify" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

#### Verification via Session Cookie
```bash
curl -X GET "https://<your-render-domain>.onrender.com/verify" \
  --cookie "session_id=s_xyz123..."
```

#### Successful Introspection Response (`200 OK`)
```json
{
  "valid": true,
  "auth_type": "jwt",
  "user_id": 12,
  "username": "jwt_client",
  "email": "jwt_client@ecommerceplatform.com",
  "app_id": 1
}
```

---

### Endpoint H: Centralized Universal Logout

Invalidates all active credentials for a given user across the entire application:
1. Deletes all active DB session records.
2. Deletes all active DB refresh tokens.
3. Increments the in-memory token version (`USER_TOKEN_VERSIONS`), immediately invalidating all unexpired JWT access tokens.
4. Clears authentication cookies (`session_id`, `access_token`, `refresh_token`).

* **Method:** `POST`
* **Path:** `/logout`
* **Headers:**
  ```http
  Content-Type: application/json
  ```

#### Request Payload
```json
{
  "username": "jwt_client"
}
```

#### Example cURL
```bash
curl -X POST "https://<your-render-domain>.onrender.com/logout" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "jwt_client"
  }'
```

#### Successful Logout Response (`200 OK`)
```json
{
  "status": "success",
  "message": "User 'jwt_client' logged out successfully. All sessions and tokens have been invalidated."
}
```

---

## 6. Standard Error Responses

| Status Code | Error Detail | Cause / Resolution |
| :--- | :--- | :--- |
| `400 Bad Request` | `"app_name cannot be empty"` | Empty name sent to `/apps/register`. |
| `400 Bad Request` | `"Username and password are required"` | Missing required credentials in request body. |
| `400 Bad Request` | `"Email is required for OAuth"` | OAuth request missing email parameter. |
| `401 Unauthorized` | `"API key is required for application authentication"` | Request sent without `X-API-Key` header or payload `api_key`. |
| `401 Unauthorized` | `"Invalid API key for application"` | Provided API key does not match any registered application. |
| `401 Unauthorized` | `"Invalid credentials"` | Incorrect username or password. |
| `401 Unauthorized` | `"Token expired"` / `"Token has been revoked"` | JWT is past expiration or invalidated by logout. |
| `401 Unauthorized` | `"Revoked refresh token reused..."` | Security violation: compromised token family invalidated. |
| `404 Not Found` | `"User not found"` | Target user does not exist for the specified application. |
| `409 Conflict` | `"Application '<name>' already exists"` | Attempted to register an application name that is already taken. |

---

## 7. End-to-End Client Workflow Example

```
                    Client Developer / App                         Centralized Auth Service
                             │                                                │
[1. WAKE-UP]                 │  GET /health                                   │
                             │ ─────────────────────────────────────────────> │ (Wakes up Render instance)
                             │ <───────────────────────────────────────────── │ 200 OK {"status": "Healthy"}
                             │                                                │
[2. APP PROVISIONING]        │  POST /apps/register {"app_name": "MyStore"}   │
                             │ ─────────────────────────────────────────────> │ (Generates unique API key)
                             │ <───────────────────────────────────────────── │ 201 Created {"api_key": "ak_live_..."}
                             │  [Store API key in app backend .env]           │
                             │                                                │
[3. USER AUTHENTICATION]     │  POST /jwt-auth                                │
                             │  Headers: X-API-Key: ak_live_...               │
                             │  Body:    {"username": "...", "password": "..."│
                             │ ─────────────────────────────────────────────> │ (Resolves App, authenticates User)
                             │ <───────────────────────────────────────────── │ 200 OK (Returns JWT tokens)
                             │                                                │
[4. PROTECTED RESOURCE]      │  GET /verify                                   │
                             │  Headers: Authorization: Bearer <access_token> │
                             │ ─────────────────────────────────────────────> │ (Checks signature & version)
                             │ <───────────────────────────────────────────── │ 200 OK {"valid": true, ...}
```
