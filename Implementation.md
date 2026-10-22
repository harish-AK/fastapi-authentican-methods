# Client Integration Guide: Using the Centralized Auth Service

This guide explains how to integrate your web or mobile application with the Centralized Authentication microservice to handle all your user registration, login, token management, session handling, and social logins.

---

## 1. Integration Architecture & Workflow

As a client developer, your application connects to the Auth Service as a consumer:

```
+-----------------------------------------------------------------------------------------+
|                                    YOUR CLIENT APP                                      |
|   (Frontend Web App / Mobile App / Backend Service)                                     |
+-----------------------------------------------------------------------------------------+
       |                                                            ^
       | 1. One-time Setup: Register app                            |
       |    POST /apps/register {"app_name": "MyApp"}               |
       |    <== Receives API Key: ak_live_... (Store in .env)       |
       |                                                            |
       | 2. End-User Actions:                                       |
       |    Pass header `X-API-Key: ak_live_...`                    |
       |    ==> /basic-auth, /session-auth, /jwt-auth, /oauth       |
       v                                                            |
+-----------------------------------------------------------------------------------------+
|                              CENTRALIZED AUTH SERVICE                                   |
|   (Manages User Database, Argon2 Hashing, Sessions, JWTs, and Google OAuth)             |
+-----------------------------------------------------------------------------------------+
```

### Live Service URL & Infrastructure Warm-Up

> [!NOTE]
> **Active Service URL:** `https://authentican-methods.onrender.com`
> 
> This service is currently deployed live on Render's free tier. Free instances spin down after periods of inactivity, so the first request may experience a **30–60 second cold start** while the container initializes. Also, Render free tier databases/services may expire after the free tier period.

Before sending critical user requests, your application should optionally send a warm-up ping:
* **Endpoint:** `GET https://authentican-methods.onrender.com/health`
* **Response (`200 OK`):** `{"status": "Healthy"}`

---

## 2. Step 1: Register Your Application (One-Time Setup)

Before authenticating users, register your application to obtain a dedicated **API Key**. All users, sessions, and tokens created with this key are isolated to your application.

### Request
* **Method:** `POST`
* **URL:** `https://authentican-methods.onrender.com/apps/register`
* **Headers:** `Content-Type: application/json`

```bash
curl -X POST "https://authentican-methods.onrender.com/apps/register" \
  -H "Content-Type: application/json" \
  -d '{
    "app_name": "EcommercePlatform"
  }'
```

### Response (`201 Created`)
```json
{
  "app_id": 1,
  "app_name": "EcommercePlatform",
  "api_key": "ak_live_u87gYt67Bv9Q2e1mZ3xK89sP..."
}
```

> [!IMPORTANT]
> **Store your API Key securely:** The `api_key` is only displayed once upon creation. Save it in your application's environment configuration:
> ```env
> AUTH_SERVICE_API_KEY=ak_live_u87gYt67Bv9Q2e1mZ3xK89sP...
> AUTH_SERVICE_URL=https://authentican-methods.onrender.com
> ```

---

## 3. Step 2: Authentication Methods

On all user authentication requests, send your application API key in the **`X-API-Key`** header.

> **Automatic Registration:** For all credential-based endpoints (`/basic-auth`, `/session-auth`, `/jwt-auth`), if the user does not exist yet, the service **automatically registers them** and returns status `"registered"`. On subsequent calls with the same credentials, it verifies the password and returns status `"verified"`.

---

### Method A: Basic Authentication

Use this for traditional username and password authentication without cookies or tokens.

* **Endpoint:** `POST /basic-auth`
* **Headers:**
  ```http
  Content-Type: application/json
  X-API-Key: ak_live_...
  ```

#### Sample Request Payload
```json
{
  "username": "alice",
  "password": "SecurePassword123!",
  "email": "alice@example.com"
}
```

#### Sample Response (`200 OK`)
```json
{
  "status": "verified",
  "message": "User verified successfully",
  "auth_type": "basic",
  "app_name": "EcommercePlatform",
  "app_id": 1,
  "user_id": 10,
  "username": "alice",
  "email": "alice@example.com"
}
```

---

### Method B: Session-Based Authentication

Use this when you want browser-based cookie authentication. The Auth Service stores a SHA-256 hash of the session in PostgreSQL and returns both a JSON response and a secure cookie.

* **Endpoint:** `POST /session-auth`
* **Headers:**
  ```http
  Content-Type: application/json
  X-API-Key: ak_live_...
  ```

#### Sample Request Payload
```json
{
  "username": "alice",
  "password": "SecurePassword123!",
  "email": "alice@example.com"
}
```

#### Sample Response
**HTTP Response Headers:**
```http
Set-Cookie: session_id=s_9a8f7c...; Max-Age=86400; Path=/; HttpOnly; SameSite=none; Secure
```

**JSON Body (`200 OK`):**
```json
{
  "status": "verified",
  "message": "User verified successfully",
  "auth_type": "session",
  "app_name": "EcommercePlatform",
  "app_id": 1,
  "user_id": 10,
  "username": "alice",
  "email": "alice@example.com",
  "session_id": "s_9a8f7c..."
}
```

#### How your client uses the session:
For subsequent requests to protected endpoints or `/verify`, browsers automatically send the `session_id` cookie when `credentials: 'include'` (in `fetch`) or `withCredentials: true` (in `axios`) is enabled.

---

### Method C: JWT Authentication (Access + Refresh Token)

Use this for SPAs, mobile apps, and microservices requiring stateless tokens and token rotation.

* **Endpoint:** `POST /jwt-auth`
* **Headers:**
  ```http
  Content-Type: application/json
  X-API-Key: ak_live_...
  ```

#### Sample Request Payload
```json
{
  "username": "alice",
  "password": "SecurePassword123!",
  "email": "alice@example.com"
}
```

#### Sample Response (`200 OK`)
```json
{
  "status": "verified",
  "message": "User verified successfully",
  "auth_type": "jwt",
  "app_name": "EcommercePlatform",
  "app_id": 1,
  "user_id": 10,
  "username": "alice",
  "email": "alice@example.com",
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMCIsInVzZXJuYW1lIjoiYWxpY2UiLCJhcHBfaWQiOjEsInRva2VuX3ZlcnNpb24iOjEsImV4cCI6MTcyOTYyOTk5OX0...",
  "token_type": "bearer",
  "refresh_token": "rt_89a7f01c3d..."
}
```

#### Refreshing Tokens (Rotation):
When the 1-hour `access_token` expires, exchange your `refresh_token` for a new token pair without requiring user re-login:

* **Endpoint:** `POST /jwt-auth/refresh`
* **Payload:**
  ```json
  {
    "refresh_token": "rt_89a7f01c3d..."
  }
  ```
* **Response (`200 OK`):**
  ```json
  {
    "access_token": "eyJhbGciOiJIUzI1Ni...new_access_token",
    "token_type": "bearer",
    "refresh_token": "rt_new_rotated_family_token...",
    "app_id": 1,
    "user_id": 10
  }
  ```

> [!TIP]
> **Token Family Protection:** If a revoked refresh token is intercepted and reused, the service automatically invalidates all refresh tokens in that family, blocking the attacker.

---

### Method D: Google OAuth 2.0 (Social Login)

For "Sign in with Google", your client application delegates identity verification to Google through the Auth Service.

#### Flow Overview:
```mermaid
sequenceDiagram
    autonumber
    actor User as User Browser
    participant Client as Your Client Web App
    participant Auth as Auth Service
    participant Google as Google Accounts

    User->>Client: 1. Clicks "Sign in with Google"
    Client->>User: 2. Redirects to Auth Service /oauth/google/login
    User->>Auth: 3. GET /oauth/google/login?api_key=ak_live_...&redirect_uri=https://myapp.com/callback
    Auth-->>User: 4. Redirects (302) to Google Consent Screen
    User->>Google: 5. Signs in & approves permissions
    Google-->>User: 6. Redirects (302) to Auth Service /oauth/google/callback?code=XYZ
    User->>Auth: 7. Hits callback
    Auth->>Google: 8. Exchanges code for Google profile (verified email)
    Auth->>Auth: 9. Creates user in DB & generates access/refresh tokens
    Auth-->>User: 10. Redirects (302) to your redirect_uri with tokens in query params
    User->>Client: 11. Hits your callback with ?access_token=...&refresh_token=...
    Client->>Client: 12. Stores tokens and logs user in!
```

#### Step 1: Redirect User to Login
When the user clicks "Sign in with Google" on your website, redirect their browser to:

```text
https://authentican-methods.onrender.com/oauth/google/login?api_key=YOUR_API_KEY&redirect_uri=https://your-client-app.com/oauth-callback
```

| Parameter | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `api_key` | Query | Yes | Your application API key (`ak_live_...`). |
| `redirect_uri` | Query | Yes | The URL on **your** frontend where the user should be returned after logging in. |

#### Step 2: Handle the Callback on Your Frontend
After the user completes login with Google, the Auth Service redirects the browser back to your `redirect_uri` with the tokens attached:

```text
https://your-client-app.com/oauth-callback?access_token=eyJhbGci...&refresh_token=rt_...&token_type=bearer
```

**JavaScript Example (on `/oauth-callback` page):**
```javascript
// Extract tokens from URL search params
const params = new URLSearchParams(window.location.search);
const accessToken = params.get('access_token');
const refreshToken = params.get('refresh_token');

if (accessToken) {
  // Store securely (e.g. in memory or secure storage)
  localStorage.setItem('access_token', accessToken);
  localStorage.setItem('refresh_token', refreshToken);
  
  // Redirect to user dashboard
  window.location.href = '/dashboard';
}
```

---

## 4. Step 3: Verification & Protecting Your Routes

When a client application receives a request from an end-user, it can verify whether the user's token or session is valid by calling the `/verify` introspection endpoint.

* **Endpoint:** `GET /verify`

### Case 1: Verifying a Bearer JWT Token
Pass the user's `access_token` in the `Authorization` header:

```bash
curl -X GET "https://authentican-methods.onrender.com/verify" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### Case 2: Verifying a Session Cookie
Pass the user's `session_id` cookie:

```bash
curl -X GET "https://authentican-methods.onrender.com/verify" \
  --cookie "session_id=s_9a8f7c..."
```

### Verification Response (`200 OK`)
```json
{
  "valid": true,
  "auth_type": "jwt",
  "user_id": 10,
  "username": "alice",
  "email": "alice@example.com",
  "app_id": 1
}
```

* If the token/session is expired, revoked, or invalid, `/verify` returns **`401 Unauthorized`**.

---

## 5. Step 4: Centralized Logout

When a user logs out, calling `/logout` invalidates all their credentials across all active devices:
1. Deletes all active database session records for that user.
2. Deletes all database refresh tokens for that user.
3. Increments token version to immediately invalidate any active JWT access tokens.
4. Clears authentication cookies.

* **Endpoint:** `POST https://authentican-methods.onrender.com/logout`
* **Headers:** `Content-Type: application/json`

### Request Payload
```bash
curl -X POST "https://authentican-methods.onrender.com/logout" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "app_name": "EcommercePlatform"
  }'
```

### Response (`200 OK`)
```json
{
  "status": "success",
  "message": "User 'alice' logged out successfully. All sessions and tokens have been invalidated."
}
```
