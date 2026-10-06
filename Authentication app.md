
Refer Authentication - [[Authentication]]

```
auth-playground/
│
├── app/
│   ├── __init__.py
│   └── main.py
│
├── tests/
│
├── .env
|-- database.py
|-- settings.py
├── .gitignore
├── requirements.txt
└── README.md
```

>settings.py

```
settings.py 
	→ application configuration 
	→ JWT secret 
	→ token expiry 
	→ database URL 
	→ environment-specific settings
```

database.py -> to make postgres connection
```python
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = "postgresql+psycopg://postgres:YOUR_PASSWORD@localhost:5432/auth_methods"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)
Base = declarative_base()
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
```

User database model
```python
class UserDatabase(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, nullable=False,unique=True)
    password_hash = Column(String, nullable=False)
    email = Column(String, nullable=False,unique=True)
    is_active = Column(Boolean, default=True,nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
```

> Alembic -> for migration


```cmd
pip install alembic
```
Alembic is an python package

```
Your SQLAlchemy models
        ↓
      Alembic
        ↓
   Migration file
        ↓
    PostgreSQL
```

with Alembic we will have migration history like 
```
001_create_users_table
002_add_unique_email
003_add_sessions_table
004_add_oauth_accounts
```

To initialize alembic
```cmd
alembic init alembic
```

This will create a folder called alembic which will have a set of files.

```cmd
├── alembic/
│   ├── versions/
│   ├── env.py
│   ├── script.py.mako
│   └── README
```

> Connect alembic to postgres

```cmd
alembic.ini
```

This cmd will open a text file, in that update,
sqlalchemy.url = postgresql+psycopg://postgres:root@localhost/auth_methods (your postgres connection)
will have **driver** (postgresql+psycopg) as prefix for sqlalchemy.url

> Register model's metadata in alembic env.py

- import the created models  (import **Base** from database.py which holds postgres connection)
- target_metadata = Base.metadata in env.py
so that alembic can know my UserDatabase model fields.

> Run migrations (to create the table in specified connection)

```c
alembic revision --autogenerate -m "create users table"
```
This will create a migration file which tells us whats will be created in postgres connection (like table and its fields)

>[!IMPORTANT] This will not create table in potgres yet


```c
alembic upgrade head
```
This will create a table in postgres.

alembic_version -> a table in the connection which will have migration histories

---

### Password hashing

```
pip install argon2-cffi
```
An algo to hash password

```python
from argon2 import PasswordHasher
password_hasher = PasswordHasher()
  
def hash_password(password: str) -> str:
    """
    Hash a password using Argon2.
    """
    return password_hasher.hash(password)

def verify_password(password: str, password_hash: str) -> bool:
    """
    Verify a password against its hash.
    """
    return password_hasher.verify(password_hash, password)
  
password = "MyPassword123"
  
hashed = hash_password(password)
  
print(hashed)
print(verify_password(password, hashed)) # True
print(verify_password("WrongPassword", hashed)) # error cause password mismatched
```

> POST -> Create User

```python
class UserCreate(BaseModel):
    username: st
    email: EmailStr
    password: str
  
class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    is_active: bool
    created_at: datetime
  
@app.post("/users", response_model=UserResponse)
def create_user(user: UserCreate, db=Depends(get_db)):
    try:
        # Application-level checks for better error messages
        if db.query(UserDatabase).filter(
            UserDatabase.username == user.username
        ).first():
            raise HTTPException(
                status_code=409,
                detail="Username already exists"
            )
  
        if db.query(UserDatabase).filter(
            UserDatabase.email == user.email
        ).first():
            raise HTTPException(
                status_code=409,
                detail="Email already exists"
            )
  
        # Hash password only after validation/checks pass
        hashed_password = hash_password(user.password)
  
        new_user = UserDatabase(
            username=user.username,
            email=user.email,
            password_hash=hashed_password
        )
  
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
  
        return new_user
  
    except HTTPException:
        # Let our intentional HTTP errors pass through unchanged
        raise
  
    except IntegrityError:
        # Database remains the final source of truth.
        # This protects gainst race conditions between the checks above
        # and the INSERT.
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="Username or email already exists"
        )
  
    except Exception:
        # Unexpected application/database failure
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Failed to create user"
        )
```


---

### Basic authentication

```
Request 1 → credentials → verify → allow
Request 2 → credentials → verify → allow
Request 3 → credentials → verify → allow
```

> A reusable authentication dependency (Depends)

```
HTTP request
     ↓
Basic Auth dependency
     ↓
username/password
     ↓
database
     ↓
Argon2 verification
     ↓
UserDatabase
     ↓
endpoint receives authenticated user
```

> HTTP Basic Auth

In HTTP Basic Auth, the application expects a header that contains a username and a
password.
```
1. HTTPBasic
↓
Extract credentials from HTTP request

2. Your authentication dependency
↓
Find user + verify password

3. Your endpoint
↓
Perform the actual business operation
```

```python
from fastapi.security import HTTPBasic, HTTPBasicCredentials

security = HTTPBasic()
@app.get('/test')
def test(credentials: HTTPBasicCredentials = Depends(security), db=Depends(get_db)):
    user_in_db = db.query(UserDatabase).filter(
        UserDatabase.username == credentials.username
    ).first()
    if not user_in_db or not verify_password(credentials.password, user_in_db.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return {"username": credentials.username, "message": "Successfully authenticated!"}
```

> Verify password using HttpBasic

```python
security = HTTPBasic()
def get_current_user(db=Depends(get_db),credentials: HTTPBasicCredentials = Depends(security)):
    user_in_db = db.query(UserDatabase).filter(
        UserDatabase.username == credentials.username
    ).first()
    if not user_in_db or not verify_password(credentials.password, user_in_db.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return user_in_db
  
@app.get('/test')
def test(current_user: UserDatabase = Depends(get_current_user)):
    return {"username": current_user.username, "message": "Successfully authenticated!"}
```

Just like /test all endpoint will call get_current_user before every request.

>Final flow

```
Client
  ↓
username + password
  ↓
HTTP Basic
  ↓
get_current_user()
  ↓
database lookup
  ↓
Argon2 verification
  ↓
authenticated User
  ↓
protected endpoint
```

```
HTTPBasic
 ↓ 
HTTP layer "Extract username/password from the Authorization header" 
	↓ 
get_current_user() 
  ↓ 
Application authentication "Is this username/password actually valid?"
```

>[!IMPORTANT] 
>HttpBasic will extract the username and password from header

---

### Session based authentication

```
                LOGIN
                  │
          username + password
                  │
                  ▼
             Authenticate
                  │
                  ▼
          Create session
                  │
          ┌───────┴────────┐
          │                │
          ▼                ▼
    Session Store       Browser
    session_id ──→      session_id
    user_id             ↑
    expires_at           │
          ▲              │
          └──────────────┘
```

> The key idea

The **browser possesses the identifier**.
The **server possesses the authentication state**.
That's why it's called a **server-side session**.

```
**Cookie ≠ stateful**  
**Authorization header ≠ stateless**
```

To prevent XSS attacks, cookies are read by HTTP requests alone.
```
JavaScript
    ✕
    │
    │ cannot read
    ▼
HttpOnly session cookie
    │
    ▼
Browser automatically sends it
    │
    ▼
FastAPI
```

`HttpOnly` = JavaScript cannot read the cookie.

| Attribute  | Protects against                  |
| ---------- | --------------------------------- |
| `HttpOnly` | JavaScript reading the cookie     |
| `Secure`   | Cookie being sent over plain HTTP |

> CSRF (Cross-Site Request Forgery).

```
Victim logs into your app
        ↓
Browser has session cookie
        ↓
Victim visits malicious-site.com
        ↓
Malicious site causes a request to your-app.com
        ↓
Browser automatically includes your session cookie
        ↓
Your FastAPI app sees a valid session
        ↓
Request may be processed
```

with XSS -> attacker will steal the session id
with CSRF -> attacker → trick browser into using its existing session since browser has already holds the cookie.

for this CSRF issue samesite will be used
```
SameSite
   ↓
Should the browser SEND the cookie
when the request originates from another site?
   → Controls this
```

>[!Important]
>Cookie holds the session id


```
             Browser
                │
        Cookie: session_id
                │
                ▼
        ┌──────────────┐
        │   FastAPI    │
        └──────┬───────┘
               │
          session_id
               │
               ▼
        ┌──────────────┐
        │   sessions   │
        │    table     │
        └──────┬───────┘
               │
            user_id
               │
               ▼
        ┌──────────────┐
        │    users     │
        │    table     │
        └──────────────┘
```

> Generate session id

secrets package

**Token Generation**: Use `secrets.token_urlsafe()`, `secrets.token_hex()`, or `secrets.token_bytes()` to generate secure tokens for password resets, session IDs, or API keys.

- Uses Python's **cryptographically secure random generator**.
- Generates **32 random bytes**.
- Encodes them in a URL-safe representation.

>[!NOTE]
>**Key distinction:** Hashing ≠ Encryption. Encryption is _reversible_ (with a key); hashing is _not_

> Sessions table

```python
class Session(Base):
    __tablename__ = "sessions"
    id = Column(Integer, primary_key=True)
    session_id_hash = Column(String(64), nullable=False,unique=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"),nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False)
```

make the migrations
```c
alembic revision --autogenerate -m "create sessions table"
```

Create table in the connection
```c
alembic upgrade head
```

Login API
```python
@app.post("/login")
def login(
    login_data: UserLogin,
    response: Response,
    db: DbSession = Depends(get_db),
):
    user = db.query(UserDatabase).filter(
        UserDatabase.username == login_data.username
    ).first()

    if not user or not verify_password(login_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )
  
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User is not active",
        )
  
    session_id = create_session(user.id, db)
  
    response.set_cookie(
        key="session_id",
        value=session_id,
        httponly=True,
        samesite="lax",
        secure=True,
    )
  
    return {"message": "Login successful"}
```

- The below code is responsible for set the cookie in browser.
- After login, cookie will be set in the session, so for every request we dont need to pass it, cookie will be taken automatically.  
```python
response.set_cookie(
        key="session_id",
        value=session_id,
        httponly=True,
        samesite="lax",
        secure=True,
    )
```

>[!NOTE]
>Backend should validate session data

For each request following steps should be followed.
```
session_id = "abc123"
       ↓
SHA-256(session_id)
       ↓
search sessions table
       ↓
does session exist?
       ↓
has it expired?
       ↓
which user does it belong to?
       ↓
is that user active?
       ↓
allow request
```

>Login endpoint creates the cookie; browser stores and sends it; `Cookie()` extracts it; our server validates it.

---

>Define relationship

```python
from sqlalchemy.orm import relationship
```

In Userdatabase model
```python
__tablename__ = "users"
sessions = relationship("Session", back_populates="user")
```
This is for mapping users table fields to session model

In Session model
```python
__tablename__ = "sessions"
user = relationship("UserDatabase", back_populates="sessions")
```
This is for mapping session table fields to users model.

```
The cookie is just the credential used to reference server-side state. It shouldn't contain business/user information.
```

Complete flow
```
                    SESSION AUTHENTICATION

POST /login
    │
    ├── username/password
    │
    ├── verify user
    ├── verify password
    ├── verify active
    │
    ▼
create_session(user.id)
    │
    ├── generate random session ID
    ├── hash session ID
    ├── store hash + user_id + expiration
    │
    ▼
Set-Cookie: session_id=<opaque-value>
    │
    ▼
Browser
    │
    │ automatically sends cookie
    ▼
GET /profile
    │
    ▼
get_current_user_session()
    │
    ├── extract cookie
    ├── hash it
    ├── find session
    ├── check expiration
    ├── find user
    │
    ▼
/profile(user)
```

---
### Logout

- **Server:** invalidate the session in PostgreSQL.
- **Browser:** remove the cookie.

```
cookie → hash → find Session → delete it → commit
```

```python
@app.post("/logout")
def logout(
    response: Response,
    db: DbSession = Depends(get_db),
    session_id: str | None = Cookie(default=None)):
  
    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session not found",
        )
    session_id_hash = hash_session_id(session_id)
    session = db.query(Session).filter(
        Session.session_id_hash == session_id_hash
    ).first()
    if not session:
        response.delete_cookie("session_id")
        return {"message": "Already logged out"}
    db.delete(session)
    db.commit()
    response.delete_cookie("session_id")
    return {"message": "Logout successful"}
```

This will clear the session and remove the cookie from browser so with the same session_id user cant access the API's

---
### JWT Token

**Session auth = server-side state.**  
**JWT auth = client carries a signed token containing claims.**


in JWT, the token itself will have the expiration date, so no need to query db for every request to find the expiration date.

```c
pip install PyJWT
```

```
SECRET_KEY
    │
    ├── sign JWT
    │
    └── verify JWT
```

JWT signing secret needs to be defined in settings.py of the fastapi application.

in settings.py
```python
import os
from dotenv import load_dotenv
  
load_dotenv(".env")
if not os.getenv("JWT_SECRET_KEY"):
    raise ValueError("JWT_SECRET_KEY is not set")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
```

in .env
```env
JWT_SECRET_KEY="<YOUR_JWT_SECRET_KEY>"
```

>[!NOTE]
>Access token       → short-lived → API access
Refresh token      → longer-lived → obtain new access token

JWT flow
```
POST /jwt-login
      ↓
find user
      ↓
verify Argon2 password
      ↓
check active
      ↓
create JWT
      ↓
return bearer token
```

>Encoding

```python
# JWT Authentication
import jwt
import settings
  
def create_jwt_token(user: UserDatabase):
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user.id),
        "iat": now,
        "exp": now + timedelta(minutes=20)
    }
    token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm="HS256")
    # encode the token with JWT secret key and algo HS256  
    return token
```


>Decoding

```python
def decode_token(token: str):
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,

            algorithms=["HS256"],
            options={"require": ["sub", "iat", "exp"]} # To check the necessary fields in token
        )
        return payload  
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired",
        )
    except jwt.MissingRequiredClaimError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token missing required claim: {e}",
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )
```

> Validate current user whose details are in the jwt token

	- Similar to HTTPBasic, HTTPBearer used to validate the token

> Get the current user token and validate it

```python
from fastapi.security import HTTPBearer
security = HTTPBearer()
def get_current_user_jwt(token = Depends(security), db: DbSession = Depends(get_db)):
    token = token.credentials
    payload = decode_token(token)
    user_id = payload.get("sub")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )
    try:
        user_id = int(user_id)
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )
    user = db.query(UserDatabase).filter(
        UserDatabase.id == user_id
    ).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User is not active",
        )
    return user
  
@app.get("/jwt-profile")
def jwt_profile(current_user: UserDatabase = Depends(get_current_user_jwt)):
    return {"username": current_user.username, "email": current_user.email, "id": current_user.id}
```

```
username/password
      ↓
   JWT login
      ↓
 short-lived JWT
      ↓
Authorization: Bearer JWT
      ↓
verify signature + exp
      ↓
extract sub
      ↓
find user
      ↓
 /jwt-profile
```

>[!NOTE]
>If payload changes detected in the generated token, token will be invalidated 


```
Original token
    ↓
valid signature
    ↓
✅ accepted

Modify payload
    ↓
signature no longer matches
    ↓
❌ rejected
```

---

#### Refresh token

Used to get new access token.

If an user using the app for more than 15 mins and access token expiration is only 15 mins, refresh token will create new access token after every 15 mins until user logs out. 

```
                    Login
                      ↓
              ┌───────┴───────┐
              ↓               ↓
       Access Token      Refresh Token
        15 minutes          longer
              ↓               ↓
       API requests      obtain new
                         access token
```

**Access token**

- Used to access protected APIs.
- Short-lived.
- Sent frequently.

**Refresh token**

- Used only to obtain a new access token.
- Longer-lived.
- Much more sensitive.

> Need to store the refresh token in server side (in a table)

Refresh token model
```python
class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id = Column(Integer, primary_key=True)
    refresh_token_hash = Column(String(64), nullable=False,unique=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"),nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked = Column(Boolean, default=False,nullable=False)
    user = relationship("UserDatabase", back_populates="refresh_tokens")
```

```
POST /jwt-login
       ↓
  verify credentials
       ↓
 ┌─────┴─────────┐
 ↓               ↓
Access JWT    Refresh token
15 min          7 days
 ↓               ↓
API access    get new access token
```

In jwt-login return both refresh and access token.
```python
@app.post("/jwt-login")
def jwt_login(login_data: UserLogin, db: DbSession = Depends(get_db)):
    token = create_jwt_token(user)
    refresh_token = create_refresh_token(user, db)
    return {"access_token": token, "token_type": "bearer", "refresh_token": refresh_token}
```

```
Refresh Token A
      │
      ▼
POST /jwt-refresh
      │
      ├── validate A
      ├── revoke A
      ├── create Refresh Token B
      └── create Access Token B
             │
             ▼
      return B + Access Token
```

once a new refresh token created, old one will be revoked and cant be accessed.

> Refresh token implementation

- Validate refresh token
- revoke current one
- Create new refresh and access token

```python
class RefreshTokenRequest(BaseModel):
    refresh_token: str
  
@app.post("/jwt-refresh")
def jwt_refresh(request: RefreshTokenRequest, db: DbSession = Depends(get_db)):
    raw_refresh_token = request.refresh_token
    refresh_token_hash = hashlib.sha256(raw_refresh_token.encode()).hexdigest()
    stored_token = db.query(RefreshToken).filter(
        RefreshToken.refresh_token_hash == refresh_token_hash
    ).first()
    if not stored_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )
    if stored_token.expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token expired",
        

    if stored_token.revoked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token revoked",
        )
    user = stored_token.user
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User is not active",
        )
  
    # Revoke old refresh token (Refresh Token Rotation)
    stored_token.revoked = True
  
    new_refresh_token = create_refresh_token(user, db)
    new_access_token = create_jwt_token(user)
    return {"access_token": new_access_token, "refresh_token": new_refresh_token}
```

> Family tree

If refresh token C created by B and B created by A and A is reused by attacker which is revoked means all the tokens created via A might also compromised so revoke all the tokens. 

Have a column called family_id which marks the tree of token creation C from B, B from A ...
```python
# in RefreshToken model
family_id = Column(String(64), nullable=False, index=True)
```

in jwt_refresh endpoint
```python
if stored_token.revoked:
    db.query(RefreshToken).filter(
        RefreshToken.family_id == stored_token.family_id
    ).update({"revoked": True})
    db.commit()
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Revoked refresh token reused. All tokens in this family have been invalidated.",
    )
```


### JWT — completed

- Access-token creation with `sub`, `iat`, `exp` ✅
- HS256 signing and verification ✅
- Required-claim validation ✅
- Expired/invalid token handling ✅
- Bearer authentication with `HTTPBearer` ✅
- Protected endpoints using JWT dependency ✅
- Opaque refresh tokens ✅
- Refresh tokens stored as hashes ✅
- Refresh-token expiry/revocation ✅
- Access + refresh token login flow ✅
- Refresh endpoint ✅
- Refresh-token rotation ✅
- Refresh-token family tracking ✅
- Reuse detection + family revocation ✅
---

## OAuth -> An Authorization framework

If user wants to sign in to my application using google.

| OAuth term               | In our example                                |
| ------------------------ | --------------------------------------------- |
| **Resource Owner**       | The user                                      |
| **Client**               | Your FastAPI application                      |
| **Authorization Server** | Google                                        |
| **Resource Server**      | Google's API that holds user data             |
| **Authorization Code**   | Temporary code Google gives your app          |
| **Access Token**         | Credential your app uses to call Google's API |
| **Redirect URI**         | Your FastAPI callback endpoint                |

**Browser:** carries the authorization code.
**Backend:** exchanges the code for tokens.

```
User
 ↓
FastAPI
 ↓
Google authorization
 ↓
Authorization Code
 ↓
FastAPI backend
 ↓
Token exchange
 ↓
Access Token
 ↓
Google API
```

- Create a project in google cloud
- Create an app
- Create an OAuth client (Web app)
	- Authorized redirect url -> http://localhost:8000/oauth/google/callback
	- client id -> <YOUR_GOOGLE_CLIENT_ID>
	- client secret -> <YOUR_GOOGLE_CLIENT_SECRET>

> Google needs to know **what information your application is asking the user to authorize**.

Add scope
- under data access, select openid, email and profile
	- openid -> I want to use OpenID Connect to establish the user's identity.
	- email -> Allows the application to obtain the user's email identity information.
	- profile -> Allows basic profile information such as the user's name and profile-related claims.
Then add a test user, once its added, google side configuration is completed.

> login with google means the following.

```
OAuth 2.0
   ↓
Authorization framework

OpenID Connect
   ↓
Identity layer built on OAuth 2.0
   ↓
"Who is this Google user?"
```


**OAuth 2.0 + OpenID Connect (OIDC)**
- OAuth handles the authorization flow.
- OIDC handles authentication/identity.

> OAuth flow

When the user clicks:
**Login with Google** ->  FastAPI application will redirect the browser to Google's **authorization endpoint**.

The following will be sent to google
```
https://accounts.google.com/o/oauth2/v2/auth
    ?client_id=YOUR_CLIENT_ID
    &redirect_uri=http://localhost:8000/oauth/google/callback
    &response_type=code
    &scope=openid email profile
    &state=SOME_RANDOM_VALUE
```

- client_id -> which google application making the request
- redirect_uri -> after authorization, send the user to specified url
- response_type=code -> this says "Don't give me an access token directly in the browser. Give me an authorization code."
- scope -> This tells Google what access/identity information we're requesting
- state=random_value -> Your application should generate a **cryptographically random state value** before redirecting the user.
	- For example:
```
state = random_value
```
Your application remembers that value.

Google eventually redirects:
```
/oauth/google/callback?code=...&state=random_value
```
Your application checks:
```
state_from_google == state_we_generated
```
If they don't match:
```
❌ Reject the request
```
Why?
Because `state` protects the OAuth authorization flow against **CSRF/login-request forgery attacks**.

>[!NOTE]
>`state` lets your application verify that the callback it receives belongs to an OAuth flow that your application actually initiated for that user's browser session.

>`state` binds the OAuth callback to the browser/session that initiated the authorization request.

```
User
 ↓
FastAPI /oauth/google/login
 ↓
Redirect to Google
 ↓
User authenticates/authorizes
 ↓
Google → callback with authorization code
 ↓
FastAPI exchanges code for tokens
 ↓
FastAPI gets user's identity
```

For:

```
GET /oauth/google/login
```

the job is actually quite small:

1. Generate a secure random `state`.
2. Construct Google's authorization URL.
3. Include:
    - `client_id`
    - `redirect_uri`
    - `response_type=code`
    - `scope=openid email profile`
    - `state`
4. Redirect the browser to Google.

```
Browser
   │
   │ 1. GET /oauth/google/login
   ↓
FastAPI
   │
   │ 2. Generate random state
   │
   │ 3. Set state in browser
   │
   │ 4. Redirect to Google
   ↓
Google
   │
   │ 5. User authenticates + authorizes
   ↓
Browser
   │
   │ 6. GET /oauth/google/callback?code=...&state=...
   ↓
FastAPI
   │
   │ 7. Compare returned state
   │    with state stored in browser
   ↓
   │
   ├── Match → continue
   └── Mismatch → reject
```


```
FastAPI
   ↓
Generate state
   ↓
Set state cookie
   ↓
Build authorization URL
   ↓
Redirect to Google
   ↓
Google authorization page
```


```python
import urllib, os
from starlette.responses import RedirectResponse

# Google OAuth
@app.get("/oauth/google/login")
def google_login():
    if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_REDIRECT_URI:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Google OAuth is not configured properly in .env",
        )
    state = secrets.token_urlsafe(32)
    auth_params = urllib.parse.urlencode({
        "client_id": settings.GOOGLE_CLIENT_ID,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "email profile openid",
        "state": state,
    })
    auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?{auth_params}"
    response = RedirectResponse(auth_url)
    response.set_cookie("gooe_state", state, httponly=True, secure=False, samesite="lax", max_age=60*10)
    return response
  
from fastapi import Request, Cookie
@app.get("/oauth/google/callback")
def google_callback(code: str,state: str, google_state: str | None = Cookie(default=None), db: DbSession = Depends(get_db)
                    ):
    if state != google_state:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid state",
        )
    if not code:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No code provided",
        )
    return {"message": "Google OAuth is working"}
```

```
/login
  ↓
generate state
  ↓
state cookie
  ↓
Google
  ↓
callback
  ↓
verify state ✅
  ↓
authorization code
```


> Exchange token for authorization code.

To exchange token make request directly to google's endpoint

```
Browser → FastAPI callback
              ↓
        authorization code
              ↓
        FastAPI → Google token endpoint
              ↓
        access token (+ ID token)
```

```python
def exchange_google_code_for_token(code: str) -> dict:
    token_url = "https://oauth2.googleapis.com/token"
    payload = urllib.parse.urlencode({
        "code": code,
        "client_id": settings.GOOGLE_CLIENT_ID,
        "client_secret": settings.GOOGLE_CLIENT_SECRET,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code",
    }).encode("utf-8")
  
    req = urllib.request.Request(
        token_url,
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to exchange token with Google: {error_body}",
        )
```

> Response from google
```json
{
  "access_token": "<ACCESS_TOKEN>",
  "expires_in": 3599,
  "scope": "https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email openid",
  "token_type": "Bearer",
  "id_token": "<ID_TOKEN>"
}
```

| Field          | Purpose                                                                       |
| -------------- | ----------------------------------------------------------------------------- |
| `access_token` | Credential used to call Google's protected APIs                               |
| `expires_in`   | How long the access token is valid                                            |
| `scope`        | Permissions Google granted                                                    |
| `token_type`   | Usually `Bearer`                                                              |
| `id_token`     | **OIDC identity token** — contains claims about the authenticated Google user |
id_token is like the jwt token which contains information of the request like user, mail etc..

id_token will have the following

```json
{
  "iss": "https://accounts.google.com",
  "azp": "<YOUR_GOOGLE_CLIENT_ID>",
  "aud": "<YOUR_GOOGLE_CLIENT_ID>",
  "sub": "<GOOGLE_SUB>",
  "email": "<USER_EMAIL>",
  "email_verified": true,
  "at_hash": "<AT_HASH>",
  "name": "<NAME>",
  "picture": "<PICTURE_URL>",
  "given_name": "<GIVEN_NAME>",
  "iat": 1789912530,
  "exp": 1789916130
}
```

```
                 Browser
                    │
                    │ state + nonce
                    ▼
                  Google
                    │
              authorization
                    │
                    ▼
              callback(code, state)
                    │
                    ├── verify state
                    │
                    └── later verify nonce
```


`state` and `nonce` serve **different purposes**:
- **state** → protects the OAuth authorization flow / callback from CSRF and request mix-up.
- **nonce** → binds the OIDC ID token to the authentication request that initiated this login.

```
pip install google-auth
```

```
Google ID token
        ↓
verify signature + issuer + audience + expiry + nonce
        ↓
sub = "google's unique user identifier"
        ↓
find Google identity in our DB
        ↓
local user_id = 42
        ↓
create OUR session
        ↓
browser receives OUR session cookie
```

>`sub` is the identifier for the Google subject.

OAuth model
```python
class OauthAccount(Base):
    __tablename__ = "oauth_accounts"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"),nullable=False)
    provider = Column(String, nullable=False)
    provider_user_id = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    user = relationship("UserDatabase", back_populates="oauth_accounts")
    __table_args__ = (UniqueConstraint("provider", "provider_user_id", name="unique_provider_user_id"),)
```

---

```python
@app.get("/oauth/google/callback")
def google_callback(
    code: str,
    state: str,
    response: Response,
    google_state: str | None = Cookie(default=None),
    google_nonce: str | None = Cookie(default=None),
    db: DbSession = Depends(get_db),
):
    if state != google_state:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid state (received query state={state!r}, cookie state={google_state!r}). 
            #Mae sure you are using the same host (localhost vs 127.0.0.1) as GOOGLE_REDIRECT_URI.",
        )
    if not code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No code provided",
        )
    if not google_nonce:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid nonce",
        )
    token_response = exchange_google_code_for_token(code)
  
    # 1. Verify ID token + nonce
    try:
        id_info = id_token.verify_oauth2_token(
            token_response['id_token'],
            requests.Request(),
            settings.GOOGLE_CLIENT_ID,
            clock_skew_in_seconds=10,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid Google ID token: {e}",
        )
    if id_info.get('nonce') != google_nonce:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid nonce",
        )
    if id_info.get('iss') not in ["accounts.google.com", "https://accounts.google.com"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid issuer",
        )
  
    # 2. Get Google `sub`
    google_sub = id_info.get("sub")
    email = id_info.get("email")
    if not google_sub or not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing 'sub' or 'email' in Google ID token",
        )
  
    # 3. Find OAuth account
    oauth_account = db.query(OauthAccount).filter(
        OauthAccount.provider == "google",
        OauthAccount.provider_user_id == google_sub,
    ).first()
  

    if oauth_account:

        # Found -> get local user

        user = db.query(UserDatabase).filter(UserDatabase.id == oauth_account.user_id).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User linked to Google account not found",
            )
    else:
        # Not found -> Find local user by email
        user = db.query(UserDatabase).filter(UserDatabase.email == email).first()
        if user:
            # Found -> link Google accout

            oauth_account = OauthAccount(
                user_id=user.id,
                provider="google",
                provider_user_id=google_sub,
            )
            db.add(oauth_account)
            db.commit()
        else:
            # Not found -> create local user
            base_username = email.split("@")[0] or f"user_{google_sub[:8]}"
            username = base_username
            suffix = 1
            while db.query(UserDatabase).filter(UserDatabase.username == username).first():
                username = f"{base_username}_{suffix}"
                suffix += 1
  
            # If the database odel allows null password_hash, use None; otherwise generate a random unusable hash
            pwd_hash = None if getattr(UserDatabase.password_hash, "nullable", False) else hash_password(secrets.token_urlsafe(32))
  
            user = UserDatabase(
                username=username,
                email=email,
                password_hash=pwd_hash,
                is_active=True,
            )
            db.add(user)
            db.commit()
            db.refresh(user)
  
            # Link Google account
            oauth_account = OauthAccount(
                user_id=user.id,
                provider="google",
                provider_user_id=google_sub,
            )
            db.add(oauth_account)
            db.commit()
  
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User is not active",
        )
  
    # 4. Create OUR application session
    session_id = create_session(user.id, db)
  
    # 5. Return JSONResponse with session cookie set and temporary oauth cookies deleted
    res = JSONResponse(content={"message": "Login successful"})
    res.delete_cookie("google_state", path="/")
    res.delete_cookie("google_nonce", path="/")
    res.set_cookie(
        key="session_id",
        value=session_id,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=86400,
        path="/",
    )
    # 6. Done
    return res
```

---

## CI - Continuous Integration, CD - Continuous Deployment

CI should eventually be able to catch things like:

```
Wrong password → 401
Inactive user → rejected
Expired JWT → rejected
Invalid JWT → rejected
Revoked refresh token → rejected
Expired session → rejected
Logout → session unusable
OAuth state mismatch → rejected
Duplicate username/email → 409
```

Automation tests

```
pip install pytest
```

pytest → FastAPI app → HTTP request → response assertion

Create a file called test_health.py
```python
from fastapi.testclient import TestClient
from app.main import app
  
def test_health_check():
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "Healthy"}
```


```cmd
(pyenv) D:\Learning\Python\networking\Authentication-methods-in-django\Auth-playground>python -m pytest
========================================= test session starts ==========================================
platform win32 -- Python 3.12.10, pytest-9.1.1, pluggy-1.6.0
rootdir: D:\Learning\Python\networking\Authentication-methods-in-django\Auth-playground
plugins: anyio-4.8.0
collected 1 item                                                                                        

tests\test_health.py .                                                                            [100%] 

========================================== 1 passed in 1.16s =========================================== 
```

> ```python -m pytest```  is the cmd used to run the pytest

 The **`assert`** keyword is a sanity check that tests if a condition evaluates to `True`.
### How it works:
- **If `True`**: Execution continues to the next line normally.
- **If `False`**: Python immediately raises an **`AssertionError`** and halts that block.

auth_methods_test -> DB for pytest, all testing entries will be inserted in this db.

To use test-db, following flow will be used

```
pytest starts
   ↓
set DATABASE_URL → auth_methods_test
   ↓
import application
   ↓
database.py reads DATABASE_URL
   ↓
create_engine(test database)
   ↓
tests run
```

Created a new env for test

```env
JWT_SECRET_KEY=<YOUR_JWT_SECRET_KEY>
GOOGLE_CLIENT_ID=<YOUR_GOOGLE_CLIENT_ID>
GOOGLE_CLIENT_SECRET=<YOUR_GOOGLE_CLIENT_SECRET>
GOOGLE_REDIRECT_URI=http://localhost:8000/oauth/google/callback
DATABASE_URL=postgresql+psycopg://postgres:<PASSWORD>@localhost:5432/auth_methods_test
```

env.py -> to use db from settings.py, cause alembic connects to the db which mentioned in alembic.ini
```python
from settings import DATABASE_URL
config = context.config
if DATABASE_URL:
    config.set_main_option("sqlalchemy.url", DATABASE_URL)

```


### Database Schema & Multi-Tenant Model Architecture

The application is built as a **multi-tenant authentication provider** where external client applications register under the `applications` table and manage users, sessions, tokens, and OAuth accounts scoped to their `app_id`.

```mermaid
erDiagram
    APPLICATION ||--o{ USER : "owns"
    APPLICATION ||--o{ SESSION : "owns"
    APPLICATION ||--o{ REFRESH_TOKEN : "owns"
    APPLICATION ||--o{ OAUTH_ACCOUNT : "owns"
    USER ||--o{ SESSION : "has"
    USER ||--o{ REFRESH_TOKEN : "has"
    USER ||--o{ OAUTH_ACCOUNT : "links"

    APPLICATION {
        int id PK
        string app_name
        string api_key_hash UK
        datetime created_at
    }
    USER {
        int id PK
        int app_id FK
        string username UK
        string password_hash
        string email UK
        boolean is_active
        datetime created_at
    }
    SESSION {
        int id PK
        string session_id_hash UK
        int user_id FK
        int app_id FK
        datetime created_at
        datetime expires_at
    }
    REFRESH_TOKEN {
        int id PK
        string refresh_token_hash UK
        int user_id FK
        int app_id FK
        string family_id
        boolean revoked
        datetime created_at
        datetime expires_at
    }
    OAUTH_ACCOUNT {
        int id PK
        int user_id FK
        int app_id FK
        string provider
        string provider_user_id UK
        datetime created_at
        datetime updated_at
    }
```

#### Why Cascades & Relationships Matter
- **`cascade="all, delete-orphan"`**: When an `Application` is deleted, all users, sessions, refresh tokens, and OAuth links belonging to that application are automatically purged by PostgreSQL.
- **`ondelete="CASCADE"`**: Database-level foreign key constraint ensuring referential integrity if rows are deleted directly via SQL.
- **`UniqueConstraint("provider", "provider_user_id")`**: Ensures an external Google account cannot be linked to more than one user within the same provider context.

---

## Centralized Universal Logout

### The Problem with Logging Out in JWT + Session Architectures

In traditional session-based systems, logout is simple: delete the session row from the `sessions` table.
However, **JWT access tokens are stateless**: once a signed JWT is issued with an expiration of 20 or 60 minutes, the server validates its cryptographic signature without querying the database on every request. Deleting cookies on the client does NOT revoke the access token if an attacker or client still holds the Bearer token!

### The Solution: 3-Pillar Invalidation

```mermaid
flowchart TD
    Client["Client POST /logout {'username': '...'}"] --> Endpoint["Centralized Logout Endpoint"]
    Endpoint --> S1["1. Delete all DB rows in `sessions` table"]
    Endpoint --> S2["2. Delete all DB rows in `refresh_tokens` table"]
    Endpoint --> S3["3. Increment in-memory `USER_TOKEN_VERSIONS[user.id]`"]
    Endpoint --> S4["4. Set Set-Cookie headers to expire all client cookies"]

    S1 --> ProfileCheck{"Old Session tries GET /profile"}
    ProfileCheck -->|Session ID not in DB| 401A["401 Invalid session"]

    S2 --> RefreshCheck{"Old Refresh Token tries POST /jwt-refresh"}
    RefreshCheck -->|Hash not in DB| 401B["401 Invalid refresh token"]

    S3 --> JWTCheck{"Old Access Token tries GET /jwt-profile"}
    JWTCheck -->|Token version mismatch| 401C["401 Token revoked"]
```

#### Implementation Code

```python
# In-memory dictionary tracking user token versions for immediate revocation
USER_TOKEN_VERSIONS: dict[int, int] = {}

class LogoutRequest(BaseModel):
    username: str

@app.post("/logout")
def logout(payload: LogoutRequest, response: Response, db: DbSession = Depends(get_db)):
    user = db.query(UserDatabase).filter(UserDatabase.username == payload.username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # 1. Purge all DB sessions
    db.query(Session).filter(Session.user_id == user.id).delete()

    # 2. Purge all DB refresh tokens
    db.query(RefreshToken).filter(RefreshToken.user_id == user.id).delete()

    # 3. Bump token_version (invalidates all existing access tokens immediately)
    USER_TOKEN_VERSIONS[user.id] = USER_TOKEN_VERSIONS.get(user.id, 1) + 1

    db.commit()

    # 4. Wipe client-side cookies
    response.delete_cookie("session_id", path="/")
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/")

    return {"message": f"User {user.username} logged out successfully. All sessions and tokens have been invalidated."}
```

#### How Access Tokens Verify Revocation

Inside `get_current_user_jwt`:

```python
expected_version = USER_TOKEN_VERSIONS.get(user.id, 1)
if payload.get("token_version") != expected_version:
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token has been revoked. Please login again.",
    )
```

- When issued, a token receives `"token_version": 1`.
- When user logs out, `USER_TOKEN_VERSIONS[user.id]` becomes `2`.
- Any subsequent request holding the old token fails immediately with `401 Unauthorized`.
- When the user logs in again, they receive a fresh token with `"token_version": 2`, which works normally.

---

## Automated Testing Suite (Pytest)

### How Pytest Runs Tests Without the Application Running

A common misconception is that you need to start the web server (e.g. `uvicorn app.main:app --reload`) before running `pytest`. **You do NOT need the application running.**

#### 1. In-Memory ASGI Invocation vs. Network HTTP Calls

```mermaid
flowchart LR
    subgraph Traditional Browser / Postman
        Browser["Browser / Postman"] -->|Real TCP Socket<br>http://localhost:8000| Uvicorn["Uvicorn Web Server<br>(Network Listener)"]
        Uvicorn -->|ASGI Interface| App1["FastAPI Application"]
    end

    subgraph Pytest In-Memory Execution
        Test["Pytest Test Function"] -->|Direct Python Call| TestClient["fastapi.testclient.TestClient<br>(based on httpx)"]
        TestClient -->|Direct ASGI in-memory pass| App2["FastAPI Application<br>(app.main.app)"]
    end
```

#### 2. How `TestClient` Works Under the Hood
FastAPI's `TestClient` inherits from Starlette and wraps `httpx`. When you do:
```python
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)
response = client.get("/health")
```
1. `TestClient` imports the ASGI `app` callable directly into memory inside the **same Python process**.
2. When `client.get(...)` is called, it constructs the ASGI request `scope`, `receive`, and `send` dictionaries internally and invokes `app(scope, receive, send)` as a direct function call.
3. **No network sockets are opened**, no ports (like `8000`) are bound, and no HTTP packets travel over the loopback interface (`127.0.0.1`).
4. This results in **ultra-fast execution** (hundreds of requests per second) and completely eliminates port-binding conflicts (`Address already in use`).

#### 3. What DOES Need to Be Running?
- **The Database (PostgreSQL)**: While the web server is in-memory, the database queries (`SQLAlchemy` $\rightarrow$ `psycopg`) are real! Your database (`auth_methods_test`) must be running and accepting connections.
- **In CI/CD (GitHub Actions)**: This is why [.github/workflows/ci.yml](file:///d:/Learning/Python/networking/Auth-playground/.github/workflows/ci.yml) spins up a `postgres:15` service container, but runs `pytest -v` directly without starting Uvicorn!

---

### Architecture of the Test Suite

```
tests/
├── __init__.py            # Makes tests an importable Python package
├── conftest.py            # Global Pytest fixtures (DB creation, TestClient)
├── utils.py               # Helper generator for unique, isolated test identities
├── test_health.py         # Basic smoke check (/health)
├── test_basic_auth.py     # HTTP Basic auth & /basic-auth service tests
├── test_session.py        # Cookie sessions, /login, /profile, /logout tests
├── test_jwt.py            # JWT tokens, refresh rotation, reuse detection, /logout tests
└── test_oauth.py          # Google OAuth URLs, token exchange, and callback tests
```

### Pytest Configuration (`pytest.ini`)

```ini
[pytest]
pythonpath = .
testpaths = tests
```
- **`pythonpath = .`**: Automatically adds the project root to `sys.path` so root modules (`database`, `models`, `settings`, `app`) can be imported without import errors.
- **`testpaths = tests`**: Restricts test collection strictly to the `tests/` directory.

### Key Fixtures & Test Isolation (`conftest.py` & `utils.py`)

```python
# tests/conftest.py
import sys
from pathlib import Path

# Ensures project root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from fastapi.testclient import TestClient
from database import engine, Base, SessionLocal
from app.main import app

@pytest.fixture(scope="session", autouse=True)
def setup_database():
    """Ensure database schema is created before tests run."""
    Base.metadata.create_all(bind=engine)
    yield

@pytest.fixture
def client():
    """Provides a fresh in-memory FastAPI test client."""
    with TestClient(app) as test_client:
        yield test_client
```

```python
# tests/utils.py
import uuid

def unique_string(prefix: str = "test") -> str:
    """Generates unique IDs (e.g. 'basic_user_a1b2c3d4') so repeated test runs never collide in the DB."""
    return f"{prefix}_{uuid.uuid4().hex[:8]}"
```

### The 15 Core Automated Test Tasks

| Test File | Test Function | Purpose / Scenarios Covered |
| :--- | :--- | :--- |
| **`test_health.py`** | `test_health_check` | Validates API liveness (`GET /health` returns `200` with `{"status": "Healthy"}`). |
| **`test_basic_auth.py`** | `test_basic_auth_service_registration_and_login` | Tests new user registration (`status: "registered"`) and repeat login (`status: "verified"`). |
| | `test_basic_auth_service_invalid_password` | Verifies wrong password triggers `401 Unauthorized ("Invalid credentials")`. |
| | `test_http_basic_auth_route` | Verifies standard HTTP Basic Auth header (`Authorization: Basic base64(u:p)`) on `GET /test`. |
| **`test_session.py`** | `test_session_auth_service` | Tests session creation, `session_id` cookie header issuance, and accessing `GET /profile`. |
| | `test_session_login_and_centralized_logout_flow` | Verifies full session lifecycle: login $\rightarrow$ access profile $\rightarrow$ logout $\rightarrow$ confirm old cookie fails with `401 Invalid session`. |
| | `test_session_invalid_login` | Rejects non-existent users on `POST /login` with `401`. |
| | `test_profile_unauthorized_without_cookie` | Rejects unauthenticated requests to `GET /profile` with `401 Session not found`. |
| **`test_jwt.py`** | `test_jwt_auth_service_and_profile` | Tests `POST /jwt-auth` issuing access and refresh tokens, and validates `GET /jwt-profile` with `Bearer <token>`. |
| | `test_jwt_login_success_and_failure` | Tests standard username/password login via `POST /jwt-login` and wrong password rejection. |
| | `test_jwt_refresh_token_rotation_and_reuse_detection` | Tests Refresh Token Rotation (RTR). Re-using an already rotated token triggers **reuse detection**, revoking the entire token family. |
| | `test_jwt_centralized_logout_invalidates_tokens` | Tests centralized logout: immediately revokes access tokens, deletes refresh tokens, and verifies re-login mints new working tokens. |
| **`test_oauth.py`** | `test_oauth_service_google_login_url_generation` | Tests Google OAuth URL generation with state/nonce parameters and CSRF cookies. |
| | `test_oauth_service_direct_login_post` | Tests backend-to-backend OAuth link provisioning via `POST /oauth-service/google/login`. |
| | `test_oauth_service_callback_flow` | Mocks Google token exchange and ID token verification, verifying account link and token generation without external network calls. |

---

## Explanation of All Imported Modules and Parameters

Below is a detailed guide to every external and internal module, class, and parameter used in this codebase:

### 1. Standard Library Modules

| Module / Function | Purpose in Auth Playground |
| :--- | :--- |
| **`datetime`, `timedelta`, `timezone`** | Handles UTC timestamp calculations for token issue dates (`iat`), token expiration (`exp`), and session lifetimes (`expires_at = now + timedelta(days=7)`). |
| **`hashlib`** | Cryptographic hashing utility: SHA-256 (`hashlib.sha256(...)`) is used to hash session IDs, refresh tokens, and application API keys before saving to PostgreSQL. |
| **`secrets`** | Cryptographically secure random number generator: `secrets.token_urlsafe(32)` is used to generate session IDs, refresh tokens, OAuth state CSRF tokens, and nonces. |
| **`urllib.parse`** | URL encoding tool: `urllib.parse.urlencode(...)` builds query parameter strings for the Google OAuth 2.0 authorization URL. |
| **`urllib.request`, `urllib.error`** | Performs HTTP POST requests to Google's Token Endpoint (`https://oauth2.googleapis.com/token`) to exchange the authorization code for tokens. |
| **`json`** | Decodes JSON payloads returned by Google's token endpoint into Python dictionaries. |

### 2. FastAPI & Web Framework Modules

| Class / Parameter | Purpose / Usage |
| :--- | :--- |
| **`FastAPI`** | Core ASGI framework application instance orchestrating all routes, middleware, and dependency injection. |
| **`Depends`** | Dependency injection provider: used to inject database sessions (`db: DbSession = Depends(get_db)`) and auth extractors (`Depends(get_current_user_jwt)`). |
| **`HTTPException`** | Standard exception class for raising HTTP errors with specific status codes (`401`, `403`, `404`, `409`) and JSON error messages (`detail="..."`). |
| **`status`** | HTTP status code constants (`status.HTTP_401_UNAUTHORIZED`, `status.HTTP_409_CONFLICT`, etc.) avoiding magic numbers. |
| **`Response`** | The raw HTTP response object, used to set or delete cookies (`response.set_cookie()`, `response.delete_cookie()`). |
| **`Cookie`** | FastAPI parameter extractor that automatically extracts named cookies from incoming HTTP requests (`session_id: str \| None = Cookie(default=None)`). |
| **`CORSMiddleware`** | Middleware enabling Cross-Origin Resource Sharing for frontends running on `localhost:3000` or `localhost:5173`. |
| **`HTTPBasic`, `HTTPBasicCredentials`** | Extracts and parses HTTP Basic Authentication headers (`Authorization: Basic ...`) into `.username` and `.password`. |
| **`HTTPBearer`** | Extracts Bearer tokens from the `Authorization: Bearer <token>` header. |
| **`RedirectResponse`** | HTTP 307 redirect response used to forward the user's browser to Google's OAuth consent screen. |
| **`JSONResponse`** | Custom HTTP response returning JSON content while setting or deleting cookies on the response headers. |

### 3. Pydantic & Data Validation

| Class | Purpose / Usage |
| :--- | :--- |
| **`BaseModel`** | Base class for defining request and response schemas, automatic JSON parsing, serialization, and OpenAPI documentation. |
| **`EmailStr`** | Validates email syntax using `pydantic[email]`, rejecting malformed email inputs with HTTP 422 before route execution. |

### 4. Database & ORM (SQLAlchemy)

| Component | Purpose / Usage |
| :--- | :--- |
| **`create_engine`** | Establishes the database connection pool using the `DATABASE_URL`. |
| **`sessionmaker`** | Factory for creating scoped database sessions (`SessionLocal`). |
| **`declarative_base`** | Base class from which all database models (`UserDatabase`, `Session`, etc.) inherit table metadata. |
| **`DbSession` (`sqlalchemy.orm.Session`)** | The active database transaction session used to query, add, commit, or rollback changes. |
| **`IntegrityError`** | Exception raised on unique constraint violations (e.g., duplicate username or duplicate email), triggering a safe transaction rollback (`db.rollback()`). |

### 5. Authentication & OAuth Libraries

| Component | Purpose / Usage |
| :--- | :--- |
| **`jwt` (`PyJWT`)** | Encodes (`jwt.encode`) and decodes (`jwt.decode`) JSON Web Tokens with HS256 signatures, checking required claims (`sub`, `iat`, `exp`). |
| **`google.oauth2.id_token`** | Validates Google OpenID Connect ID tokens (`verify_oauth2_token`), checking signature against Google's public certificates, verifying client ID audience (`aud`), issuer (`iss`), and expiration. |
| **`google.auth.transport.requests.Request`** | HTTP transport adapter utilized by Google's token verification library to fetch Google's public keys. |
| **`passlib` / `hash_password`, `verify_password`** | One-way hashing algorithm (bcrypt / argon2 / PBKDF2) ensuring raw passwords are never saved in plaintext. |

---

## Continuous Integration & Continuous Deployment (CI/CD)

The repository includes a ready-to-deploy **GitHub Actions** CI/CD pipeline in [`.github/workflows/ci.yml`](file:///d:/Learning/Python/networking/Auth-playground/.github/workflows/ci.yml).

### How the CI/CD Pipeline Operates

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer
    participant Git as GitHub Actions Runner
    participant PG as PostgreSQL Service Container (Docker)
    participant Py as Pytest Test Runner

    Dev->>Git: git push / pull_request (main/master)
    Git->>PG: Spin up postgres:15 container (auth_methods_test on port 5432)
    PG-->>Git: Health check passed (pg_isready)
    Git->>Git: Checkout repo & Set up Python 3.11 (with pip cache)
    Git->>Git: pip install -r requirements.txt
    Git->>Py: Run `pytest -v`
    Py->>PG: Base.metadata.create_all(bind=engine)
    Py->>Py: Execute 15 test tasks across all auth modules
    Py-->>Git: All 15 tests PASSED (0 failures)
    Git-->>Dev: Green Checkmark / Ready to deploy!
```

### GitHub Actions Workflow File Breakdown

```yaml
name: CI/CD Pipeline

on:
  push:
    branches: [ main, master ]
  pull_request:
    branches: [ main, master ]

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
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"
          cache: "pip"

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt

      - name: Run Pytest Suite
        run: |
          pytest -v
```

### Steps to Push & Run in GitHub Actions

1. Commit and push your code to GitHub:
   ```bash
   git add .
   git commit -m "Complete multi-tenant auth service with centralized logout, tests, and CI/CD"
   git push origin main
   ```
2. Navigate to your repository's **Actions** tab on GitHub.
3. The **CI/CD Pipeline** will trigger automatically, start the PostgreSQL container, install dependencies, and run all 15 tests.
