
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
JWT_SECRET_KEY="<JWT_SECRET_KEY>"
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
	- client id -> <GOOGLE_CLIENT_ID>
	- client secret -> <GOOGLE_CLIENT_SECRET>

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
  "azp": "<GOOGLE_CLIENT_ID>",
  "aud": "<GOOGLE_CLIENT_ID>",
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
            detail=fInvalid state (received query state={state!r}, cookie state={google_state!r}). Mae sure you are using the same host (localhost vs 127.0.0.1) as GOOGLE_REDIRECT_URI.",
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