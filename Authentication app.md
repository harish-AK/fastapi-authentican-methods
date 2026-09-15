
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
JWT_SECRET_KEY="sjngkrg45kw4ntpwoihgnklrni5"
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
>If payload changes in the generated token, token will be invalidated 


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

If an user using the app for more than 15 mins and access token expiration is only 15 mins, refresh token will create new access token after every 15 mins untill user logs out. 

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

If refresh token C created by B and B created A and A is reused by attacker which is revoked means all the tokens created via A might also compromised so revoke all the tokens. 

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