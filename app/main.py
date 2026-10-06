import hashlib
import json
import secrets
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

from fastapi import Cookie, Depends, FastAPI, HTTPException, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBasic, HTTPBasicCredentials, HTTPBearer
from google.auth.transport import requests
from google.oauth2 import id_token
import jwt
from pydantic import BaseModel, EmailStr
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession
from starlette.responses import JSONResponse, RedirectResponse

from database import get_db
from models import Application, OauthAccount, RefreshToken, Session, UserDatabase
from .security import hash_password, verify_password
import settings
from settings import ORIGINS

# ==============================================================================
# FASTAPI APPLICATION SETUP
# ==============================================================================

app = FastAPI(title="Authentication Playground Service")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Distinct security schemes (avoids variable shadowing)
basic_security = HTTPBasic()
bearer_security = HTTPBearer()

# In-memory user token versioning for instant access token revocation
USER_TOKEN_VERSIONS: dict[int, int] = {}


# ==============================================================================
# PYDANTIC SCHEMAS
# ==============================================================================

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    is_active: bool
    created_at: datetime


class UserLogin(BaseModel):
    username: str
    password: str


class LogoutRequest(BaseModel):
    username: str


class BasicAuthPayload(BaseModel):
    app_id: int
    username: str
    password: str
    email: EmailStr | None = None
    app_name: str | None = None


class BasicAuthResponse(BaseModel):
    status: str
    message: str
    app_id: int
    user_id: int
    username: str
    email: str


class SessionAuthPayload(BaseModel):
    app_id: int
    username: str
    password: str
    email: EmailStr | None = None
    app_name: str | None = None


class SessionAuthResponse(BaseModel):
    status: str
    message: str
    app_id: int
    user_id: int
    username: str
    email: str
    session_id: str


class JwtAuthPayload(BaseModel):
    app_id: int
    username: str
    password: str
    email: EmailStr | None = None
    app_name: str | None = None


class JwtAuthResponse(BaseModel):
    status: str
    message: str
    app_id: int
    user_id: int
    username: str
    email: str
    access_token: str
    token_type: str = "bearer"
    refresh_token: str


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class JwtRefreshPayload(BaseModel):
    refresh_token: str


class JwtRefreshResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    refresh_token: str
    app_id: int
    user_id: int


class GoogleOAuthPayload(BaseModel):
    app_id: int
    email: EmailStr
    provider: str = "google"
    provider_user_id: str | None = None
    app_name: str | None = None


class OAuthTokenResponse(BaseModel):
    status: str
    message: str
    app_id: int
    user_id: int
    username: str
    email: str
    access_token: str
    token_type: str = "bearer"
    refresh_token: str


# ==============================================================================
# HELPER FUNCTIONS (DRY & REUSABLE)
# ==============================================================================

def get_or_create_application(db: DbSession, app_id: int, app_name: str | None = None) -> Application:
    """Finds or creates an Application record for multi-tenant services."""
    app_record = db.query(Application).filter(Application.id == app_id).first()
    if not app_record:
        name = app_name or f"Application-{app_id}"
        api_key_hash = hashlib.sha256(f"{app_id}_{secrets.token_hex(16)}".encode()).hexdigest()
        app_record = Application(
            id=app_id,
            app_name=name,
            api_key_hash=api_key_hash,
        )
        db.add(app_record)
        try:
            db.flush()
        except IntegrityError:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Could not create application with provided app_id {app_id}",
            )
    return app_record


def authenticate_or_register_app_user(
    db: DbSession,
    app_id: int,
    username: str,
    password: str,
    email: str | None = None,
    app_name: str | None = None,
) -> tuple[Application, UserDatabase, str, str]:
    """
    Unified user provisioning and credential verification across Basic, Session, and JWT auth.
    Returns: (app_record, user, status_str, message_str)
    """
    app_record = get_or_create_application(db=db, app_id=app_id, app_name=app_name)

    user = db.query(UserDatabase).filter(
        UserDatabase.app_id == app_record.id,
        UserDatabase.username == username,
    ).first()

    if not user:
        # Register new user
        user_email = email or f"{username}@app{app_id}.com"
        user = UserDatabase(
            app_id=app_record.id,
            username=username,
            email=user_email,
            password_hash=hash_password(password),
            is_active=True,
        )
        db.add(user)
        try:
            db.commit()
            db.refresh(user)
            return app_record, user, "registered", "New user registered"
        except IntegrityError:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="User with this username or email already exists",
            )

    # Existing user -> verify credentials
    if not verify_password(password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive",
        )

    return app_record, user, "authenticated", "Login successful"


def generate_session_id() -> str:
    return secrets.token_urlsafe(32)


def hash_session_id(session_id: str) -> str:
    return hashlib.sha256(session_id.encode()).hexdigest()


def create_session(user_id: int, db: DbSession, app_id: int | None = None) -> str:
    session_id = generate_session_id()
    session_id_hash = hash_session_id(session_id)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=24)

    if app_id is None:
        user = db.query(UserDatabase).filter(UserDatabase.id == user_id).first()
        app_id = user.app_id if user else None

    new_session = Session(
        session_id_hash=session_id_hash,
        user_id=user_id,
        app_id=app_id,
        expires_at=expires_at,
    )
    try:
        db.add(new_session)
        db.commit()
        return session_id
    except IntegrityError:
        db.rollback()
        raise


def create_jwt_token(user: UserDatabase) -> str:
    now = datetime.now(timezone.utc)
    token_version = USER_TOKEN_VERSIONS.get(user.id, 1)
    payload = {
        "sub": str(user.id),
        "username": user.username,
        "token_version": token_version,
        "iat": now,
        "exp": now + timedelta(minutes=20),
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm="HS256")


def create_app_jwt_token(user: UserDatabase, app_id: int) -> str:
    now = datetime.now(timezone.utc)
    token_version = USER_TOKEN_VERSIONS.get(user.id, 1)
    payload = {
        "sub": str(user.id),
        "username": user.username,
        "email": user.email,
        "app_id": app_id,
        "token_version": token_version,
        "iat": now,
        "exp": now + timedelta(minutes=60),
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm="HS256")


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=["HS256"],
            options={"require": ["sub", "iat", "exp"]},
        )
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


def create_refresh_token(
    user: UserDatabase,
    db: DbSession,
    app_id: int | None = None,
    family_id: str | None = None,
) -> str:
    raw_refresh_token = secrets.token_urlsafe(64)
    token_hash = hashlib.sha256(raw_refresh_token.encode()).hexdigest()
    expires_at = datetime.now(timezone.utc) + timedelta(days=7)

    if family_id is None:
        family_id = secrets.token_urlsafe(32)

    if app_id is None:
        app_id = user.app_id

    new_refresh_token = RefreshToken(
        refresh_token_hash=token_hash,
        user_id=user.id,
        app_id=app_id,
        expires_at=expires_at,
        family_id=family_id,
    )
    try:
        db.add(new_refresh_token)
        db.commit()
        return raw_refresh_token
    except IntegrityError:
        db.rollback()
        raise


def perform_refresh_token_rotation(
    raw_token: str,
    db: DbSession,
    app_scoped: bool = False,
) -> tuple[UserDatabase, RefreshToken, str, str]:
    """
    Unified Refresh Token Rotation (RTR) and Reuse Detection engine.
    Returns: (user, stored_token, new_access_token, new_refresh_token)
    """
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    stored_token = db.query(RefreshToken).filter(
        RefreshToken.refresh_token_hash == token_hash
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
        )

    # Reuse detection: if an already revoked token is used, revoke the entire token family
    if stored_token.revoked:
        db.query(RefreshToken).filter(
            RefreshToken.family_id == stored_token.family_id
        ).update({"revoked": True})
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Revoked refresh token reused. All tokens in this family have been invalidated.",
        )

    user = stored_token.user
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    # Revoke current token
    stored_token.revoked = True

    # Mint rotated refresh token in the same family
    new_refresh_token = create_refresh_token(
        user=user,
        db=db,
        app_id=stored_token.app_id,
        family_id=stored_token.family_id,
    )

    # Generate new access token
    if app_scoped:
        new_access_token = create_app_jwt_token(user=user, app_id=stored_token.app_id)
    else:
        new_access_token = create_jwt_token(user)

    return user, stored_token, new_access_token, new_refresh_token


def exchange_google_code_for_token(code: str, nonce: str | None = None, redirect_uri: str | None = None) -> dict:
    token_url = "https://oauth2.googleapis.com/token"
    token_data = {
        "code": code,
        "client_id": settings.GOOGLE_CLIENT_ID,
        "client_secret": settings.GOOGLE_CLIENT_SECRET,
        "redirect_uri": redirect_uri or settings.GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code",
    }
    if nonce:
        token_data["nonce"] = nonce

    payload = urllib.parse.urlencode(token_data).encode("utf-8")
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


def process_google_oauth_user(
    app_id: int,
    email: str,
    provider_user_id: str | None = None,
    app_name: str | None = None,
    provider: str = "google",
    db: DbSession = None,
) -> OAuthTokenResponse:
    google_sub = provider_user_id or hashlib.sha256(f"google_{email.lower()}".encode()).hexdigest()[:21]

    # 1. Find or create Application
    app_record = get_or_create_application(db=db, app_id=app_id, app_name=app_name)

    # 2. Find OauthAccount scoped to this app + provider
    oauth_account = db.query(OauthAccount).filter(
        OauthAccount.provider == provider,
        OauthAccount.provider_user_id == google_sub,
        OauthAccount.app_id == app_id,
    ).first()

    status_str = "authenticated"
    message_str = "Google OAuth login successful"

    if oauth_account:
        user = db.query(UserDatabase).filter(UserDatabase.id == oauth_account.user_id).first()
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User linked to OAuth account not found")
    else:
        user = db.query(UserDatabase).filter(
            UserDatabase.app_id == app_id,
            UserDatabase.email == email,
        ).first()

        if not user:
            base_username = email.split("@")[0] or f"user_{google_sub[:8]}"
            username = base_username
            suffix = 1
            while db.query(UserDatabase).filter(
                UserDatabase.app_id == app_id,
                UserDatabase.username == username,
            ).first():
                username = f"{base_username}_{suffix}"
                suffix += 1

            user = UserDatabase(
                app_id=app_id,
                username=username,
                email=email,
                password_hash=hash_password(secrets.token_urlsafe(32)),
                is_active=True,
            )
            db.add(user)
            db.flush()
            status_str = "registered"
            message_str = "New user registered via Google OAuth"

        oauth_account = OauthAccount(
            user_id=user.id,
            app_id=app_id,
            provider=provider,
            provider_user_id=google_sub,
        )
        db.add(oauth_account)

    try:
        db.commit()
        db.refresh(user)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Could not save OAuth account")

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is inactive")

    access_token = create_app_jwt_token(user=user, app_id=app_id)
    refresh_token = create_refresh_token(user=user, db=db, app_id=app_id)

    return OAuthTokenResponse(
        status=status_str,
        message=message_str,
        app_id=app_id,
        user_id=user.id,
        username=user.username,
        email=user.email,
        access_token=access_token,
        token_type="bearer",
        refresh_token=refresh_token,
    )


# ==============================================================================
# DEPENDENCIES (AUTH EXTRACTORS)
# ==============================================================================

def get_current_user_basic(
    db: DbSession = Depends(get_db),
    credentials: HTTPBasicCredentials = Depends(basic_security),
) -> UserDatabase:
    user = db.query(UserDatabase).filter(UserDatabase.username == credentials.username).first()
    if not user or not verify_password(credentials.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User is not active",
            headers={"WWW-Authenticate": "Basic"},
        )
    return user


def get_current_user_session(
    db: DbSession = Depends(get_db),
    session_id: str | None = Cookie(default=None),
) -> UserDatabase:
    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session not found",
        )
    session_id_hash = hash_session_id(session_id)
    session = db.query(Session).filter(
        Session.session_id_hash == session_id_hash
    ).first()

    if not session or session.expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid session",
        )
    return session.user


def get_current_user_jwt(
    token=Depends(bearer_security),
    db: DbSession = Depends(get_db),
) -> UserDatabase:
    payload = decode_token(token.credentials)
    user_id = payload.get("sub")
    if user_id is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    try:
        user_id = int(user_id)
    except (ValueError, TypeError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    user = db.query(UserDatabase).filter(UserDatabase.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User is not active")

    # Verify token version hasn't been revoked via logout
    expected_version = USER_TOKEN_VERSIONS.get(user.id, 1)
    if payload.get("token_version") != expected_version:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked. Please login again.",
        )

    return user


# ==============================================================================
# ROUTE ENDPOINTS
# ==============================================================================

@app.get("/")
def read_root():
    return {"Hello": "World"}


@app.get("/health")
def health_check():
    return {"status": "Healthy"}


@app.post("/users", response_model=UserResponse)
def create_user(user: UserCreate, db: DbSession = Depends(get_db)):
    if db.query(UserDatabase).filter(UserDatabase.username == user.username).first():
        raise HTTPException(status_code=409, detail="Username already exists")

    if db.query(UserDatabase).filter(UserDatabase.email == user.email).first():
        raise HTTPException(status_code=409, detail="Email already exists")

    app_record = get_or_create_application(db=db, app_id=1, app_name="Default Application")
    hashed_password = hash_password(user.password)

    new_user = UserDatabase(
        app_id=app_record.id,
        username=user.username,
        email=user.email,
        password_hash=hashed_password,
    )
    try:
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        return new_user
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Username or email already exists")


# ------------------------------------------------------------------------------
# 1. HTTP Basic Auth
# ------------------------------------------------------------------------------

@app.get("/test")
def test_basic_auth(current_user: UserDatabase = Depends(get_current_user_basic)):
    return {"username": current_user.username, "message": "Successfully authenticated!"}


@app.post("/basic-auth", response_model=BasicAuthResponse)
def basic_auth_service(payload: BasicAuthPayload, db: DbSession = Depends(get_db)):
    app_record, user, status_str, _ = authenticate_or_register_app_user(
        db=db,
        app_id=payload.app_id,
        username=payload.username,
        password=payload.password,
        email=payload.email,
        app_name=payload.app_name,
    )
    # Match exact status string required by existing tests ("registered" / "verified")
    final_status = "registered" if status_str == "registered" else "verified"
    message = "New application and user created successfully" if status_str == "registered" else "User verified successfully"
    return BasicAuthResponse(
        status=final_status,
        message=message,
        app_id=app_record.id,
        user_id=user.id,
        username=user.username,
        email=user.email,
    )


# ------------------------------------------------------------------------------
# 2. Session Auth
# ------------------------------------------------------------------------------

@app.post("/login")
def login(login_data: UserLogin, response: Response, db: DbSession = Depends(get_db)):
    user = db.query(UserDatabase).filter(UserDatabase.username == login_data.username).first()
    if not user or not verify_password(login_data.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User is not active")

    session_id = create_session(user.id, db)
    response.set_cookie(
        key="session_id",
        value=session_id,
        httponly=True,
        samesite="lax",
        secure=False,
    )
    return {"message": "Login successful"}


@app.get("/profile")
def profile(user: UserDatabase = Depends(get_current_user_session)):
    return {"username": user.username, "email": user.email, "id": user.id}


@app.post("/session-auth", response_model=SessionAuthResponse)
def session_auth_service(
    payload: SessionAuthPayload,
    response: Response,
    db: DbSession = Depends(get_db),
):
    app_record, user, status_str, message_str = authenticate_or_register_app_user(
        db=db,
        app_id=payload.app_id,
        username=payload.username,
        password=payload.password,
        email=payload.email,
        app_name=payload.app_name,
    )
    session_id = create_session(user_id=user.id, db=db, app_id=app_record.id)
    response.set_cookie(
        key="session_id",
        value=session_id,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=86400,
    )
    return SessionAuthResponse(
        status=status_str,
        message=message_str,
        app_id=app_record.id,
        user_id=user.id,
        username=user.username,
        email=user.email,
        session_id=session_id,
    )


# ------------------------------------------------------------------------------
# 3. JWT Auth
# ------------------------------------------------------------------------------

@app.post("/jwt-login")
def jwt_login(login_data: UserLogin, db: DbSession = Depends(get_db)):
    user = db.query(UserDatabase).filter(UserDatabase.username == login_data.username).first()
    if not user or not verify_password(login_data.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User is not active")

    token = create_jwt_token(user)
    refresh_token = create_refresh_token(user, db)
    return {"access_token": token, "token_type": "bearer", "refresh_token": refresh_token}


@app.get("/jwt-profile")
def jwt_profile(current_user: UserDatabase = Depends(get_current_user_jwt)):
    return {"username": current_user.username, "email": current_user.email, "id": current_user.id}


@app.post("/jwt-refresh")
def jwt_refresh(request: RefreshTokenRequest, db: DbSession = Depends(get_db)):
    _, _, new_access_token, new_refresh_token = perform_refresh_token_rotation(
        raw_token=request.refresh_token,
        db=db,
        app_scoped=False,
    )
    return {"access_token": new_access_token, "refresh_token": new_refresh_token}


@app.post("/jwt-auth", response_model=JwtAuthResponse)
def jwt_auth_service(payload: JwtAuthPayload, db: DbSession = Depends(get_db)):
    app_record, user, status_str, message_str = authenticate_or_register_app_user(
        db=db,
        app_id=payload.app_id,
        username=payload.username,
        password=payload.password,
        email=payload.email,
        app_name=payload.app_name,
    )
    access_token = create_app_jwt_token(user=user, app_id=app_record.id)
    refresh_token = create_refresh_token(user=user, db=db, app_id=app_record.id)

    return JwtAuthResponse(
        status=status_str,
        message=message_str,
        app_id=app_record.id,
        user_id=user.id,
        username=user.username,
        email=user.email,
        access_token=access_token,
        token_type="bearer",
        refresh_token=refresh_token,
    )


@app.post("/jwt-auth/refresh", response_model=JwtRefreshResponse)
def jwt_auth_refresh_service(payload: JwtRefreshPayload, db: DbSession = Depends(get_db)):
    user, stored_token, new_access_token, new_refresh_token = perform_refresh_token_rotation(
        raw_token=payload.refresh_token,
        db=db,
        app_scoped=True,
    )
    return JwtRefreshResponse(
        access_token=new_access_token,
        token_type="bearer",
        refresh_token=new_refresh_token,
        app_id=stored_token.app_id,
        user_id=user.id,
    )


# ------------------------------------------------------------------------------
# 4. Centralized Universal Logout
# ------------------------------------------------------------------------------

@app.post("/logout")
def logout(
    payload: LogoutRequest,
    response: Response,
    db: DbSession = Depends(get_db),
):
    user = db.query(UserDatabase).filter(UserDatabase.username == payload.username).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # 1. Delete all active sessions in DB
    db.query(Session).filter(Session.user_id == user.id).delete()

    # 2. Revoke and delete all refresh tokens in DB
    db.query(RefreshToken).filter(RefreshToken.user_id == user.id).delete()

    # 3. Immediately invalidate all active JWT access tokens
    USER_TOKEN_VERSIONS[user.id] = USER_TOKEN_VERSIONS.get(user.id, 1) + 1

    db.commit()

    # 4. Clear auth cookies
    response.delete_cookie("session_id", path="/")
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/")

    return {
        "message": f"User {user.username} logged out successfully. All sessions and tokens have been invalidated."
    }


# ------------------------------------------------------------------------------
# 5. OAuth 2.0 (Google)
# ------------------------------------------------------------------------------

@app.get("/oauth/google/login")
def google_login_prototype():
    if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_REDIRECT_URI:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Google OAuth is not configured properly in .env",
        )
    nonce = secrets.token_urlsafe(32)
    state = secrets.token_urlsafe(32)
    auth_params = urllib.parse.urlencode({
        "client_id": settings.GOOGLE_CLIENT_ID,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "email profile openid",
        "state": state,
        "nonce": nonce,
    })
    auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?{auth_params}"
    res = RedirectResponse(auth_url)
    res.set_cookie("google_state", state, httponly=True, secure=False, samesite="lax", max_age=600)
    res.set_cookie("google_nonce", nonce, httponly=True, secure=False, samesite="lax", max_age=600)
    return res


@app.get("/oauth/google/callback")
def google_callback_prototype(
    code: str,
    state: str,
    response: Response,
    google_state: str | None = Cookie(default=None),
    google_nonce: str | None = Cookie(default=None),
    db: DbSession = Depends(get_db),
):
    if state != google_state:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid state")
    if not code:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No code provided")
    if not google_nonce:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid nonce")

    token_response = exchange_google_code_for_token(code)
    try:
        id_info = id_token.verify_oauth2_token(
            token_response["id_token"],
            requests.Request(),
            settings.GOOGLE_CLIENT_ID,
            clock_skew_in_seconds=10,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid Google ID token: {e}")

    if id_info.get("nonce") != google_nonce:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid nonce")

    if id_info.get("iss") not in ["accounts.google.com", "https://accounts.google.com"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid issuer")

    email = id_info.get("email")
    google_sub = id_info.get("sub")
    if not google_sub or not email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing sub or email in Google ID token")

    token_data = process_google_oauth_user(app_id=1, email=email, provider_user_id=google_sub, db=db)
    session_id = create_session(token_data.user_id, db=db, app_id=1)

    res = JSONResponse(content={"message": "Login successful"})
    res.delete_cookie("google_state", path="/")
    res.delete_cookie("google_nonce", path="/")
    res.set_cookie("session_id", session_id, httponly=True, samesite="lax", secure=False, max_age=86400, path="/")
    return res


@app.post("/login/google", response_model=OAuthTokenResponse)
@app.post("/oauth-service/google/login", response_model=OAuthTokenResponse)
def oauth_service_google_login_post(
    payload: GoogleOAuthPayload,
    db: DbSession = Depends(get_db),
):
    return process_google_oauth_user(
        app_id=payload.app_id,
        email=payload.email,
        provider_user_id=payload.provider_user_id,
        app_name=payload.app_name,
        provider=payload.provider,
        db=db,
    )


@app.get("/oauth-service/google/login")
def oauth_service_google_login(
    app_id: int,
    redirect: bool = True,
):
    redirect_uri = settings.OAUTH_SERVICE_REDIRECT_URI or settings.GOOGLE_REDIRECT_URI
    if not settings.GOOGLE_CLIENT_ID or not redirect_uri:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Google OAuth is not configured in .env",
        )

    nonce = secrets.token_urlsafe(32)
    raw_state = secrets.token_urlsafe(32)
    state = f"{raw_state}.{app_id}"

    auth_params = urllib.parse.urlencode({
        "client_id": settings.GOOGLE_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "email profile openid",
        "state": state,
        "nonce": nonce,
    })
    auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?{auth_params}"

    if redirect:
        res = RedirectResponse(auth_url)
    else:
        res = JSONResponse(content={
            "status": "ok",
            "app_id": app_id,
            "auth_url": auth_url,
            "state": state,
        })

    res.set_cookie("oauth_service_state", raw_state, httponly=True, secure=False, samesite="lax", max_age=600, path="/")
    res.set_cookie("oauth_service_nonce", nonce, httponly=True, secure=False, samesite="lax", max_age=600, path="/")
    return res


@app.get("/oauth-service/google/callback", response_model=OAuthTokenResponse)
def oauth_service_google_callback(
    code: str,
    state: str,
    response: Response,
    oauth_service_state: str | None = Cookie(default=None),
    oauth_service_nonce: str | None = Cookie(default=None),
    db: DbSession = Depends(get_db),
):
    if not state or "." not in state:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid state format")

    raw_state, _, app_id_str = state.rpartition(".")
    if raw_state != oauth_service_state:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid state (CSRF check failed)")

    try:
        app_id = int(app_id_str)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid app_id in state")

    if not oauth_service_nonce:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing nonce cookie")

    redirect_uri = settings.OAUTH_SERVICE_REDIRECT_URI or settings.GOOGLE_REDIRECT_URI
    token_response = exchange_google_code_for_token(code, redirect_uri=redirect_uri)

    try:
        id_info = id_token.verify_oauth2_token(
            token_response["id_token"],
            requests.Request(),
            settings.GOOGLE_CLIENT_ID,
            clock_skew_in_seconds=10,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid Google ID token: {e}")

    if id_info.get("nonce") != oauth_service_nonce:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Nonce mismatch")

    if id_info.get("iss") not in ["accounts.google.com", "https://accounts.google.com"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid issuer")

    google_sub = id_info.get("sub")
    email = id_info.get("email")
    if not google_sub or not email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing sub or email from Google")

    token_data = process_google_oauth_user(
        app_id=app_id,
        email=email,
        provider_user_id=google_sub,
        provider="google",
        db=db,
    )

    res = JSONResponse(content=token_data.model_dump())
    res.delete_cookie("oauth_service_state", path="/")
    res.delete_cookie("oauth_service_nonce", path="/")
    return res
