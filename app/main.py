import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import Cookie, Depends, FastAPI, HTTPException, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBasic, HTTPBasicCredentials, HTTPBearer, HTTPAuthorizationCredentials
import jwt
from pydantic import BaseModel, EmailStr
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession

from database import get_db
from models import Application, OauthAccount, RefreshToken, Session, UserDatabase
from .security import hash_password, verify_password
import settings
from settings import ORIGINS

# ==============================================================================
# FASTAPI APPLICATION SETUP
# ==============================================================================

app = FastAPI(
    title="Centralized Authentication Service",
    description="Microservice providing Basic, Session, JWT, and OAuth authentication.",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

bearer_scheme = HTTPBearer(auto_error=False)

# In-memory tracking of user token versions for immediate JWT revocation
USER_TOKEN_VERSIONS: dict[int, int] = {}


# ==============================================================================
# SCHEMAS
# ==============================================================================

class AuthRequest(BaseModel):
    username: str | None = None
    password: str | None = None
    email: EmailStr | None = None
    app_name: str = "DefaultApp"
    app_id: int | None = None
    auth_type: str | None = None  # "basic", "session", "jwt", "oauth"


class AuthResponse(BaseModel):
    status: str
    message: str
    auth_type: str
    app_name: str
    app_id: int
    user_id: int
    username: str
    email: str
    session_id: str | None = None
    access_token: str | None = None
    token_type: str | None = None
    refresh_token: str | None = None


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class RefreshResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    refresh_token: str
    app_id: int
    user_id: int


class LogoutRequest(BaseModel):
    username: str
    app_name: str | None = None


# ==============================================================================
# CORE REUSABLE HELPERS
# ==============================================================================

def get_or_create_app(db: DbSession, app_name: str, app_id: int | None = None) -> Application:
    """Finds or creates an Application record by app_name or app_id."""
    query = db.query(Application)
    if app_id is not None:
        app_record = query.filter(Application.id == app_id).first()
        if app_record:
            return app_record

    app_record = query.filter(Application.app_name == app_name).first()
    if not app_record:
        api_key_hash = hashlib.sha256(f"{app_name}_{secrets.token_hex(16)}".encode()).hexdigest()
        app_record = Application(
            id=app_id,
            app_name=app_name,
            api_key_hash=api_key_hash,
        )
        db.add(app_record)
        try:
            db.flush()
        except IntegrityError:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Could not initialize application '{app_name}'",
            )
    return app_record


def get_or_create_user(
    db: DbSession,
    app_record: Application,
    username: str,
    password: str | None = None,
    email: str | None = None,
    is_oauth: bool = False,
) -> tuple[UserDatabase, str, str]:
    """Finds an existing user or creates a new one under the given application."""
    user = db.query(UserDatabase).filter(
        UserDatabase.app_id == app_record.id,
        UserDatabase.username == username,
    ).first()

    if not user:
        user_email = email or f"{username}@{app_record.app_name.lower().replace(' ', '')}.com"
        pwd_hash = hash_password(password) if password else hash_password(secrets.token_urlsafe(32))
        user = UserDatabase(
            app_id=app_record.id,
            username=username,
            email=user_email,
            password_hash=pwd_hash,
            is_active=True,
        )
        db.add(user)
        try:
            db.commit()
            db.refresh(user)
            return user, "registered", "New user registered successfully"
        except IntegrityError:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="User with this username or email already exists",
            )

    # User exists
    if not is_oauth:
        if not password or not verify_password(password, user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
            )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive",
        )

    return user, "verified", "User verified successfully"


def create_user_session(user_id: int, app_id: int, db: DbSession) -> str:
    session_id = secrets.token_urlsafe(32)
    session_hash = hashlib.sha256(session_id.encode()).hexdigest()
    expires_at = datetime.now(timezone.utc) + timedelta(hours=24)

    session = Session(
        session_id_hash=session_hash,
        user_id=user_id,
        app_id=app_id,
        expires_at=expires_at,
    )
    db.add(session)
    db.commit()
    return session_id


def create_user_jwt(user: UserDatabase, app_id: int) -> str:
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


def create_user_refresh_token(
    user: UserDatabase,
    app_id: int,
    db: DbSession,
    family_id: str | None = None,
) -> str:
    raw_token = secrets.token_urlsafe(64)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    expires_at = datetime.now(timezone.utc) + timedelta(days=7)

    refresh_token = RefreshToken(
        refresh_token_hash=token_hash,
        user_id=user.id,
        app_id=app_id,
        expires_at=expires_at,
        family_id=family_id or secrets.token_urlsafe(32),
    )
    db.add(refresh_token)
    db.commit()
    return raw_token


def decode_jwt(token: str) -> dict:
    try:
        return jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=["HS256"],
            options={"require": ["sub", "iat", "exp"]},
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except (jwt.MissingRequiredClaimError, jwt.InvalidTokenError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")


# ==============================================================================
# AUTH ENGINE (CENTRAL DISPATCHER)
# ==============================================================================

def execute_authentication(
    payload: AuthRequest,
    target_auth_type: str,
    response: Response,
    db: DbSession,
) -> AuthResponse:
    app_record = get_or_create_app(db=db, app_name=payload.app_name, app_id=payload.app_id)

    # 1. BASIC AUTH
    if target_auth_type == "basic":
        if not payload.username or not payload.password:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username and password are required")
        user, status_str, message_str = get_or_create_user(
            db=db, app_record=app_record, username=payload.username, password=payload.password, email=payload.email
        )
        return AuthResponse(
            status=status_str,
            message=message_str,
            auth_type="basic",
            app_name=app_record.app_name,
            app_id=app_record.id,
            user_id=user.id,
            username=user.username,
            email=user.email,
        )

    # 2. SESSION AUTH
    elif target_auth_type == "session":
        if not payload.username or not payload.password:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username and password are required")
        user, status_str, message_str = get_or_create_user(
            db=db, app_record=app_record, username=payload.username, password=payload.password, email=payload.email
        )
        session_id = create_user_session(user_id=user.id, app_id=app_record.id, db=db)
        response.set_cookie(
            key="session_id",
            value=session_id,
            httponly=True,
            samesite="lax",
            secure=False,
            max_age=86400,
        )
        return AuthResponse(
            status=status_str,
            message=message_str,
            auth_type="session",
            app_name=app_record.app_name,
            app_id=app_record.id,
            user_id=user.id,
            username=user.username,
            email=user.email,
            session_id=session_id,
        )

    # 3. JWT AUTH
    elif target_auth_type == "jwt":
        if not payload.username or not payload.password:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username and password are required")
        user, status_str, message_str = get_or_create_user(
            db=db, app_record=app_record, username=payload.username, password=payload.password, email=payload.email
        )
        access_token = create_user_jwt(user=user, app_id=app_record.id)
        refresh_token = create_user_refresh_token(user=user, app_id=app_record.id, db=db)
        return AuthResponse(
            status=status_str,
            message=message_str,
            auth_type="jwt",
            app_name=app_record.app_name,
            app_id=app_record.id,
            user_id=user.id,
            username=user.username,
            email=user.email,
            access_token=access_token,
            token_type="bearer",
            refresh_token=refresh_token,
        )

    # 4. OAUTH (GOOGLE / SOCIAL)
    elif target_auth_type == "oauth":
        if not payload.email:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email is required for OAuth")
        username = payload.username or payload.email.split("@")[0]
        user, status_str, message_str = get_or_create_user(
            db=db, app_record=app_record, username=username, email=payload.email, is_oauth=True
        )
        # Ensure OAuth link exists
        provider_sub = hashlib.sha256(f"oauth_{payload.email}".encode()).hexdigest()[:21]
        oauth_link = db.query(OauthAccount).filter(
            OauthAccount.app_id == app_record.id,
            OauthAccount.user_id == user.id,
            OauthAccount.provider == "google",
        ).first()
        if not oauth_link:
            oauth_link = OauthAccount(
                user_id=user.id,
                app_id=app_record.id,
                provider="google",
                provider_user_id=provider_sub,
            )
            db.add(oauth_link)
            db.commit()

        access_token = create_user_jwt(user=user, app_id=app_record.id)
        refresh_token = create_user_refresh_token(user=user, app_id=app_record.id, db=db)
        return AuthResponse(
            status=status_str,
            message=message_str,
            auth_type="oauth",
            app_name=app_record.app_name,
            app_id=app_record.id,
            user_id=user.id,
            username=user.username,
            email=user.email,
            access_token=access_token,
            token_type="bearer",
            refresh_token=refresh_token,
        )

    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported auth_type '{target_auth_type}'. Choose from: 'basic', 'session', 'jwt', 'oauth'.",
        )


# ==============================================================================
# STREAMLINED ENDPOINTS
# ==============================================================================

# 1. Health Check
@app.get("/health")
def health_check():
    return {"status": "Healthy"}


# 2. Master Unified Auth Endpoint
@app.post("/auth", response_model=AuthResponse)
def unified_auth_endpoint(
    payload: AuthRequest,
    response: Response,
    db: DbSession = Depends(get_db),
):
    target_type = (payload.auth_type or "jwt").lower()
    return execute_authentication(payload, target_type, response, db)


# 3. Basic Auth Route
@app.post("/basic", response_model=AuthResponse)
@app.post("/basic-auth", response_model=AuthResponse)
def basic_auth_endpoint(
    payload: AuthRequest,
    response: Response,
    db: DbSession = Depends(get_db),
):
    return execute_authentication(payload, "basic", response, db)


# 4. Session Auth Route
@app.post("/session", response_model=AuthResponse)
@app.post("/session-auth", response_model=AuthResponse)
def session_auth_endpoint(
    payload: AuthRequest,
    response: Response,
    db: DbSession = Depends(get_db),
):
    return execute_authentication(payload, "session", response, db)


# 5. JWT Auth Route
@app.post("/jwt", response_model=AuthResponse)
@app.post("/jwt-auth", response_model=AuthResponse)
def jwt_auth_endpoint(
    payload: AuthRequest,
    response: Response,
    db: DbSession = Depends(get_db),
):
    return execute_authentication(payload, "jwt", response, db)


# 6. OAuth Route
@app.post("/oauth", response_model=AuthResponse)
@app.post("/login/google", response_model=AuthResponse)
@app.post("/oauth-service/google/login", response_model=AuthResponse)
def oauth_auth_endpoint(
    payload: AuthRequest,
    response: Response,
    db: DbSession = Depends(get_db),
):
    return execute_authentication(payload, "oauth", response, db)


# 7. JWT Refresh Route
@app.post("/jwt/refresh", response_model=RefreshResponse)
@app.post("/jwt-refresh", response_model=RefreshResponse)
@app.post("/jwt-auth/refresh", response_model=RefreshResponse)
def refresh_token_endpoint(
    payload: RefreshTokenRequest,
    db: DbSession = Depends(get_db),
):
    token_hash = hashlib.sha256(payload.refresh_token.encode()).hexdigest()
    stored_token = db.query(RefreshToken).filter(
        RefreshToken.refresh_token_hash == token_hash
    ).first()

    if not stored_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    if stored_token.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired")

    # Reuse detection
    if stored_token.revoked:
        db.query(RefreshToken).filter(RefreshToken.family_id == stored_token.family_id).update({"revoked": True})
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Revoked refresh token reused. All tokens in this family have been invalidated.",
        )

    user = stored_token.user
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")

    stored_token.revoked = True
    new_refresh = create_user_refresh_token(
        user=user, app_id=stored_token.app_id, db=db, family_id=stored_token.family_id
    )
    new_access = create_user_jwt(user=user, app_id=stored_token.app_id)

    return RefreshResponse(
        access_token=new_access,
        token_type="bearer",
        refresh_token=new_refresh,
        app_id=stored_token.app_id,
        user_id=user.id,
    )


# 8. Centralized Universal Logout
@app.post("/logout")
def centralized_logout_endpoint(
    payload: LogoutRequest,
    response: Response,
    db: DbSession = Depends(get_db),
):
    query = db.query(UserDatabase).filter(UserDatabase.username == payload.username)
    if payload.app_name:
        query = query.join(Application).filter(Application.app_name == payload.app_name)

    user = query.first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Invalidate all sessions in DB
    db.query(Session).filter(Session.user_id == user.id).delete()

    # Invalidate all refresh tokens in DB
    db.query(RefreshToken).filter(RefreshToken.user_id == user.id).delete()

    # Invalidate all active JWT access tokens immediately
    USER_TOKEN_VERSIONS[user.id] = USER_TOKEN_VERSIONS.get(user.id, 1) + 1

    db.commit()

    # Clear cookies
    response.delete_cookie("session_id", path="/")
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/")

    return {
        "status": "success",
        "message": f"User '{user.username}' logged out successfully. All sessions and tokens have been invalidated.",
    }


# 9. Token & Session Verification Introspection Route
@app.get("/verify")
def verify_token_or_session_endpoint(
    bearer: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    session_id: str | None = Cookie(default=None),
    db: DbSession = Depends(get_db),
):
    """
    Introspection route for deployed instances:
    Validates either a Bearer JWT or a session_id cookie.
    Returns the authenticated user details or raises 401.
    """
    # 1. Check Bearer JWT
    if bearer and bearer.credentials:
        payload = decode_jwt(bearer.credentials)
        user_id = payload.get("sub")
        user = db.query(UserDatabase).filter(UserDatabase.id == int(user_id)).first() if user_id else None

        if not user or not user.is_active:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")

        # Check token version revocation
        expected_version = USER_TOKEN_VERSIONS.get(user.id, 1)
        if payload.get("token_version") != expected_version:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has been revoked")

        return {
            "valid": True,
            "auth_type": "jwt",
            "user_id": user.id,
            "username": user.username,
            "email": user.email,
            "app_id": user.app_id,
        }

    # 2. Check Session Cookie
    if session_id:
        session_hash = hashlib.sha256(session_id.encode()).hexdigest()
        session_record = db.query(Session).filter(
            Session.session_id_hash == session_hash,
            Session.expires_at > datetime.now(timezone.utc),
        ).first()

        if session_record and session_record.user and session_record.user.is_active:
            return {
                "valid": True,
                "auth_type": "session",
                "user_id": session_record.user.id,
                "username": session_record.user.username,
                "email": session_record.user.email,
                "app_id": session_record.app_id,
            }

        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid session")

    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No authentication credentials provided")
