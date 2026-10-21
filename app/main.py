from contextlib import asynccontextmanager
import hashlib
from pathlib import Path
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

from alembic.config import Config
from alembic import command
from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Query, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from pydantic import BaseModel, EmailStr
import requests
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession

from database import get_db, engine, Base
from models import Application, RefreshToken, Session, UserDatabase, OauthAccount
from .security import hash_password, verify_password
import settings
from settings import ORIGINS

BASE_DIR = Path(__file__).resolve().parent.parent
ALEMBIC_INI_PATH = str(BASE_DIR / "alembic.ini")


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        alembic_cfg = Config(ALEMBIC_INI_PATH)
        command.upgrade(alembic_cfg, "head")
        print("Database migrations applied successfully to head.")
    except Exception as e:
        print(f"Alembic auto-migration notice: {e}")
        Base.metadata.create_all(bind=engine)
    yield


# ==============================================================================
# FASTAPI APPLICATION SETUP
# ==============================================================================

app = FastAPI(
    title="Centralized Authentication Service",
    description="Microservice providing Basic, Session, JWT, and OAuth authentication.",
    version="2.0.0",
    lifespan=lifespan,
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

class AppRegisterRequest(BaseModel):
    app_name: str


class AppRegisterResponse(BaseModel):
    app_id: int
    app_name: str
    api_key: str


class AuthRequest(BaseModel):
    username: str | None = None
    password: str | None = None
    email: EmailStr | None = None
    api_key: str | None = None


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

def register_application(db: DbSession, app_name: str) -> tuple[Application, str]:
    """Registers a new Application and returns the record and newly generated raw API key."""
    clean_name = app_name.strip()
    if not clean_name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="app_name cannot be empty",
        )
    existing = db.query(Application).filter(Application.app_name == clean_name).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Application '{clean_name}' already exists",
        )
    raw_api_key = f"ak_live_{secrets.token_urlsafe(24)}"
    api_key_hash = hashlib.sha256(raw_api_key.encode()).hexdigest()
    app_record = Application(
        app_name=clean_name,
        api_key_hash=api_key_hash,
    )
    db.add(app_record)
    try:
        db.commit()
        db.refresh(app_record)
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Could not register application '{clean_name}'",
        )
    return app_record, raw_api_key


def get_app_by_api_key(db: DbSession, api_key: str | None) -> Application:
    """Finds an Application record by hashing the provided API key."""
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key is required for application authentication",
        )
    api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    app_record = db.query(Application).filter(Application.api_key_hash == api_key_hash).first()
    if not app_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key for application",
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
    if not is_oauth and (not password or not verify_password(password, user.password_hash)):
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
    header_api_key: str | None = None,
) -> AuthResponse:
    effective_api_key = payload.api_key or header_api_key
    app_record = get_app_by_api_key(db=db, api_key=effective_api_key)

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
            samesite="none",
            secure=True,
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


# 2. Application Registration Endpoint
@app.post("/apps/register", response_model=AppRegisterResponse, status_code=status.HTTP_201_CREATED)
def register_app_endpoint(
    payload: AppRegisterRequest,
    db: DbSession = Depends(get_db),
):
    app_record, raw_api_key = register_application(db=db, app_name=payload.app_name)
    return AppRegisterResponse(
        app_id=app_record.id,
        app_name=app_record.app_name,
        api_key=raw_api_key,
    )


# 3. Basic Auth Route
@app.post("/basic-auth", response_model=AuthResponse)
def basic_auth_endpoint(
    payload: AuthRequest,
    response: Response,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: DbSession = Depends(get_db),
):
    return execute_authentication(payload, "basic", response, db, header_api_key=x_api_key)


# 4. Session Auth Route
@app.post("/session-auth", response_model=AuthResponse)
def session_auth_endpoint(
    payload: AuthRequest,
    response: Response,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: DbSession = Depends(get_db),
):
    return execute_authentication(payload, "session", response, db, header_api_key=x_api_key)


# 5. JWT Auth Route
@app.post("/jwt-auth", response_model=AuthResponse)
def jwt_auth_endpoint(
    payload: AuthRequest,
    response: Response,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: DbSession = Depends(get_db),
):
    return execute_authentication(payload, "jwt", response, db, header_api_key=x_api_key)


# 6. Direct OAuth Route (For SDKs and automated calls)
@app.post("/oauth", response_model=AuthResponse)
def oauth_auth_endpoint(
    payload: AuthRequest,
    response: Response,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: DbSession = Depends(get_db),
):
    return execute_authentication(payload, "oauth", response, db, header_api_key=x_api_key)


# 6a. OAuth Google Interactive Login Route (Redirects browser to Google)
@app.get("/oauth/google/login")
def google_oauth_login(
    api_key: str = Query(..., description="Application API key"),
    redirect_uri: str | None = Query(default=None, description="Client frontend URL to return to after login"),
    db: DbSession = Depends(get_db),
):
    """
    Initiates Google OAuth 2.0 flow:
    1. Validates the client application's API key.
    2. Encodes a secure signed JWT state containing the app reference and client redirect URI.
    3. Redirects the user's browser to Google's consent screen.
    """
    app_record = get_app_by_api_key(db=db, api_key=api_key)

    if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_REDIRECT_URI:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Google OAuth is not configured on this server",
        )

    state_payload = {
        "api_key": api_key,
        "app_id": app_record.id,
        "redirect_uri": redirect_uri,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
    }
    state_token = jwt.encode(state_payload, settings.JWT_SECRET_KEY, algorithm="HS256")

    google_auth_params = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "response_type": "code",
        "scope": "openid email profile",
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "state": state_token,
        "access_type": "offline",
        "prompt": "select_account",
    }
    google_url = f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(google_auth_params)}"
    return RedirectResponse(url=google_url, status_code=status.HTTP_302_FOUND)


# 6b. OAuth Google Callback Route (Exchanges code with Google and issues tokens)
@app.get("/oauth/google/callback")
def google_oauth_callback(
    code: str | None = Query(default=None),
    state: str | None = Query(default=None),
    error: str | None = Query(default=None),
    db: DbSession = Depends(get_db),
):
    """
    Google OAuth 2.0 Callback:
    1. Receives authorization code from Google redirect.
    2. Decodes and verifies state to identify client application and frontend redirect URL.
    3. Exchanges code for Google access token and retrieves verified email.
    4. Provisions or retrieves user in database and generates access & refresh tokens.
    5. Redirects back to client frontend with tokens, or returns JSON.
    """
    if error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Google OAuth error: {error}",
        )

    if not code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authorization code was not provided by Google",
        )

    if not state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing OAuth state parameter",
        )

    try:
        state_data = jwt.decode(state, settings.JWT_SECRET_KEY, algorithms=["HS256"])
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired OAuth state parameter",
        )

    api_key = state_data.get("api_key")
    client_redirect_uri = state_data.get("redirect_uri")
    app_record = get_app_by_api_key(db=db, api_key=api_key)

    # Exchange code for Google tokens
    token_url = "https://oauth2.googleapis.com/token"
    token_payload = {
        "code": code,
        "client_id": settings.GOOGLE_CLIENT_ID,
        "client_secret": settings.GOOGLE_CLIENT_SECRET,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code",
    }
    token_res = requests.post(token_url, data=token_payload, timeout=10)
    if token_res.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to exchange authorization code with Google",
        )

    google_tokens = token_res.json()
    google_access_token = google_tokens.get("access_token")
    if not google_access_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google did not return an access token",
        )

    # Fetch user profile using Google's userinfo endpoint
    userinfo_res = requests.get(
        "https://www.googleapis.com/oauth2/v3/userinfo",
        headers={"Authorization": f"Bearer {google_access_token}"},
        timeout=10,
    )
    if userinfo_res.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to fetch user profile from Google",
        )

    user_info = userinfo_res.json()
    email = user_info.get("email")
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google account has no associated email",
        )

    google_sub = user_info.get("sub") or hashlib.sha256(f"oauth_{email}".encode()).hexdigest()[:21]
    username = user_info.get("name") or email.split("@")[0]

    user, status_str, message_str = get_or_create_user(
        db=db, app_record=app_record, username=username, email=email, is_oauth=True
    )

    # Ensure OAuth link exists
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
            provider_user_id=google_sub,
        )
        db.add(oauth_link)
        db.commit()

    access_token = create_user_jwt(user=user, app_id=app_record.id)
    refresh_token = create_user_refresh_token(user=user, app_id=app_record.id, db=db)

    # If client app passed a redirect_uri, redirect back with tokens in query params
    if client_redirect_uri:
        delimiter = "&" if "?" in client_redirect_uri else "?"
        final_url = f"{client_redirect_uri}{delimiter}access_token={access_token}&refresh_token={refresh_token}&token_type=bearer"
        return RedirectResponse(url=final_url, status_code=status.HTTP_302_FOUND)

    return {
        "status": status_str,
        "message": message_str,
        "auth_type": "oauth",
        "app_name": app_record.app_name,
        "app_id": app_record.id,
        "user_id": user.id,
        "username": user.username,
        "email": user.email,
        "access_token": access_token,
        "token_type": "bearer",
        "refresh_token": refresh_token,
    }


# 7. JWT Refresh Route
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
