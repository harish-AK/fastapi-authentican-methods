from datetime import datetime, timedelta, timezone
import hashlib
import secrets

from fastapi import FastAPI, Depends, HTTPException, status, Response, Cookie
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session as DbSession
from sqlalchemy.exc import IntegrityError

from .security import hash_password, verify_password
from database import get_db
from models import UserDatabase, Session, RefreshToken, OauthAccount

app = FastAPI()

@app.get("/")
def read_root():
    return {"Hello": "World"}

@app.get("/health")
def health_check():
    return {"status": "Healthy"}


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


@app.post("/users", response_model=UserResponse)
def create_user(user: UserCreate, db: DbSession = Depends(get_db)):
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
        # This protects against race conditions between the checks above
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

security = HTTPBasic()
def get_current_user(db: DbSession = Depends(get_db), credentials: HTTPBasicCredentials = Depends(security)):
    user_in_db = db.query(UserDatabase).filter(
        UserDatabase.username == credentials.username
    ).first()

    if not user_in_db or not verify_password(credentials.password, user_in_db.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )

    if not user_in_db.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User is not active",
            headers={"WWW-Authenticate": "Basic"},
        )

    return user_in_db

@app.get('/test')
def test(current_user: UserDatabase = Depends(get_current_user)):
    return {"username": current_user.username, "message": "Successfully authenticated!"}

def generate_session_id() -> str:
    return secrets.token_urlsafe(32)

def hash_session_id(session_id: str) -> str:
    return hashlib.sha256(session_id.encode()).hexdigest()

def create_session(user_id: int, db: DbSession) -> str:
    session_id = generate_session_id()
    session_id_hash = hash_session_id(session_id)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
    new_session = Session(
        session_id_hash=session_id_hash,
        user_id=user_id,
        expires_at=expires_at
    )
    try:
        db.add(new_session)
        db.commit()
        return session_id
    except IntegrityError:
        db.rollback()
        raise

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

def get_current_user_session(db: DbSession = Depends(get_db), 
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
    if not session or session.expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid session",
        )
    return session.user

@app.get("/profile")
def profile(user:UserDatabase = Depends(get_current_user_session)):
    return {"username": user.username, "email": user.email, "id": user.id}

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
    return token  


@app.post("/jwt-login")
def jwt_login(login_data: UserLogin, db: DbSession = Depends(get_db)):
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

    token = create_jwt_token(user)
    refresh_token = create_refresh_token(user, db)
    return {"access_token": token, "token_type": "bearer", "refresh_token": refresh_token}  

def decode_token(token: str):
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=["HS256"],
            options={"require": ["sub", "iat", "exp"]}
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


def create_refresh_token(user: UserDatabase, db: DbSession, family_id: str | None = None):
    refresh_token = secrets.token_urlsafe(64)
    refresh_token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    expires_at = datetime.now(timezone.utc) + timedelta(days=7)
    
    if family_id is None:
        family_id = secrets.token_urlsafe(32)

    new_refresh_token = RefreshToken(
        refresh_token_hash=refresh_token_hash,
        user_id=user.id,
        expires_at=expires_at,
        family_id=family_id
    )
    try:
        db.add(new_refresh_token)
        db.commit()
        return refresh_token
    except IntegrityError:
        db.rollback()
        raise


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
        )
    if stored_token.revoked:
        # Reuse detection: Revoke all tokens belonging to this family
        db.query(RefreshToken).filter(
            RefreshToken.family_id == stored_token.family_id
        ).update({"revoked": True})
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Revoked refresh token reused. All tokens in this family have been invalidated.",
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

    # Rotate token within the same family
    new_refresh_token = create_refresh_token(user, db, family_id=stored_token.family_id)
    new_access_token = create_jwt_token(user)
    return {"access_token": new_access_token, "refresh_token": new_refresh_token}
    
import json
import urllib.request
import urllib.parse
from google.oauth2 import id_token
from google.auth.transport import requests
from starlette.responses import RedirectResponse, JSONResponse

def exchange_google_code_for_token(code: str, nonce: str | None = None) -> dict:
    token_url = "https://oauth2.googleapis.com/token"
    token_data = {
        "code": code,
        "client_id": settings.GOOGLE_CLIENT_ID,
        "client_secret": settings.GOOGLE_CLIENT_SECRET,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
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

# Google OAuth
@app.get("/oauth/google/login")
def google_login():
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
        "nonce":nonce
    })
    auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?{auth_params}"
    response = RedirectResponse(auth_url)
    response.set_cookie("google_state", state, httponly=True, secure=False, samesite="lax", max_age=60*10)
    response.set_cookie("google_nonce", nonce, httponly=True, secure=False, samesite="lax", max_age=60*10)
    return response

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
            detail=f"Invalid state (received query state={state!r}, cookie state={google_state!r}). Make sure you are using the same host (localhost vs 127.0.0.1) as GOOGLE_REDIRECT_URI.",
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
            # Found -> link Google account
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

            # If the database model allows null password_hash, use None; otherwise generate a random unusable hash
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

