from datetime import datetime

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, EmailStr

from .security import hash_password, verify_password
from database import get_db
from models import UserDatabase

from sqlalchemy.exc import IntegrityError

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
def get_current_user(db=Depends(get_db),credentials: HTTPBasicCredentials = Depends(security)):
    user_in_db = db.query(UserDatabase).filter(
        UserDatabase.username == credentials.username
    ).first()

    if not user_in_db.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User is not active",
            headers={"WWW-Authenticate": "Basic"},
        )
    
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


