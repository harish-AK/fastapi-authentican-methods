from datetime import datetime

from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel, EmailStr

from .security import hash_password
from database import get_db
from models import UserDatabase

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
    


@app.post("/users",response_model=UserResponse)
def create_user(user: UserCreate, db = Depends(get_db)):
    try:
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
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to create user")


