from sqlalchemy import Column, Integer, String, Boolean, DateTime, func
from database import Base

class UserDatabase(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, nullable=False,unique=True)
    password_hash = Column(String, nullable=False)
    email = Column(String, nullable=False,unique=True)
    is_active = Column(Boolean, default=True,nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())