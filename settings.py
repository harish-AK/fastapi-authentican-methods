import os
from dotenv import load_dotenv

load_dotenv(".env")
if not os.getenv("JWT_SECRET_KEY"):
    raise ValueError("JWT_SECRET_KEY is not set")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
