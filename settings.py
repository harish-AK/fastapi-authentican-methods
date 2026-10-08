import os
import sys
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent

# Automatically detect test environment (CI, pytest execution, or APP_ENV=test)
is_test = (
    os.getenv("APP_ENV", "").lower() in ("test", "testing", "ci")
    or "pytest" in sys.modules
    or any("pytest" in arg for arg in sys.argv)
    or "PYTEST_CURRENT_TEST" in os.environ
)

ENVIRONMENT = "test" if is_test else os.getenv("APP_ENV", "production").lower()

# Dynamically select env file
env_file = BASE_DIR / (".env.test" if is_test else ".env")

if env_file.exists():
    load_dotenv(env_file, override=is_test)
else:
    load_dotenv(BASE_DIR / ".env", override=False)

if not os.getenv("JWT_SECRET_KEY"):
    raise ValueError(f"JWT_SECRET_KEY is not set (Environment: {ENVIRONMENT})")

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")
OAUTH_SERVICE_REDIRECT_URI = os.getenv(
    "OAUTH_SERVICE_REDIRECT_URI", "http://localhost:8000/oauth-service/google/callback"
)
DATABASE_URL = os.getenv("DATABASE_URL")

ORIGINS = [
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:3000",
    "http://localhost:5173",
    "https://localhost:8000",
]