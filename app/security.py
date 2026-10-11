from argon2 import PasswordHasher

password_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    """
    Hash a password using Argon2.
    """
    return password_hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    """
    Verify a password against its hash.
    """
    if not password_hash:
        return False
    try:
        return password_hasher.verify(password_hash, password)
    except Exception:
        return False