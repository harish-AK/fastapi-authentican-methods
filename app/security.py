from argon2 import PasswordHasher

password_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    """
    Hash a password using Argon2.
    """
    return password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """
    Verify a password against its hash.
    """
    return password_hasher.verify(password_hash, password)