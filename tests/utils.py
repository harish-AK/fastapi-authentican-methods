import uuid


def unique_string(prefix: str = "test") -> str:
    """Generates a random unique string to ensure tests are isolated and idempotent."""
    return f"{prefix}_{uuid.uuid4().hex[:8]}"
