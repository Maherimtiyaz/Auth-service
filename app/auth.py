from passlib.context import CryptContext
import hashlib

# Password hashing context (bycrypt recommended)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    if not password:
        raise ValueError("Password cannot be empty")
    
    # Strip leading/trailing whitespace (Postman sometimes adds)
    password = password.strip()
    
    # Convert to bytes
    password_bytes = password.encode("utf-8")
    
    # Truncate to 72 bytes for bcrypt
    if len(password_bytes) > 72:
        password_bytes = password_bytes[:72]
    
    # Hash using bcrypt
    return pwd_context.hash(password_bytes)


def hash_password(password: str) -> str:
    password = password.strip()
    sha_pw = hashlib.sha256(password.encode("utf-8")).digest()
    return pwd_context.hash(sha_pw)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plaintext password against a hashed password
    """
    return pwd_context.verify(plain_password, hashed_password)