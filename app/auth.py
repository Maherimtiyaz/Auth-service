from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from fastapi import Depends, HTTPException, status, Response
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import RefreshToken
from app import models
from jose import jwt, JWTError, ExpiredSignatureError
from dotenv import load_dotenv
import hashlib
import secrets
import os



SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# oAuth2 Bearer Scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# Password hashing context (bycrypt recommended)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Access token
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))

# Refresh token
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", 7))

# Hash password

def hash_password(password: str) -> str:
    password = password.strip()
    return pwd_context.hash(password)

# Verify password

def verify_password(plain_password: str, hashed_password: str) -> bool:
   
    return pwd_context.verify(plain_password.strip(), hashed_password)

# Create Access Token

def create_access_token(data: dict) -> str:
    to_encode = data.copy()

    expire = datetime.now(timezone.utc) + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )

    to_encode.update({"exp": expire})


    encoded_jwt = jwt.encode(
        to_encode, 
        SECRET_KEY, 
        algorithm=ALGORITHM
    )
    return encoded_jwt

# Get current user

def get_current_user(
        token: str = Depends(oauth2_scheme),
        db: Session = Depends(get_db)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str | None = payload.get("sub")
        if email is None:
            raise credentials_exception
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail = "Token has expired",
            headers = {"WW-Authenticate": "Bearer"},
        )
    
    except JWTError:
        raise credentials_exception
    
    user = db.query(models.User).filter(models.User.email == email).first()
    if user is None:
        raise credentials_exception
    
    return user

# role checking

def require_role(required_role: str):
    def role_checker(current_user: models.User = Depends(get_current_user)):
        if current_user.role != required_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Operation not permitted"

            )
        return current_user
    return role_checker


# Refresh Token Generation

def generate_refresh_token() -> str:
    """
    Generate a cryptographically secure refresh token.
    """
    return secrets.token_urlsafe(32)

# Hash refresh token

def hash_refresh_token(token: str) -> str:
    """
    Hash refresh token before storing in DB.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

# Token Expiry

def get_refresh_token_expiry() -> datetime:
    return datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

# Create Refresh Token

def create_refresh_token(user_id: int) -> tuple[str, RefreshToken]:
    """
    Create a refresh token and corresponding DB object.
    Returns (raw_token, refresh_token_model)
    """
  
    raw_token = generate_refresh_token()
    token_hash = hash_refresh_token(raw_token)

    refresh_token = RefreshToken(
        user_id = user_id,
        token_hash = token_hash,
        expires_at = get_refresh_token_expiry(),
        revoked = False,
    )

    return raw_token, refresh_token

# Auth refresh access token


def rotate_refresh_token(
    db: Session,
    raw_refresh_token: str,
    response: Response,
):
    # 1. Hash incoming refresh token
    token_hash = hash_refresh_token(raw_refresh_token)

    # 2. Lookup token in DB
    db_token = (
        db.query(RefreshToken)
        .filter(
            RefreshToken.token_hash == token_hash,
            RefreshToken.revoked == False,
        )
        .first()
    )

    if not db_token:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    if db_token.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Refresh token expired")

    user = db_token.user

    # 3. Revoke old token
    db_token.revoked = True

    # 4. Create new refresh token
    new_raw_token, new_db_token = create_refresh_token(user.id)
    print("CREATING NEW REFRESH TOKEN FOR USER:", user.id)
    print("NEW TOKEN HASH:", new_db_token.token_hash)

    db.add(new_db_token)
    

    # 5. Commit rotation
    db.commit()

    # 6. Set new refresh token cookie
    response.set_cookie(
        key="refresh_token",
        value=new_raw_token,
        httponly=True,
        secure=False,  # True in prod
        samesite="lax",
        path="/",
    )

    # 7. Issue new access token
    access_token = create_access_token(
        {"sub": user.email, "role": user.role}
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
    }

# Logout point

def logout_user(
        db: Session,
        raw_refresh_token: str,
        response: Response,
):
    if not raw_refresh_token:
        return {"detail": "Logged out"}
    
    token_hash = hash_refresh_token(raw_refresh_token)

    db_token = (
        db.query(RefreshToken)
        .filter(
            RefreshToken.token_hash == token_hash,
            RefreshToken.revoked == False,
        )
        .first()
    )

    if db_token:
        db_token.revoked = True
        db.commit()

    # Delete refresh token cookie

    response.delete_cookie(
        key="refresh_token",
        path="/",
    )

    return {"detail": "Logged out"}