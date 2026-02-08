from fastapi import APIRouter, Depends, HTTPException, status, Response, Request
from sqlalchemy.orm import Session
from app import models, schemas, auth
from app.database import get_db
from app.models import User



router = APIRouter(
    prefix="/auth", 
    tags=["auth"]
)

@router.post("/register", response_model=schemas.UserResponse)
def register_user(user_in: schemas.UserCreate, db: Session = Depends(get_db)):
    """
    Register a new user:
    - Validate input via Pydantic schema
    - Check if email already exists
    - Hash password
    - Save user
    - Return safe UserResponse
    """

    # Check for dublicate email

    existing_user = db.query(models.User).filter(models.User.email == user_in.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Hash Password
    
    try:
        hashed_pw = auth.hash_password(user_in.password)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Password hashing error: {str(e)}")

    # Create User model instance

    new_user = models.User(
        email=user_in.email,
        password_hash=hashed_pw
    )

    # Save to DB
    
    try:
        db.add(new_user)
        db.commit()
        db.refresh(new_user) # reload from DB to get ID & timestamps
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

    # Return safe response

    return new_user

# Login endpoint

@router.post("/login", response_model=schemas.TokenResponse)
def login_user(
    login_data: schemas.LoginRequest,
    response: Response,
    db: Session = Depends(get_db),
):
    
    # Fetch user by email 
    user = (
        db.query(models.User)
        .filter(models.User.email == login_data.email)
        .first()
    )

    if not user or not auth.verify_password(
        login_data.password, user.password_hash
    ):
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )
    
    # Access token (unchanged)
    access_token = auth.create_access_token(
        data={"sub": str(user.id), "role": user.role}
    )

    # Refresh token (new)
    raw_refresh_token, refresh_token = auth.create_refresh_token(
        user_id = user.id
    )

    db.add(refresh_token)
    db.commit()

    # Set refresh token as httpOnly cookie
    response.set_cookie(
        key="refresh_token",
        value=raw_refresh_token,
        httponly=True,
        secure=False, # True in production (HTTPS)
        samesite="lax",
        max_age=auth.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
        path="/auth/refresh"
    )

    return {"access_token": access_token, "token_type": "bearer"}

    # Verify password

    if not auth.verify_password(login_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        
        )
    
    # Create access token

    access_token = auth.create_access_token(
        data={
            "sub": user.email,
            "role": user.role
        }
    )

    return {"access_token": access_token, "token_type": "bearer"}

# Refresh token endpoint

@router.post("/refresh", response_model=schemas.TokenResponse)
def refresh_access_token(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    refresh_token = request.cookies.get("refresh_token")

    if not refresh_token:
        raise HTTPException(
            status_code=401,
            detail="Missing refresh token",
        )
    
    return auth.rotate_refresh_token(
        raw_refresh_token=refresh_token,
        db=db,
        response=response,
    )

# Logout endpoint

@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    refresh_token = request.cookies.get("refresh_token")

    return auth.logout_user(
        db=db,
        raw_refresh_token=refresh_token,
        response=response,
    )