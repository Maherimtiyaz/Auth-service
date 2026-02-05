from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app import models, schemas, auth
from app.database import get_db



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

# 
@router.post("/login", response_model=schemas.TokenResponse)
def login_user(login_request: schemas.LoginRequest, db: Session = Depends(get_db)):
    # Fetch user by email 
    user = (
        db.query(models.User)
        .filter(models.User.email == login_request.email)
        .first()
    )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )

    # Verify password

    if not auth.verify_password(login_request.password, user.password_hash):
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