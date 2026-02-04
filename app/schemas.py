from pydantic import BaseModel, EmailStr
from datetime import datetime

class UserCreate(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: int
    email: EmailStr
    is_active: bool
    created_at: datetime

    class Config:
        orm_mode = True

# Login request

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

# Login Response

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"