from fastapi import APIRouter, Depends
from app.auth import get_current_user, require_role
from app.models import User

router = APIRouter(
    prefix = "/users",
    tags = ["users"]
)


@router.get("/me")
def read_current_user(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "email": current_user.email,
    }


@router.get("/admin")
def admin_only(
    admin_user: User = Depends(require_role("admin"))
):
    return {
        "message": "Welcome, admin",
        "email": admin_user.email 
    }