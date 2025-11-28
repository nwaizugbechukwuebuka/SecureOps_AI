from fastapi import APIRouter, Depends
from app.dependencies.auth_dep import get_current_user

router = APIRouter()

@router.post("/login", tags=["Auth"])
def login():
    return {"message": "Login endpoint"}

@router.get("/me", tags=["Auth"])
def get_me(user=Depends(get_current_user)):
    return {"user": user}
