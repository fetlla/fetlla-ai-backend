from fastapi import Depends
from fastapi.routing import APIRouter

from utils.auth_utils import get_current_user

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/auth-check")
async def auth_check(current_user=Depends(get_current_user)):
    return {"message": "Authenticated"}
