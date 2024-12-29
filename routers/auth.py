from datetime import datetime, timezone, timedelta

import jwt
from fastapi.routing import APIRouter
from fastapi import Depends, HTTPException
from pydantic import BaseModel, field_validator, EmailStr, Field
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from starlette import status

from dependencies import bcrypt_context, db_dependency
from llm.llm import login, llm_based_login, LoginRequest
from models import Users
from utils.auth_utils import authenticate_user, create_access_token

router = APIRouter(prefix="/auth", tags=["auth"])


class RegisterRequest(BaseModel):
    username: str = Field(
        description="Username length must be 4-32 characters", min_length=4, max_length=32)
    password: str = Field(
        description="Password length must be at least 8 characters", min_length=4)
    first_name: str = Field(
        description="First name must be 1-50 characters", min_length=1, max_length=50)
    last_name: str = Field(
        description="Last name must be 1-50 characters", min_length=1, max_length=50)


class UserResponse(BaseModel):
    username: str
    first_name: str
    last_name: str


@router.post("/login")
async def login_llm(login_request: LoginRequest):
    res = llm_based_login(login_request)
    return res


@router.post("/login-normal")
async def login_normal(login_request: LoginRequest, db: db_dependency):
    user = authenticate_user(login_request.username, login_request.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail='Could not validate user.')
    token = create_access_token(
        user.username, user.id, user.role, timedelta(minutes=15))
    return {"detail": "Login success", 'token': token}


@router.post("/register")
async def register(register_request: RegisterRequest, db: db_dependency):
    existing_user = db.query(Users).filter((Users.username == register_request.username)).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Username already exists.'
        )

    user = Users(username=register_request.username,
                 first_name=register_request.first_name,
                 last_name=register_request.last_name,
                 password=bcrypt_context.hash(register_request.password),
                 role='user')
    db.add(user)
    db.commit()
    return {"detail": "User created successfully"}


@router.get("/get_users", response_model=list[UserResponse])
async def get_users(db: db_dependency):
    users = db.query(Users.username, Users.first_name, Users.last_name).all()
    return users
