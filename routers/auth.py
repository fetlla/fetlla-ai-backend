from datetime import datetime, timezone, timedelta

import jwt
from fastapi.routing import APIRouter
from fastapi import Depends, HTTPException
from pydantic import BaseModel, field_validator, EmailStr, Field
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from starlette import status

from dependencies import bcrypt_context, db_dependency
from models import Users

router = APIRouter(prefix="/auth", tags=["auth"])

# Dev only
SECRET_KEY = '5cd3e5b6fff276840d7f9a0a974868cd10bf8753bd207d2443238f78c5cd11b8'
ALGORITHM = 'HS256'


class LoginRequest(BaseModel):
    username: str
    password: str


class RegisterRequest(BaseModel):
    username: str = Field(
        description="Username length must be 4-32 characters", min_length=4, max_length=32)
    password: str = Field(
        description="Password length must be at least 8 characters", min_length=4)
    email: EmailStr = Field(description="Enter a valid email address")
    first_name: str = Field(
        description="First name must be 1-50 characters", min_length=1, max_length=50)
    last_name: str = Field(
        description="Last name must be 1-50 characters", min_length=1, max_length=50)


def authenticate_user(username: str, password: str, db) -> Users | bool:
    user = db.query(Users).filter(Users.username == username).first()
    if not user:
        return False
    if not bcrypt_context.verify(password, user.password):
        return False
    return user


def create_access_token(username: str, user_id: int, role: str, expires_delta: timedelta):
    encode = {'sub': username, 'id': user_id, 'role': role}
    expires = datetime.now(timezone.utc) + expires_delta
    encode.update({'exp': expires})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)


@router.post("/login")
async def login(login_request: LoginRequest, db: db_dependency):
    user = authenticate_user(login_request.username,
                             login_request.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail='Could not validate user.')
    token = create_access_token(
        user.username, user.id, user.role, timedelta(minutes=15))
    return {"detail": "Login success", 'token': token}


@router.post("/register")
async def register(register_request: RegisterRequest, db: db_dependency):
    existing_user = db.query(Users).filter(
        (Users.username == register_request.username) |
        (Users.email == register_request.email)
    ).first()
    if existing_user:
        if existing_user.username == register_request.username:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail='Username already exists.'
            )
        if existing_user.email == register_request.email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail='Email already exists.'
            )

    user = Users(username=register_request.username,
                 email=register_request.email,
                 first_name=register_request.first_name,
                 last_name=register_request.last_name,
                 password=bcrypt_context.hash(register_request.password),
                 role='user')
    db.add(user)
    db.commit()
    return {"detail": "User created successfully"}
