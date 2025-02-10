from datetime import timedelta
from fastapi.params import File
from fastapi.routing import APIRouter
from fastapi import HTTPException, UploadFile, Form
from pydantic import BaseModel, Field
from starlette import status

from dependencies import bcrypt_context, db_dependency
from llm.langchain_llm import langgraph_agent_login, langgraph_agent_2fa
from llm.llm_logic import  llm_based_login, LoginRequest
from db.models import Users
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

class LoginResponse(BaseModel):
    message: str

@router.post("/login")
async def login_llm(login_request: LoginRequest):
    res = llm_based_login(login_request)
    if not res.success:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=res.detail)
    return {"detail":res.detail}

@router.post("/login-lang-graph")
async def login_llm(login_request: LoginRequest):
    res = await langgraph_agent_login(login_request)
    if not res.success:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=res.detail)
    return res


class TwoFactorForm(BaseModel):
    image:UploadFile = File(...)
    model_config = {"extra": "forbid"}

@router.post("/2fa")
async def two_factor_auth(twofactor_request: TwoFactorForm=Form(..., media_type="multipart/form-data")):
    image = twofactor_request.image
    accepted_file_types = ["image/png", "image/jpeg", "image/jpg"]
    if image.content_type not in accepted_file_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Only image files jpeg/png are accepted")
    if image.size> 1*1024*1024 :
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="File size should be less than 1MB")
    res = await  langgraph_agent_2fa(image)
    if not res.success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail=res.detail)
    return res

@router.post("/login-normal")
async def login_normal(login_request: LoginRequest, db: db_dependency):
    user = authenticate_user(login_request.username, login_request.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail='Could not validate user.')
    token = create_access_token(
        user.username, user.id, user.role, timedelta(minutes=15))
    return {"detail": {"token":token} }


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
