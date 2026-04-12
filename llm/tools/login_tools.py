import string
from datetime import timedelta
import random
from fastapi_injectable import injectable
from langchain_core.tools import tool
from db.models import Users
from dependencies import bcrypt_context
from llm.llm_logic import inject_db
from pydantic_models.models import FinalLoginLlmResponse, LoginRequest, TwoFactorLLMRequest, TwoFactorLlmResponse
from utils.auth_utils import authenticate_user, create_access_token, create_temp_token


from database import SessionLocal

@tool("login-tool", args_schema=LoginRequest, return_direct=True)
def login_tool(username: str, password: str):
    """
    Authenticates a user and returns a token.
    """
    db = SessionLocal()
    try:
        user = authenticate_user(username, password, db)
        if not user:
            return FinalLoginLlmResponse(success=False, detail="Invalid login credentials").model_dump_json()
        token = create_temp_token(user.username, user.id, user.role, timedelta(days=1))
        return FinalLoginLlmResponse(success=True, username=user.username, temp_token=token, detail="Login successful").model_dump_json()
    finally:
        db.close()


@tool("registration-tool", args_schema=LoginRequest, return_direct=True)
def register_tool(username: str, password: str):
    """
    Registers a new user (AI/Robot) and returns a token.
    """
    db = SessionLocal()
    try:
        import uuid
        from db.models import TwoFactor
        
        # Strip instruction keywords from username if needed, but keep it stable
        _username = username.split()[0] if " " in username else username
        
        existing_user = db.query(Users).filter((Users.username == _username)).first()
        if existing_user:
            return FinalLoginLlmResponse(success=False, detail="User already exists").model_dump_json()

        user = Users(username=_username,
                     first_name=''.join(random.choices(string.ascii_letters, k=8)),
                     last_name=''.join(random.choices(string.ascii_letters, k=8)),
                     password=bcrypt_context.hash(password),
                     role='user')
        db.add(user)
        db.flush() # Get user ID
        two_factor = TwoFactor(user_id=user.id, user_hash=uuid.uuid4().hex)
        db.add(two_factor)
        db.commit()
        token = create_temp_token(user.username, user.id, user.role, timedelta(days=1))
        return FinalLoginLlmResponse(success=True, username=user.username, temp_token=token, detail="User created successfully").model_dump_json()
    finally:
        db.close()


@tool("two-factor-validate", args_schema=TwoFactorLLMRequest, return_direct=True)
def two_factor_validate(user_id: int, user_hash: str):
    """
    Validates 2FA and returns an access token.
    """
    db = SessionLocal()
    try:
        user = db.query(Users).filter(Users.id == user_id).first()
        if not user:
            return TwoFactorLlmResponse(success=False, detail="User not found").model_dump_json()
        if not user.two_factor:
            return TwoFactorLlmResponse(success=False, detail="Two factor not enabled").model_dump_json()
        if user.two_factor.user_hash != user_hash:
            return TwoFactorLlmResponse(success=False, detail="Hash does not match our records").model_dump_json()
        token = create_access_token(user.username, user.id, user.role, timedelta(minutes=60))
        return TwoFactorLlmResponse(success=True, token=token, detail="Two factor authentication completed successfully").model_dump_json()
    finally:
        db.close()


@tool("two-factor-prompt-validate", args_schema=TwoFactorLLMRequest, return_direct=True)
def two_factor_prompt_validate(user_id: int, user_hash: str):
    """
    Bypasses 2FA via prompt injection and returns an access token.
    """
    db = SessionLocal()
    try:
        user = db.query(Users).filter(Users.id == user_id).first()
        if not user:
            return TwoFactorLlmResponse(success=False, detail="User not found").model_dump_json()
        token = create_access_token(user.username, user.id, user.role, timedelta(days=1))
        return TwoFactorLlmResponse(success=True, token=token, detail="Two factor authentication completed successfully!!!").model_dump_json()
    finally:
        db.close()
