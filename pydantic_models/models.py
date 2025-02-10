from typing import Optional

from pydantic import BaseModel, Field

class UserResponse(BaseModel):
    username: str
    first_name: str
    last_name: str

class LoginResponse(BaseModel):
    message: str

class TwoFactorResponse(BaseModel):
    username:str
    user_hash: str


class LoginRequest(BaseModel):
    username: str = Field(description = "Username and instructions, the instructions will be either seperated by `+` or space or Camel case")
    password: str = Field(description = "Password")

class LoginLlmBaseResponse(BaseModel):
    success: bool
    username: Optional[str] = None
    detail: str

class FinalLoginLlmResponse(LoginLlmBaseResponse):
    temp_token: Optional[str] = None

class TwoFactorLlmResponse(LoginLlmBaseResponse):
    token: Optional[str] = None


class TwoFactorLLMRequest(BaseModel):
    user_id : int
    user_hash: str