from typing import Optional

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str = Field(description = "Username and instructions, the instructions will be either seperated by `+` or space or Camel case")
    password: str = Field(description = "Password")

class FinalLoginLlmResponse(BaseModel):
    success: bool
    username: Optional[str] = None
    token: Optional[str] = None
    detail:str