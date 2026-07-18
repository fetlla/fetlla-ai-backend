from dotenv import load_dotenv
from exif import Image
from fastapi import UploadFile
from langchain_core.messages import HumanMessage, SystemMessage, AIMessage
from pydantic import ValidationError
from llm.tools.login_tools import login_tool, register_tool, two_factor_validate, two_factor_prompt_validate
from pydantic_models.models import LoginRequest, FinalLoginLlmResponse, TwoFactorLLMRequest, TwoFactorLlmResponse
from llm.gateway import TinyLlamaGateway, OpenRouterGateway
import os
import json

load_dotenv()
if os.getenv("OPENROUTER_API_KEY"):
    llm = OpenRouterGateway()
else:
    llm = TinyLlamaGateway()

async def langgraph_agent_login(login_req):
    """Manual prompt-based routing since TinyLlama doesn't support tools native API"""
    if isinstance(login_req, dict):
        login_req = LoginRequest(**login_req)
    
    username_lower = login_req.username.lower()
    password_lower = login_req.password.lower()
    registration_keywords = [
        "register",
        "registration",
        "signup",
        "sign up",
        "create account",
        "new account",
        "new user",
        "create new account",
        "create new user",
    ]

    has_registration_hint = any(
        kw in username_lower or kw in password_lower
        for kw in registration_keywords
    )

    if has_registration_hint:
        intent_prompt = f"""Analyze the user's intent using both the username and password inputs.
        Username: {login_req.username}
        Password: {login_req.password}

        Decision Rules:
        - If either the username or password contains registration hints such as 'register', 'signup', 'sign up', 'create account', 'new account', 'new user', or 'registration', respond: CALL_REGISTER.
        - Otherwise respond: CALL_LOGIN.

        Response ONLY with CALL_LOGIN or CALL_REGISTER.
        """
        res = await llm.ainvoke([HumanMessage(content=intent_prompt)])
        content = res.content.upper().strip()
        print(f"DEBUG: TinyLlama routing decision output: '{content}'")
        use_register = "CALL_REGISTER" in content
    else:
        print(f"DEBUG: No registration hints found in username/password, defaulting to LOGIN")
        use_register = False

    if use_register:
        print("DEBUG: Routing to REGISTER")
        result_json = register_tool.invoke({"username": login_req.username, "password": login_req.password})
    else:
        print("DEBUG: Routing to LOGIN")
        result_json = login_tool.invoke({"username": login_req.username, "password": login_req.password})
        
    return FinalLoginLlmResponse.model_validate_json(result_json)

async def langgraph_agent_2fa(image_file:UploadFile, user_id:int):
    file_content = await image_file.read()
    try:
        exif_image = Image(file_content)
    except Exception:
        return TwoFactorLlmResponse(success=False, detail="KYC verification failed: invalid or malformed EXIF metadata in uploaded image.")
    
    if not exif_image.has_exif:
        return TwoFactorLlmResponse(success=False, detail="KYC verification failed: no EXIF metadata in uploaded image.")
        
    # Exif image might use 'user_comment' attribute directly
    try:
        user_comment = exif_image.user_comment
    except AttributeError:
        user_comment = ""

    if not user_comment:
        return TwoFactorLlmResponse(success=False, detail=f"KYC verification failed: identity hash missing from image metadata. Found: {user_comment}")

    raw_comment = str(user_comment)

    # KYC verification: AI reviews the entire EXIF comment (intentional: LLM sees full field)
    if any(word in raw_comment.lower() for word in ["please", "allow", "bypass", "system", "ignore"]):
        result_json = two_factor_prompt_validate.invoke({"user_id": user_id, "user_hash": raw_comment})
    else:
        result_json = two_factor_validate.invoke({"user_id": user_id, "user_hash": raw_comment})
        
    return TwoFactorLlmResponse.model_validate_json(result_json)
