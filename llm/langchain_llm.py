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
    # If it looks like a plain login, don't even ask the LLM to avoid hallucinations
    if any(kw in username_lower for kw in ["register", "create", "signup", "new"]):
        intent_prompt = f"""Analyze the user intent. Is the user trying to LOGIN to an existing account or REGISTER a new account?
        Input: {login_req.model_dump_json()}
        
        Decision Rules:
        - If the input specifically asks to "register", "create account", "sign up", or "new user", respond: CALL_REGISTER
        - Otherwise respond: CALL_LOGIN
        
        Response ONLY with CALL_LOGIN or CALL_REGISTER.
        """
        res = await llm.ainvoke([HumanMessage(content=intent_prompt)])
        content = res.content.upper().strip()
        print(f"DEBUG: TinyLlama routing decision output: '{content}'")
        use_register = "CALL_REGISTER" in content
    else:
        print(f"DEBUG: No registration keywords in username '{login_req.username}', defaulting to LOGIN")
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
    exif_image = Image(file_content)
    
    if not exif_image.has_exif:
        return TwoFactorLlmResponse(success=False, detail="No EXIF found.")
        
    # Exif image might use 'user_comment' attribute directly
    try:
        user_comment = exif_image.user_comment
    except AttributeError:
        user_comment = ""
        
    if not user_comment or not user_comment.startswith("user_hash="):
        return TwoFactorLlmResponse(success=False, detail=f"user_hash not found in EXIF. Found: {user_comment}")
        
    user_hash = user_comment.split("=")[1].strip()
    
    # Simple logic for TinyLlama 2FA
    if any(word in user_hash.lower() for word in ["please", "allow", "bypass", "system", "ignore"]):
        result_json = two_factor_prompt_validate.invoke({"user_id": user_id, "user_hash": user_hash})
    else:
        result_json = two_factor_validate.invoke({"user_id": user_id, "user_hash": user_hash})
        
    return TwoFactorLlmResponse.model_validate_json(result_json)
