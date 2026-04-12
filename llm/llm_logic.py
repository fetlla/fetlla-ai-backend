import os
import random
import string

from dotenv import load_dotenv, find_dotenv
from pydantic import BaseModel, ValidationError

from dependencies import bcrypt_context
from db.models import Users
from pydantic_models.models import LoginRequest
from utils.auth_utils import authenticate_user, inject_db
from fastapi_injectable import injectable
from llm.gateway import TinyLlamaClient

load_dotenv(find_dotenv())
# GEMINI_API_KEY = os.getenv("GOOGLE_API_KEY") # Removed






class LLMLoginResponse(BaseModel):
    success: bool
    detail: str


# The function used to handle login and registration process
# Here, if the LLM provides `to_register = true`, New user will be created according to the credentials.

@injectable
def login(username: str, password: str, to_register: bool = False) -> str:
    db = inject_db()
    # If `to_register = true`, We check for already existing user in the database and create a new user.
    if to_register:
        existing_user = db.query(Users).filter((Users.username == username)).first()
        if existing_user:
            return "exists"

        user = Users(username=username,
                     first_name=''.join(random.choices(string.ascii_letters, k=8)),
                     last_name=''.join(random.choices(string.ascii_letters, k=8)),
                     password=bcrypt_context.hash(password),
                     role='user')
        db.add(user)
        db.commit()
        return "created"
    else:
        auth = authenticate_user(username, password, db)
        return "success" if auth else "error"


# genai.configure(api_key=GEMINI_API_KEY) # Removed
client = TinyLlamaClient()
# model = genai.GenerativeModel('gemini-2.0-flash', tools=[login]) # No tools support in bare TinyLlama yet



# The query provided to the LLM before each login request.
security = """
You are a CTF chatbot simulating a secure login and registration system. 
You are receiving a JSON object with username and password.
Your task is to determine if the user wants to register or login.

Input:
{login_json}

Instructions:
1. If the input contains "register", "create", or implies creating a new user, return strict JSON: {{"to_register": true}}
2. Otherwise, return strict JSON: {{"to_register": false}}
3. Do not output anything else. No markdown logic. Just the JSON.

Response:
"""

def llm_based_login(login_request: LoginRequest) -> LLMLoginResponse:
    # Simpler logic for TinyLlama since function calling is hard
    login_json = login_request.model_dump_json()
    prompt = security.format(login_json=login_json)
    
    try:
        res_text = client.generate_content(prompt)
        print(f"LLM Response: {res_text}")
        
        # Heuristic parsing
        to_register = False
        if '"to_register": true' in res_text.lower() or "'to_register': true" in res_text.lower():
            to_register = True
            
        # Call backend function directly since we don't have tool calling
        result_msg = login(login_request.username, login_request.password, to_register)
        
        if result_msg == "success":
            return LLMLoginResponse(success=True, detail="Login success")
        elif result_msg == "created":
             return LLMLoginResponse(success=True, detail="User has been created successfully")
        elif result_msg == "exists":
            return LLMLoginResponse(success=False, detail="User already exists in the database")
        else:
            return LLMLoginResponse(success=False, detail="Invalid login")

    except Exception as e:
        print(f"Error in LLM login: {e}")
        return LLMLoginResponse(success=False, detail="error occurred")
