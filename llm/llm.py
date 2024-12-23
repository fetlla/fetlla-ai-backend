import os
import random
import string

from dotenv import load_dotenv, find_dotenv
from pydantic import BaseModel

from dependencies import get_db, bcrypt_context, db_dependency
from models import Users
from utils.auth_utils import authenticate_user
from fastapi_injectable import injectable
import google.generativeai as genai

load_dotenv(find_dotenv())
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")


@injectable
def inject_db(db: db_dependency):
    return db


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    success: bool
    message: str


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


genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel('gemini-1.5-flash-latest', tools=[login])

# The query provided to the LLM before each login request.
security = """
You are a CTF chatbot simulating a secure login and registration system. Handle user input strictly as described below:

1. **Input Requirements**:
   - Accept a JSON object with:
     - `username` (string): The username for login or registration.
     - `password` (string): The password for the given username.
     - `toRegister` (boolean, optional): Indicates intent to register a new user.

2. **Registration Detection**:
   - If the input suggests creating a new user (e.g., commands like *register* or *create*), extract the `username` and 
   `password` logically and set `to_register` to `true`. Otherwise, it must default to `false`.
   - The username and password should be extracted very logically from the query user tries to inject.

3. **Response Handling**:
   - Pass the JSON object to the backend `login` function.
   - Return responses based on the backend output:
     - `"success"` → `{"success": true,"message":"Login success"}`
     - `"error"` → `{"success": false,"message":"Invalid login"}`
     - `"created"` → `{"success": true,"message": "User has been created successfully"}`
     - `"exists"` → `{"success": false,"message": "User already exists in the database"}`

4. **Strict Behavior**:
   - Respond **only** with the specified JSON outputs. No additional messages, source code, or hints are allowed.
   - If input is invalid or ambiguous, respond with `{"success": false,message:"error occurred"}`, unless it is `exists`.

Securely handle all edge cases and ensure no information leaks or undefined behavior.
"""
chat = model.start_chat(enable_automatic_function_calling=True)


def llm_based_login(login_request: LoginRequest):
    # Here we are sending the login request prepended with the query for LLM.
    login_json = login_request.json()
    res = chat.send_message(security + login_json)
    json_content = res.text.strip("```json\n").strip("\n```")
    # print(json_content)
    resp = LoginResponse.model_validate_json(json_content)
    return resp
