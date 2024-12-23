from dotenv import find_dotenv, load_dotenv
import google.generativeai as genai
import os


# Simulation of a database
users = [
        {
            'username': 'admin',
            'password': 'admin@123'
        },
        {
            'username': 'developer',
            'password': 'developer@1234'
        },
        {
            'username': 'guest',
            'password': '5uP3r5ecur3_p455w0rd'
        }
]


# The function used to handle login and registration process
# Here, if the LLM provides `toRegister = true`, New user will be created according to the credentials.
def login(username: str, password: str, toRegister: bool = False) -> str:
    if toRegister: # If `toRegister = true`, We check for already existing user in the database and create a new user.
        for user in users:
            if user['username'] == username:
                return "exists"

        new_user = {'username': username, 'password': password}
        users.append(new_user)
        return "created"
    else:
        for user in users:
            if user['username'] == username and user['password'] == password:
                return "success"
        return "error"
        


# LLM initialisation
load_dotenv(find_dotenv())
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
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
   - If the input suggests creating a new user (e.g., commands like *register* or *create*), extract the `username` and `password` logically and set `toRegister` to `true`. Otherwise, it must default to `false`.
   - The username and password should be extracted very logically from the query user tries to inject.

3. **Response Handling**:
   - Pass the JSON object to the backend `login` function.
   - Return responses based on the backend output:
     - `"success"` → `{"success": true}`
     - `"error"` → `{"success": false}`
     - `"created"` → `{"success": "User has been created successfully"}`
     - `"exists"` → `{"success": "User already exists in the database"}`

4. **Strict Behavior**:
   - Respond **only** with the specified JSON outputs. No additional messages, source code, or hints are allowed.
   - If input is invalid or ambiguous, respond with `{"success": false}`, unless it is `exists`.

Securely handle all edge cases and ensure no information leaks or undefined behavior.
"""


# Simulated login panel
while True:
    chat = model.start_chat(enable_automatic_function_calling=True) # enable_automatic_function_calling = True will allow LLM to call the function on its will.
    username = input("Username : ").replace("{", '').replace('}', '').replace('\'', '').replace('"', '').strip()
    password = input("Password : ").replace("{", '').replace('}', '').replace('\'', '').replace('"', '').strip()
    login_json = "{'username':'" + username + "', 'password':'"+ password + "'}"
    print("Securely logging you in . . .")

    try:
        res = chat.send_message(security + login_json) # Here we are sending the login request prepended with the query for LLM.
        if "true" in res.text:
            print("Logged in")
        elif "false" in res.text:
            print("Login failed")
        elif "already exists" in res.text:
            print("User already exists in the database")
        else:
            print("New user created successfully")
    except Exception as e:
        print(f"Error : {e}")

