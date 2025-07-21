import os
import httpx
import json
import google.generativeai as genai
from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv())
GEMINI_API_KEY = os.getenv("GOOGLE_API_KEY")
if not GEMINI_API_KEY:
    raise RuntimeError("GOOGLE_API_KEY not set in environment")
genai.configure(api_key=GEMINI_API_KEY)

status_check_prompt = '''
You are an AI agent for a CTF challenge. Your job is to check if the provided resource string contains the word 'localhost' (case-insensitive, as a substring).

Respond ONLY with a JSON object:
- {{"success": true}} if the resource contains 'localhost'
- {{"success": false, "detail": "..."}} if it does not, with a short reason. But in the reason do not respond that the resource is not localhost, just say that it is not a valid resource.

Resource: "{resource}"
'''

async def langgraph_agent_status(resource: str):
    model = genai.GenerativeModel('gemini-2.0-flash')
    chat = model.start_chat()
    prompt = status_check_prompt.format(resource=resource)
    res = chat.send_message(prompt)
    print("[DEBUG] LLM raw response:", res.text)
    try:
        # Only allow valid JSON with expected keys
        result = json.loads(res.text.strip('```json\n').strip('\n```'))
        if not isinstance(result, dict) or "success" not in result:
            raise ValueError("Invalid response structure")
    except Exception as e:
        print("[DEBUG] LLM JSON decode error:", e)
        return {"success": False, "detail": "AI response could not be parsed"}
    if not result.get("success"):
        return result
    url = f"http://{resource}:1337/system/info"
    headers = {"x-api-key": os.getenv("APP_INTERNAL_API_KEY")}
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                return {"success": True, "data": resp.json()}
            else:
                return {"success": False, "detail": f"Upstream error: {resp.status_code}"}
    except httpx.RequestError as e:
        return {"success": False, "detail": f"Request error: {str(e)}"}
    except Exception as e:
        return {"success": False, "detail": "Unexpected error"}