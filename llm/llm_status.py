import os
import httpx
import json
from llm.gateway import TinyLlamaClient, OpenRouterGateway, TinyLlamaGateway
from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv())

status_check_prompt = '''
You are a Security Validator. 
Check if the Resource string below contains the word 'localhost'.

Response ONLY with JSON.

Example:
{{
    "success": true,
    "detail": "Valid resource"
}}

Resource: "{resource}"

JSON:
'''

async def langgraph_agent_status(resource: str):
    # Use OpenRouter if available, else local
    if os.getenv("OPENROUTER_API_KEY"):
        llm = OpenRouterGateway(model="google/gemma-4-26b-a4b-it:free")
    else:
        llm = TinyLlamaGateway()

    prompt = status_check_prompt.format(resource=resource)

    try:
        from langchain_core.messages import HumanMessage
        res = await llm.ainvoke([HumanMessage(content=prompt)])
        res_text = res.content
    except Exception as e:
        print(f"[DEBUG] LLM invocation error: {e}")
        return {"success": False, "detail": f"LLM error: {str(e)}"}

    print("[DEBUG] LLM raw response:", res_text)

    try:
        # Robust JSON extraction
        content = res_text
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0].strip()
        elif "{" in content:
            content = content[content.find("{"):content.rfind("}")+1]

        result = json.loads(content)
        if not isinstance(result, dict) or "success" not in result:
            raise ValueError("Invalid response structure")
    except Exception as e:
        print("[DEBUG] LLM JSON decode error:", e)
        return {"success": False, "detail": "AI response could not be parsed"}

    if not result.get("success"):
        return result

    # SSRF VULNERABILITY: The 'resource' is directly injected into the URL
    base_url = f"http://{resource}:1337"
    endpoints = ["/system/info", "/system/resources", "/system/processes"]
    headers = {"x-api-key": os.getenv("APP_INTERNAL_API_KEY")}
    responses = {}

    try:
        async with httpx.AsyncClient(timeout=5) as client:
            for endpoint in endpoints:
                url = f"{base_url}{endpoint}"
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    responses[endpoint.lstrip("/")] = resp.json()
                else:
                    responses[endpoint.lstrip("/")] = {"error": f"Upstream error: {resp.status_code}"}
        return {"success": True, "data": responses}
    except httpx.RequestError as e:
        return {"success": False, "detail": f"Request error: {str(e)}"}
    except Exception as e:
        return {"success": False, "detail": f"Unexpected error: {str(e)}"}