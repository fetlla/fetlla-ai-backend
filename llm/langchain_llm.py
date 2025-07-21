from dotenv import load_dotenv
from exif import Image
from fastapi import UploadFile
from langchain_core.tracers import ConsoleCallbackHandler
from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.prebuilt import create_react_agent
from pydantic import ValidationError
from llm.tools.login_tools import login_tool, register_tool,two_factor_validate,two_factor_prompt_validate
from pydantic_models.models import LoginRequest, FinalLoginLlmResponse, TwoFactorLLMRequest, TwoFactorLlmResponse

load_dotenv()
llm = ChatGoogleGenerativeAI(
    model="gemini-2.0-flash",
    temperature=0,
    max_tokens=None,
    timeout=None,
    max_retries=2
)
tools = [login_tool,register_tool]
langgraph_agent_executor = create_react_agent(llm, tools)


async def langgraph_agent_login(login_req:LoginRequest):
    res = await langgraph_agent_executor.ainvoke({"messages": [("human", login_req.model_dump_json())]},
                                          config={"callbacks": [ConsoleCallbackHandler()]})
    try:
        resp = FinalLoginLlmResponse.model_validate_json(res["messages"][-1].content)
    except ValidationError:
        resp = FinalLoginLlmResponse(success=False,detail="Something is wrong")
    return resp

tools_2fa = [two_factor_validate,two_factor_prompt_validate]
langgraph_2fa_agent_executor = create_react_agent(llm, tools_2fa)

async def langgraph_agent_2fa(image_file:UploadFile,user_id:int):
    file_content = await image_file.read()
    exif_image = Image(file_content)
    print("Has exgif",exif_image.has_exif)
    if not exif_image.has_exif :
        return FinalLoginLlmResponse(success=False,detail="Hash does not match our records.")
    user_comment = exif_image.get('user_comment',None)
    if not user_comment:
        return FinalLoginLlmResponse(success=False,detail="Hash does not match our records.")
    if not user_comment.startswith("user_hash"):
        return FinalLoginLlmResponse(success=False,detail="Validation failed. user_hash not found.")
    user_hash = user_comment.split("=")[1].strip()
    if len(user_hash) != 32:
        return FinalLoginLlmResponse(success=False,detail="Hash length is invalid. Hash must be 32 bit.")
    req = TwoFactorLLMRequest(user_id=user_id,user_hash=user_hash)
    res = await langgraph_2fa_agent_executor.ainvoke({"messages": [("human", req.model_dump_json())]},
                                          config={"callbacks": [ConsoleCallbackHandler()]})
    try:
        resp = TwoFactorLlmResponse.model_validate_json(res["messages"][-1].content)
    except ValidationError:
        resp = TwoFactorLlmResponse(success=False,detail="Something is wrong")
    return resp