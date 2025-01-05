from dotenv import load_dotenv
from langchain_core.tracers import ConsoleCallbackHandler
from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.prebuilt import create_react_agent
from pydantic import ValidationError
from llm.tools.login_tools import login_tool, register_tool
from pydantic_models.models import LoginRequest, FinalLoginLlmResponse


load_dotenv()
llm = ChatGoogleGenerativeAI(
    model="gemini-1.5-pro",
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
        resp = FinalLoginLlmResponse(success=False,msg="Something is wrong")
    return resp

