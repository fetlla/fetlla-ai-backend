from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from llm.llm_status import langgraph_agent_status

router = APIRouter(prefix="/status", tags=["status"])

class FetchStatusRequest(BaseModel):
    resource: str = Field(..., description="Resource string to check and forward to agent.")

@router.post("/fetchStatus")
async def fetch_status(request: FetchStatusRequest):
    result = await langgraph_agent_status(request.resource)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("detail", "Unknown error"))
    return result
