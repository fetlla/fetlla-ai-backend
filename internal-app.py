from fastapi import FastAPI, Header, HTTPException, Request, Security, Depends
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from typing import Optional
import httpx
import os
import psutil
import platform
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="Fetlla Internal API")
API_KEY = os.getenv("APP_INTERNAL_API_KEY")


api_key_header = APIKeyHeader(name="x-api-key", auto_error=False)

async def get_api_key(api_key: str = Security(api_key_header)):
    if not api_key or api_key != API_KEY:
        raise HTTPException(
            status_code=403,
            detail="Access denied. API key is required in x-api-key header"
        )
    return api_key

@app.get("/ping")
async def ping():
    return {"message": "pong"}

@app.get("/api-docs")
async def get_api_docs():
    return get_openapi(
        title=app.title,
        version="1.0.0",
        description="API documentation for Fetlla Internal API",
        routes=app.routes,
    )

@app.get("/")
async def root():
    return {
        "name": "Fetlla Internal API",
        "version": "1.0.0",
        "status": "operational"
    }

@app.get("/system/info")
async def system_info(api_key: str = Depends(get_api_key)):
    return {
        "os": platform.system(),
        "platform": platform.platform(),
        "processor": platform.processor(),
        "python_version": platform.python_version(),
        "hostname": platform.node()
    }

@app.get("/system/resources")
async def system_resources(api_key: str = Depends(get_api_key)):
    return {
        "cpu_percent": psutil.cpu_percent(),
        "memory": {
            "total": psutil.virtual_memory().total,
            "available": psutil.virtual_memory().available,
            "percent": psutil.virtual_memory().percent
        },
        "disk": {
            "total": psutil.disk_usage('/').total,
            "used": psutil.disk_usage('/').used,
            "free": psutil.disk_usage('/').free,
            "percent": psutil.disk_usage('/').percent
        }
    }

@app.get("/system/processes")
async def system_processes(api_key: str = Depends(get_api_key)):
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
        try:
            processes.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return {"processes": processes[:10]}  # Return top 10 processes

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=1337)
