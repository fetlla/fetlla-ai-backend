from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.cors import CORSMiddleware
import os

from routers import auth, status, dashboard
from db.models import Base
from database import engine

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=[
                   "*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
Base.metadata.create_all(bind=engine)

# Mount static files with directory listing
@app.get("/static/", response_class=HTMLResponse)
@app.get("/static", response_class=HTMLResponse)
async def list_static_files():
    static_dir = "static"
    files = []
    if os.path.exists(static_dir):
        files = os.listdir(static_dir)
    
    html = "<html><head><title>Index of /static/</title></head><body>"
    html += "<h1>Index of /static/</h1><hr><pre>"
    html += '<a href="../">../</a>\n'
    for file in files:
        file_path = os.path.join(static_dir, file)
        size = os.path.getsize(file_path)
        html += f'<a href="/static/{file}">{file}</a>{"".ljust(50 - len(file))} {size} bytes\n'
    html += "</pre><hr></body></html>"
    return HTMLResponse(content=html)

app.mount("/static", StaticFiles(directory="static"), name="static")

app.include_router(auth.router)
app.include_router(status.router)
app.include_router(dashboard.router)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    first_error = exc.errors()[0] if exc.errors() else {}
    error_message = first_error.get('msg', 'Validation Error')
    error_field = first_error.get('loc', [''])[1] if len(
        first_error.get('loc', [])) > 1 else ''
    return JSONResponse(status_code=400, content={"detail": f"{error_field} {error_message}"})


