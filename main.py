from fastapi import FastAPI,Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from routers import auth
from models import Base
from database import engine

app = FastAPI()
Base.metadata.create_all(bind=engine)
app.include_router(auth.router)

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request:Request,exc:RequestValidationError):
    first_error = exc.errors()[0] if exc.errors() else {}
    error_message = first_error.get('msg','Validation Error')
    error_field = first_error.get('loc', [''])[1] if len(first_error.get('loc', [])) > 1 else ''
    return JSONResponse(status_code=400,content={"message":f"{error_field} {error_message}"})


@app.get("/")
async def home():
    return {"message": "visit /docs for Swagger"}
