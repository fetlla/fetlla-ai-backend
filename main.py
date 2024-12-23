from fastapi import FastAPI
from routers import auth
from models import Base
from database import engine

app = FastAPI()
Base.metadata.create_all(bind=engine)
app.include_router(auth.router)


@app.get("/")
async def home():
    return {"message": "LLM project"}
