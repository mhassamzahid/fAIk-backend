from fastapi import FastAPI
from .database import engine
from . import models
from .routers import auth
from starlette.middleware.sessions import SessionMiddleware
import os
from dotenv import load_dotenv

models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="Auth API")

app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET_KEY", "super-secret-key")  # change for production
)

app.include_router(auth.router)

@app.get("/")
def root():
    return {"message": "API running"}