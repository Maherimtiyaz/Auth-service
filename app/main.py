from fastapi import FastAPI
from app.database import engine, Base
from app.routes import auth_routes
from app.routes import user_routes
from app import models

app = FastAPI()

# CREATE TABLES AFTER MODELS ARE LOADED 

Base.metadata.create_all(bind=engine)

#Connection auth routes
app.include_router(auth_routes.router)

# Connection user routes
app.include_router(user_routes.router)


@app.get("/")
async def reas_root():
    """
    A simple root endpoint that returns a welcome message.
    """
    return {"message": "Welcome to the FastAPI application!"}


@app.get("/health")
async def health_check():
    """
    A health check endpoint that returns the status of the application.
    """
    return {"status": "healthy"}