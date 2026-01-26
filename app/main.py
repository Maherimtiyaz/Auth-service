from fastapi import FastAPI

app = FastAPI()

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