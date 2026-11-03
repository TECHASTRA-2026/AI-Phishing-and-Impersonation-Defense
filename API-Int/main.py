from fastapi import FastAPI
from routes.analyze import router

app = FastAPI(
    title="TechAstra API",
    description="AI Phishing and Impersonation Defense System",
    version="1.0"
)


@app.get("/")
def home():

    return {
        "message": "Welcome to TechAstra API",
        "project": "AI Phishing and Impersonation Defense System",
        "status": "Running"
    }


# Connect all API routes
app.include_router(router)