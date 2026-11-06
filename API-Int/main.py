import sys
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

# Setup paths so imports resolve cleanly whether run from workspace root or API-Int
APP_DIR = Path(__file__).resolve().parent
ROOT_DIR = APP_DIR.parent
for p in (APP_DIR, ROOT_DIR, ROOT_DIR / "security-layer", ROOT_DIR / "ML"):
    p_str = str(p)
    if p_str not in sys.path:
        sys.path.insert(0, p_str)

from routes.analyze import router

app = FastAPI(
    title="TechAstra AI Phishing & Impersonation Defense API",
    description="Unified API combining AI/ML classification, rule-based heuristics, and brand impersonation detection.",
    version="1.0"
)

# Enable CORS so browser frontend can call API from any host or file:// origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Connect analysis routes
app.include_router(router)

UI_FILE = ROOT_DIR / "ui-ux" / "prototype.html"
PREVIEWS_DIR = ROOT_DIR / "ui-ux" / "previews"
if PREVIEWS_DIR.exists():
    app.mount("/previews", StaticFiles(directory=str(PREVIEWS_DIR)), name="previews")


@app.get("/")
def serve_website():
    """Serves the interactive web application directly."""
    if UI_FILE.exists():
        return FileResponse(UI_FILE)
    return {
        "message": "Welcome to TechAstra API",
        "project": "AI Phishing and Impersonation Defense System",
        "status": "Running"
    }


@app.get("/health")
@app.get("/api/status")
def api_status():
    """Health check endpoint for system monitoring."""
    return {
        "message": "Welcome to TechAstra API",
        "project": "AI Phishing and Impersonation Defense System",
        "status": "Running",
        "version": "1.0"
    }
