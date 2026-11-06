"""
TechAstra AI Phishing & Impersonation Defense System
Main Application Runner
"""
import sys
from pathlib import Path
import uvicorn

BASE_DIR = Path(__file__).resolve().parent
API_DIR = BASE_DIR / "API-Int"
sys.path.insert(0, str(API_DIR))
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "security-layer"))
sys.path.insert(0, str(BASE_DIR / "ML"))

if __name__ == "__main__":
    print("\n" + "=" * 65)
    print("  TechAstra AI Phishing & Impersonation Defense System")
    print("=" * 65)
    print("  Website & API starting at: http://127.0.0.1:8000")
    print("  Interactive API Docs at:   http://127.0.0.1:8000/docs")
    print("=" * 65 + "\n")

    uvicorn.run(
        "main:app",
        app_dir=str(API_DIR),
        host="127.0.0.1",
        port=8000,
        reload=False
    )
