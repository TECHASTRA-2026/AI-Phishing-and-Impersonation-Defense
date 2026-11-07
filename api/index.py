import sys
from pathlib import Path

# Add project root and internal modules to sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
API_INT_DIR = ROOT_DIR / "API-Int"
SEC_DIR = ROOT_DIR / "security-layer"
ML_DIR = ROOT_DIR / "ML"

for p in (ROOT_DIR, API_INT_DIR, SEC_DIR, ML_DIR):
    p_str = str(p)
    if p_str not in sys.path:
        sys.path.insert(0, p_str)

from main import app
