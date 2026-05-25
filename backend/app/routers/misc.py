# backend/app/routers/misc.py
"""Misc endpoints - health, screenshot serving, root frontend."""

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..database import get_db

router = APIRouter()

SCREENSHOTS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "data" / "screenshots"
FRONTEND_DIR    = Path(__file__).resolve().parent.parent.parent.parent / "frontend"


@router.get("/api/health", tags=["API"])
async def health_check(db: Session = Depends(get_db)):
    """Check API + database status."""
    try:
        db.execute(text("SELECT 1"))
        return {"api": "healthy", "database": "connected"}
    except Exception as e:
        return {"api": "healthy", "database": f"error: {e}"}


@router.get("/api/screenshot/{filename}", tags=["API"])
async def serve_screenshot(filename: str):
    """Serve a captured screenshot image."""
    filepath = SCREENSHOTS_DIR / filename
    if not filepath.exists():
        raise HTTPException(status_code=404, detail="Screenshot non trouvé")
    return FileResponse(str(filepath), media_type="image/png")


@router.get("/", include_in_schema=False)
async def serve_frontend():
    """Serve the frontend SPA."""
    html_path = FRONTEND_DIR / "index.html"
    if html_path.exists():
        return FileResponse(str(html_path), media_type="text/html")
    return {"message": "Frontend non trouvé", "api_docs": "/api/docs"}
