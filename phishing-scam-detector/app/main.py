"""FastAPI application: JSON API plus the demo web page."""
from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from .detector import analyze
from .model import get_model

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

@asynccontextmanager
async def lifespan(_: FastAPI):
    get_model()  # trains on first run if no saved model exists
    yield


app = FastAPI(
    lifespan=lifespan,
    title="AI Phishing & Scam Detector",
    description="Scores messages, emails and URLs for phishing/scam risk and explains why.",
    version="1.0.0",
)


class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=10_000,
                      description="Message, email body or URL to check.")

    @field_validator("text")
    @classmethod
    def not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("text must not be blank")
        return v


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/api/analyze")
def analyze_endpoint(req: AnalyzeRequest) -> dict:
    return analyze(req.text)


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")
